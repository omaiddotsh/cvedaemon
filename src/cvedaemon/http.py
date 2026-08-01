"""Async HTTP client with on-disk response cache + TTL eviction."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from cvedaemon.log import get_logger

log = get_logger("http")

# json.loads can yield either dict or list. The disk cache stores whatever
# the upstream returned; callers branch on isinstance(body, list).
JsonBody = Any


def _parse_retry_after(value: str | None) -> float:
    """Parse RFC 7231 Retry-After: integer seconds OR HTTP-date.

    Returns seconds to sleep. Defaults to 1.0 for None/garbage.
    """
    if not value:
        return 1.0
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(value)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        delta = (target - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except (TypeError, ValueError, IndexError):
        return 1.0


class HttpClient:
    """Wraps httpx.AsyncClient with optional disk cache for GETs."""

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        cache_ttl_seconds: int = 3600,
        default_timeout: float = 30.0,
        user_agent: str = "cvedaemon/0.1",
    ):
        self._cache_dir = Path(cache_dir) if cache_dir else None
        self._ttl = cache_ttl_seconds
        self._client = httpx.AsyncClient(
            timeout=default_timeout,
            headers={"User-Agent": user_agent},
            follow_redirects=True,
        )
        if self._cache_dir:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._evict_expired()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        cache: bool = True,
        timeout: float | None = None,
    ) -> tuple[int, JsonBody, dict[str, str]]:
        cached = self._cache_get(url, params) if cache and self._cache_dir else None
        if cached is not None:
            return 200, cached, {}

        for attempt in range(3):
            try:
                r = await self._client.get(
                    url, headers=headers, params=params, timeout=timeout
                )
            except httpx.HTTPError:
                if attempt == 2:
                    raise
                await asyncio.sleep(0.5 * (2**attempt))
                continue

            if r.status_code in (429, 502, 503, 504) and attempt < 2:
                retry_after = _parse_retry_after(r.headers.get("Retry-After"))
                log.warning("http.retry", status=r.status_code, url=url, sleep=retry_after)
                await asyncio.sleep(min(retry_after, 30.0))
                continue

            try:
                data = r.json() if r.content else {}
            except json.JSONDecodeError:
                data = {"_raw": r.text}

            if cache and self._cache_dir and r.status_code == 200:
                self._cache_put(url, params, data)
            return r.status_code, data, dict(r.headers)

        log.warning("http.retry_exhausted", url=url)
        raise RuntimeError(f"http retries exhausted for {url}")

    async def post(
        self,
        url: str,
        *,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> httpx.Response:
        # follow_redirects defaults False on POST so an attacker-controlled
        # redirect cannot re-target the request (and the auth header) at a
        # different host.
        return await self._client.post(
            url,
            json=json_body,
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> httpx.Response:
        return await self._client.request(
            method,
            url,
            json=json_body,
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    async def get_bytes_cached(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> tuple[int, bytes | None]:
        """GET a binary resource with ETag / Last-Modified conditional revalidation.

        Returns (status, body). On a cache hit revalidated as still-fresh
        (HTTP 304), status is 200 and body is the previously-cached payload.
        On a real 200, body is the response bytes (and the cache is updated).
        On any other status, body is None.
        """
        meta = self._bytes_cache_load_meta(url)
        req_headers: dict[str, str] = {}
        if meta:
            if meta.get("etag"):
                req_headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                req_headers["If-Modified-Since"] = meta["last_modified"]
        try:
            r = await self._client.get(url, headers=req_headers, timeout=timeout)
        except httpx.HTTPError as exc:
            log.warning("http.get_bytes_failed", url=url, error=str(exc))
            return 0, None
        if r.status_code == 304 and meta:
            body = self._bytes_cache_load_body(url)
            if body is not None:
                # Refresh meta timestamp so TTL cleanup leaves it alone.
                self._bytes_cache_store(url, body, r.headers, refresh_only=True)
                return 200, body
            # Cache file lost but server says unchanged; degrade to fresh GET.
            r = await self._client.get(url, timeout=timeout)
        if r.status_code == 200:
            body = r.content
            self._bytes_cache_store(url, body, r.headers)
            return 200, body
        return r.status_code, None

    # ---------- bytes cache helpers ----------

    def _bytes_cache_meta_path(self, url: str) -> Path:
        assert self._cache_dir is not None
        key = hashlib.sha256(("bytes::" + url).encode()).hexdigest()
        return self._cache_dir / f"bytes-{key}.meta.json"

    def _bytes_cache_body_path(self, url: str) -> Path:
        assert self._cache_dir is not None
        key = hashlib.sha256(("bytes::" + url).encode()).hexdigest()
        return self._cache_dir / f"bytes-{key}.bin"

    def _bytes_cache_load_meta(self, url: str) -> dict[str, Any] | None:
        if not self._cache_dir:
            return None
        path = self._bytes_cache_meta_path(url)
        if not path.exists():
            return None
        try:
            meta = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - meta.get("_ts", 0) > self._ttl:
            try:
                path.unlink(missing_ok=True)
                self._bytes_cache_body_path(url).unlink(missing_ok=True)
            except OSError:
                pass
            return None
        return meta

    def _bytes_cache_load_body(self, url: str) -> bytes | None:
        if not self._cache_dir:
            return None
        path = self._bytes_cache_body_path(url)
        try:
            return path.read_bytes()
        except OSError:
            return None

    def _bytes_cache_store(
        self,
        url: str,
        body: bytes,
        headers: httpx.Headers | dict[str, str],
        *,
        refresh_only: bool = False,
    ) -> None:
        if not self._cache_dir:
            return
        meta_path = self._bytes_cache_meta_path(url)
        body_path = self._bytes_cache_body_path(url)
        try:
            etag = headers.get("etag") or headers.get("ETag")
            last_mod = headers.get("last-modified") or headers.get("Last-Modified")
            meta = {
                "_ts": time.time(),
                "etag": etag or "",
                "last_modified": last_mod or "",
            }
            # Atomic body write only when actually fetching a new payload.
            if not refresh_only:
                fd, tmp_body = tempfile.mkstemp(
                    prefix=".bytes.", suffix=".tmp", dir=str(self._cache_dir)
                )
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(body)
                    os.replace(tmp_body, body_path)
                except OSError:
                    try:
                        os.unlink(tmp_body)
                    except OSError:
                        pass
                    raise
            fd, tmp_meta = tempfile.mkstemp(
                prefix=".bytes.", suffix=".meta.tmp", dir=str(self._cache_dir)
            )
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(json.dumps(meta))
                os.replace(tmp_meta, meta_path)
            except OSError:
                try:
                    os.unlink(tmp_meta)
                except OSError:
                    pass
                raise
        except OSError as exc:
            log.warning("http.bytes_cache_write_failed", url=url, error=str(exc))

    # ---------- cache helpers ----------

    def _cache_key(self, url: str, params: dict[str, Any] | None) -> str:
        h = hashlib.sha256()
        h.update(url.encode())
        if params:
            h.update(json.dumps(params, sort_keys=True, default=str).encode())
        return h.hexdigest()

    def _cache_path(self, key: str) -> Path:
        assert self._cache_dir is not None
        return self._cache_dir / f"{key}.json"

    def _cache_get(self, url: str, params: dict[str, Any] | None) -> dict[str, Any] | None:
        path = self._cache_path(self._cache_key(url, params))
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - payload.get("_ts", 0) > self._ttl:
            try:
                path.unlink()
            except OSError:
                pass
            return None
        return payload.get("body")

    def _cache_put(self, url: str, params: dict[str, Any] | None, body: JsonBody) -> None:
        path = self._cache_path(self._cache_key(url, params))
        payload = json.dumps({"_ts": time.time(), "body": body})
        # Atomic write: tmp file in the same dir, then rename. Eliminates
        # torn-file reads when two coroutines write the same key.
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=".cache.", suffix=".tmp", dir=str(path.parent)
            )
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(payload)
                os.replace(tmp_path, path)
            except OSError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as exc:
            log.warning("http.cache_write_failed", error=str(exc))

    def _evict_expired(self) -> None:
        if not self._cache_dir or not self._cache_dir.exists():
            return
        now = time.time()
        for p in self._cache_dir.glob("*.json"):
            try:
                ts = json.loads(p.read_text()).get("_ts", 0)
                if now - ts > self._ttl:
                    p.unlink()
            except (OSError, json.JSONDecodeError):
                try:
                    p.unlink()
                except OSError:
                    pass
