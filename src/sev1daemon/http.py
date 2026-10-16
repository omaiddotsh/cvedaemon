"""Async HTTP client with on-disk response cache + TTL eviction."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from sev1daemon.log import get_logger

log = get_logger("http")

# json.loads can yield either dict or list. The disk cache stores whatever
# the upstream returned; callers branch on isinstance(body, list).
JsonBody = Any

# Statuses retried by get_json and stream_lines (after honoring Retry-After).
_RETRY_STATUSES = (429, 502, 503, 504)
# Longest Retry-After we will sleep through before retrying. GitHub secondary
# rate limits ask for 60s+; anything longer is handed back to the caller (with
# the 429/403 status) so it can back off instead of wedging the cycle.
_MAX_RETRY_AFTER_SECONDS = 300.0


# Minimum wait before retrying a retryable status, doubled per attempt.
_RETRY_BACKOFF_SECONDS = 1.0


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


def _is_retryable(r: httpx.Response) -> bool:
    if r.status_code in _RETRY_STATUSES:
        return True
    # GitHub secondary rate limits come back as 403 + Retry-After. A 403
    # without it is an auth/permission answer and is not retried.
    return r.status_code == 403 and "retry-after" in r.headers


class HttpClient:
    """Wraps httpx.AsyncClient with optional disk cache for GETs."""

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        cache_ttl_seconds: int = 3600,
        default_timeout: float = 30.0,
        user_agent: str = "sev1daemon/0.1",
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

    def _timeout(self, timeout: float | None) -> httpx.Timeout:
        """``None`` means the client's default timeout, not httpx's "no timeout"."""
        return self._client.timeout if timeout is None else httpx.Timeout(timeout)

    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        cache: bool = True,
        refresh: bool = False,
        timeout: float | None = None,
        max_retry_after: float = _MAX_RETRY_AFTER_SECONDS,
    ) -> tuple[int, JsonBody, dict[str, str]]:
        """GET + parse JSON. Returns ``(status, body, headers)``.

        429/502/503/504 — and 403 carrying ``Retry-After`` (GitHub's secondary
        rate limit) — are retried after the server's Retry-After, as long as
        it is at most ``max_retry_after`` seconds. A longer requested wait is
        not slept through: the response is returned so the caller backs off.

        ``refresh=True`` skips the cached copy but still stores the new
        response (when ``cache`` is on), replacing a copy the caller knows is
        stale. ``timeout=None`` uses the client's default timeout.
        """
        if cache and not refresh and self._cache_dir:
            cached = self._cache_get(url, params)
            if cached is not None:
                return 200, cached, {}

        for attempt in range(3):
            try:
                r = await self._client.get(
                    url, headers=headers, params=params, timeout=self._timeout(timeout)
                )
            except httpx.HTTPError:
                if attempt == 2:
                    raise
                await asyncio.sleep(0.5 * (2**attempt))
                continue

            if _is_retryable(r) and attempt < 2:
                retry_after = _parse_retry_after(r.headers.get("Retry-After"))
                if retry_after <= max_retry_after:
                    # Never retry faster than exponential backoff: some APIs
                    # (npm's downloads endpoint) answer 429 with Retry-After: 0.
                    sleep_for = max(retry_after, _RETRY_BACKOFF_SECONDS * (2**attempt))
                    log.warning("http.retry", status=r.status_code, url=url, sleep=sleep_for)
                    await asyncio.sleep(sleep_for)
                    continue
                log.warning(
                    "http.retry_after_too_long",
                    status=r.status_code,
                    url=url,
                    retry_after=retry_after,
                    ceiling=max_retry_after,
                )

            try:
                data = r.json() if r.content else {}
            except json.JSONDecodeError:
                data = {"_raw": r.text}

            if cache and self._cache_dir and r.status_code == 200:
                self._cache_put(url, params, data)
            return r.status_code, data, dict(r.headers)

        log.warning("http.retry_exhausted", url=url)
        raise RuntimeError(f"http retries exhausted for {url}")

    @asynccontextmanager
    async def stream_lines(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_retry_after: float = _MAX_RETRY_AFTER_SECONDS,
    ) -> AsyncIterator[tuple[int, AsyncIterator[str]]]:
        """Streaming GET for line-oriented bodies; yields ``(status, lines)``.

        ``lines`` reads the body lazily and yields each decoded line without
        its terminator. Leaving the ``async with`` block closes the response,
        so a caller that stops iterating early never downloads the rest.

        Opening the response follows ``get_json``'s retry policy (transport
        errors, then 429/502/503/504 and 403 + Retry-After up to
        ``max_retry_after``). Once body bytes are flowing, an
        ``httpx.HTTPError`` mid-body propagates: the caller has consumed part
        of the body, so it decides whether to retry. Never cached. On a
        non-2xx status ``lines`` is left unread and the body is discarded.
        """
        r = await self._open_stream(
            url, headers=headers, timeout=timeout, max_retry_after=max_retry_after
        )
        try:
            yield r.status_code, r.aiter_lines()
        finally:
            await r.aclose()

    async def _open_stream(
        self,
        url: str,
        *,
        headers: dict[str, str] | None,
        timeout: float | None,
        max_retry_after: float,
    ) -> httpx.Response:
        for attempt in range(3):
            request = self._client.build_request(
                "GET", url, headers=headers, timeout=self._timeout(timeout)
            )
            try:
                r = await self._client.send(request, stream=True)
            except httpx.HTTPError:
                if attempt == 2:
                    raise
                await asyncio.sleep(0.5 * (2**attempt))
                continue

            if _is_retryable(r) and attempt < 2:
                retry_after = _parse_retry_after(r.headers.get("Retry-After"))
                if retry_after <= max_retry_after:
                    await r.aclose()
                    log.warning("http.retry", status=r.status_code, url=url, sleep=retry_after)
                    await asyncio.sleep(retry_after)
                    continue
                log.warning(
                    "http.retry_after_too_long",
                    status=r.status_code,
                    url=url,
                    retry_after=retry_after,
                    ceiling=max_retry_after,
                )
            return r

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

    async def evict_expired(self) -> int:
        """Remove expired cache entries and stale temp files; returns files removed.

        Runs the directory scan in a worker thread so housekeeping does not
        block the event loop.
        """
        return await asyncio.to_thread(self._evict_expired)

    def _evict_expired(self) -> int:
        if not self._cache_dir or not self._cache_dir.exists():
            return 0
        now = time.time()
        removed = 0

        def _unlink(path: Path) -> None:
            nonlocal removed
            try:
                path.unlink()
                removed += 1
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.warning("http.cache_evict_failed", file=path.name, error=str(exc))

        # Legacy binary cache (bytes-<key>.bin + bytes-<key>.meta.json) from
        # the old OSV all.zip download, hundreds of MB. Nothing writes or
        # reads it any more, so it is reclaimed whatever its age.
        for p in self._cache_dir.glob("bytes-*"):
            _unlink(p)

        # JSON responses (<key>.json) carry a ``_ts`` stamp. Unreadable or
        # corrupt entries are removed too.
        for p in self._cache_dir.glob("*.json"):
            try:
                ts = json.loads(p.read_text()).get("_ts", 0)
                expired = now - ts > self._ttl
            except (OSError, json.JSONDecodeError, AttributeError, TypeError):
                expired = True
            if expired:
                _unlink(p)

        # Temp files left behind by a crash mid-write (including the legacy
        # ``.bytes.*.tmp``). Age-gated on mtime so in-flight writes are never
        # touched.
        for p in self._cache_dir.glob("*.tmp"):
            try:
                stale = now - p.stat().st_mtime > self._ttl
            except OSError:
                continue
            if stale:
                _unlink(p)
        return removed
