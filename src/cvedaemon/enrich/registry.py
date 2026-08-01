"""Per-ecosystem registry download counts.

Window per ecosystem varies; scoring normalizes against the configured
threshold per ecosystem.
"""

from __future__ import annotations

from urllib.parse import quote

from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger

log = get_logger("registry")


class RegistryClient:
    def __init__(self, http: HttpClient):
        self._http = http

    async def downloads(self, ecosystem: str, name: str) -> int | None:
        if not name:
            return None
        handler = {
            "npm": self._npm,
            "PyPI": self._pypi,
            "RubyGems": self._rubygems,
            "crates.io": self._crates,
            "NuGet": self._nuget,
            "Packagist": self._packagist,
        }.get(ecosystem)
        if handler is None:
            return None
        try:
            return await handler(name)
        except Exception as exc:
            log.warning(
                "registry.lookup_failed",
                ecosystem=ecosystem,
                name=name,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return None

    # ---------- per ecosystem ----------

    async def _npm(self, name: str) -> int | None:
        url = f"https://api.npmjs.org/downloads/point/last-week/{quote(name, safe='/@')}"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            _log_bad_status("npm", name, status, body)
            return None
        return _safe_int(body.get("downloads"))

    async def _pypi(self, name: str) -> int | None:
        # pypistats.org gives per-day/week/month totals.
        url = f"https://pypistats.org/api/packages/{quote(name, safe='')}/recent"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            _log_bad_status("PyPI", name, status, body)
            return None
        data = body.get("data") or {}
        return _safe_int(data.get("last_month"))

    async def _rubygems(self, name: str) -> int | None:
        url = f"https://rubygems.org/api/v1/gems/{quote(name, safe='')}.json"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            _log_bad_status("RubyGems", name, status, body)
            return None
        return _safe_int(body.get("downloads"))

    async def _crates(self, name: str) -> int | None:
        url = f"https://crates.io/api/v1/crates/{quote(name, safe='')}"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            _log_bad_status("crates.io", name, status, body)
            return None
        crate = body.get("crate") or {}
        return _safe_int(crate.get("recent_downloads"))

    async def _nuget(self, name: str) -> int | None:
        url = (
            f"https://api-v2v3search-0.nuget.org/query?q=packageid:{quote(name, safe='')}"
            "&prerelease=true"
        )
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            _log_bad_status("NuGet", name, status, body)
            return None
        data = body.get("data") or []
        if not data:
            return None
        return _safe_int(data[0].get("totalDownloads"))

    async def _packagist(self, name: str) -> int | None:
        url = f"https://packagist.org/packages/{quote(name, safe='/')}.json"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            _log_bad_status("Packagist", name, status, body)
            return None
        pkg = body.get("package") or {}
        downloads = pkg.get("downloads") or {}
        return _safe_int(downloads.get("monthly"))


def _log_bad_status(ecosystem: str, name: str, status: int, body) -> None:
    # 404 is the common "package never published / typo" case; log at debug
    # would be ideal but structlog filtering already drops debug by default.
    # info keeps it visible while staying out of warn/error noise.
    log.info(
        "registry.no_data",
        ecosystem=ecosystem,
        name=name,
        status=status,
        body=str(body)[:120],
    )


def _safe_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
