"""deps.dev dependents count lookup."""

from __future__ import annotations

from urllib.parse import quote

from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger

log = get_logger("depsdev")


# deps.dev "system" name per ecosystem.
_SYSTEM = {
    "npm": "npm",
    "PyPI": "pypi",
    "RubyGems": "rubygems",
    "crates.io": "cargo",
    "NuGet": "nuget",
    "Maven": "maven",
    "Go": "go",
    "Packagist": "packagist",
    "Pub": "pub",
    "Hex": "hex",
    "SwiftURL": "swifturl",
    "GitHub Actions": "ghactions",
}


class DepsDevClient:
    def __init__(self, http: HttpClient):
        self._http = http
        self._base = "https://api.deps.dev/v3"

    async def dependents(self, ecosystem: str, name: str) -> int | None:
        system = _SYSTEM.get(ecosystem)
        if not system or not name:
            return None
        url = f"{self._base}/systems/{system}/packages/{quote(name, safe='')}:dependents"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            log.info(
                "depsdev.no_data", endpoint="dependents", ecosystem=ecosystem,
                name=name, status=status,
            )
            return None
        # deps.dev v3 dependents response shape:
        # {"dependentCount": {"direct": int, "indirect": int, "total": int}}
        dc = body.get("dependentCount") or body.get("dependent_count") or {}
        total = dc.get("total")
        if total is None:
            direct = dc.get("direct") or 0
            indirect = dc.get("indirect") or 0
            total = direct + indirect
        try:
            return int(total) if total is not None else None
        except (TypeError, ValueError):
            return None

    async def repo_url(self, ecosystem: str, name: str) -> str | None:
        """Best-effort lookup of the package's source repo URL via deps.dev."""
        system = _SYSTEM.get(ecosystem)
        if not system or not name:
            return None
        url = f"{self._base}/systems/{system}/packages/{quote(name, safe='')}"
        status, body, _ = await self._http.get_json(url, cache=True, timeout=20.0)
        if status != 200:
            log.info(
                "depsdev.no_data", endpoint="package", ecosystem=ecosystem,
                name=name, status=status,
            )
            return None
        versions = body.get("versions") or []
        if not versions:
            return None
        latest_key = versions[-1].get("versionKey", {}).get("version")
        if not latest_key:
            return None
        version_url = (
            f"{self._base}/systems/{system}/packages/{quote(name, safe='')}/versions/"
            f"{quote(latest_key, safe='')}"
        )
        status, vbody, _ = await self._http.get_json(version_url, cache=True, timeout=20.0)
        if status != 200:
            log.info(
                "depsdev.no_data", endpoint="version", ecosystem=ecosystem,
                name=name, status=status,
            )
            return None
        for link in vbody.get("links") or []:
            href = link.get("url", "")
            if "github.com" in href:
                return href
        return None
