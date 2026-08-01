"""GitHub Global Security Advisories ingestor (GHSA)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger
from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from cvedaemon.sources.base import Source

log = get_logger("github")


_OSV_ECOSYSTEM_FROM_GHSA = {
    "npm": "npm",
    "pip": "PyPI",
    "rubygems": "RubyGems",
    "rust": "crates.io",
    "nuget": "NuGet",
    "maven": "Maven",
    "go": "Go",
    "composer": "Packagist",
    "pub": "Pub",
    "erlang": "Hex",
    "swift": "SwiftURL",
    "actions": "GitHub Actions",
}

_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


class GithubSource(Source):
    name = "github"

    def __init__(
        self,
        http: HttpClient,
        base_url: str,
        token: str,
        severities: list[str],
        min_cvss: float,
    ):
        self._http = http
        self._base = base_url.rstrip("/")
        self._token = token
        self._severities = [s.lower() for s in severities] or ["critical"]
        self._min_cvss = min_cvss
        if not token:
            log.warning("github.no_token")

    async def fetch(self, since: datetime) -> list[Advisory]:
        # We require since to carry a tzinfo so the upstream "modified=>=..."
        # query is unambiguous (GHSA expects UTC). Defensive assert — never
        # observed in production but cheap.
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        results: list[Advisory] = []
        url = f"{self._base}/advisories"
        params = {
            "type": "reviewed",
            "modified": f">={since.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "per_page": 100,
        }
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        next_url: str | None = url
        next_params: dict[str, Any] | None = params
        for _ in range(50):  # hard cap on pagination
            if next_url is None:
                break
            status, body, resp_headers = await self._http.get_json(
                next_url, headers=headers, params=next_params, cache=False, timeout=60.0
            )
            if status == 403:
                # GHSA returns 403 with X-RateLimit-* on quota exhaustion.
                # Surface reset epoch so operators know when it'll recover.
                reset = resp_headers.get("x-ratelimit-reset") or resp_headers.get("X-RateLimit-Reset")
                remaining = resp_headers.get("x-ratelimit-remaining") or resp_headers.get("X-RateLimit-Remaining")
                log.warning("github.rate_limited", reset=reset, remaining=remaining)
                break
            if status != 200:
                log.warning(
                    "github.bad_status",
                    status=status,
                    body=str(body)[:200],
                )
                break
            if not isinstance(body, list):
                break
            for raw in body:
                if raw.get("severity", "").lower() not in self._severities:
                    continue
                adv = _parse_ghsa(raw, self._min_cvss)
                if adv is not None:
                    results.append(adv)

            link = resp_headers.get("link") or resp_headers.get("Link") or ""
            m = _LINK_RE.search(link)
            if m:
                next_url = m.group(1)
                next_params = None  # next URL already encodes params
            else:
                next_url = None
        return results


def _parse_ghsa(raw: dict[str, Any], min_cvss: float) -> Advisory | None:
    ghsa_id = raw.get("ghsa_id")
    if not ghsa_id:
        return None
    cvss = None
    cvss_block = raw.get("cvss") or {}
    if cvss_block.get("score") is not None:
        try:
            cvss = float(cvss_block["score"])
        except (TypeError, ValueError):
            cvss = None
    if cvss is not None and cvss < min_cvss:
        return None

    affected: list[AffectedPackage] = []
    for vuln in raw.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        ecosystem = _OSV_ECOSYSTEM_FROM_GHSA.get(
            (pkg.get("ecosystem") or "").lower(), pkg.get("ecosystem") or ""
        )
        name = pkg.get("name")
        if ecosystem and name:
            affected.append(AffectedPackage(ecosystem=ecosystem, name=name))

    aliases = []
    cve_id = raw.get("cve_id")
    if cve_id:
        aliases.append(cve_id)
    aliases.append(ghsa_id)

    return Advisory(
        id=ghsa_id,
        source=SourceKind.GITHUB,
        advisory_class=AdvisoryClass.CVE,
        cvss=cvss,
        summary=(raw.get("summary") or "")[:1000],
        published=_parse_dt(raw.get("published_at")),
        modified=_parse_dt(raw.get("updated_at")),
        affected=affected,
        aliases=aliases,
        references=[r.get("url", "") for r in (raw.get("references") or []) if r.get("url")],
        raw=raw,
    )


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
