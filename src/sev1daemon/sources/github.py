"""GitHub Global Security Advisories ingestor (GHSA)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, NoReturn

import httpx

from sev1daemon.http import HttpClient
from sev1daemon.log import get_logger
from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from sev1daemon.sources.base import Source, SourceFetchIncomplete

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

# Hard cap on pagination per fetch. Reaching it with a next link still pending
# means the window was not fully read, which is reported as incomplete.
_MAX_PAGES = 50


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
            # Retractions bump updated_at, so a withdrawn advisory lands in the
            # poll window the moment it is withdrawn; _parse_ghsa drops any that
            # still come through (the filter is advisory, the parse check is not).
            "is_withdrawn": "false",
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
        for page in range(_MAX_PAGES):
            if next_url is None:
                break
            try:
                status, body, resp_headers = await self._http.get_json(
                    next_url, headers=headers, params=next_params, cache=False, timeout=60.0
                )
            except httpx.HTTPError as exc:
                if not page:
                    raise
                log.error(
                    "github.page_failed",
                    page=page,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                raise SourceFetchIncomplete(
                    f"github: page {page} failed: {exc}", results
                ) from exc
            if status == 403:
                # GHSA returns 403 with X-RateLimit-* on quota exhaustion.
                # Surface reset epoch so operators know when it'll recover.
                reset = resp_headers.get("x-ratelimit-reset") or resp_headers.get("X-RateLimit-Reset")
                remaining = resp_headers.get("x-ratelimit-remaining") or resp_headers.get("X-RateLimit-Remaining")
                log.warning("github.rate_limited", reset=reset, remaining=remaining)
                self._raise_page_failure(f"github: HTTP 403 on page {page}", page, results)
            if status != 200:
                log.warning(
                    "github.bad_status",
                    status=status,
                    body=str(body)[:200],
                )
                self._raise_page_failure(f"github: HTTP {status} on page {page}", page, results)
            if not isinstance(body, list):
                log.warning("github.unexpected_body", body=str(body)[:200])
                self._raise_page_failure(
                    f"github: unexpected response body on page {page}", page, results
                )
            for raw in body:
                if not isinstance(raw, dict):
                    continue
                if (raw.get("severity") or "").lower() not in self._severities:
                    continue
                # One malformed advisory must not drop the rest of the page.
                try:
                    adv = _parse_ghsa(raw, self._min_cvss)
                except (AttributeError, KeyError, TypeError, ValueError) as e:
                    log.warning(
                        "github.parse_failed",
                        ghsa_id=raw.get("ghsa_id"),
                        error_type=type(e).__name__,
                        error=str(e)[:200],
                    )
                    continue
                if adv is not None:
                    results.append(adv)

            link = resp_headers.get("link") or resp_headers.get("Link") or ""
            m = _LINK_RE.search(link)
            if m:
                next_url = m.group(1)
                next_params = None  # next URL already encodes params
            else:
                next_url = None
        if next_url is not None:
            log.warning("github.page_cap_reached", pages=_MAX_PAGES, advisories=len(results))
            raise SourceFetchIncomplete(
                f"github: stopped at the {_MAX_PAGES}-page cap with more pages pending",
                results,
            )
        return results

    @staticmethod
    def _raise_page_failure(message: str, page: int, results: list[Advisory]) -> NoReturn:
        """First page failed → nothing usable (plain error); later page → partial."""
        if not page:
            raise RuntimeError(message)
        raise SourceFetchIncomplete(message, results)


def _parse_ghsa(raw: dict[str, Any], min_cvss: float) -> Advisory | None:
    ghsa_id = raw.get("ghsa_id")
    if not ghsa_id:
        return None
    if raw.get("withdrawn_at"):
        # Retracted; OSV drops the same record on its ``withdrawn`` field, and
        # the GitHub copy must not survive the merge and alert on its own.
        return None
    cvss = _ghsa_cvss(raw)
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
        references=_ghsa_references(raw.get("references")),
        raw=raw,
    )


def _ghsa_cvss(raw: dict[str, Any]) -> float | None:
    """Highest CVSS score on the advisory, or None when it has none.

    The global advisories API carries scores in ``cvss_severities`` (``cvss_v3``
    and ``cvss_v4``); the older ``cvss`` field is deprecated and is often null
    when only a v4 vector exists. A score of 0 means "not scored".
    """
    candidates: list[Any] = []
    severities = raw.get("cvss_severities")
    if isinstance(severities, dict):
        for key in ("cvss_v4", "cvss_v3"):
            block = severities.get(key)
            if isinstance(block, dict):
                candidates.append(block.get("score"))
    legacy = raw.get("cvss")
    if isinstance(legacy, dict):
        candidates.append(legacy.get("score"))

    scores: list[float] = []
    for value in candidates:
        try:
            score = float(value)
        except (TypeError, ValueError):
            continue
        if score > 0:
            scores.append(score)
    return max(scores) if scores else None


def _ghsa_references(refs: Any) -> list[str]:
    """The API returns references as plain URL strings; accept ``{"url": ...}`` too."""
    out: list[str] = []
    for ref in refs or []:
        url = ref.get("url") if isinstance(ref, dict) else ref
        if isinstance(url, str) and url:
            out.append(url)
    return out


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
