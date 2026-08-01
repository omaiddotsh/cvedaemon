"""NVD API 2.0 ingestor.

Respects 5/30s (no key) or 50/30s (with key) rate windows.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
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

log = get_logger("nvd")


_NVD_WINDOW_MAX_DAYS = 120  # NVD requires lastModStartDate/lastModEndDate ≤ 120d


class NvdSource(Source):
    name = "nvd"

    def __init__(
        self,
        http: HttpClient,
        base_url: str,
        api_key: str,
        results_per_page: int,
        min_cvss: float,
    ):
        self._http = http
        self._base = base_url
        self._api_key = api_key
        self._page_size = min(max(results_per_page, 1), 2000)
        self._min_cvss = min_cvss
        # Rate limit budget: 5 per 30s without key, 50 per 30s with key.
        self._sleep_between = 6.5 if not api_key else 0.7

    async def fetch(self, since: datetime) -> list[Advisory]:
        now = datetime.now(timezone.utc)
        # Clamp window to 120 days — NVD rejects wider ranges with 400.
        if (now - since).days > _NVD_WINDOW_MAX_DAYS:
            since = now.replace(microsecond=0) - timedelta(days=_NVD_WINDOW_MAX_DAYS)

        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        params: dict[str, Any] = {
            "lastModStartDate": _nvd_dt(since),
            "lastModEndDate": _nvd_dt(now),
            "resultsPerPage": self._page_size,
            "startIndex": 0,
        }

        results: list[Advisory] = []
        while True:
            status, body, _ = await self._http.get_json(
                self._base, headers=headers, params=params, cache=False, timeout=60.0
            )
            if status != 200:
                # 5xx mid-pagination silently drops the remainder; log at
                # error so the on-call notices partial fetch coverage.
                level_method = log.error if 500 <= status < 600 else log.warning
                level_method(
                    "nvd.bad_status",
                    status=status,
                    start_index=params["startIndex"],
                    body=str(body)[:200],
                )
                break
            vulns = body.get("vulnerabilities") or []
            for entry in vulns:
                adv = _parse_nvd_record(entry, self._min_cvss)
                if adv is not None:
                    results.append(adv)
            total = body.get("totalResults", 0)
            start = params["startIndex"] + self._page_size
            if start >= int(total or 0):
                break
            params["startIndex"] = start
            await asyncio.sleep(self._sleep_between)
        return results


def _parse_nvd_record(entry: dict[str, Any], min_cvss: float) -> Advisory | None:
    cve = entry.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    summary = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        "",
    )[:1000]

    cvss = _highest_cvss(cve.get("metrics") or {})
    if cvss is not None and cvss < min_cvss:
        return None

    published_raw = cve.get("published")
    published = _parse_dt(published_raw) if isinstance(published_raw, str) else None
    modified_raw = cve.get("lastModified")
    modified = _parse_dt(modified_raw) if isinstance(modified_raw, str) else None

    affected = _extract_affected_from_cpe(cve.get("configurations") or [])

    references = [
        r.get("url", "") for r in (cve.get("references") or []) if r.get("url")
    ]

    return Advisory(
        id=cve_id,
        source=SourceKind.NVD,
        advisory_class=AdvisoryClass.CVE,
        cvss=cvss,
        summary=summary,
        published=published,
        modified=modified,
        affected=affected,
        aliases=[],
        references=references,
        raw=cve,
    )


def _highest_cvss(metrics: dict[str, Any]) -> float | None:
    best: float | None = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            try:
                best = max(best or 0.0, float(score))
            except (TypeError, ValueError):
                pass
    return best


def _extract_affected_from_cpe(configurations: list[dict[str, Any]]) -> list[AffectedPackage]:
    """NVD configurations contain CPE strings — extract package-ish names.

    CPE format: cpe:2.3:a:vendor:product:version:...
    We map to a generic ecosystem of the form ``cpe:vendor`` since NVD CPEs
    don't translate cleanly to npm/PyPI/etc. Downstream OSV enrichment will
    fill in the canonical ecosystem when possible via aliases.
    """
    out: list[AffectedPackage] = []
    seen: set[tuple[str, str]] = set()
    for cfg in configurations:
        for node in cfg.get("nodes") or []:
            for cpe in node.get("cpeMatch") or []:
                criteria = cpe.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) >= 5 and parts[0] == "cpe" and parts[2] == "a":
                    vendor, product = parts[3], parts[4]
                    if not vendor or not product:
                        continue
                    key = (vendor, product)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(AffectedPackage(ecosystem=f"cpe:{vendor}", name=product))
    return out


def _nvd_dt(dt: datetime) -> str:
    # NVD wants ISO 8601 with milliseconds + explicit UTC marker.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
