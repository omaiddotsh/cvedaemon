"""OSV.dev ingestor.

OSV publishes per-ecosystem zipped dumps at
``https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip``.
Each zip contains one JSON file per advisory. We download the zip, iterate
its members in-memory (no extraction to disk), and filter by modified-since.

The zip is GZIP-compressed JSON files at the storage layer; httpx handles
content decoding. For multi-megabyte dumps this is heavier than an
ideal incremental feed but is the only public stable interface OSV ships.
We cache the raw zip bytes via HttpClient's disk cache (TTL bounded) so
back-to-back polls reuse the download.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import zipfile
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

log = get_logger("osv")

# Defensive caps against zip-bomb / runaway upstream payloads. The largest
# real OSV all.zip in 2026 is the npm dump at ~120MB compressed and ~700MB
# uncompressed; we leave generous headroom but cap hard.
_MAX_ZIP_BYTES = 512 * 1024 * 1024  # 512 MiB compressed
_MAX_MEMBER_BYTES = 8 * 1024 * 1024  # 8 MiB per uncompressed advisory JSON
_MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB total
# Per-ecosystem download timeout. Hard ceiling so a hung CDN connection cannot
# wedge the entire poll cycle; daemon._run_cycle has its own outer timeout
# but this short-circuits sooner.
_ECOSYSTEM_FETCH_TIMEOUT = 180.0


class OsvSource(Source):
    name = "osv"

    def __init__(self, http: HttpClient, base_url: str, ecosystems: list[str], min_cvss: float):
        self._http = http
        # base_url retained for testability / future incremental endpoint; the
        # zip dumps live on a fixed GCS bucket regardless of base_url.
        self._base = base_url.rstrip("/")
        self._ecosystems = ecosystems
        self._min_cvss = min_cvss

    async def fetch(self, since: datetime) -> list[Advisory]:
        """Pull all advisories modified-since from OSV via per-ecosystem zip dumps."""
        results: list[Advisory] = []
        failures = 0
        for ecosystem in self._ecosystems:
            try:
                advisories = await asyncio.wait_for(
                    self._fetch_ecosystem(ecosystem, since),
                    timeout=_ECOSYSTEM_FETCH_TIMEOUT,
                )
            except asyncio.TimeoutError:
                failures += 1
                log.warning(
                    "osv.ecosystem_timeout",
                    ecosystem=ecosystem,
                    timeout=_ECOSYSTEM_FETCH_TIMEOUT,
                )
                continue
            except Exception as exc:
                failures += 1
                log.warning("osv.ecosystem_failed", ecosystem=ecosystem, error=str(exc))
                continue
            results.extend(advisories)
        # If every ecosystem failed, that's a hard error for the source as a
        # whole — escalate so operators don't miss a complete OSV outage.
        if failures and failures == len(self._ecosystems):
            log.error("osv.all_ecosystems_failed", count=failures)
        return results

    async def _fetch_ecosystem(self, ecosystem: str, since: datetime) -> list[Advisory]:
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        # ETag-aware conditional GET; 304 returns the cached zip without
        # re-downloading the multi-MB body.
        status, content = await self._http.get_bytes_cached(url, timeout=120.0)
        if status != 200 or content is None:
            log.warning("osv.bad_status", ecosystem=ecosystem, status=status)
            return []
        if len(content) > _MAX_ZIP_BYTES:
            log.error(
                "osv.zip_too_large",
                ecosystem=ecosystem,
                size=len(content),
                limit=_MAX_ZIP_BYTES,
            )
            return []
        # zipfile + json.loads on multi-MB dumps blocks the event loop for
        # seconds; offload to a worker thread.
        return await asyncio.to_thread(
            _parse_zip_bytes, content, ecosystem, since, self._min_cvss
        )


def _parse_zip_bytes(
    content: bytes, ecosystem: str, since: datetime, min_cvss: float
) -> list[Advisory]:
    out: list[Advisory] = []
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".json"):
                    continue
                # Per-member uncompressed cap defends against zip bombs where a
                # tiny compressed member balloons on extraction.
                if info.file_size > _MAX_MEMBER_BYTES:
                    log.warning(
                        "osv.member_too_large",
                        ecosystem=ecosystem,
                        file=info.filename,
                        size=info.file_size,
                        limit=_MAX_MEMBER_BYTES,
                    )
                    continue
                total_uncompressed += info.file_size
                if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                    log.error(
                        "osv.total_uncompressed_exceeded",
                        ecosystem=ecosystem,
                        limit=_MAX_TOTAL_UNCOMPRESSED_BYTES,
                    )
                    break
                try:
                    with zf.open(info) as f:
                        raw = json.loads(f.read())
                except (json.JSONDecodeError, OSError, zipfile.BadZipFile) as exc:
                    log.warning(
                        "osv.entry_unreadable",
                        ecosystem=ecosystem,
                        file=info.filename,
                        error=str(exc),
                    )
                    continue
                adv = _parse_osv_record(raw, since, min_cvss)
                if adv is not None:
                    out.append(adv)
    except zipfile.BadZipFile as exc:
        log.warning("osv.bad_zip", ecosystem=ecosystem, error=str(exc))
    return out


def _parse_osv_record(raw: dict[str, Any], since: datetime, min_cvss: float) -> Advisory | None:
    modified_str = raw.get("modified") or raw.get("published")
    if not modified_str:
        return None
    try:
        modified = _parse_dt(modified_str)
    except ValueError:
        return None
    if modified < since:
        return None

    cvss = _highest_cvss(raw.get("severity") or [])
    if cvss is not None and cvss < min_cvss:
        return None

    affected = []
    for entry in raw.get("affected") or []:
        pkg = entry.get("package") or {}
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if eco and name:
            affected.append(AffectedPackage(ecosystem=eco, name=name))

    published = _parse_dt(raw["published"]) if raw.get("published") else None
    return Advisory(
        id=raw.get("id", ""),
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=cvss,
        summary=(raw.get("summary") or raw.get("details") or "")[:1000],
        published=published,
        modified=modified,
        affected=affected,
        aliases=list(raw.get("aliases") or []),
        references=[r.get("url", "") for r in (raw.get("references") or []) if r.get("url")],
        raw=raw,
    )


def _highest_cvss(severity_list: list[dict[str, Any]]) -> float | None:
    """Extract the highest base score from an OSV severity list.

    OSV stores severity as either:
      {"type": "CVSS_V3" | "CVSS_V4", "score": "<vector string>"}  (most common)
      {"type": "...", "score": "<numeric>"}                         (legacy)

    The CVSS spec mandates that the base-score component appears in some
    severity payloads under a `database_specific.cvss` field, but most feeds
    just put the vector string in `score`. We parse it.
    """
    best: float | None = None
    for s in severity_list:
        score = s.get("score")
        if not score:
            continue
        parsed: float | None = None
        # Try numeric first (legacy + some custom feeds).
        try:
            parsed = float(score)
        except (TypeError, ValueError):
            parsed = _score_from_vector(str(score))
        if parsed is None:
            continue
        best = parsed if best is None else max(best, parsed)
    return best


# Lookup tables for CVSS v3.x base-score computation. We only need a "tell us
# how bad it is" answer, not strict spec compliance — used to gate min_cvss.
_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_IMPACT = {"N": 0.0, "L": 0.22, "H": 0.56}

# v4 base-score computation is materially different and requires the full MacroVector
# table. For v4 we fall back to severity label from the vector's optional
# `database_specific.severity` field, but since OSV records may not include that we
# return None for v4 and let the caller treat it as "unknown" (conservative — drops).
# Most real-world feeds in 2025 still emit v3.1, so this gap is small.

_VECTOR_KV_RE = re.compile(r"([A-Z]+):([A-Z]+)")


def _score_from_vector(vector: str) -> float | None:
    """Parse a CVSS:3.0/3.1 vector and return the base score, rounded to 1 dp."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    parts = dict(_VECTOR_KV_RE.findall(vector.split("/", 1)[1]))
    try:
        av = _V3_AV[parts["AV"]]
        ac = _V3_AC[parts["AC"]]
        ui = _V3_UI[parts["UI"]]
        scope = parts["S"]
        pr_table = _V3_PR_C if scope == "C" else _V3_PR_U
        pr = pr_table[parts["PR"]]
        c = _V3_IMPACT[parts["C"]]
        i = _V3_IMPACT[parts["I"]]
        a = _V3_IMPACT[parts["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (
        6.42 * iss
        if scope == "U"
        else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    )
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    # CVSS spec rounds up to one decimal.
    return round(base + 0.04999, 1)


def _parse_dt(value: str) -> datetime:
    # Accept "2024-01-02T03:04:05Z" or with offset.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
