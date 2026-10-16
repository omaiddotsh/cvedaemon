"""OSV.dev ingestor.

OSV publishes, per ecosystem, an incremental change index plus one JSON file
per advisory on a public GCS bucket:

* ``{bucket}/{ecosystem}/modified_id.csv`` — ``<modified>,<id>`` rows, newest
  first (``2026-10-13T02:56:32.03282437Z,GHSA-6688-9rhm-gjv2``). We stream it
  and stop at the first row older than ``since``, closing the response so the
  rest (npm's file is ~9 MB; a day of changes is the first ~10 KB) is never
  downloaded.
* ``{bucket}/{ecosystem}/{id}.json`` — the record itself (~9 KB), fetched for
  each changed id with bounded concurrency.

Records go through the HTTP client's TTL cache: a cycle that is cut short
(timeout, partial failure) is retried next cycle without re-downloading what
already arrived. A cached copy older than the CSV row is refetched.

OpenSSF malicious-packages reports (``MAL-`` ids) carry no CVSS, so they skip
the ``min_cvss`` gate and are classed ``malicious_package``: they are scored
like CVEs, so only popular packages alert.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

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

log = get_logger("osv")

_BUCKET_URL = "https://osv-vulnerabilities.storage.googleapis.com"
# Per-ecosystem ceiling on the CSV read + record fetches. A normal cycle needs
# seconds; a backlog after a long outage can need minutes. Records fetched
# before a timeout stay in the HTTP cache, so the next cycle resumes cheaply.
_ECOSYSTEM_FETCH_TIMEOUT = 600.0
_CSV_TIMEOUT = 60.0
_RECORD_TIMEOUT = 30.0
# Record fetches in flight at once (ecosystems are fetched one after another,
# so this is per source).
_RECORD_FETCH_CONCURRENCY = 8
# A window this large means a long outage or a reset checkpoint. Still fetched
# in full (never truncated), but worth a warning: it takes a while.
_LARGE_WINDOW_IDS = 20_000
# Stop starting new record fetches in an ecosystem after this many failures:
# upstream is clearly unhealthy, and retrying thousands of records would burn
# the ecosystem timeout and lose everything fetched so far. The ecosystem is
# reported incomplete either way.
_MAX_RECORD_FAILURES = 25

_MALICIOUS_PACKAGES_SOURCE = "github.com/ossf/malicious-packages/"


class _RecordFetchError(Exception):
    """One record could not be fetched (non-404 HTTP status)."""


class OsvSource(Source):
    name = "osv"

    def __init__(self, http: HttpClient, base_url: str, ecosystems: list[str], min_cvss: float):
        self._http = http
        # base_url (the OSV query API) is unused: the change index and records
        # live on a fixed GCS bucket. Kept for config/constructor compatibility.
        self._base = base_url.rstrip("/")
        self._ecosystems = ecosystems
        self._min_cvss = min_cvss

    async def fetch(self, since: datetime) -> list[Advisory]:
        """Pull all advisories modified-since from OSV's per-ecosystem change index.

        A failed ecosystem (its CSV, or any of its record fetches) does not
        abort the others: everything that did arrive is returned inside
        ``SourceFetchIncomplete`` so the daemon processes it without advancing
        the checkpoint. If every ecosystem fails and nothing was parsed, a
        plain ``RuntimeError`` is raised.
        """
        results: list[Advisory] = []
        failed: list[str] = []
        for ecosystem in self._ecosystems:
            try:
                advisories = await asyncio.wait_for(
                    self._fetch_ecosystem(ecosystem, since),
                    timeout=_ECOSYSTEM_FETCH_TIMEOUT,
                )
            except asyncio.TimeoutError:
                failed.append(ecosystem)
                log.warning(
                    "osv.ecosystem_timeout",
                    ecosystem=ecosystem,
                    timeout=_ECOSYSTEM_FETCH_TIMEOUT,
                )
                continue
            except SourceFetchIncomplete as exc:
                # Some of this ecosystem's records failed; keep what arrived.
                failed.append(ecosystem)
                log.warning("osv.ecosystem_incomplete", ecosystem=ecosystem, error=str(exc))
                results.extend(exc.advisories)
                continue
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                failed.append(ecosystem)
                log.warning(
                    "osv.ecosystem_failed",
                    ecosystem=ecosystem,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                continue
            results.extend(advisories)
        if not failed:
            return results
        if len(failed) == len(self._ecosystems) and not results:
            # Complete OSV outage: escalate so operators don't miss it.
            log.error("osv.all_ecosystems_failed", count=len(failed))
            raise RuntimeError(f"osv: all {len(failed)} ecosystems failed")
        raise SourceFetchIncomplete(
            f"osv: {len(failed)}/{len(self._ecosystems)} ecosystems failed "
            f"({', '.join(failed)})",
            results,
        )

    async def _fetch_ecosystem(self, ecosystem: str, since: datetime) -> list[Advisory]:
        """Advisories for one ecosystem; ``SourceFetchIncomplete`` if any record failed."""
        changed = await self._changed_since(ecosystem, since)
        if len(changed) > _LARGE_WINDOW_IDS:
            log.warning(
                "osv.large_window",
                ecosystem=ecosystem,
                ids=len(changed),
                threshold=_LARGE_WINDOW_IDS,
                since=since.isoformat(),
            )
        advisories, failed, not_attempted = await self._fetch_records(ecosystem, changed, since)
        log.info(
            "osv.ecosystem_fetched",
            ecosystem=ecosystem,
            changed=len(changed),
            advisories=len(advisories),
            failed=failed,
        )
        if failed:
            detail = f"{failed}/{len(changed)} record fetches failed"
            if not_attempted:
                detail += f", {not_attempted} not attempted"
            raise SourceFetchIncomplete(f"osv {ecosystem}: {detail}", advisories)
        return advisories

    async def _changed_since(
        self, ecosystem: str, since: datetime
    ) -> list[tuple[str, datetime | None]]:
        """``(id, modified)`` for every record modified at or after ``since``, newest first.

        Reads ``modified_id.csv`` as a stream and stops at the first row older
        than ``since``. A row whose timestamp does not parse is kept with
        ``modified=None`` (the record's own ``modified`` decides), never
        treated as the end of the window.
        """
        url = f"{_BUCKET_URL}/{quote(ecosystem, safe='')}/modified_id.csv"
        changed: dict[str, datetime | None] = {}
        bad_rows = 0
        async with self._http.stream_lines(url, timeout=_CSV_TIMEOUT) as (status, lines):
            if status != 200:
                log.warning(
                    "osv.bad_status", ecosystem=ecosystem, file="modified_id.csv", status=status
                )
                raise RuntimeError(f"osv {ecosystem}: modified_id.csv HTTP {status}")
            async for line in lines:
                row = line.strip()
                if not row:
                    continue
                stamp, _, rec_id = row.partition(",")
                rec_id = rec_id.strip()
                if not rec_id:
                    bad_rows += 1
                    continue
                modified: datetime | None
                try:
                    modified = _parse_dt(stamp)
                except ValueError:
                    bad_rows += 1
                    modified = None
                if modified is not None and modified < since:
                    break  # newest first: every remaining row is older too
                changed.setdefault(rec_id, modified)
        if bad_rows:
            log.warning("osv.csv_bad_rows", ecosystem=ecosystem, rows=bad_rows)
        return list(changed.items())

    async def _fetch_records(
        self,
        ecosystem: str,
        changed: list[tuple[str, datetime | None]],
        since: datetime,
    ) -> tuple[list[Advisory], int, int]:
        """Fetch + parse records with bounded concurrency.

        Returns ``(advisories in CSV order, failed fetches, ids not attempted)``.
        404s (record deleted after the CSV was written), unreadable bodies and
        records that fail to parse are logged and skipped, not failures.
        """
        parsed: list[Advisory | None] = [None] * len(changed)
        pending = iter(enumerate(changed))
        attempted = 0
        failed = 0

        async def worker() -> None:
            nonlocal attempted, failed
            # One shared iterator: each id is taken by exactly one worker.
            for idx, (rec_id, csv_modified) in pending:
                if failed >= _MAX_RECORD_FAILURES:
                    return
                attempted += 1
                try:
                    raw = await self._get_record(ecosystem, rec_id, csv_modified)
                except (httpx.HTTPError, RuntimeError, _RecordFetchError) as exc:
                    failed += 1
                    log.warning(
                        "osv.record_fetch_failed",
                        ecosystem=ecosystem,
                        id=rec_id,
                        error_type=type(exc).__name__,
                        error=str(exc)[:200],
                    )
                    continue
                if raw is not None:
                    parsed[idx] = self._parse_record(raw, ecosystem, since)

        workers = min(_RECORD_FETCH_CONCURRENCY, len(changed))
        await asyncio.gather(*(worker() for _ in range(workers)))
        if failed >= _MAX_RECORD_FAILURES and attempted < len(changed):
            log.error(
                "osv.record_fetch_aborted",
                ecosystem=ecosystem,
                failed=failed,
                not_attempted=len(changed) - attempted,
            )
        return [a for a in parsed if a is not None], failed, len(changed) - attempted

    async def _get_record(
        self, ecosystem: str, rec_id: str, csv_modified: datetime | None
    ) -> Any:
        """One record's JSON body, or None when it is gone (404) or unreadable."""
        url = f"{_BUCKET_URL}/{quote(ecosystem, safe='')}/{quote(rec_id, safe='')}.json"
        status, body, _ = await self._http.get_json(url, timeout=_RECORD_TIMEOUT)
        if status == 200 and not _is_current(body, csv_modified):
            # Cached copy predates this CSV row (re-modified within the cache
            # TTL): refetch and replace it.
            status, body, _ = await self._http.get_json(
                url, timeout=_RECORD_TIMEOUT, refresh=True
            )
        if status == 404:
            # Deleted or renamed between the CSV write and now; nothing to fetch.
            log.warning("osv.record_missing", ecosystem=ecosystem, id=rec_id)
            return None
        if status != 200:
            raise _RecordFetchError(f"HTTP {status}")
        if isinstance(body, dict) and "_raw" in body:
            # get_json's marker for a 200 whose body is not JSON.
            log.warning("osv.record_unreadable", ecosystem=ecosystem, id=rec_id)
            return None
        return body

    def _parse_record(self, raw: Any, ecosystem: str, since: datetime) -> Advisory | None:
        # One malformed record must not drop the rest of the ecosystem.
        try:
            return _parse_osv_record(raw, since, self._min_cvss)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            log.warning(
                "osv.parse_failed",
                ecosystem=ecosystem,
                id=_record_id(raw),
                error_type=type(exc).__name__,
                error=str(exc)[:200],
            )
            return None


def _is_current(body: Any, csv_modified: datetime | None) -> bool:
    """Whether a fetched record is at least as new as its change-index row."""
    if csv_modified is None:
        return True
    modified = body.get("modified") if isinstance(body, dict) else None
    if not isinstance(modified, str):
        return False
    try:
        return _parse_dt(modified) >= csv_modified
    except ValueError:
        return False


def _record_id(raw: Any) -> str | None:
    """Best-effort id for log lines about a record that failed to parse."""
    if isinstance(raw, dict):
        rid = raw.get("id")
        return rid if isinstance(rid, str) else None
    return None


def _parse_osv_record(raw: dict[str, Any], since: datetime, min_cvss: float) -> Advisory | None:
    """Normalize one OSV record.

    None when it is out of window, withdrawn, or below min_cvss. Malicious-
    package reports never carry a CVSS, so they bypass min_cvss; as class
    ``malicious_package`` they are scored like CVEs downstream (enrichment +
    threshold), so only popular packages alert.

    Malformed input (bad dates, wrong types) raises; the caller logs and skips.
    """
    modified_str = raw.get("modified") or raw.get("published")
    if not modified_str:
        return None
    modified = _parse_dt(modified_str)
    if modified < since:
        return None
    if raw.get("withdrawn"):
        # Retracted (e.g. a malicious-package false positive); never alert.
        return None

    cvss = _highest_cvss(raw.get("severity") or [])
    malicious = _is_malicious_package(raw)
    if not malicious and not _passes_min_cvss(raw, cvss, min_cvss):
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
        advisory_class=AdvisoryClass.MALICIOUS_PACKAGE if malicious else AdvisoryClass.CVE,
        cvss=cvss,
        summary=(raw.get("summary") or raw.get("details") or "")[:1000],
        published=published,
        modified=modified,
        affected=affected,
        aliases=list(raw.get("aliases") or []),
        references=[r.get("url", "") for r in (raw.get("references") or []) if r.get("url")],
        raw=raw,
    )


def _is_malicious_package(raw: dict[str, Any]) -> bool:
    """An OpenSSF malicious-packages report, as OSV publishes it.

    Matches the ``MAL-`` id prefix, or the provenance OSV attaches to those
    records in case one is ever published under another id: a top-level
    ``database_specific["malicious-packages-origins"]`` list, or an
    ``affected[].database_specific.source`` URL into ossf/malicious-packages.
    """
    rec_id = raw.get("id")
    if isinstance(rec_id, str) and rec_id.startswith("MAL-"):
        return True
    db_specific = raw.get("database_specific")
    if isinstance(db_specific, dict) and db_specific.get("malicious-packages-origins"):
        return True
    for entry in raw.get("affected") or []:
        entry_db = entry.get("database_specific") if isinstance(entry, dict) else None
        source = entry_db.get("source") if isinstance(entry_db, dict) else None
        if isinstance(source, str) and _MALICIOUS_PACKAGES_SOURCE in source:
            return True
    return False


def _passes_min_cvss(raw: dict[str, Any], cvss: float | None, min_cvss: float) -> bool:
    """Gate a record on min_cvss.

    A known score is compared directly. An unknown score (no severity entry,
    or only a CVSS v4 vector we cannot compute) is dropped — conservative —
    unless the record's ``database_specific.severity`` label is CRITICAL, in
    which case it passes with ``cvss`` left None. With ``min_cvss <= 0`` every
    record passes, since no score can fall below the gate.
    """
    if min_cvss <= 0:
        return True
    if cvss is not None:
        return cvss >= min_cvss
    db_specific = raw.get("database_specific")
    if isinstance(db_specific, dict):
        label = db_specific.get("severity")
        if isinstance(label, str) and label.strip().upper() == "CRITICAL":
            return True
    return False


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
        if not isinstance(s, dict):
            continue
        score = s.get("score")
        if not score:
            continue
        parsed: float | None = None
        # Try numeric first (legacy + some custom feeds). A numeric score is
        # used whatever its CVSS version, so v4 records that ship one are scored.
        try:
            parsed = float(score)
        except (TypeError, ValueError):
            parsed = _score_from_vector(str(score))
        if parsed is None or not 0.0 <= parsed <= 10.0:
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
# table, so a v4 *vector* is not scored here (a numeric v4 score is used as-is).
# An unscored record is "unknown": _passes_min_cvss drops it unless the record's
# `database_specific.severity` label is CRITICAL (conservative).

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


_FRACTION_RE = re.compile(r"(?<=\d\d:\d\d:\d\d)\.(\d+)")


def _parse_dt(value: str) -> datetime:
    """Parse an RFC 3339 timestamp ("...Z" or with offset) as an aware datetime.

    OSV stamps carry nanoseconds ("2026-10-13T02:56:32.03282437Z"); fractional
    seconds are truncated to microseconds (normalized to 6 digits, which is
    all ``fromisoformat`` accepts on Python 3.10). Raises ``ValueError`` when
    unparseable.
    """
    value = value.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    value = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value, count=1)
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
