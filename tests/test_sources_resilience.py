"""Resilience tests for the source ingestors. No network: HTTP is mocked with respx.

Covers: partial fetches surface as ``SourceFetchIncomplete`` (never a silently
truncated list), per-record parse resilience, the OSV change-index feed
(early stop at ``since``, bounded record fetches, 404 skips, URL encoding,
stale-cache refetch), the OSV min_cvss gate for unscored records, malicious-
package classification, and RSS id namespacing + ecosystem cue matching.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx
import pytest
import respx

from sev1daemon.config import RssSourceConfig
from sev1daemon.http import HttpClient
from sev1daemon.models import AdvisoryClass, AffectedPackage
from sev1daemon.sources import github as github_mod
from sev1daemon.sources import nvd as nvd_mod
from sev1daemon.sources import osv as osv_mod
from sev1daemon.sources import rss as rss_mod
from sev1daemon.sources.base import SourceFetchIncomplete
from sev1daemon.sources.github import GithubSource
from sev1daemon.sources.nvd import NvdSource
from sev1daemon.sources.osv import OsvSource, _parse_dt, _parse_osv_record
from sev1daemon.sources.rss import RssSource, _guess_ecosystems

NOW = datetime.now(timezone.utc)
TS = NOW.isoformat().replace("+00:00", "Z")
SINCE = NOW - timedelta(days=1)
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_URL = "https://api.github.com/advisories"


class _RecordingLog:
    """Stand-in for a module's structlog logger; records (level, event, fields)."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def _rec(self, level: str):
        def _log(event: str, **kw: Any) -> None:
            self.events.append((level, event, kw))

        return _log

    def __getattr__(self, level: str):
        return self._rec(level)

    def named(self, event: str) -> list[dict[str, Any]]:
        return [kw for _, ev, kw in self.events if ev == event]


@pytest.fixture
async def http(tmp_path):
    client = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    yield client
    await client.aclose()


def _csv_url(ecosystem: str) -> str:
    return f"{OSV_BUCKET}/{quote(ecosystem, safe='')}/modified_id.csv"


def _rec_url(ecosystem: str, rec_id: str) -> str:
    return f"{OSV_BUCKET}/{quote(ecosystem, safe='')}/{quote(rec_id, safe='')}.json"


# Rows older than SINCE. Never fetched: no routes exist for them, so a fetch
# would trip respx's assert_all_mocked and fail the test.
_OLD_ROWS = "".join(f"2000-01-0{i}T00:00:00.123456789Z,OLD-{i}\n" for i in range(1, 4))


def _osv_csv(*rows: tuple[str, str], older: bool = True) -> str:
    """modified_id.csv body: ``(modified, id)`` rows, newest first, then old rows."""
    return "".join(f"{stamp},{rec_id}\n" for stamp, rec_id in rows) + (_OLD_ROWS if older else "")


def _mock_osv(ecosystem: str, records: list[dict[str, Any]]) -> dict[str, respx.Route]:
    """Serve a change index listing ``records`` (stamped TS) plus each record's JSON."""
    respx.get(_csv_url(ecosystem)).mock(
        return_value=httpx.Response(200, text=_osv_csv(*((TS, r["id"]) for r in records)))
    )
    return {
        r["id"]: respx.get(_rec_url(ecosystem, r["id"])).mock(
            return_value=httpx.Response(200, json=r)
        )
        for r in records
    }


def _osv_rec(rec_id: str, **extra: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "id": rec_id,
        "modified": TS,
        "published": TS,
        "summary": rec_id,
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [{"package": {"ecosystem": "npm", "name": rec_id.lower()}}],
    }
    rec.update(extra)
    return rec


def _nvd_vuln(cve_id: str, score: float = 9.8, **cve_extra: Any) -> dict[str, Any]:
    cve: dict[str, Any] = {
        "id": cve_id,
        "published": TS,
        "lastModified": TS,
        "descriptions": [{"lang": "en", "value": cve_id}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
    }
    cve.update(cve_extra)
    return {"cve": cve}


def _ghsa(ghsa_id: str) -> dict[str, Any]:
    return {
        "ghsa_id": ghsa_id,
        "severity": "critical",
        "summary": ghsa_id,
        "published_at": TS,
        "updated_at": TS,
        "cvss": {"score": 9.8},
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "pkg"}}],
        "references": [],
    }


@pytest.fixture
def fast_sleep(monkeypatch):
    """Make retry/backoff sleeps instant; records the requested durations."""
    real_sleep = asyncio.sleep
    calls: list[float] = []

    async def _sleep(seconds: float, *args: Any, **kwargs: Any) -> None:
        calls.append(seconds)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    return calls


# ======================================================================
# NVD
# ======================================================================


def _nvd(http: HttpClient) -> NvdSource:
    src = NvdSource(http, NVD_URL, api_key="", results_per_page=1, min_cvss=9.0)
    src._sleep_between = 0  # type: ignore[attr-defined]
    return src


@respx.mock
async def test_nvd_mid_pagination_error_is_incomplete_with_partial(http):
    respx.get(NVD_URL).mock(
        side_effect=[
            httpx.Response(200, json={"totalResults": 3, "vulnerabilities": [_nvd_vuln("CVE-2099-0001")]}),
            httpx.Response(500, json={"message": "boom"}),
        ]
    )
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _nvd(http).fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["CVE-2099-0001"]
    assert "startIndex=1" in str(exc.value)


@respx.mock
async def test_nvd_first_page_error_is_plain_exception(http):
    respx.get(NVD_URL).mock(return_value=httpx.Response(403, json={}))
    with pytest.raises(Exception) as exc:
        await _nvd(http).fetch(SINCE)
    assert not isinstance(exc.value, SourceFetchIncomplete)


@respx.mock
async def test_nvd_transport_error_mid_pagination_is_incomplete(http, fast_sleep):
    respx.get(NVD_URL).mock(
        side_effect=[
            httpx.Response(200, json={"totalResults": 2, "vulnerabilities": [_nvd_vuln("CVE-2099-0002")]}),
            httpx.ConnectError("reset"),
            httpx.ConnectError("reset"),
            httpx.ConnectError("reset"),
        ]
    )
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _nvd(http).fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["CVE-2099-0002"]
    assert isinstance(exc.value.__cause__, httpx.ConnectError)


@respx.mock
async def test_nvd_complete_fetch_returns_list(http):
    respx.get(NVD_URL).mock(
        return_value=httpx.Response(
            200, json={"totalResults": 1, "vulnerabilities": [_nvd_vuln("CVE-2099-0003")]}
        )
    )
    out = await _nvd(http).fetch(SINCE)
    assert [a.id for a in out] == ["CVE-2099-0003"]


@respx.mock
async def test_nvd_window_wider_than_120_days_is_clamped_to_120(http, monkeypatch):
    """NVD rejects a lastMod window wider than 120 days, even by an hour
    ("Date range cannot exceed 120 days", HTTP 404, checked live 2026-10).
    ``(now - since).days`` truncates, so a 120d 1h window used to go out
    unclamped and fail every cycle until it had grown past 121 days."""
    rec_log = _RecordingLog()
    monkeypatch.setattr(nvd_mod, "log", rec_log)
    route = respx.get(NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    since = datetime.now(timezone.utc) - timedelta(days=120, hours=1)
    await _nvd(http).fetch(since)
    params = route.calls.last.request.url.params
    start = datetime.strptime(params["lastModStartDate"], "%Y-%m-%dT%H:%M:%S.000Z").replace(
        tzinfo=timezone.utc
    )
    end = datetime.strptime(params["lastModEndDate"], "%Y-%m-%dT%H:%M:%S.000Z").replace(
        tzinfo=timezone.utc
    )
    assert end - start <= timedelta(days=120)
    assert end - start > timedelta(days=119, hours=23)
    # Clamping drops part of the requested window; that must be visible.
    clamped = rec_log.named("nvd.window_clamped")
    assert len(clamped) == 1
    assert clamped[0]["requested_since"] == since.isoformat()


@respx.mock
async def test_nvd_window_within_120_days_is_not_clamped(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(nvd_mod, "log", rec_log)
    route = respx.get(NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    since = (datetime.now(timezone.utc) - timedelta(days=119, hours=23)).replace(microsecond=0)
    await _nvd(http).fetch(since)
    params = route.calls.last.request.url.params
    assert params["lastModStartDate"] == since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert rec_log.named("nvd.window_clamped") == []


@respx.mock
async def test_nvd_malformed_record_is_logged_and_skipped(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(nvd_mod, "log", rec_log)
    vulns = [
        "not-a-dict",
        _nvd_vuln("CVE-2099-0100", published="not-a-date"),
        _nvd_vuln("CVE-2099-0101", descriptions=[None]),
        _nvd_vuln("CVE-2099-0102"),
    ]
    respx.get(NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 4, "vulnerabilities": vulns})
    )
    src = NvdSource(http, NVD_URL, api_key="", results_per_page=10, min_cvss=9.0)
    out = await src.fetch(SINCE)
    assert [a.id for a in out] == ["CVE-2099-0102"]
    failed = rec_log.named("nvd.parse_failed")
    assert [f["cve_id"] for f in failed] == [None, "CVE-2099-0100", "CVE-2099-0101"]
    assert [f["error_type"] for f in failed] == ["AttributeError", "ValueError", "AttributeError"]
    assert all(lvl == "warning" for lvl, ev, _ in rec_log.events if ev == "nvd.parse_failed")


# ======================================================================
# GitHub
# ======================================================================


def _gh(http: HttpClient) -> GithubSource:
    return GithubSource(
        http, base_url="https://api.github.com", token="ghp_dummy", severities=["critical"], min_cvss=9.0
    )


def _next_link(page: int) -> dict[str, str]:
    return {"Link": f'<{GH_URL}?page={page}>; rel="next"'}


@respx.mock
async def test_github_rate_limit_mid_pagination_is_incomplete(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(github_mod, "log", rec_log)
    respx.get(GH_URL).mock(
        side_effect=[
            httpx.Response(200, json=[_ghsa("GHSA-aaaa-aaaa-aaaa")], headers=_next_link(2)),
            httpx.Response(
                403,
                json={"message": "API rate limit exceeded"},
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "4102444800"},
            ),
        ]
    )
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _gh(http).fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["GHSA-aaaa-aaaa-aaaa"]
    # The existing rate-limit warning is kept.
    assert rec_log.named("github.rate_limited") == [{"reset": "4102444800", "remaining": "0"}]


@pytest.mark.parametrize("status", [401, 403, 500, 404])
@respx.mock
async def test_github_first_page_failure_is_plain_exception(http, status):
    respx.get(GH_URL).mock(return_value=httpx.Response(status, json={"message": "no"}))
    with pytest.raises(Exception) as exc:
        await _gh(http).fetch(SINCE)
    assert not isinstance(exc.value, SourceFetchIncomplete)
    assert str(status) in str(exc.value)


@respx.mock
async def test_github_server_error_mid_pagination_is_incomplete(http):
    respx.get(GH_URL).mock(
        side_effect=[
            httpx.Response(200, json=[_ghsa("GHSA-bbbb-bbbb-bbbb")], headers=_next_link(2)),
            httpx.Response(500, json={"message": "oops"}),
        ]
    )
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _gh(http).fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["GHSA-bbbb-bbbb-bbbb"]


@respx.mock
async def test_github_unexpected_body_is_not_success(http):
    respx.get(GH_URL).mock(return_value=httpx.Response(200, json={"message": "not a list"}))
    with pytest.raises(RuntimeError):
        await _gh(http).fetch(SINCE)


@respx.mock
async def test_github_page_cap_is_incomplete(http, monkeypatch):
    monkeypatch.setattr(github_mod, "_MAX_PAGES", 2)
    route = respx.get(GH_URL).mock(
        side_effect=[
            httpx.Response(200, json=[_ghsa("GHSA-cccc-cccc-0001")], headers=_next_link(2)),
            httpx.Response(200, json=[_ghsa("GHSA-cccc-cccc-0002")], headers=_next_link(3)),
        ]
    )
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _gh(http).fetch(SINCE)
    assert route.call_count == 2
    assert [a.id for a in exc.value.advisories] == ["GHSA-cccc-cccc-0001", "GHSA-cccc-cccc-0002"]


@respx.mock
async def test_github_withdrawn_advisory_is_dropped(http):
    """A retraction bumps updated_at, so a withdrawn GHSA lands in the poll
    window the moment it is withdrawn (GHSA-vv44-hjm2-qw2f, 2026-10-16: the
    withdrawal and the last update are one second apart). OSV drops its copy on
    ``withdrawn``; the GitHub copy must go too, or it survives the merge and
    alerts as a live critical CVE."""
    withdrawn = _ghsa("GHSA-wdrn-0001-0001")
    withdrawn["withdrawn_at"] = TS
    route = respx.get(GH_URL).mock(
        return_value=httpx.Response(200, json=[withdrawn, _ghsa("GHSA-live-0001-0001")])
    )
    out = await _gh(http).fetch(SINCE)
    assert [a.id for a in out] == ["GHSA-live-0001-0001"]
    # And the API is asked to leave them out in the first place.
    assert route.calls.last.request.url.params["is_withdrawn"] == "false"


@respx.mock
async def test_github_withdrawn_at_null_is_live(http):
    live = _ghsa("GHSA-live-0002-0002")
    live["withdrawn_at"] = None
    respx.get(GH_URL).mock(return_value=httpx.Response(200, json=[live]))
    out = await _gh(http).fetch(SINCE)
    assert [a.id for a in out] == ["GHSA-live-0002-0002"]


@respx.mock
async def test_github_last_page_without_next_is_complete(http):
    respx.get(GH_URL).mock(
        side_effect=[
            httpx.Response(200, json=[_ghsa("GHSA-dddd-dddd-0001")], headers=_next_link(2)),
            httpx.Response(200, json=[_ghsa("GHSA-dddd-dddd-0002")]),
        ]
    )
    out = await _gh(http).fetch(SINCE)
    assert [a.id for a in out] == ["GHSA-dddd-dddd-0001", "GHSA-dddd-dddd-0002"]


# ======================================================================
# OSV — partial fetches
# ======================================================================


def _osv(http: HttpClient, *ecosystems: str) -> OsvSource:
    return OsvSource(http, "https://api.osv.dev", list(ecosystems), min_cvss=9.0)


@respx.mock
async def test_osv_one_ecosystem_failing_is_incomplete_with_others(http, fast_sleep):
    _mock_osv("npm", [_osv_rec("OSV-NPM-1")])
    respx.get(_csv_url("PyPI")).mock(return_value=httpx.Response(503))
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _osv(http, "npm", "PyPI").fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["OSV-NPM-1"]
    assert "PyPI" in str(exc.value)


@respx.mock
async def test_osv_network_error_counts_as_failed_ecosystem(http, fast_sleep):
    _mock_osv("npm", [_osv_rec("OSV-NPM-2")])
    respx.get(_csv_url("Go")).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _osv(http, "npm", "Go").fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["OSV-NPM-2"]


@respx.mock
async def test_osv_all_ecosystems_failing_raises(http, fast_sleep):
    respx.get(_csv_url("npm")).mock(return_value=httpx.Response(404))
    respx.get(_csv_url("PyPI")).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError) as exc:
        await _osv(http, "npm", "PyPI").fetch(SINCE)
    assert not isinstance(exc.value, SourceFetchIncomplete)


@respx.mock
async def test_osv_ecosystem_timeout_is_incomplete(http, monkeypatch):
    monkeypatch.setattr(osv_mod, "_ECOSYSTEM_FETCH_TIMEOUT", 0.05)
    _mock_osv("npm", [_osv_rec("OSV-NPM-3")])
    src = _osv(http, "npm", "Maven")
    real = src._fetch_ecosystem

    async def _slow_for_maven(ecosystem: str, since: datetime):
        if ecosystem == "Maven":
            await asyncio.sleep(5)
        return await real(ecosystem, since)

    monkeypatch.setattr(src, "_fetch_ecosystem", _slow_for_maven)
    with pytest.raises(SourceFetchIncomplete) as exc:
        await src.fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["OSV-NPM-3"]
    assert "Maven" in str(exc.value)


class _ChunkStream(httpx.AsyncByteStream):
    """Response body served chunk by chunk; records how much of it was read."""

    def __init__(self, chunks: list[bytes], *, fail_after: int | None = None) -> None:
        self.chunks = chunks
        self.fail_after = fail_after
        self.served = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            if self.fail_after is not None and self.served >= self.fail_after:
                raise httpx.ReadError("connection reset mid-body")
            self.served += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@respx.mock
async def test_osv_csv_broken_mid_body_fails_the_ecosystem(http):
    _mock_osv("npm", [_osv_rec("OSV-NPM-5")])
    # The first row arrives, then the connection drops: no record is fetched
    # (no route exists for it) and PyPI counts as failed, not as empty.
    body = _ChunkStream([f"{TS},OSV-PY-1\n".encode(), _OLD_ROWS.encode()], fail_after=1)
    respx.get(_csv_url("PyPI")).mock(return_value=httpx.Response(200, stream=body))
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _osv(http, "npm", "PyPI").fetch(SINCE)
    assert [a.id for a in exc.value.advisories] == ["OSV-NPM-5"]
    assert "PyPI" in str(exc.value)


@respx.mock
async def test_osv_failed_record_fetch_makes_ecosystem_incomplete(http):
    routes = _mock_osv("npm", [_osv_rec("OSV-A"), _osv_rec("OSV-B"), _osv_rec("OSV-C")])
    routes["OSV-B"].mock(return_value=httpx.Response(500))
    _mock_osv("PyPI", [_osv_rec("OSV-PY")])
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _osv(http, "npm", "PyPI").fetch(SINCE)
    # Everything else that arrived, from npm and the healthy PyPI, is carried.
    assert [a.id for a in exc.value.advisories] == ["OSV-A", "OSV-C", "OSV-PY"]
    assert "(npm)" in str(exc.value)


@respx.mock
async def test_osv_stops_fetching_records_after_repeated_failures(http, monkeypatch):
    monkeypatch.setattr(osv_mod, "_MAX_RECORD_FAILURES", 2)
    monkeypatch.setattr(osv_mod, "_RECORD_FETCH_CONCURRENCY", 1)
    records = [_osv_rec(f"OSV-{i}") for i in range(5)]
    respx.get(_csv_url("npm")).mock(
        return_value=httpx.Response(200, text=_osv_csv(*((TS, r["id"]) for r in records)))
    )
    respx.get(_rec_url("npm", "OSV-0")).mock(return_value=httpx.Response(200, json=records[0]))
    failing = respx.get(url__regex=rf"^{re.escape(OSV_BUCKET)}/npm/OSV-[12]\.json$").mock(
        return_value=httpx.Response(500)
    )
    # OSV-3 and OSV-4 have no route: fetching them would fail the test.
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _osv(http, "npm")._fetch_ecosystem("npm", SINCE)
    assert [a.id for a in exc.value.advisories] == ["OSV-0"]
    assert "2/5 record fetches failed, 2 not attempted" in str(exc.value)
    assert failing.call_count == 2


@respx.mock
async def test_osv_record_404_is_skipped_not_a_failure(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(osv_mod, "log", rec_log)
    routes = _mock_osv("npm", [_osv_rec("OSV-GONE"), _osv_rec("OSV-HERE")])
    routes["OSV-GONE"].mock(
        return_value=httpx.Response(
            404,
            text="<?xml version='1.0'?><Error><Code>NoSuchKey</Code></Error>",
            headers={"Content-Type": "application/xml"},
        )
    )
    out = await _osv(http, "npm").fetch(SINCE)  # plain list: the fetch is complete
    assert [a.id for a in out] == ["OSV-HERE"]
    assert rec_log.named("osv.record_missing") == [{"ecosystem": "npm", "id": "OSV-GONE"}]


@respx.mock
async def test_osv_non_json_record_body_is_skipped(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(osv_mod, "log", rec_log)
    routes = _mock_osv("npm", [_osv_rec("OSV-GARBLED"), _osv_rec("OSV-OK")])
    routes["OSV-GARBLED"].mock(return_value=httpx.Response(200, text="<html>oops</html>"))
    out = await _osv(http, "npm").fetch(SINCE)
    assert [a.id for a in out] == ["OSV-OK"]
    assert [e["id"] for e in rec_log.named("osv.record_unreadable")] == ["OSV-GARBLED"]


@respx.mock
async def test_osv_all_ok_returns_plain_list(http):
    _mock_osv("npm", [_osv_rec("OSV-NPM-4")])
    # Nothing in the window: only old rows, or an empty file.
    respx.get(_csv_url("PyPI")).mock(return_value=httpx.Response(200, text=_osv_csv()))
    respx.get(_csv_url("Go")).mock(return_value=httpx.Response(200, text=""))
    out = await _osv(http, "npm", "PyPI", "Go").fetch(SINCE)
    assert [a.id for a in out] == ["OSV-NPM-4"]


# ======================================================================
# OSV — change index (modified_id.csv)
# ======================================================================


@respx.mock
async def test_osv_csv_read_stops_at_since_and_closes_the_response(http):
    older = (SINCE - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    body = _ChunkStream(
        [
            _osv_csv((TS, "OSV-NEW-1"), (TS, "OSV-NEW-2"), (older, "OSV-OLD-1"), older=False).encode(),
            # The rest of the (multi-MB) file: never read.
            _OLD_ROWS.encode(),
            b"only read if the early stop failed\n",
        ]
    )
    respx.get(_csv_url("npm")).mock(return_value=httpx.Response(200, stream=body))
    for rec in (_osv_rec("OSV-NEW-1"), _osv_rec("OSV-NEW-2")):
        respx.get(_rec_url("npm", rec["id"])).mock(return_value=httpx.Response(200, json=rec))
    out = await _osv(http, "npm").fetch(SINCE)
    assert [a.id for a in out] == ["OSV-NEW-1", "OSV-NEW-2"]
    assert body.served == 1
    assert body.closed


def _utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("2026-10-13T02:56:32.03282437Z", _utc(2026, 10, 13, 2, 56, 32, 32824)),
        ("2026-10-12T19:30:04.572220135Z", _utc(2026, 10, 12, 19, 30, 4, 572220)),
        ("2026-10-12T19:30:04.5602794Z", _utc(2026, 10, 12, 19, 30, 4, 560279)),
        ("2026-10-12T19:30:04.5Z", _utc(2026, 10, 12, 19, 30, 4, 500000)),
        ("2026-10-12T19:30:04Z", _utc(2026, 10, 12, 19, 30, 4)),
        ("2026-10-12T21:30:04.123456789+02:00", _utc(2026, 10, 12, 19, 30, 4, 123456)),
    ],
)
def test_osv_parse_dt_truncates_nanoseconds(stamp: str, expected: datetime):
    parsed = _parse_dt(stamp)
    assert parsed == expected
    assert parsed.tzinfo is not None


def test_osv_parse_dt_rejects_garbage():
    with pytest.raises(ValueError):
        _parse_dt("yesterday-ish")


@respx.mock
async def test_osv_nanosecond_stamps_bound_the_window_exactly(http):
    since = datetime(2026, 10, 12, 0, 0, 0, 1, tzinfo=timezone.utc)
    inside = "2026-10-12T00:00:00.0000019Z"  # truncates to .000001 == since
    before = "2026-10-12T00:00:00.000000999Z"  # truncates to .000000 < since
    rec = _osv_rec("OSV-EDGE", modified=inside)
    respx.get(_csv_url("npm")).mock(
        return_value=httpx.Response(200, text=_osv_csv((inside, "OSV-EDGE"), (before, "OSV-BEFORE")))
    )
    respx.get(_rec_url("npm", "OSV-EDGE")).mock(return_value=httpx.Response(200, json=rec))
    out = await _osv(http, "npm").fetch(since)
    assert [a.id for a in out] == ["OSV-EDGE"]
    assert out[0].modified == since


@respx.mock
async def test_osv_csv_bad_rows_are_logged_and_unparseable_stamps_still_fetched(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(osv_mod, "log", rec_log)
    body = (
        f"{TS},OSV-GOOD\n"
        "\n"
        "no-comma-here\n"
        f"{TS},\n"
        "not-a-date,OSV-ODD-STAMP\n"
        f"{TS},OSV-GOOD\n" + _OLD_ROWS
    )
    respx.get(_csv_url("npm")).mock(return_value=httpx.Response(200, text=body))
    good = respx.get(_rec_url("npm", "OSV-GOOD")).mock(
        return_value=httpx.Response(200, json=_osv_rec("OSV-GOOD"))
    )
    respx.get(_rec_url("npm", "OSV-ODD-STAMP")).mock(
        return_value=httpx.Response(200, json=_osv_rec("OSV-ODD-STAMP"))
    )
    out = await _osv(http, "npm").fetch(SINCE)
    # A bad stamp is not the end of the window: the record's own `modified` decides.
    assert [a.id for a in out] == ["OSV-GOOD", "OSV-ODD-STAMP"]
    assert good.call_count == 1  # duplicate row, one fetch
    assert rec_log.named("osv.csv_bad_rows") == [{"ecosystem": "npm", "rows": 3}]


@respx.mock
async def test_osv_large_window_is_fetched_in_full_with_a_warning(http, monkeypatch):
    monkeypatch.setattr(osv_mod, "_LARGE_WINDOW_IDS", 3)
    rec_log = _RecordingLog()
    monkeypatch.setattr(osv_mod, "log", rec_log)
    _mock_osv("npm", [_osv_rec(f"OSV-BIG-{i}") for i in range(5)])
    out = await _osv(http, "npm").fetch(SINCE)
    assert len(out) == 5  # never truncated
    [warning] = rec_log.named("osv.large_window")
    assert (warning["ecosystem"], warning["ids"], warning["threshold"]) == ("npm", 5, 3)


# ======================================================================
# OSV — record fetches
# ======================================================================


@respx.mock
async def test_osv_record_fetches_are_bounded_and_keep_csv_order(http):
    records = [_osv_rec(f"OSV-{i:03d}") for i in range(40)]
    respx.get(_csv_url("npm")).mock(
        return_value=httpx.Response(200, text=_osv_csv(*((TS, r["id"]) for r in records)))
    )
    by_path = {f"/npm/{r['id']}.json": r for r in records}
    in_flight = 0
    peak = 0

    async def _serve(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return httpx.Response(200, json=by_path[request.url.path])

    route = respx.get(url__regex=rf"^{re.escape(OSV_BUCKET)}/npm/OSV-\d+\.json$").mock(
        side_effect=_serve
    )
    out = await _osv(http, "npm").fetch(SINCE)
    assert route.call_count == 40
    assert [a.id for a in out] == [r["id"] for r in records]
    assert peak == osv_mod._RECORD_FETCH_CONCURRENCY == 8


@respx.mock
async def test_osv_urls_percent_encode_ecosystem_and_id(http):
    action = _osv_rec(
        "GHSA-aaaa-bbbb-cccc",
        affected=[{"package": {"ecosystem": "GitHub Actions", "name": "org/action"}}],
    )
    odd = _osv_rec("ODD ID+1/x")
    csv = respx.get(f"{OSV_BUCKET}/GitHub%20Actions/modified_id.csv").mock(
        return_value=httpx.Response(200, text=_osv_csv((TS, action["id"]), (TS, odd["id"])))
    )
    action_route = respx.get(f"{OSV_BUCKET}/GitHub%20Actions/GHSA-aaaa-bbbb-cccc.json").mock(
        return_value=httpx.Response(200, json=action)
    )
    odd_route = respx.get(f"{OSV_BUCKET}/GitHub%20Actions/ODD%20ID%2B1%2Fx.json").mock(
        return_value=httpx.Response(200, json=odd)
    )
    out = await _osv(http, "GitHub Actions").fetch(SINCE)
    assert [a.id for a in out] == ["GHSA-aaaa-bbbb-cccc", "ODD ID+1/x"]
    assert csv.calls[0].request.url.raw_path == b"/GitHub%20Actions/modified_id.csv"
    assert action_route.calls[0].request.url.raw_path == b"/GitHub%20Actions/GHSA-aaaa-bbbb-cccc.json"
    assert odd_route.calls[0].request.url.raw_path == b"/GitHub%20Actions/ODD%20ID%2B1%2Fx.json"


@respx.mock
async def test_osv_cached_record_is_reused_until_the_csv_says_it_changed(http):
    t1 = (NOW - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    t2 = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    respx.get(_csv_url("npm")).mock(
        side_effect=[
            httpx.Response(200, text=_osv_csv((t1, "OSV-EDITED"))),
            httpx.Response(200, text=_osv_csv((t1, "OSV-EDITED"))),
            httpx.Response(200, text=_osv_csv((t2, "OSV-EDITED"))),
        ]
    )
    record = respx.get(_rec_url("npm", "OSV-EDITED")).mock(
        side_effect=[
            httpx.Response(200, json=_osv_rec("OSV-EDITED", modified=t1, summary="v1")),
            httpx.Response(200, json=_osv_rec("OSV-EDITED", modified=t2, summary="v2")),
        ]
    )
    src = _osv(http, "npm")
    assert [a.summary for a in await src.fetch(SINCE)] == ["v1"]
    # Retried window (e.g. after an incomplete cycle): served from the cache.
    assert [a.summary for a in await src.fetch(SINCE)] == ["v1"]
    assert record.call_count == 1
    # The CSV row is newer than the cached copy: refetched.
    assert [a.summary for a in await src.fetch(SINCE)] == ["v2"]
    assert record.call_count == 2


# ======================================================================
# OSV — per-record resilience
# ======================================================================


@respx.mock
async def test_osv_malformed_records_are_logged_and_skipped(http, monkeypatch):
    rec_log = _RecordingLog()
    monkeypatch.setattr(osv_mod, "log", rec_log)
    records: list[dict[str, Any]] = [
        _osv_rec("OSV-BAD-DATE", modified="yesterday-ish"),
        _osv_rec("OSV-BAD-AFFECTED", affected=["not-a-dict"]),
        _osv_rec("OSV-NULL-PKG", affected=[{"package": {"ecosystem": None, "name": "x"}}]),
        _osv_rec("OSV-BAD-REFS", references=[None]),
        _osv_rec("OSV-INT-DATE", modified=12345),
        {"id": "OSV-LIST"},
        _osv_rec("OSV-GOOD"),
    ]
    routes = _mock_osv("npm", records)
    routes["OSV-LIST"].mock(
        return_value=httpx.Response(200, json=["a", "list", "not", "an", "object"])
    )
    out = await _osv(http, "npm").fetch(SINCE)  # complete: parse errors are not fetch failures
    # Null ecosystem only drops the package, not the record.
    assert sorted(a.id for a in out) == ["OSV-GOOD", "OSV-NULL-PKG"]
    failed = {f["id"]: f["error_type"] for f in rec_log.named("osv.parse_failed")}
    assert failed == {
        "OSV-BAD-DATE": "ValueError",
        "OSV-BAD-AFFECTED": "AttributeError",
        "OSV-BAD-REFS": "AttributeError",
        "OSV-INT-DATE": "AttributeError",
        None: "AttributeError",
    }
    assert all(f["ecosystem"] == "npm" for f in rec_log.named("osv.parse_failed"))


# ======================================================================
# OSV — min_cvss gate for unscored records
# ======================================================================


def _gate(records: list[dict[str, Any]], min_cvss: float = 9.0) -> dict[str, Any]:
    parsed = (_parse_osv_record(r, SINCE, min_cvss) for r in records)
    return {a.id: a for a in parsed if a is not None}


def test_osv_unscored_record_dropped_unless_critical_label():
    kept = _gate(
        [
            _osv_rec("NO-SEV", severity=[]),
            _osv_rec("NO-SEV-HIGH", severity=None, database_specific={"severity": "HIGH"}),
            _osv_rec("NO-SEV-CRIT", severity=[], database_specific={"severity": "critical"}),
            _osv_rec("NO-SEV-CRIT-UPPER", database_specific={"severity": "CRITICAL"}, severity=None),
        ]
    )
    assert set(kept) == {"NO-SEV-CRIT", "NO-SEV-CRIT-UPPER"}
    assert kept["NO-SEV-CRIT"].cvss is None


def test_osv_known_score_wins_over_critical_label():
    kept = _gate(
        [
            _osv_rec(
                "LOW-BUT-LABELLED",
                severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
                database_specific={"severity": "CRITICAL"},
            )
        ]
    )
    assert kept == {}


def test_osv_cvss_v4_vector_falls_back_to_label_and_numeric_v4_is_scored():
    v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    kept = _gate(
        [
            _osv_rec("V4-VEC-ONLY", severity=[{"type": "CVSS_V4", "score": v4_vector}]),
            _osv_rec(
                "V4-VEC-CRIT",
                severity=[{"type": "CVSS_V4", "score": v4_vector}],
                database_specific={"severity": "CRITICAL"},
            ),
            _osv_rec("V4-NUM-HIGH", severity=[{"type": "CVSS_V4", "score": "9.3"}]),
            _osv_rec("V4-NUM-LOW", severity=[{"type": "CVSS_V4", "score": "6.1"}]),
        ]
    )
    assert set(kept) == {"V4-VEC-CRIT", "V4-NUM-HIGH"}
    assert kept["V4-VEC-CRIT"].cvss is None
    assert kept["V4-NUM-HIGH"].cvss == 9.3


def test_osv_min_cvss_zero_keeps_unscored_records():
    kept = _gate([_osv_rec("NO-SEV", severity=[])], min_cvss=0.0)
    assert set(kept) == {"NO-SEV"}


def test_osv_withdrawn_records_are_dropped():
    kept = _gate(
        [
            _osv_rec("MAL-2099-9", severity=None, withdrawn=TS),
            _osv_rec("GHSA-wdrn-0001", withdrawn=TS),
            _osv_rec("GHSA-live-0001"),
        ]
    )
    assert set(kept) == {"GHSA-live-0001"}


# ======================================================================
# OSV — malicious packages (OpenSSF MAL- records)
# ======================================================================

_MAL_SOURCE = "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/{}/{}.json"


def test_osv_malicious_package_records_bypass_min_cvss_as_their_own_class():
    pkg = {"package": {"ecosystem": "npm", "name": "evil"}}
    kept = _gate(
        [
            _osv_rec("MAL-2099-1", severity=None),
            _osv_rec("MAL-2099-2", severity=None, database_specific={"severity": "CRITICAL"}),
            # Malicious-packages provenance under a non-MAL id.
            _osv_rec(
                "GHSA-orig-0001",
                severity=None,
                database_specific={"malicious-packages-origins": [{"source": "ghsa-malware"}]},
            ),
            _osv_rec(
                "GHSA-srce-0001",
                severity=None,
                affected=[{**pkg, "database_specific": {"source": _MAL_SOURCE.format("evil", "x")}}],
            ),
            # Not malicious-packages: still gated on CVSS.
            _osv_rec("GHSA-empty-0001", severity=None, database_specific={"malicious-packages-origins": []}),
            _osv_rec(
                "GHSA-other-0001",
                severity=None,
                affected=[{**pkg, "database_specific": {"source": "https://github.com/github/advisory-database/x.json"}}],
            ),
            _osv_rec("MALWARE-2099-1", severity=None),
        ]
    )
    assert set(kept) == {"MAL-2099-1", "MAL-2099-2", "GHSA-orig-0001", "GHSA-srce-0001"}
    for adv in kept.values():
        assert adv.advisory_class is AdvisoryClass.MALICIOUS_PACKAGE
        # Scored path (enrichment + threshold), never the always-fire supply-chain path.
        assert not adv.is_supply_chain
        assert adv.cvss is None


def test_osv_scored_records_stay_class_cve():
    kept = _gate([_osv_rec("GHSA-crit-0001")])
    assert kept["GHSA-crit-0001"].advisory_class is AdvisoryClass.CVE


def _live_mal_record() -> dict[str, Any]:
    """Trimmed from the live record fetched 2026-10-12:
    https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2026-17763.json
    """
    return {
        "schema_version": "1.9.0",
        "id": "MAL-2026-17763",
        "published": "2026-10-11T14:01:05Z",
        "modified": "2026-10-12T19:30:04.572220135Z",
        "aliases": ["GHSA-8jgp-jmwc-7fxg"],
        "summary": "Malicious code in @coopeuch/core (npm)",
        "details": "On npm install, postinstall.js automatically executes ...",
        "affected": [
            {
                "package": {
                    "name": "@coopeuch/core",
                    "ecosystem": "npm",
                    "purl": "pkg:npm/%40coopeuch/core",
                },
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                "versions": ["1.999.999"],
                "database_specific": {
                    "cwes": [{"cweId": "CWE-506", "name": "Embedded Malicious Code"}],
                    "source": _MAL_SOURCE.format("@coopeuch/core", "MAL-2026-17763"),
                },
            }
        ],
        "references": [
            {"type": "PACKAGE", "url": "https://www.npmjs.com/package/@coopeuch/core/v/1.999.999"},
            {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-8jgp-jmwc-7fxg"},
        ],
        "database_specific": {
            "malicious-packages-origins": [
                {"id": "IN-MAL-2026-021446", "source": "amazon-inspector", "versions": ["1.999.999"]},
                {"id": "GHSA-8jgp-jmwc-7fxg", "source": "ghsa-malware"},
            ]
        },
        "credits": [{"name": "Amazon Inspector", "type": "FINDER"}],
    }


@respx.mock
async def test_osv_live_shaped_mal_record_end_to_end(http):
    rec = _live_mal_record()
    respx.get(_csv_url("npm")).mock(
        return_value=httpx.Response(200, text=_osv_csv((rec["modified"], rec["id"])))
    )
    respx.get(_rec_url("npm", rec["id"])).mock(return_value=httpx.Response(200, json=rec))
    out = await _osv(http, "npm").fetch(datetime(2026, 10, 12, tzinfo=timezone.utc))
    [adv] = out
    assert adv.advisory_class is AdvisoryClass.MALICIOUS_PACKAGE
    assert not adv.is_supply_chain
    assert adv.cvss is None  # min_cvss=9.0 did not drop it
    assert adv.affected == [AffectedPackage("npm", "@coopeuch/core")]
    assert adv.aliases == ["GHSA-8jgp-jmwc-7fxg"]
    assert adv.modified == datetime(2026, 10, 12, 19, 30, 4, 572220, tzinfo=timezone.utc)


# ======================================================================
# RSS — partial fetches
# ======================================================================

_RSS_OK = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>t</title>
<item>
  <title>Malicious npm packages hit registry (CVE-2099-5555)</title>
  <link>https://news.example/a</link>
  <guid>urn:example:item-1</guid>
  <pubDate>{date}</pubDate>
  <description>supply chain attack</description>
</item>
</channel></rss>
"""


def _rss_body() -> str:
    from email.utils import format_datetime

    return _RSS_OK.format(date=format_datetime(NOW))


def _rss(http: HttpClient, *names: str) -> RssSource:
    feeds = [{"name": n, "url": f"https://feeds.example/{n}.xml"} for n in names]
    return RssSource(http, feeds=feeds, keywords=["supply chain"])


@respx.mock
async def test_rss_failing_feed_is_incomplete_with_other_feeds(http):
    respx.get("https://feeds.example/good.xml").mock(return_value=httpx.Response(200, text=_rss_body()))
    respx.get("https://feeds.example/bad.xml").mock(return_value=httpx.Response(500))
    with pytest.raises(SourceFetchIncomplete) as exc:
        await _rss(http, "good", "bad").fetch(SINCE)
    assert len(exc.value.advisories) == 1
    assert exc.value.advisories[0].raw["feed"] == "good"
    assert "bad" in str(exc.value)


@respx.mock
async def test_rss_unparseable_feed_counts_as_failure(http):
    respx.get("https://feeds.example/good.xml").mock(return_value=httpx.Response(200, text=_rss_body()))
    respx.get("https://feeds.example/html.xml").mock(
        return_value=httpx.Response(200, text="<html><body>maintenance</body>")
    )
    with pytest.raises(SourceFetchIncomplete):
        await _rss(http, "good", "html").fetch(SINCE)


@respx.mock
async def test_rss_all_feeds_failing_raises(http):
    respx.get("https://feeds.example/a.xml").mock(return_value=httpx.Response(502))
    respx.get("https://feeds.example/b.xml").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(RuntimeError) as exc:
        await _rss(http, "a", "b").fetch(SINCE)
    assert not isinstance(exc.value, SourceFetchIncomplete)


@respx.mock
async def test_rss_all_feeds_ok_returns_list(http):
    respx.get("https://feeds.example/good.xml").mock(return_value=httpx.Response(200, text=_rss_body()))
    out = await _rss(http, "good").fetch(SINCE)
    assert len(out) == 1


# ======================================================================
# RSS — id namespace + ecosystem cues + keywords
# ======================================================================


def _entry(title: str, *, guid: str | None = None, link: str = "https://news.example/x", summary: str = ""):
    class E:
        pass

    e = E()
    e.title = title
    e.summary = summary
    e.link = link
    e.published_parsed = (2099, 1, 1, 0, 0, 0)
    if guid is not None:
        e.id = guid
    return e


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_rss_id_is_namespaced_and_cve_goes_to_aliases_only():
    src = RssSource(http=None, feeds=[], keywords=["supply chain"])  # type: ignore[arg-type]
    adv = src._entry_to_advisory(
        "thn",
        _entry("Supply chain attack, tracked as CVE-2099-1234 / GHSA-abcd-efgh-ijkl", guid="guid-42"),
        EPOCH,
    )
    assert adv is not None
    expected = hashlib.sha256(b"thn\nguid-42").hexdigest()[:16]
    assert adv.id == f"rss:{expected}"
    assert adv.aliases == ["CVE-2099-1234", "GHSA-ABCD-EFGH-IJKL"]
    assert adv.advisory_class is AdvisoryClass.SUPPLY_CHAIN


def test_rss_id_uses_link_when_no_guid_and_differs_per_feed():
    src = RssSource(http=None, feeds=[], keywords=["supply chain"])  # type: ignore[arg-type]
    a = src._entry_to_advisory("feed-a", _entry("supply chain", link="https://n.example/1"), EPOCH)
    b = src._entry_to_advisory("feed-b", _entry("supply chain", link="https://n.example/1"), EPOCH)
    assert a is not None and b is not None
    assert a.id == "rss:" + hashlib.sha256(b"feed-a\nhttps://n.example/1").hexdigest()[:16]
    assert a.id != b.id


def test_rss_feedparser_dict_entry_uses_guid():
    import feedparser

    parsed = feedparser.parse(_rss_body())
    src = RssSource(http=None, feeds=[], keywords=["supply chain"])  # type: ignore[arg-type]
    adv = src._entry_to_advisory("thn", parsed.entries[0], EPOCH)
    assert adv is not None
    assert adv.id == "rss:" + hashlib.sha256(b"thn\nurn:example:item-1").hexdigest()[:16]
    assert adv.aliases == ["CVE-2099-5555"]


@pytest.mark.parametrize(
    "text",
    [
        "we trust the vendor's response",
        "a swift response from the maintainers",
        "attackers hosted payloads on evil-example.net",
        "cargo ship operator hit by ransomware",
        "a crate of stolen credentials",
        "the phishing kit used javascript to redirect victims",
    ],
)
def test_rss_ordinary_words_do_not_imply_an_ecosystem(text):
    assert _guess_ecosystems(text.lower()) == []


@pytest.mark.parametrize(
    ("text", "ecosystem"),
    [
        ("malicious rust crates stole keys", "crates.io"),
        ("packages published to crates.io", "crates.io"),
        ("the cargo registry removed them", "crates.io"),
        ("typosquats on nuget", "NuGet"),
        ("a compromised swift package", "SwiftURL"),
        ("published via swiftpm", "SwiftURL"),
        ("pods on cocoapods", "SwiftURL"),
        ("dozens of npm packages", "npm"),
        ("a backdoored pypi project", "PyPI"),
        ("tampered github action", "GitHub Actions"),
    ],
)
def test_rss_specific_cues_imply_an_ecosystem(text, ecosystem):
    assert [p.ecosystem for p in _guess_ecosystems(text.lower())] == [ecosystem]


def test_rss_default_keywords_skip_generic_malware_news():
    keywords = RssSourceConfig().keywords
    assert "malware" not in keywords
    assert {"malicious npm", "malicious pypi", "malicious package", "malicious crate"} <= set(keywords)
    src = RssSource(http=None, feeds=[], keywords=keywords)  # type: ignore[arg-type]
    generic = _entry("New Android malware steals banking credentials")
    specific = _entry("Malicious npm package drops infostealer")
    assert src._entry_to_advisory("thn", generic, EPOCH) is None
    assert src._entry_to_advisory("thn", specific, EPOCH) is not None


def test_rss_module_has_no_bare_substring_hints():
    # Every hint is a compiled regex now (word-boundary matching).
    assert all(hasattr(pattern, "search") for pattern, _ in rss_mod._ECOSYSTEM_HINTS)
