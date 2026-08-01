"""Regression tests for bug fixes B1, B3, B6, B7, B8, B10, B11, B12, B14."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

from cvedaemon.health import HealthState
from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    Alert,
    SourceKind,
)
from cvedaemon.redact import redact
from cvedaemon.sources.nvd import _nvd_dt
from cvedaemon.sources.osv import _score_from_vector
from cvedaemon.sources.rss import RssSource

# ---------- B1: CVSS vector parser ----------


def test_cvss_vector_critical_parses_near_98():
    score = _score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert 9.7 <= score <= 9.9


def test_cvss_vector_medium_parses_around_53():
    score = _score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    assert score is not None
    assert 5.0 <= score <= 5.5


def test_cvss_vector_unknown_returns_none():
    assert _score_from_vector("not-a-vector") is None
    # CVSS v4 explicitly not handled by the v3 parser — conservative.
    assert _score_from_vector("CVSS:4.0/AV:N") is None


# ---------- B3: NVD date Z suffix ----------


def test_nvd_dt_emits_Z_suffix():
    dt = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert _nvd_dt(dt) == "2025-01-02T03:04:05.000Z"


# ---------- B6 + B11: RSS stable id + drop dateless ----------


def make_entry(title="t", summary="", link="https://example.test/x", published=True):
    class E:
        pass

    e = E()
    e.title = title
    e.summary = summary
    e.link = link
    if published:
        e.published_parsed = (2099, 1, 1, 0, 0, 0)
    return e


def test_rss_id_is_stable_sha256_when_no_cve_or_ghsa():
    rss = RssSource(http=None, feeds=[], keywords=["supply chain"])
    entry = make_entry(
        title="supply chain attack on registry",
        link="https://example.test/article-1",
    )
    adv1 = rss._entry_to_advisory(
        "thn", entry, datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    adv2 = rss._entry_to_advisory(
        "thn", entry, datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    assert adv1 is not None and adv2 is not None
    assert adv1.id == adv2.id
    # Confirms id is the sha256 prefix we expect
    expected = hashlib.sha256(b"thn\0https://example.test/article-1").hexdigest()[:16]
    assert adv1.id == f"thn:{expected}"


def test_rss_entries_without_published_dropped():
    rss = RssSource(http=None, feeds=[], keywords=["supply chain"])
    entry = make_entry(title="supply chain bad thing", published=False)
    assert (
        rss._entry_to_advisory("x", entry, datetime(1970, 1, 1, tzinfo=timezone.utc))
        is None
    )


# ---------- B7: healthz recency ----------


def test_healthz_goes_unhealthy_after_stale_window():
    state = HealthState(grace_seconds=0, stale_seconds=1)
    assert state.healthz_ok() is False  # never succeeded, no grace
    state.mark_success()
    assert state.healthz_ok() is True
    # Force last_success to look old by reaching in.
    state._last_success = time.monotonic() - 10.0
    assert state.healthz_ok() is False


def test_healthz_ok_during_grace_even_without_success():
    state = HealthState(grace_seconds=60, stale_seconds=1)
    assert state.healthz_ok() is True


# ---------- B8: shell template safety ----------


def test_shell_template_quotes_injected_value():
    from cvedaemon.actions.shell import _render

    alert = Alert(
        advisory=Advisory(
            id="CVE-2099-0001; rm -rf /",
            source=SourceKind.NVD,
            advisory_class=AdvisoryClass.CVE,
            cvss=9.8,
            summary="harmless summary",
            published=None,
            modified=None,
            affected=[AffectedPackage("npm", "foo bar")],
            aliases=[],
            references=[],
        ),
        package=AffectedPackage("npm", "foo bar"),
        score=99.0,
        breakdown=None,
    )
    rendered = _render("notify {{advisory_id}} {{package}}", alert)
    # The advisory_id contains a literal `;` but shlex.quote wraps it in
    # single quotes so it remains a single argv element.
    import shlex

    argv = shlex.split(rendered)
    assert argv[0] == "notify"
    assert argv[1] == "CVE-2099-0001; rm -rf /"
    assert argv[2] == "foo bar"
    # Free-form summary is NOT exposed as a template var (allowlist).
    rendered2 = _render("{{summary}}", alert)
    assert rendered2 == "{{summary}}"


# ---------- B10: dispatcher cpe-skip in scoring ----------
# (Covered via daemon integration; unit test would require full enrichment
# fakes. Implementation guards in daemon._process_cve.)


# ---------- B12: redact header regex bounded ----------


def test_redact_header_does_not_eat_adjacent_content():
    text = "Authorization: Bearer abc12345 and other_field: kept"
    out = redact(text)
    # We expect the header value to be redacted but the trailing fields to survive.
    assert "kept" in out
    assert "abc12345" not in out


# ---------- B14: cache atomic write ----------


def test_http_cache_atomic_write_replaces_corrupt_partial(tmp_path):
    from cvedaemon.http import HttpClient

    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    http._cache_put("https://example.test/x", None, {"a": 1})
    # File exists, no leftover *.tmp
    leftovers = list((tmp_path / "cache").glob(".cache.*.tmp"))
    assert leftovers == []
    body = http._cache_get("https://example.test/x", None)
    assert body == {"a": 1}


# ---------- B24: Retry-After parser ----------


def test_retry_after_parses_seconds():
    from cvedaemon.http import _parse_retry_after

    assert _parse_retry_after("30") == 30.0
    assert _parse_retry_after("0") == 0.0


def test_retry_after_parses_http_date():
    from cvedaemon.http import _parse_retry_after

    # Far-future date → returns a large positive number (not a crash).
    val = _parse_retry_after("Fri, 31 Dec 2999 23:59:59 GMT")
    assert val > 0


def test_retry_after_garbage_returns_default():
    from cvedaemon.http import _parse_retry_after

    assert _parse_retry_after(None) == 1.0
    assert _parse_retry_after("") == 1.0
    assert _parse_retry_after("garbage-xyz") == 1.0


# ---------- B27: shell subprocess timeout kills child ----------


import asyncio as _aio  # noqa: E402

import pytest as _pytest  # noqa: E402


@_pytest.mark.asyncio
async def test_shell_timeout_kills_subprocess():
    from cvedaemon.actions.shell import ShellRunner
    from cvedaemon.config import ShellAction
    from cvedaemon.models import (
        Advisory,
        AdvisoryClass,
        AffectedPackage,
        Alert,
        SourceKind,
    )

    cfg = ShellAction(name="sleep", command="/bin/sleep 30", timeout_seconds=0.2)
    runner = ShellRunner(cfg)
    alert = Alert(
        advisory=Advisory(
            id="X",
            source=SourceKind.OSV,
            advisory_class=AdvisoryClass.CVE,
            cvss=9.8,
            summary="",
            published=None,
            modified=None,
            affected=[AffectedPackage("npm", "x")],
        ),
        package=AffectedPackage("npm", "x"),
        score=100.0,
        breakdown=None,
    )
    start = _aio.get_event_loop().time()
    res = await runner.run(alert)
    elapsed = _aio.get_event_loop().time() - start
    assert res.status == "error"
    assert res.detail == "timeout"
    # Should not have waited the full 30s.
    assert elapsed < 10.0


# ---------- B29: RSS aliases uppercase ----------


def test_rss_aliases_are_uppercase():
    from cvedaemon.sources.rss import RssSource

    rss = RssSource(http=None, feeds=[], keywords=["supply chain"])
    entry = make_entry(
        title="supply chain tracked as cve-2024-12345 / ghsa-aaaa-bbbb-cccc",
        link="https://example.test/y",
    )
    adv = rss._entry_to_advisory(
        "thn", entry, datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    assert adv is not None
    # All aliases uppercase regardless of how they appeared in the feed text.
    assert all(a == a.upper() for a in adv.aliases)
    assert "CVE-2024-12345" in adv.aliases
    assert "GHSA-AAAA-BBBB-CCCC" in adv.aliases


# ---------- B16+B17: OSV zip uses conditional GET, served from cache on 304 ----------


@_pytest.mark.asyncio
async def test_get_bytes_cached_uses_cache_on_304(tmp_path):
    import httpx
    import respx

    from cvedaemon.http import HttpClient

    url = "https://example.test/big.zip"
    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    with respx.mock:
        # First call: 200 with body + ETag.
        respx.get(url).mock(
            return_value=httpx.Response(
                200, content=b"PK\x03\x04\x00DUMMY", headers={"ETag": '"abc123"'}
            )
        )
        status, body = await http.get_bytes_cached(url, timeout=10.0)
        assert status == 200
        assert body == b"PK\x03\x04\x00DUMMY"

        # Second call: server returns 304 → we serve from cache.
        respx.get(url).mock(return_value=httpx.Response(304))
        status2, body2 = await http.get_bytes_cached(url, timeout=10.0)
        assert status2 == 200
        assert body2 == b"PK\x03\x04\x00DUMMY"
    await http.aclose()
