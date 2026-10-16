"""Mocked source ingestor tests. No network."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from sev1daemon.http import HttpClient
from sev1daemon.models import AdvisoryClass, SourceKind
from sev1daemon.sources.github import GithubSource
from sev1daemon.sources.nvd import NvdSource
from sev1daemon.sources.osv import OsvSource

pytestmark = pytest.mark.asyncio


OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"


def _mock_osv_feed(ecosystem: str, records: list[dict]) -> None:
    """Serve ``modified_id.csv`` listing every record, newest first.

    Callers add JSON routes only for records the source should fetch, so
    fetching one past the window trips respx's assert_all_mocked.
    """
    newest_first = sorted(records, key=lambda r: r["modified"], reverse=True)
    csv = "".join(f"{r['modified']},{r['id']}\n" for r in newest_first)
    respx.get(f"{OSV_BUCKET}/{ecosystem}/modified_id.csv").mock(
        return_value=httpx.Response(200, text=csv, headers={"Content-Type": "text/csv"})
    )


# ---------- OSV ----------


@respx.mock
async def test_osv_fetch_parses_and_filters_old(tmp_path):
    now = datetime.now(timezone.utc)
    recent = now - timedelta(hours=1)
    stale = now - timedelta(days=30)

    records = [
        {
            "id": "OSV-RECENT-1",
            "modified": recent.isoformat().replace("+00:00", "Z"),
            "published": recent.isoformat().replace("+00:00", "Z"),
            "summary": "recent crit",
            # numeric legacy form to confirm the float path still works
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}],
            "aliases": ["CVE-2099-9999"],
            "references": [{"url": "https://example.test/x"}],
        },
        {
            "id": "OSV-STALE-1",
            "modified": stale.isoformat().replace("+00:00", "Z"),
            "summary": "too old",
            "severity": [{"score": "9.9"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "old"}}],
        },
        {
            "id": "OSV-LOW-1",
            "modified": recent.isoformat().replace("+00:00", "Z"),
            "summary": "below min_cvss",
            "severity": [{"score": "5.0"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "low"}}],
        },
        {
            # Real-world OSV format: CVSS vector string (NOT a numeric).
            # Vector below scores 9.8 — should pass min_cvss=9.0.
            "id": "OSV-VECTOR-1",
            "modified": recent.isoformat().replace("+00:00", "Z"),
            "summary": "vector form crit",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
            "affected": [{"package": {"ecosystem": "npm", "name": "vector-pkg"}}],
        },
        {
            # Vector form scoring ~5.3 — should be filtered out by min_cvss=9.0.
            "id": "OSV-VECTOR-LOW-1",
            "modified": recent.isoformat().replace("+00:00", "Z"),
            "summary": "vector form medium",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                }
            ],
            "affected": [{"package": {"ecosystem": "npm", "name": "vector-low"}}],
        },
    ]

    since = now - timedelta(days=2)
    _mock_osv_feed("npm", records)
    for rec in records:
        if rec["id"] != "OSV-STALE-1":  # past the window: the CSV read stops first
            respx.get(f"{OSV_BUCKET}/npm/{rec['id']}.json").mock(
                return_value=httpx.Response(200, json=rec)
            )

    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        src = OsvSource(http, "https://api.osv.dev", ["npm"], min_cvss=9.0)
        out = await src.fetch(since=since)
    finally:
        await http.aclose()

    ids = {a.id for a in out}
    assert "OSV-RECENT-1" in ids
    assert "OSV-VECTOR-1" in ids
    assert "OSV-STALE-1" not in ids
    assert "OSV-LOW-1" not in ids
    assert "OSV-VECTOR-LOW-1" not in ids
    recent_adv = next(a for a in out if a.id == "OSV-RECENT-1")
    assert recent_adv.source is SourceKind.OSV
    assert recent_adv.advisory_class is AdvisoryClass.CVE
    assert recent_adv.affected[0].ecosystem == "npm"
    assert recent_adv.affected[0].name == "left-pad"
    vector_adv = next(a for a in out if a.id == "OSV-VECTOR-1")
    assert vector_adv.cvss is not None
    assert vector_adv.cvss >= 9.0


# ---------- NVD ----------


@respx.mock
async def test_nvd_fetch_paginates_and_parses(tmp_path):
    now = datetime.now(timezone.utc)
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    page1 = {
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "published": now.isoformat().replace("+00:00", "Z"),
                    "lastModified": now.isoformat().replace("+00:00", "Z"),
                    "descriptions": [{"lang": "en", "value": "boom"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8}},
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:vendor:product:1.0"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [{"url": "https://example.test/r"}],
                }
            }
        ],
    }
    page2 = {
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0002",
                    "descriptions": [{"lang": "en", "value": "below cvss"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
                }
            }
        ],
    }
    route = respx.get(base).mock(
        side_effect=[
            httpx.Response(200, json=page1),
            httpx.Response(200, json=page2),
        ]
    )

    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        src = NvdSource(http, base, api_key="", results_per_page=1, min_cvss=9.0)
        # Override sleep to keep test fast.
        src._sleep_between = 0  # type: ignore[attr-defined]
        out = await src.fetch(since=now - timedelta(hours=2))
    finally:
        await http.aclose()

    assert route.call_count == 2
    ids = {a.id for a in out}
    assert ids == {"CVE-2099-0001"}
    adv = out[0]
    assert adv.cvss == 9.8
    assert any(p.ecosystem == "cpe:vendor" and p.name == "product" for p in adv.affected)


# ---------- GHSA ----------


@respx.mock
async def test_github_fetch_parses_severity_and_pagination(tmp_path):
    now = datetime.now(timezone.utc)
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2099-1111",
            "severity": "critical",
            "summary": "remote code execution",
            "published_at": now.isoformat().replace("+00:00", "Z"),
            "updated_at": now.isoformat().replace("+00:00", "Z"),
            "cvss": {"score": 9.8},
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "popular"}}
            ],
            "references": [{"url": "https://example.test/g"}],
        },
        {
            "ghsa_id": "GHSA-zzzz-yyyy-xxxx",
            "severity": "medium",  # filtered out
            "summary": "low",
            "cvss": {"score": 5.0},
        },
    ]
    respx.get("https://api.github.com/advisories").mock(
        return_value=httpx.Response(200, json=advisories)
    )

    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        src = GithubSource(
            http,
            base_url="https://api.github.com",
            token="ghp_dummy",
            severities=["critical"],
            min_cvss=9.0,
        )
        out = await src.fetch(since=now - timedelta(hours=2))
    finally:
        await http.aclose()

    ids = {a.id for a in out}
    assert "GHSA-aaaa-bbbb-cccc" in ids
    assert "GHSA-zzzz-yyyy-xxxx" not in ids
    adv = next(a for a in out if a.id == "GHSA-aaaa-bbbb-cccc")
    assert adv.cvss == 9.8
    assert "CVE-2099-1111" in adv.aliases
    assert adv.affected[0].ecosystem == "npm"
    assert adv.affected[0].name == "popular"


@respx.mock
async def test_github_fetch_handles_live_api_shape(tmp_path):
    """Shape returned by the real /advisories API (checked 2026-10): references
    are plain URL strings, and v4-only advisories have a null legacy ``cvss``
    score with the real score under ``cvss_severities``. A malformed entry must
    not drop the rest of the page."""
    now = datetime.now(timezone.utc)
    ts = now.isoformat().replace("+00:00", "Z")
    advisories = [
        {
            "ghsa_id": "GHSA-v4v4-v4v4-v4v4",
            "severity": "critical",
            "summary": "v4-only score",
            "published_at": ts,
            "updated_at": ts,
            "cvss": {"score": None, "vector_string": None},
            "cvss_severities": {
                "cvss_v3": {"score": 0, "vector_string": None},
                "cvss_v4": {"score": 9.3, "vector_string": "CVSS:4.0/AV:N"},
            },
            "vulnerabilities": [{"package": {"ecosystem": "go", "name": "example.com/mod"}}],
            "references": ["https://example.test/a", "https://example.test/b"],
        },
        {
            "ghsa_id": "GHSA-low4-low4-low4",
            "severity": "critical",
            "summary": "scored below min_cvss under cvss_severities",
            "cvss": {"score": None},
            "cvss_severities": {"cvss_v3": {"score": 7.5}, "cvss_v4": {"score": 0}},
            "references": [],
        },
        {
            "ghsa_id": "GHSA-bad0-bad0-bad0",
            "severity": "critical",
            "summary": "malformed vulnerabilities block",
            "vulnerabilities": ["not-a-dict"],
        },
        {"ghsa_id": "GHSA-null-sevr-null", "severity": None},
    ]
    respx.get("https://api.github.com/advisories").mock(
        return_value=httpx.Response(200, json=advisories)
    )

    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        src = GithubSource(
            http,
            base_url="https://api.github.com",
            token="ghp_dummy",
            severities=["critical"],
            min_cvss=9.0,
        )
        out = await src.fetch(since=now - timedelta(hours=2))
    finally:
        await http.aclose()

    assert [a.id for a in out] == ["GHSA-v4v4-v4v4-v4v4"]
    adv = out[0]
    assert adv.cvss == 9.3
    assert adv.references == ["https://example.test/a", "https://example.test/b"]
    assert adv.affected[0].ecosystem == "Go"
