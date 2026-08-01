"""Mocked source ingestor tests. No network."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from cvedaemon.http import HttpClient
from cvedaemon.models import AdvisoryClass, SourceKind
from cvedaemon.sources.github import GithubSource
from cvedaemon.sources.nvd import NvdSource
from cvedaemon.sources.osv import OsvSource

pytestmark = pytest.mark.asyncio


def _build_osv_zip(records: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rec in records:
            zf.writestr(f"{rec['id']}.json", json.dumps(rec))
    return buf.getvalue()


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

    respx.get("https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip").mock(
        return_value=httpx.Response(
            200,
            content=_build_osv_zip(records),
            headers={"Content-Type": "application/zip"},
        )
    )

    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        src = OsvSource(http, "https://api.osv.dev", ["npm"], min_cvss=9.0)
        out = await src.fetch(since=now - timedelta(days=2))
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
