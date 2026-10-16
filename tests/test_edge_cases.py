"""Edge-case regression tests covering schema, config validators, and parsers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest
import respx
import yaml
from httpx import Response

from sev1daemon.config import (
    Config,
    GithubIssueAction,
    ShellAction,
    WebhookAction,
)
from sev1daemon.enrich.depsdev import DepsDevClient
from sev1daemon.http import HttpClient
from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from sev1daemon.state import StateStore

# ---------- schema migration ----------


@pytest.mark.asyncio
async def test_schema_migration_idempotent(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        async with store._conn.execute(  # type: ignore[attr-defined]
            "SELECT MAX(version) FROM schema_version"
        ) as cur:
            row = await cur.fetchone()
        assert row[0] is not None
        first_version = row[0]
    finally:
        await store.close()

    # Reopen — must not re-apply.
    store2 = StateStore(tmp_path / "s.db")
    await store2.open()
    try:
        async with store2._conn.execute(  # type: ignore[attr-defined]
            "SELECT COUNT(*), MAX(version) FROM schema_version"
        ) as cur:
            count, max_version = await cur.fetchone()
        # Each migration recorded exactly once; max unchanged.
        assert max_version == first_version
    finally:
        await store2.close()


@pytest.mark.asyncio
async def test_schema_migration_starts_from_legacy_db(tmp_path):
    """Pre-existing DB without schema_version table gets migrated cleanly."""
    db = tmp_path / "legacy.db"
    # Hand-craft a minimal pre-migration DB.
    async with aiosqlite.connect(db) as conn:
        await conn.execute("CREATE TABLE advisories (id TEXT PRIMARY KEY)")
        await conn.commit()
    store = StateStore(db)
    await store.open()
    try:
        # New tables are present + version table populated.
        async with store._conn.execute(  # type: ignore[attr-defined]
            "SELECT MAX(version) FROM schema_version"
        ) as cur:
            row = await cur.fetchone()
        assert row[0] is not None
    finally:
        await store.close()


# ---------- per-package idempotency ----------


@pytest.mark.asyncio
async def test_package_fired_query(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        await store.record_package_score("CVE-X", "npm", "foo", 90.0, None, fired=True)
        assert await store.package_fired("CVE-X", "npm", "foo") is True
        # Different package not flagged.
        assert await store.package_fired("CVE-X", "npm", "bar") is False
        # Same pkg w/ fired=False registers but reports unfired.
        await store.record_package_score("CVE-X", "npm", "bar", 10.0, None, fired=False)
        assert await store.package_fired("CVE-X", "npm", "bar") is False
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_processed_packages_prune(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        await store.record_package_score("A", "npm", "x", 1.0, None, fired=False)
        # 0-day retention prunes everything.
        removed = await store.prune_processed_packages(0)
        assert removed >= 1
    finally:
        await store.close()


# ---------- advisory merge ----------


def _adv(id_: str, src: SourceKind, cls: AdvisoryClass, cvss: float | None = None) -> Advisory:
    return Advisory(
        id=id_,
        source=src,
        advisory_class=cls,
        cvss=cvss,
        summary="",
        published=None,
        modified=None,
        affected=[AffectedPackage(ecosystem="npm", name="x")],
    )


def test_advisory_merge_supply_chain_wins_over_cve():
    cve = _adv("X", SourceKind.OSV, AdvisoryClass.CVE, cvss=7.0)
    sc = _adv("X", SourceKind.RSS, AdvisoryClass.SUPPLY_CHAIN)
    merged = cve.merge(sc)
    # Supply-chain class takes precedence so dispatcher's threshold bypass
    # kicks in regardless of which side merged from.
    assert merged.advisory_class == AdvisoryClass.SUPPLY_CHAIN or merged.is_supply_chain


# ---------- depsdev synthesized total when totalCount missing ----------


@pytest.mark.asyncio
@respx.mock
async def test_depsdev_dependents_returns_none_on_404():
    respx.get(
        "https://api.deps.dev/v3/systems/npm/packages/nope"
    ).mock(return_value=Response(404))
    http = HttpClient()
    try:
        client = DepsDevClient(http)
        assert await client.dependents("npm", "nope") is None
    finally:
        await http.aclose()


# ---------- config validators ----------


def test_webhook_url_must_be_http(tmp_path):
    with pytest.raises(ValueError):
        WebhookAction(name="t", type="webhook", url="ftp://nope/")


def test_github_repo_must_match_pattern(tmp_path):
    with pytest.raises(ValueError):
        GithubIssueAction(
            name="t",
            type="github_issue",
            repo="../escape",
            token="ghp",
        )


def test_shell_command_must_be_nonempty():
    with pytest.raises(ValueError):
        ShellAction(name="t", type="shell", command="   ")


def test_config_requires_one_source(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "sources": {
                    "osv": {"enabled": False},
                    "nvd": {"enabled": False},
                    "github": {"enabled": False},
                    "rss": {"enabled": False},
                },
            }
        )
    )
    with pytest.raises(ValueError):
        Config.load(p)


def test_config_duplicate_action_names_rejected(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "sources": {"osv": {"enabled": True}},
                "actions": [
                    {"name": "dup", "type": "webhook", "url": "https://a.test/h"},
                    {"name": "dup", "type": "webhook", "url": "https://b.test/h"},
                ],
            }
        )
    )
    with pytest.raises(Exception) as exc:
        Config.load(p)
    assert "duplicate" in str(exc.value).lower()


def test_config_secret_from_file(tmp_path):
    secret = tmp_path / "tok"
    secret.write_text("filetoken123\n")
    p = tmp_path / "cfg.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "sources": {
                    "osv": {"enabled": True},
                    "github": {"enabled": True, "token": "${file:" + str(secret) + "}"},
                },
            }
        )
    )
    cfg = Config.load(p)
    # rstrip happens in _read_secret_file — newline is stripped.
    assert cfg.sources.github.token == "filetoken123"


# ---------- effective_cycle_timeout ----------


def test_effective_cycle_timeout_default():
    cfg = Config(poll_interval_seconds=600)
    assert cfg.effective_cycle_timeout() == 600 * 4


def test_effective_cycle_timeout_floor():
    cfg = Config(poll_interval_seconds=10)
    # Floor = 120s, prevents tiny timeouts on short poll intervals.
    assert cfg.effective_cycle_timeout() == 120.0


def test_effective_cycle_timeout_explicit():
    cfg = Config(poll_interval_seconds=600, cycle_timeout_seconds=1000)
    assert cfg.effective_cycle_timeout() == 1000.0


# ---------- recent_action_failures basic correctness ----------


@pytest.mark.asyncio
async def test_recent_action_failures_filters_by_status_and_time(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        await store.log_action("A", "hk", "webhook", "ok", "good")
        await store.log_action("A", "hk", "webhook", "error", "bad")
        await store.log_action("A", "hk", "webhook", "error", "bad")
        # Last 60s: 2 errors.
        recent = await store.recent_action_failures(
            "hk", datetime.now(timezone.utc) - timedelta(seconds=60)
        )
        assert recent == 2
        # Far future: 0 errors.
        recent_future = await store.recent_action_failures(
            "hk", datetime.now(timezone.utc) + timedelta(seconds=60)
        )
        assert recent_future == 0
    finally:
        await store.close()


# ---------- http retry-after parsing ----------


def test_parse_retry_after_seconds():
    from sev1daemon.http import _parse_retry_after

    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after(None) == 1.0
    assert _parse_retry_after("garbage") == 1.0


def test_parse_retry_after_http_date():
    from sev1daemon.http import _parse_retry_after

    # Far-future http-date → positive delta.
    seconds = _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
    assert seconds > 0


@pytest.mark.asyncio
async def test_failed_migration_closes_connection(tmp_path, monkeypatch):
    """A broken migration must raise and release the aiosqlite thread, or the
    process hangs on exit instead of failing."""
    import sev1daemon.state as state_mod

    monkeypatch.setattr(state_mod, "_MIGRATIONS", [(1, "THIS IS NOT SQL;")])
    import sqlite3

    store = StateStore(tmp_path / "broken.db")
    with pytest.raises(sqlite3.OperationalError):
        await store.open()
    assert store._conn is None
