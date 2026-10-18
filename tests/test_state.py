import dataclasses
import sqlite3
from datetime import datetime, timezone

import pytest

from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from sev1daemon.state import StateStore

pytestmark = pytest.mark.asyncio


async def test_advisory_roundtrip(tmp_path):
    db = tmp_path / "state.db"
    store = StateStore(db)
    await store.open()
    try:
        adv = Advisory(
            id="CVE-2099-0001",
            source=SourceKind.NVD,
            advisory_class=AdvisoryClass.CVE,
            cvss=9.8,
            summary="test",
            published=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            affected=[AffectedPackage(ecosystem="npm", name="x")],
        )
        assert await store.advisory_seen(adv.id) is False
        await store.upsert_advisory(adv)
        await store.mark_processed(adv.id)
        assert await store.advisory_seen(adv.id) is True
    finally:
        await store.close()


async def test_failed_migration_leaves_nothing_behind(tmp_path, monkeypatch):
    """A migration and its schema_version row commit together. A crash (or an
    error) half-way through must not leave DDL applied without the version
    row, or every later start would fail re-applying it (ALTER TABLE ADD COLUMN
    is not idempotent)."""
    from sev1daemon import state as state_mod

    good = list(state_mod._MIGRATIONS)
    broken = [
        *good,
        (good[-1][0] + 1, "CREATE TABLE review_half (x INTEGER); SELECT * FROM no_such_table;"),
    ]
    monkeypatch.setattr(state_mod, "_MIGRATIONS", broken)
    store = StateStore(tmp_path / "state.db")
    with pytest.raises(sqlite3.OperationalError):
        await store.open()

    monkeypatch.setattr(state_mod, "_MIGRATIONS", good)
    store = StateStore(tmp_path / "state.db")
    await store.open()  # must not trip over a half-applied migration
    try:
        conn = store._conn  # type: ignore[attr-defined]
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='review_half'"
        ) as cur:
            assert await cur.fetchone() is None
        async with conn.execute("SELECT MAX(version) FROM schema_version") as cur:
            row = await cur.fetchone()
        assert row is not None and row[0] == good[-1][0]
    finally:
        await store.close()


async def test_upsert_advisories_keeps_processed_flag_and_attempts(tmp_path):
    store = StateStore(tmp_path / "state.db")
    await store.open()
    try:
        adv = Advisory(
            id="CVE-2099-0002",
            source=SourceKind.OSV,
            advisory_class=AdvisoryClass.CVE,
            cvss=9.1,
            summary="first",
            published=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            affected=[AffectedPackage(ecosystem="npm", name="x")],
        )
        await store.upsert_advisories([adv])
        await store.record_attempt(adv.id, "boom")
        await store.mark_processed(adv.id)
        again = dataclasses.replace(adv, summary="refreshed")
        await store.upsert_advisories([again])
        assert await store.advisory_seen(adv.id) is True
        stored = await store.get_advisory(adv.id)
        assert stored is not None and stored.summary == "refreshed"
        assert await store.unscored_packages(adv.id, [("npm", "x"), ("npm", "y")]) == [
            ("npm", "x"),
            ("npm", "y"),
        ]
        await store.record_package_score(adv.id, "npm", "x", 80.0, None, True)
        assert await store.unscored_packages(adv.id, [("npm", "x"), ("npm", "y")]) == [("npm", "y")]
        await store.reopen(adv.id)
        assert await store.advisory_seen(adv.id) is False
        assert [a.id for a in await store.pending_advisories(48)] == [adv.id]
    finally:
        await store.close()


async def test_action_log_redacts(tmp_path):
    db = tmp_path / "state.db"
    store = StateStore(db)
    await store.open()
    try:
        await store.log_action(
            advisory_id="X",
            action_name="hook",
            action_type="webhook",
            status="ok",
            detail="posted to https://hooks.slack.com/services/T/B/secret",
        )
        async with store._conn.execute(  # type: ignore[attr-defined]
            "SELECT detail FROM action_log WHERE advisory_id='X'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert "secret" not in row[0]
        assert "<redacted>" in row[0]
    finally:
        await store.close()


async def test_prune_action_log(tmp_path):
    store = StateStore(tmp_path / "state.db")
    await store.open()
    try:
        await store.log_action("A", "h", "webhook", "ok", "msg")
        # 0 retention days → everything pruned
        removed = await store.prune_action_log(0)
        assert removed >= 1
    finally:
        await store.close()


async def test_poll_state_tracks_success_and_failure(tmp_path):
    store = StateStore(tmp_path / "state.db")
    await store.open()
    try:
        await store.set_poll_failure("nvd", "boom")
        assert await store.get_last_success("nvd") is None
        await store.set_poll_success("nvd")
        ts = await store.get_last_success("nvd")
        assert ts is not None
    finally:
        await store.close()
