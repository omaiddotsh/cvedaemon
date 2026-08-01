from datetime import datetime, timezone

import pytest

from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from cvedaemon.state import StateStore

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
