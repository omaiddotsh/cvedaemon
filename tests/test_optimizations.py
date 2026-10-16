"""Defaults and housekeeping that keep the daemon cheap to run."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sev1daemon.config import Config, NvdSourceConfig
from sev1daemon.models import Advisory, AdvisoryClass, SourceKind
from sev1daemon.state import StateStore

pytestmark = pytest.mark.asyncio


async def test_nvd_is_off_by_default():
    assert NvdSourceConfig().enabled is False


async def test_advisory_retention_validated():
    with pytest.raises(ValueError):
        Config(advisory_retention_days=-1)


def _adv(adv_id: str, modified: datetime) -> Advisory:
    return Advisory(
        id=adv_id,
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="x",
        published=modified,
        modified=modified,
    )


async def test_prune_advisories_keeps_pending_and_recent(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        old = datetime.now(timezone.utc) - timedelta(days=400)
        now = datetime.now(timezone.utc)
        for adv in (_adv("OLD-DONE", old), _adv("OLD-PENDING", old), _adv("NEW-DONE", now)):
            await store.upsert_advisory(adv)
        await store.mark_processed("OLD-DONE")
        await store.mark_processed("NEW-DONE")
        conn = store._require_conn()
        # Age the first two rows' seen_at past the window.
        await conn.execute(
            "UPDATE advisories SET seen_at = ? WHERE id IN ('OLD-DONE', 'OLD-PENDING')",
            (old.isoformat(),),
        )
        await conn.commit()

        assert await store.prune_advisories(365) == 1
        async with conn.execute("SELECT id FROM advisories ORDER BY id") as cur:
            remaining = [r[0] for r in await cur.fetchall()]
        assert remaining == ["NEW-DONE", "OLD-PENDING"]
        assert await store.prune_advisories(0) == 0  # 0 disables
    finally:
        await store.close()
