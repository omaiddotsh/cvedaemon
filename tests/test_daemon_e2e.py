"""End-to-end daemon test: fake source feeds advisories through the pipeline
with a fake action runner and a real SQLite state store. Verifies dedupe,
scoring, dispatch, idempotency, and dry-run.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sev1daemon.config import WebhookAction
from sev1daemon.daemon import Daemon
from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)

from .support import FakeSource, RecordingWebhook, minimal_config

pytestmark = [pytest.mark.asyncio, pytest.mark.usefixtures("stub_enrich")]


async def test_pipeline_dispatch_and_idempotency(tmp_path):
    cfg = minimal_config(tmp_path)
    adv = Advisory(
        id="CVE-2099-1000",
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="x",
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        affected=[AffectedPackage(ecosystem="npm", name="left-pad")],
    )

    d = Daemon(cfg)
    await d.setup()
    try:
        # Inject fake source + fake runner directly.
        fake = FakeSource("fake", [adv])
        d._sources = [fake]
        runner = RecordingWebhook("hook")
        assert d._dispatcher is not None
        d._dispatcher._runners = [
            (
                WebhookAction(
                    name="hook",
                    type="webhook",
                    url="https://example.test/hook",
                ),
                runner,
            )
        ]

        fired = await d._run_cycle()
        assert fired == 1, "advisory should fire once"
        assert len(runner.calls) == 1

        # Second cycle: same advisory; should NOT re-fire (advisory_seen + per-package guard).
        fired2 = await d._run_cycle()
        assert fired2 == 0
        assert len(runner.calls) == 1, "dispatch must be idempotent"
    finally:
        await d.shutdown()


async def test_dry_run_skips_actions(tmp_path):
    cfg = minimal_config(tmp_path)
    adv = Advisory(
        id="CVE-2099-2000",
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="x",
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        affected=[AffectedPackage(ecosystem="npm", name="left-pad")],
    )
    d = Daemon(cfg)
    await d.setup()
    try:
        fake = FakeSource("fake", [adv])
        d._sources = [fake]
        runner = RecordingWebhook("hook")
        assert d._dispatcher is not None
        d._dispatcher._runners = [
            (
                WebhookAction(
                    name="hook",
                    type="webhook",
                    url="https://example.test/hook",
                ),
                runner,
            )
        ]
        d._dispatcher.dry_run = True
        fired = await d._run_cycle()
        # dry-run still returns 0 fired (skipped result is not "ok")
        assert fired == 0
        assert runner.calls == []
    finally:
        await d.shutdown()
