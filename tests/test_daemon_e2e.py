"""End-to-end daemon test: fake source feeds advisories through the pipeline
with a fake action runner and a real SQLite state store. Verifies dedupe,
scoring, dispatch, idempotency, and dry-run.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from cvedaemon.config import (
    BlastRadiusConfig,
    Config,
    DepsDevConfig,
    DownloadsConfig,
    GithubSourceConfig,
    NvdSourceConfig,
    OsvSourceConfig,
    RssSourceConfig,
    SourcesConfig,
    StarsConfig,
    WebhookAction,
)
from cvedaemon.daemon import Daemon
from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from cvedaemon.sources.base import Source

pytestmark = pytest.mark.asyncio


class _FakeSource(Source):
    def __init__(self, name: str, advisories: list[Advisory]):
        self.name = name
        self._advisories = advisories
        self.fetch_count = 0

    async def fetch(self, since: datetime) -> list[Advisory]:
        self.fetch_count += 1
        return list(self._advisories)


class _RecordingWebhook:
    """Stand-in for WebhookRunner — records dispatches without HTTP."""

    type = "webhook"

    def __init__(self, name: str):
        self.name = name
        self.calls: list[Any] = []

    async def run(self, alert):
        self.calls.append(alert)

        class _R:
            status = "ok"
            detail = "fake"

        return _R()


def _minimal_config(tmp_path) -> Config:
    # Enable OSV in config so the "at least one source enabled" validator
    # passes; tests overwrite Daemon._sources after setup() runs.
    return Config(
        poll_interval_seconds=60,
        state_db=str(tmp_path / "s.db"),
        http_cache_dir=str(tmp_path / "cache"),
        # Test target is example.test which doesn't resolve; allow_private_urls
        # bypasses the SSRF DNS lookup so the fake runner gets invoked.
        allow_private_urls=True,
        # Disable rate limit + circuit breaker — they'd hide the real call path.
        action_rate_per_second=0.0,
        action_circuit_failures=0,
        sources=SourcesConfig(
            osv=OsvSourceConfig(enabled=True, ecosystems=["npm"]),
            nvd=NvdSourceConfig(enabled=False),
            github=GithubSourceConfig(enabled=False),
            rss=RssSourceConfig(enabled=False),
        ),
        blast_radius=BlastRadiusConfig(
            score_threshold=0,  # always crosses, so we exercise dispatch
            stars=StarsConfig(weight=0, saturate_at=1),
            downloads=DownloadsConfig(weight=0, thresholds={"npm": 1}),
            depsdev=DepsDevConfig(weight=0, saturate_at=1),
        ),
    )


@pytest.fixture(autouse=True)
def _stub_enrich(monkeypatch):
    """Stub enrich HTTP so the test doesn't hit real registries / deps.dev."""
    from cvedaemon.enrich import depsdev as dd
    from cvedaemon.enrich import github_stars as gs
    from cvedaemon.enrich import registry as reg

    async def _none_int(self, *a, **kw):
        return None

    async def _none_str(self, *a, **kw):
        return None

    monkeypatch.setattr(reg.RegistryClient, "downloads", _none_int)
    monkeypatch.setattr(dd.DepsDevClient, "dependents", _none_int)
    monkeypatch.setattr(dd.DepsDevClient, "repo_url", _none_str)
    monkeypatch.setattr(gs.GithubStarsClient, "stars_for_repo_url", _none_int)


async def test_pipeline_dispatch_and_idempotency(tmp_path):
    cfg = _minimal_config(tmp_path)
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
        fake = _FakeSource("fake", [adv])
        d._sources = [fake]
        runner = _RecordingWebhook("hook")
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
    cfg = _minimal_config(tmp_path)
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
        fake = _FakeSource("fake", [adv])
        d._sources = [fake]
        runner = _RecordingWebhook("hook")
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
