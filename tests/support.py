"""Shared helpers for daemon-level tests: a minimal config, a fake source and
a fake webhook runner. The ``stub_enrich`` fixture lives in conftest.py."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sev1daemon.config import (
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
)
from sev1daemon.models import Advisory
from sev1daemon.sources.base import Source


class FakeSource(Source):
    def __init__(self, name: str, advisories: list[Advisory]):
        self.name = name
        self._advisories = advisories
        self.fetch_count = 0

    async def fetch(self, since: datetime) -> list[Advisory]:
        self.fetch_count += 1
        return list(self._advisories)


class RecordingWebhook:
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


def minimal_config(tmp_path) -> Config:
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
