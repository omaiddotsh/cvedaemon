"""End to end: OSV malicious-package (MAL-) records go through the scored path.

The real OsvSource reads a respx-mocked change index + records; enrichment is
stubbed so one package is popular and one is an unused typosquat. Only the
popular one alerts, with a blast-radius score (not the supply-chain 100).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import respx

from sev1daemon.config import (
    BlastRadiusConfig,
    Config,
    GithubSourceConfig,
    NvdSourceConfig,
    OsvSourceConfig,
    RssSourceConfig,
    SourcesConfig,
    WebhookAction,
)
from sev1daemon.daemon import Daemon
from sev1daemon.enrich import depsdev as depsdev_mod
from sev1daemon.enrich import github_stars as stars_mod
from sev1daemon.enrich import registry as registry_mod
from sev1daemon.models import AdvisoryClass

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
TS = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _mal(rec_id: str, package: str) -> dict[str, Any]:
    return {
        "id": rec_id,
        "modified": TS,
        "published": TS,
        "summary": f"Malicious code in {package} (npm)",
        "affected": [{"package": {"ecosystem": "npm", "name": package}}],
        "database_specific": {"malicious-packages-origins": [{"source": "ghsa-malware"}]},
    }


class _Recorder:
    type = "webhook"

    def __init__(self) -> None:
        self.name = "hook"
        self.calls: list[Any] = []

    async def run(self, alert: Any) -> Any:
        self.calls.append(alert)

        class _Result:
            status = "ok"
            detail = "recorded"

        return _Result()


@respx.mock
async def test_mal_records_alert_only_for_popular_packages(tmp_path, monkeypatch):
    records = [_mal("MAL-2099-10", "popular-pkg"), _mal("MAL-2099-11", "typo-pkg")]
    respx.get(f"{BUCKET}/npm/modified_id.csv").mock(
        return_value=httpx.Response(200, text="".join(f"{TS},{r['id']}\n" for r in records))
    )
    for rec in records:
        respx.get(f"{BUCKET}/npm/{rec['id']}.json").mock(return_value=httpx.Response(200, json=rec))

    async def _downloads(self, ecosystem: str, name: str) -> int:
        return 5_000_000 if name == "popular-pkg" else 3

    async def _dependents(self, ecosystem: str, name: str) -> int:
        return 2_000 if name == "popular-pkg" else 0

    async def _none(self, *args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(registry_mod.RegistryClient, "downloads", _downloads)
    monkeypatch.setattr(depsdev_mod.DepsDevClient, "dependents", _dependents)
    monkeypatch.setattr(depsdev_mod.DepsDevClient, "repo_url", _none)
    monkeypatch.setattr(stars_mod.GithubStarsClient, "stars_for_repo_url", _none)

    cfg = Config(
        state_db=str(tmp_path / "s.db"),
        http_cache_dir=str(tmp_path / "cache"),
        health_port=0,  # ephemeral: no clash with other test runs
        allow_private_urls=True,
        action_rate_per_second=0.0,
        action_circuit_failures=0,
        min_cvss=9.0,  # MAL records carry no CVSS; they must not be dropped by it
        sources=SourcesConfig(
            osv=OsvSourceConfig(enabled=True, ecosystems=["npm"]),
            nvd=NvdSourceConfig(enabled=False),
            github=GithubSourceConfig(enabled=False),
            rss=RssSourceConfig(enabled=False),
        ),
        blast_radius=BlastRadiusConfig(score_threshold=50),
    )
    daemon = Daemon(cfg)
    await daemon.setup()
    try:
        runner = _Recorder()
        assert daemon._dispatcher is not None
        daemon._dispatcher._runners = [
            (WebhookAction(name="hook", type="webhook", url="https://example.test/hook"), runner)
        ]
        fired = await daemon._run_cycle()
    finally:
        await daemon.shutdown()

    assert fired == 1
    [alert] = runner.calls
    assert alert.advisory.id == "MAL-2099-10"
    assert alert.advisory.advisory_class is AdvisoryClass.MALICIOUS_PACKAGE
    # Scored like a CVE: downloads (40) + deps.dev dependents (20), no stars.
    assert alert.breakdown is not None
    assert alert.score == 60.0
    assert alert.as_payload()["advisory_class"] == "malicious_package"
