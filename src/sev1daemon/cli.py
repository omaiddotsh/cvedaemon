"""click-based CLI."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

import click

from sev1daemon.actions.dispatcher import ActionDispatcher
from sev1daemon.config import Config
from sev1daemon.daemon import run_daemon, run_one_shot
from sev1daemon.enrich import DepsDevClient, GithubStarsClient, RegistryClient
from sev1daemon.http import HttpClient
from sev1daemon.log import configure_logging, get_logger
from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    Alert,
    SourceKind,
)
from sev1daemon.redact import redact
from sev1daemon.scoring import Scorer
from sev1daemon.state import StateStore

log = get_logger("cli")


_CONFIG_OPT = click.option(
    "-c",
    "--config",
    "config_path",
    default="config.yaml",
    show_default=True,
    help="Path to YAML config",
)


def _load(config_path: str) -> Config:
    cfg = Config.load(config_path)
    configure_logging(cfg.log_level, cfg.log_json)
    return cfg


@click.group()
@click.version_option(package_name="sev1daemon")
def main() -> None:
    """sev1daemon — critical OSS CVE + supply chain attack monitoring."""


@main.command()
@_CONFIG_OPT
def run(config_path: str) -> None:
    """Run the daemon poll loop forever."""
    cfg = _load(config_path)
    log.info("cli.run", config=config_path)
    asyncio.run(run_daemon(cfg))


@main.command()
@_CONFIG_OPT
@click.option(
    "--dry-run/--no-dry-run",
    default=False,
    help="Score advisories and log dispatch decisions, but skip actually firing actions.",
)
def check(config_path: str, dry_run: bool) -> None:
    """Run one poll cycle and exit."""
    cfg = _load(config_path)
    log.info("cli.check", config=config_path, dry_run=dry_run)
    fired = asyncio.run(run_one_shot(cfg, dry_run=dry_run))
    click.echo(f"alerts_fired={fired}")


@main.command("show-config")
@_CONFIG_OPT
def show_config(config_path: str) -> None:
    """Dump the effective config as JSON (secrets redacted)."""
    cfg = _load(config_path)
    raw = cfg.model_dump()
    raw = _redact_secrets(raw)
    click.echo(json.dumps(raw, indent=2, default=str))


@main.command()
@_CONFIG_OPT
@click.option("--ecosystem", required=True)
@click.option("--name", required=True)
def score(config_path: str, ecosystem: str, name: str) -> None:
    """Score a single package."""
    cfg = _load(config_path)
    asyncio.run(_score_pkg(cfg, ecosystem, name))


async def _score_pkg(cfg: Config, ecosystem: str, name: str) -> None:
    http = HttpClient(cache_dir=cfg.http_cache_dir, cache_ttl_seconds=cfg.http_cache_ttl_seconds)
    try:
        registry = RegistryClient(http)
        depsdev = DepsDevClient(http)
        stars_client = GithubStarsClient(http, cfg.sources.github.token)

        downloads = await registry.downloads(ecosystem, name)
        deps = await depsdev.dependents(ecosystem, name)
        repo_url = await depsdev.repo_url(ecosystem, name)
        stars = await stars_client.stars_for_repo_url(repo_url or "")

        scorer = Scorer(cfg.blast_radius)
        breakdown = scorer.score(
            AffectedPackage(ecosystem=ecosystem, name=name), stars, downloads, deps
        )
        click.echo(json.dumps(breakdown.as_dict(), indent=2))
    finally:
        await http.aclose()


@main.command("test-action")
@_CONFIG_OPT
@click.option("--action", "action_name", required=True, help="action.name to fire")
def test_action(config_path: str, action_name: str) -> None:
    """Fire one synthetic alert at a single named action."""
    cfg = _load(config_path)
    asyncio.run(_test_action(cfg, action_name))


async def _test_action(cfg: Config, action_name: str) -> None:
    http = HttpClient(cache_dir=cfg.http_cache_dir, cache_ttl_seconds=cfg.http_cache_ttl_seconds)
    state = StateStore(cfg.state_db)
    try:
        await state.open()
        dispatcher = ActionDispatcher(
            cfg.actions, http, state, cfg.blast_radius.score_threshold
        )
        runner = dispatcher.get_by_name(action_name)
        if runner is None:
            click.echo(f"action not found: {action_name}", err=True)
            sys.exit(2)
        synthetic = Alert(
            advisory=Advisory(
                id="TEST-0001",
                source=SourceKind.OSV,
                advisory_class=AdvisoryClass.CVE,
                cvss=9.8,
                summary="Synthetic test advisory from sev1daemon test-action.",
                published=datetime.now(timezone.utc),
                modified=datetime.now(timezone.utc),
                affected=[AffectedPackage(ecosystem="npm", name="test-package")],
                aliases=["CVE-2099-0001"],
                references=["https://example.test/advisory"],
            ),
            package=AffectedPackage(ecosystem="npm", name="test-package"),
            score=100.0,
            breakdown=None,
        )
        res = await runner.run(synthetic)
        click.echo(json.dumps({"status": res.status, "detail": res.detail}, indent=2))
    finally:
        await state.close()
        await http.aclose()


@main.command("replay")
@_CONFIG_OPT
@click.option("--advisory-id", required=True, help="Stored advisory id to replay")
@click.option(
    "--dry-run/--no-dry-run",
    default=False,
    help="Score + log dispatch decisions without firing actions.",
)
def replay(config_path: str, advisory_id: str, dry_run: bool) -> None:
    """Re-process a stored advisory against the current action config.

    Useful after editing actions/min_score thresholds: replay an advisory
    that was originally below threshold to confirm the new config would have
    fired it (use --dry-run for safe inspection).
    """
    cfg = _load(config_path)
    asyncio.run(_replay(cfg, advisory_id, dry_run))


async def _replay(cfg: Config, advisory_id: str, dry_run: bool) -> None:
    from sev1daemon.daemon import Daemon, dry_run_config

    # Dry runs work on a snapshot so they can't mark anything processed/fired.
    async with dry_run_config(cfg, dry_run) as run_cfg:
        d = Daemon(run_cfg, dry_run=dry_run)
        await d.setup()
        try:
            fired = await d.replay(advisory_id)
        finally:
            await d.shutdown()
    if fired is None:
        click.echo(f"advisory not found: {advisory_id}", err=True)
        sys.exit(2)
    click.echo(f"replayed advisory={advisory_id} fired={fired} dry_run={dry_run}")


_FULL_REDACT_KEYS = {"token", "api_key"}


def _redact_url(value: str) -> str:
    """Keep scheme + host; drop path, query and credentials (webhook secrets live there)."""
    parts = urlsplit(value)
    if not parts.scheme or not parts.hostname:
        return redact(value)
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    hidden = parts.path not in ("", "/") or parts.query or parts.username
    return f"{parts.scheme}://{host}" + ("/<redacted>" if hidden else "")


def _redact_secrets(obj):
    """Redact tokens, URL paths/queries and every header value from a model_dump dict."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _FULL_REDACT_KEYS and isinstance(v, str) and v:
                out[k] = "<redacted>"
            elif k.endswith("url") and isinstance(v, str) and k != "base_url":
                out[k] = _redact_url(v)
            elif k == "headers" and isinstance(v, dict):
                # Header values are credentials as often as not (Basic auth,
                # X-Webhook-Secret, API keys); show the names only.
                out[k] = {hk: "<redacted>" for hk in v}
            elif k == "command" and isinstance(v, str):
                out[k] = redact(v)
            else:
                out[k] = _redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [_redact_secrets(v) for v in obj]
    return obj


if __name__ == "__main__":
    main()
