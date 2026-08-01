"""click-based CLI."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone

import click

from cvedaemon.actions.dispatcher import ActionDispatcher
from cvedaemon.config import Config
from cvedaemon.daemon import run_daemon, run_one_shot
from cvedaemon.enrich import DepsDevClient, GithubStarsClient, RegistryClient
from cvedaemon.http import HttpClient
from cvedaemon.log import configure_logging, get_logger
from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    Alert,
    SourceKind,
)
from cvedaemon.redact import redact
from cvedaemon.scoring import Scorer
from cvedaemon.state import StateStore

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
@click.version_option(package_name="cvedaemon")
def main() -> None:
    """cvedaemon — critical OSS CVE + supply chain attack monitoring."""


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
                summary="Synthetic test advisory from cvedaemon test-action.",
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
    from cvedaemon.daemon import Daemon

    d = Daemon(cfg)
    await d.setup()
    if dry_run and d._dispatcher is not None:
        d._dispatcher.dry_run = True
    try:
        # Load advisory payload from state and re-process. The advisory_seen
        # check is bypassed by reading directly from the payload column.
        conn = d._state._require_conn()
        async with conn.execute(
            "SELECT payload FROM advisories WHERE id = ?", (advisory_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            click.echo(f"advisory not found: {advisory_id}", err=True)
            sys.exit(2)
        payload = json.loads(row[0])
        adv = Advisory(
            id=payload["id"],
            source=SourceKind(payload["source"]),
            advisory_class=AdvisoryClass(payload["advisory_class"]),
            cvss=payload.get("cvss"),
            summary=payload.get("summary") or "",
            published=_parse_iso(payload.get("published")),
            modified=_parse_iso(payload.get("modified")),
            affected=[
                AffectedPackage(ecosystem=p["ecosystem"], name=p["name"])
                for p in payload.get("affected", [])
            ],
            aliases=payload.get("aliases", []),
            references=payload.get("references", []),
        )
        # Force re-process: clear processed flag + per-package fired rows
        # only when NOT dry-running so the replay path is honest.
        if not dry_run:
            await conn.execute(
                "UPDATE advisories SET processed = 0 WHERE id = ?", (advisory_id,)
            )
            await conn.execute(
                "DELETE FROM processed_packages WHERE advisory_id = ?", (advisory_id,)
            )
            await conn.commit()
        fired = await d._process_advisory(adv)
        click.echo(f"replayed advisory={advisory_id} fired={fired} dry_run={dry_run}")
    finally:
        await d.shutdown()


def _parse_iso(value):
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


_FULL_REDACT_KEYS = {"token", "api_key"}
_VALUE_REDACT_KEYS = {"url", "command", "headers"}


def _redact_secrets(obj):
    """Redact tokens + webhook URLs + auth headers from a model_dump dict."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _FULL_REDACT_KEYS and isinstance(v, str) and v:
                out[k] = "<redacted>"
            elif k in _VALUE_REDACT_KEYS:
                if isinstance(v, str):
                    out[k] = redact(v)
                elif isinstance(v, dict):
                    out[k] = {hk: redact(str(hv)) for hk, hv in v.items()}
                else:
                    out[k] = _redact_secrets(v)
            else:
                out[k] = _redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [_redact_secrets(v) for v in obj]
    return obj


if __name__ == "__main__":
    main()
