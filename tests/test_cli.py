"""CLI smoke tests via click's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from cvedaemon.cli import main


def _write_config(path: Path, **overrides) -> Path:
    base = {
        "poll_interval_seconds": 60,
        "state_db": str(path.parent / "s.db"),
        "http_cache_dir": str(path.parent / "cache"),
        "sources": {
            "osv": {"enabled": True, "ecosystems": ["npm"]},
            "nvd": {"enabled": False},
            "github": {"enabled": False},
            "rss": {"enabled": False},
        },
        "actions": [],
    }
    base.update(overrides)
    path.write_text(yaml.safe_dump(base))
    return path


def test_show_config_redacts_secrets(tmp_path):
    cfg = _write_config(
        tmp_path / "cfg.yaml",
        sources={
            "osv": {"enabled": False},
            "nvd": {"enabled": True, "api_key": "secret-nvd-key-xyz"},
            "github": {"enabled": True, "token": "ghp_topsecrettoken"},
            "rss": {"enabled": False},
        },
    )
    runner = CliRunner()
    result = runner.invoke(main, ["show-config", "-c", str(cfg)])
    assert result.exit_code == 0
    data = json.loads(result.output)
    # Top-level keys preserved.
    assert "sources" in data
    # Tokens fully redacted.
    assert data["sources"]["nvd"]["api_key"] == "<redacted>"
    assert data["sources"]["github"]["token"] == "<redacted>"
    assert "secret-nvd-key-xyz" not in result.output
    assert "ghp_topsecrettoken" not in result.output


def test_show_config_missing_file_errors(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["show-config", "-c", str(tmp_path / "nope.yaml")])
    assert result.exit_code != 0
    assert "config not found" in str(result.exception) or "FileNotFound" in str(
        result.exception
    )


def test_test_action_unknown_action(tmp_path):
    cfg = _write_config(tmp_path / "cfg.yaml")
    runner = CliRunner()
    result = runner.invoke(main, ["test-action", "-c", str(cfg), "--action", "no-such"])
    assert result.exit_code == 2
