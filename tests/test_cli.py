"""CLI smoke tests via click's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from sev1daemon.cli import main


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


def test_test_action_refuses_a_target_the_daemon_would_block(tmp_path):
    """test-action applies the dispatcher's SSRF guard: a target the daemon
    skips on every dispatch must not pass its own test (and nothing is sent)."""
    cfg = _write_config(
        tmp_path / "cfg.yaml",
        actions=[
            {
                "name": "loopback",
                "type": "webhook",
                "enabled": True,
                # port 9 (discard) is never listened on: a request would error
                "url": "https://127.0.0.1:9/hook",
            }
        ],
    )
    runner = CliRunner()
    result = runner.invoke(main, ["test-action", "-c", str(cfg), "--action", "loopback"])
    assert result.exit_code == 1
    assert "ssrf_blocked" in result.output
    assert "allow_private_urls" in result.output


def test_test_action_exits_nonzero_when_the_action_fails(tmp_path):
    cfg = _write_config(
        tmp_path / "cfg.yaml",
        allow_private_urls=True,
        actions=[
            {
                "name": "dead",
                "type": "webhook",
                "enabled": True,
                "url": "https://127.0.0.1:9/hook",
                "timeout_seconds": 1,
            }
        ],
    )
    result = CliRunner().invoke(main, ["test-action", "-c", str(cfg), "--action", "dead"])
    assert result.exit_code == 1
    assert '"status": "error"' in result.output


def test_plain_http_webhook_is_refused_at_load_unless_private_urls_allowed(tmp_path):
    action = {"name": "plain", "type": "webhook", "enabled": True, "url": "http://soar.internal/x"}
    cfg = _write_config(tmp_path / "cfg.yaml", actions=[action])
    result = CliRunner().invoke(main, ["show-config", "-c", str(cfg)])
    assert result.exit_code != 0
    assert "allow_private_urls" in str(result.exception)

    cfg = _write_config(tmp_path / "cfg2.yaml", allow_private_urls=True, actions=[action])
    result = CliRunner().invoke(main, ["show-config", "-c", str(cfg)])
    assert result.exit_code == 0, result.output

    disabled = dict(action, enabled=False)
    cfg = _write_config(tmp_path / "cfg3.yaml", actions=[disabled])
    result = CliRunner().invoke(main, ["show-config", "-c", str(cfg)])
    assert result.exit_code == 0, result.output


def test_webhook_url_with_a_bad_port_is_refused_at_load(tmp_path):
    cfg = _write_config(
        tmp_path / "cfg.yaml",
        actions=[
            {"name": "p", "type": "webhook", "enabled": True, "url": "https://hooks.example.com:80a/x"}
        ],
    )
    result = CliRunner().invoke(main, ["show-config", "-c", str(cfg)])
    assert result.exit_code != 0
    assert "invalid port" in str(result.exception)


def test_show_config_is_quiet_about_disabled_placeholders(tmp_path):
    """Disabled actions are placeholders (missing fields allowed); dumping them
    must not spray pydantic serializer warnings on stderr."""
    cfg = _write_config(
        tmp_path / "cfg.yaml",
        actions=[{"name": "later", "type": "github_issue", "enabled": False}],
    )
    result = CliRunner().invoke(main, ["show-config", "-c", str(cfg)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["actions"][0]["name"] == "later"
    assert "PydanticSerializationUnexpectedValue" not in result.stderr
