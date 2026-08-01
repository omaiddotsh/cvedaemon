from pathlib import Path

import pytest

from cvedaemon.config import Config, WebhookAction


def write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(content)
    return p


def test_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TOKEN", "abc123")
    cfg_path = write_yaml(
        tmp_path,
        """
sources:
  github:
    token: "${FAKE_TOKEN}"
""",
    )
    cfg = Config.load(cfg_path)
    assert cfg.sources.github.token == "abc123"


def test_env_default_when_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    cfg_path = write_yaml(
        tmp_path,
        """
sources:
  github:
    token: "${MISSING_VAR:-fallback}"
""",
    )
    cfg = Config.load(cfg_path)
    assert cfg.sources.github.token == "fallback"


def test_invalid_cvss_rejected(tmp_path):
    from pydantic import ValidationError

    cfg_path = write_yaml(tmp_path, "min_cvss: 12.0\n")
    with pytest.raises(ValidationError):
        Config.load(cfg_path)


def test_actions_parsed_by_type(tmp_path):
    cfg_path = write_yaml(
        tmp_path,
        """
actions:
  - name: hook1
    type: webhook
    url: "https://example.test/in"
""",
    )
    cfg = Config.load(cfg_path)
    assert len(cfg.actions) == 1
    a = cfg.actions[0]
    assert isinstance(a, WebhookAction)
    assert a.url == "https://example.test/in"


def test_unknown_action_type_raises(tmp_path):
    cfg_path = write_yaml(
        tmp_path,
        """
actions:
  - name: bogus
    type: not_a_real_type
""",
    )
    with pytest.raises(ValueError):
        Config.load(cfg_path)
