"""Tests for the subprocess-based shell runner.

These actions launch real OS subprocesses; the tests use ``/bin/sh -c true``
style commands that are present on any POSIX machine. No network. The env allowlist is verified by spawning ``env`` and
checking that an unrelated parent env var is NOT inherited.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import pytest

from sev1daemon.actions.shell import ShellRunner
from sev1daemon.config import ShellAction
from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    Alert,
    SourceKind,
)

pytestmark = pytest.mark.asyncio


def _alert() -> Alert:
    adv = Advisory(
        id="CVE-2099-9001",
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="test",
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        affected=[AffectedPackage(ecosystem="npm", name="x")],
    )
    return Alert(
        advisory=adv,
        package=AffectedPackage(ecosystem="npm", name="x"),
        score=99.0,
        breakdown=None,
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
async def test_shell_runs_command_and_captures_stdout():
    cfg = ShellAction(name="t", type="shell", command="/bin/echo hello-{{package}}")
    runner = ShellRunner(cfg)
    res = await runner.run(_alert())
    assert res.status == "ok"
    assert "hello-x" in res.detail


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
async def test_shell_rejects_placeholder_executable():
    # Feed data must never pick the program: a placeholder as argv[0] is now
    # rejected when the config loads, before any alert can render it.
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ShellAction(name="t", type="shell", command="{{package}}")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
async def test_shell_env_allowlist_blocks_secrets(monkeypatch):
    # Inject a fake secret in parent env; the child env must NOT see it.
    monkeypatch.setenv("SECRET_TOKEN_DO_NOT_LEAK", "leak-me")
    cfg = ShellAction(
        name="t",
        type="shell",
        command="/usr/bin/env",
    )
    runner = ShellRunner(cfg)
    res = await runner.run(_alert())
    assert res.status == "ok"
    assert "SECRET_TOKEN_DO_NOT_LEAK" not in res.detail
    # SEV1DAEMON_* allowlisted keys ARE forwarded (the runner truncates output
    # to the last 400 bytes; SEV1DAEMON_PAYLOAD is alphabetically last and
    # always lands in the tail).
    assert "SEV1DAEMON_PAYLOAD" in res.detail
    assert "CVE-2099-9001" in res.detail


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
async def test_shell_timeout_kills_subprocess():
    # /bin/sleep 30 exceeds the 1-second timeout; runner must kill and return
    # error within ~1-2 seconds.
    cfg = ShellAction(
        name="t",
        type="shell",
        command="/bin/sleep 30",
        timeout_seconds=1.0,
    )
    runner = ShellRunner(cfg)
    res = await runner.run(_alert())
    assert res.status == "error"
    assert "timeout" in res.detail
