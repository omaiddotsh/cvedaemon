"""Shell command action — opt-in. Dangerous by design.

Templating model: each template variable is shlex-quoted BEFORE substitution
so an attacker-controlled CVE summary cannot inject additional argv elements.
After substitution the rendered string is shlex-split and run with shell=False.
Only the allowlisted structural payload fields are substitutable. The free-form
summary is NOT exposed as a template var (only as CVEDAEMON_SUMMARY env var)
to keep advisory text out of argv.

Environment policy: the child receives an allowlisted minimal environment
(``PATH``, ``HOME``, ``LANG``, ``LC_*``) plus CVEDAEMON_* fields. The parent's
full env is NOT propagated so action scripts cannot accidentally read tokens
out of the daemon's own environment (the action_log redactor would catch it
in logs, but not in user-controlled stdout).
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex

from cvedaemon.actions.base import Action, ActionResult
from cvedaemon.config import ShellAction
from cvedaemon.models import Alert

# Allowlisted fields that may be substituted directly into argv. Excludes
# free-form text (summary, aliases, references, score_breakdown) which can
# carry attacker-controlled content from upstream feeds.
_ARGV_SAFE_KEYS = (
    "advisory_id",
    "source",
    "advisory_class",
    "cvss",
    "ecosystem",
    "package",
    "score",
    "fired_at",
)

# Env vars copied from the daemon's process env into the child's env. Anything
# not in this list (tokens, webhook URLs, secrets) stays in the parent only.
_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
)


def _build_env(alert: Alert) -> dict[str, str]:
    p = alert.as_payload()
    cvedaemon_env = {
        "CVEDAEMON_ADVISORY_ID": str(p["advisory_id"]),
        "CVEDAEMON_SOURCE": str(p["source"]),
        "CVEDAEMON_ADVISORY_CLASS": str(p["advisory_class"]),
        "CVEDAEMON_CVSS": str(p["cvss"] or ""),
        "CVEDAEMON_ECOSYSTEM": str(p["ecosystem"]),
        "CVEDAEMON_PACKAGE": str(p["package"]),
        "CVEDAEMON_SCORE": str(p["score"]),
        "CVEDAEMON_SUMMARY": str(p["summary"] or ""),
        "CVEDAEMON_PAYLOAD": json.dumps(p),
    }
    base = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    return {**base, **cvedaemon_env}


def _render(template: str, alert: Alert) -> str:
    """Substitute allowlisted payload fields, each shlex-quoted."""
    p = alert.as_payload()
    safe_subs = {
        k: shlex.quote("" if p.get(k) is None else str(p.get(k)))
        for k in _ARGV_SAFE_KEYS
    }
    rendered = template
    for key, quoted in safe_subs.items():
        rendered = rendered.replace("{{" + key + "}}", quoted)
    return rendered


class ShellRunner(Action):
    def __init__(self, cfg: ShellAction):
        self.name = cfg.name
        self.type = "shell"
        self._cfg = cfg

    async def run(self, alert: Alert) -> ActionResult:
        rendered = _render(self._cfg.command, alert)
        try:
            argv = shlex.split(rendered)
        except ValueError as exc:
            return ActionResult(status="error", detail=f"parse_failed: {exc}")
        if not argv:
            return ActionResult(status="error", detail="empty command")

        env = _build_env(alert)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as exc:
            return ActionResult(status="error", detail=f"exec_failed: {exc}")
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._cfg.timeout_seconds
            )
        except asyncio.TimeoutError:
            # Ensure the subprocess is terminated; otherwise it orphans.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass
            return ActionResult(status="error", detail="timeout")
        rc = proc.returncode
        tail = (stdout or b"")[-400:].decode(errors="replace")
        if rc == 0:
            return ActionResult(status="ok", detail=f"rc=0 out={tail}")
        err_tail = (stderr or b"")[-400:].decode(errors="replace")
        return ActionResult(status="error", detail=f"rc={rc} err={err_tail}")
