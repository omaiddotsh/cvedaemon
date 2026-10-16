"""Shell command action — opt-in. Dangerous by design.

Templating model: the configured command template is shlex-split into argv
FIRST, then ``{{placeholder}}`` occurrences are substituted inside each
argument and the result is run with shell=False. Substituted values are never
re-parsed, so quotes, spaces or ``;`` in an advisory id or package name stay
inside the argument they were placed in and cannot add, remove or merge argv
elements (no quoting is needed — there is no shell). Only the allowlisted
structural payload fields are substitutable. The free-form summary is NOT
exposed as a template var (only as SEV1DAEMON_SUMMARY env var) to keep
advisory text out of argv.

Environment policy: the child receives an allowlisted minimal environment
(``PATH``, ``HOME``, ``LANG``, ``LC_*``) plus SEV1DAEMON_* fields. The parent's
full env is NOT propagated so action scripts cannot accidentally read tokens
out of the daemon's own environment (the action_log redactor would catch it
in logs, but not in user-controlled stdout).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex

from sev1daemon.actions.base import Action, ActionResult
from sev1daemon.config import ShellAction
from sev1daemon.models import Alert

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
    sev1daemon_env = {
        "SEV1DAEMON_ADVISORY_ID": str(p["advisory_id"]),
        "SEV1DAEMON_SOURCE": str(p["source"]),
        "SEV1DAEMON_ADVISORY_CLASS": str(p["advisory_class"]),
        "SEV1DAEMON_CVSS": str(p["cvss"] or ""),
        "SEV1DAEMON_ECOSYSTEM": str(p["ecosystem"]),
        "SEV1DAEMON_PACKAGE": str(p["package"]),
        "SEV1DAEMON_SCORE": str(p["score"]),
        "SEV1DAEMON_SUMMARY": str(p["summary"] or ""),
        "SEV1DAEMON_PAYLOAD": json.dumps(p),
    }
    base = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    return {**base, **sev1daemon_env}


_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def _render_argv(template: str, alert: Alert) -> list[str]:
    """Split ``template`` into argv, then substitute allowlisted payload fields.

    Substitution is a single regex pass per argument, so a value that itself
    contains ``{{...}}`` is not expanded again. Unknown placeholders are left
    as-is. Raises ``ValueError`` if the template is not valid shell-style argv.
    """
    p = alert.as_payload()
    values = {k: "" if p.get(k) is None else str(p.get(k)) for k in _ARGV_SAFE_KEYS}

    def _sub(match: re.Match[str]) -> str:
        return values.get(match.group(1), match.group(0))

    return [_PLACEHOLDER_RE.sub(_sub, arg) for arg in shlex.split(template)]


class ShellRunner(Action):
    def __init__(self, cfg: ShellAction):
        self.name = cfg.name
        self.type = "shell"
        self._cfg = cfg

    async def run(self, alert: Alert) -> ActionResult:
        try:
            argv = _render_argv(self._cfg.command, alert)
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
