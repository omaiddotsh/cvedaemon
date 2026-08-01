"""Nebari CVE response — shells out to an external ``cve_response.py``.

The child receives the alert payload as JSON on stdin plus a strict
``--advisory-id / --ecosystem / --package / --score`` argv. The parent's env
is NOT propagated except for a minimal allowlist (PATH/HOME/locale); secret
tokens and webhook URLs stay in the daemon process.
"""

from __future__ import annotations

import asyncio
import json
import os

from cvedaemon.actions.base import Action, ActionResult
from cvedaemon.config import NebariAction
from cvedaemon.models import Alert

_ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ")


def _child_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}


class NebariRunner(Action):
    def __init__(self, cfg: NebariAction):
        self.name = cfg.name
        self.type = "nebari_cve_response"
        self._cfg = cfg

    async def run(self, alert: Alert) -> ActionResult:
        argv = [
            "python3",
            self._cfg.script_path,
            "--advisory-id",
            alert.advisory.id,
            "--ecosystem",
            alert.package.ecosystem,
            "--package",
            alert.package.name,
            "--score",
            str(alert.score),
        ]
        if alert.advisory.cvss is not None:
            argv += ["--cvss", str(alert.advisory.cvss)]
        argv += [*self._cfg.extra_args]

        payload_json = json.dumps(alert.as_payload())
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_child_env(),
            )
        except FileNotFoundError as exc:
            return ActionResult(status="error", detail=f"exec_failed: {exc}")
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(payload_json.encode()),
                timeout=self._cfg.timeout_seconds,
            )
        except asyncio.TimeoutError:
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
