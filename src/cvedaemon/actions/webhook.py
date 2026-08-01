"""Generic JSON webhook action.

POSTs the alert payload as JSON. ``follow_redirects=False`` on the underlying
client prevents an attacker-controlled redirect from leaking the Authorization
header (or whatever ``headers:`` block the operator configured) to a host
they don't trust. SSRF validation against private/loopback IPs happens at the
dispatcher layer before we even get here.
"""

from __future__ import annotations

from cvedaemon.actions.base import Action, ActionResult
from cvedaemon.config import WebhookAction
from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger
from cvedaemon.models import Alert

log = get_logger("action.webhook")


class WebhookRunner(Action):
    def __init__(self, cfg: WebhookAction, http: HttpClient):
        self.name = cfg.name
        self.type = "webhook"
        self._cfg = cfg
        self._http = http

    async def run(self, alert: Alert) -> ActionResult:
        try:
            resp = await self._http.request(
                self._cfg.method.upper(),
                self._cfg.url,
                json_body=alert.as_payload(),
                headers=self._cfg.headers or None,
                timeout=self._cfg.timeout_seconds,
                follow_redirects=False,
            )
        except Exception as exc:
            log.warning(
                "webhook.request_failed",
                action=self.name,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return ActionResult(status="error", detail=f"request_failed: {exc!s}")

        if 200 <= resp.status_code < 300:
            return ActionResult(status="ok", detail=f"http {resp.status_code}")
        log.warning(
            "webhook.bad_status",
            action=self.name,
            status=resp.status_code,
            body=resp.text[:200],
        )
        return ActionResult(
            status="error",
            detail=f"http {resp.status_code}: {resp.text[:200]}",
        )
