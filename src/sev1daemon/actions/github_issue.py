"""Open GitHub issue via REST API."""

from __future__ import annotations

from sev1daemon.actions.base import Action, ActionResult
from sev1daemon.config import GithubIssueAction
from sev1daemon.http import HttpClient
from sev1daemon.log import get_logger
from sev1daemon.models import Alert

log = get_logger("action.github_issue")


def _format_body(alert: Alert) -> str:
    a = alert.advisory
    refs = "\n".join(f"- {r}" for r in a.references) if a.references else "(none)"
    aliases = ", ".join(a.aliases) if a.aliases else "(none)"
    brk = alert.breakdown.as_dict() if alert.breakdown else {}
    return (
        f"## {a.id}\n\n"
        f"**Class:** {a.advisory_class.value}\n"
        f"**CVSS:** {a.cvss}\n"
        f"**Score:** {alert.score}\n"
        f"**Ecosystem / package:** {alert.package.ecosystem} / {alert.package.name}\n\n"
        f"### Summary\n{a.summary}\n\n"
        f"### Breakdown\n```json\n{brk}\n```\n\n"
        f"### Aliases\n{aliases}\n\n"
        f"### References\n{refs}\n"
    )


class GithubIssueRunner(Action):
    def __init__(self, cfg: GithubIssueAction, http: HttpClient):
        self.name = cfg.name
        self.type = "github_issue"
        self._cfg = cfg
        self._http = http

    async def run(self, alert: Alert) -> ActionResult:
        if not self._cfg.token:
            return ActionResult(status="error", detail="missing github token")
        url = f"https://api.github.com/repos/{self._cfg.repo}/issues"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._cfg.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        body = {
            "title": f"[{alert.advisory.id}] {alert.package.ecosystem}/{alert.package.name}",
            "body": _format_body(alert),
            "labels": self._cfg.labels or [],
            "assignees": self._cfg.assignees or [],
        }
        try:
            resp = await self._http.post(
                url,
                json_body=body,
                headers=headers,
                timeout=20.0,
                follow_redirects=False,
            )
        except Exception as exc:
            log.warning(
                "github_issue.request_failed",
                action=self.name,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return ActionResult(status="error", detail=f"request_failed: {exc!s}")
        if resp.status_code == 201:
            issue = resp.json() if resp.content else {}
            return ActionResult(status="ok", detail=f"issue #{issue.get('number')}")
        log.warning(
            "github_issue.bad_status",
            action=self.name,
            status=resp.status_code,
            body=resp.text[:200],
        )
        return ActionResult(
            status="error",
            detail=f"http {resp.status_code}: {resp.text[:200]}",
        )
