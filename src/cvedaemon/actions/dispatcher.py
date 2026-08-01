"""Action dispatcher.

Owns the lifecycle of action runners and the guards that wrap every dispatch:

1. **Match** — ``min_score`` + ecosystem allow-list filter (per-action).
2. **Dry-run** — short-circuit before guards/runners when the daemon was
   invoked with ``--dry-run`` (logging + state still occur).
3. **Circuit breaker** — skip if the action has tripped recent-failure
   threshold inside the rolling window.
4. **SSRF guard** — for webhook + github_issue actions, refuse if the target
   resolves to a private IP unless ``allow_private_urls=true``.
5. **Rate limit** — per-``(action_name, host)`` token bucket gates dispatch.
6. **Run** — the runner itself; any exception is caught and recorded as an
   error result.

Every outcome (dispatched, skipped, errored) is recorded in ``action_log``
and emitted as a Prometheus counter so SREs can alert on circuit trips or
SSRF rejections.
"""

from __future__ import annotations

from cvedaemon.actions.base import Action, ActionResult
from cvedaemon.actions.github_issue import GithubIssueRunner
from cvedaemon.actions.guards import (
    CircuitBreaker,
    TokenBucket,
    host_of,
    is_safe_url,
)
from cvedaemon.actions.nebari import NebariRunner
from cvedaemon.actions.shell import ShellRunner
from cvedaemon.actions.webhook import WebhookRunner
from cvedaemon.config import (
    AnyAction,
    GithubIssueAction,
    NebariAction,
    ShellAction,
    WebhookAction,
)
from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger
from cvedaemon.metrics import Metrics
from cvedaemon.models import Alert
from cvedaemon.state import StateStore

log = get_logger("action")


def build_runner(cfg: AnyAction, http: HttpClient) -> Action:
    if isinstance(cfg, WebhookAction):
        return WebhookRunner(cfg, http)
    if isinstance(cfg, GithubIssueAction):
        return GithubIssueRunner(cfg, http)
    if isinstance(cfg, ShellAction):
        return ShellRunner(cfg)
    if isinstance(cfg, NebariAction):
        return NebariRunner(cfg)
    raise ValueError(f"unknown action type: {type(cfg).__name__}")


class ActionDispatcher:
    def __init__(
        self,
        actions: list[AnyAction],
        http: HttpClient,
        state: StateStore,
        global_threshold: int,
        *,
        circuit_failures: int = 5,
        circuit_window_seconds: int = 600,
        rate_per_second: float = 5.0,
        rate_burst: int = 5,
        allow_private_urls: bool = False,
        metrics: Metrics | None = None,
    ):
        self._global_threshold = global_threshold
        self._runners: list[tuple[AnyAction, Action]] = [
            (cfg, build_runner(cfg, http)) for cfg in actions if cfg.enabled
        ]
        self._state = state
        self._breaker = CircuitBreaker(state, circuit_failures, circuit_window_seconds)
        self._bucket = TokenBucket(rate_per_second, rate_burst)
        self._allow_private = allow_private_urls
        self._metrics = metrics
        self.dry_run = False

    @property
    def runner_count(self) -> int:
        return len(self._runners)

    def get_by_name(self, name: str) -> Action | None:
        for _, runner in self._runners:
            if runner.name == name:
                return runner
        return None

    async def dispatch(self, alert: Alert) -> list[ActionResult]:
        results: list[ActionResult] = []
        for cfg, runner in self._runners:
            if not self._matches(cfg, alert):
                continue
            res = await self._dispatch_one(cfg, runner, alert)
            results.append(res)
        return results

    async def _dispatch_one(
        self, cfg: AnyAction, runner: Action, alert: Alert
    ) -> ActionResult:
        if self.dry_run:
            self._record_skip(runner, alert, "dry_run")
            return ActionResult(status="skipped", detail="dry_run")

        if await self._breaker.is_open(runner.name):
            self._record_skip(runner, alert, "circuit_open")
            log.warning(
                "action.skipped",
                reason="circuit_open",
                action=runner.name,
                advisory=alert.advisory.id,
            )
            return ActionResult(status="skipped", detail="circuit_open")

        target_host = self._target_host(cfg)
        if target_host is None:
            # ssrf check returned False — refused before any IO.
            self._record_skip(runner, alert, "ssrf_blocked")
            return ActionResult(status="skipped", detail="ssrf_blocked")

        bucket_key = f"{runner.name}::{target_host}"
        if not await self._bucket.acquire(bucket_key, timeout=10.0):
            self._record_skip(runner, alert, "rate_limited")
            log.warning(
                "action.skipped",
                reason="rate_limited",
                action=runner.name,
                host=target_host,
            )
            return ActionResult(status="skipped", detail="rate_limited")

        return await self._run_one(runner, alert)

    def _target_host(self, cfg: AnyAction) -> str | None:
        """Resolve and SSRF-check the outbound host for guards.

        Returns the hostname on success, or ``None`` if the URL is rejected.
        For non-HTTP actions (shell/nebari) returns a stable label so rate
        limiting still applies per-action.
        """
        if isinstance(cfg, WebhookAction):
            ok, reason = is_safe_url(cfg.url, allow_private=self._allow_private)
            if not ok:
                log.warning(
                    "action.ssrf_blocked",
                    action=cfg.name,
                    reason=reason,
                )
                return None
            return host_of(cfg.url)
        if isinstance(cfg, GithubIssueAction):
            # github_issue always hits api.github.com; the repo path is
            # already regex-validated in config.
            return "api.github.com"
        if isinstance(cfg, ShellAction):
            return f"local-shell::{cfg.name}"
        if isinstance(cfg, NebariAction):
            return f"local-nebari::{cfg.name}"
        return "unknown"

    def _record_skip(self, runner: Action, alert: Alert, reason: str) -> None:
        if self._metrics is not None:
            self._metrics.action_skipped_total.labels(
                action=runner.name, reason=reason
            ).inc()

    async def _run_one(self, runner: Action, alert: Alert) -> ActionResult:
        try:
            res = await runner.run(alert)
        except Exception as exc:
            log.exception(
                "action.unhandled",
                action=runner.name,
                advisory=alert.advisory.id,
                error=str(exc),
            )
            res = ActionResult(status="error", detail=f"unhandled: {exc!s}")
        await self._state.log_action(
            advisory_id=alert.advisory.id,
            action_name=runner.name,
            action_type=runner.type,
            status=res.status,
            detail=res.detail,
            ecosystem=alert.package.ecosystem,
            package=alert.package.name,
        )
        if self._metrics is not None:
            self._metrics.action_dispatch_total.labels(
                action=runner.name, status=res.status
            ).inc()
        log.info(
            "action.ran",
            action=runner.name,
            type=runner.type,
            status=res.status,
            advisory=alert.advisory.id,
            ecosystem=alert.package.ecosystem,
            package=alert.package.name,
        )
        return res

    def _matches(self, cfg: AnyAction, alert: Alert) -> bool:
        # Supply chain bypasses score, but per-action min_score still respected.
        # Per-action min_score must be ≥ global threshold per README.
        effective_min = max(cfg.min_score, self._global_threshold)
        # Supply-chain alerts force score=100, so anything with min_score ≤ 100
        # matches them regardless of per-package signals.
        if alert.score < effective_min:
            return False
        return not (cfg.ecosystems and alert.package.ecosystem not in cfg.ecosystems)
