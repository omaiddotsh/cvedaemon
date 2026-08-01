"""Prometheus metrics. Single-process model — no multiproc dir needed.

We expose:

* ``cvedaemon_cycle_seconds`` (Histogram) — wall time of each poll cycle.
* ``cvedaemon_cycle_timeouts_total`` — cycles killed by ``cycle_timeout``.
* ``cvedaemon_cycle_failures_total`` — cycles that raised before completion.
* ``cvedaemon_source_success_total{source}`` / ``..._failure_total{source}``.
* ``cvedaemon_source_fetched_advisories_total{source}``.
* ``cvedaemon_advisories_collected_total`` — post-dedupe count per cycle.
* ``cvedaemon_advisory_failures_total`` — advisories that raised in pipeline.
* ``cvedaemon_action_dispatched_total{action,status}``.
* ``cvedaemon_action_skipped_total{action,reason}`` — circuit/rate/ssrf/dry_run.

The dependency on ``prometheus_client`` is hard — it's a small pure-Python
library and the daemon is intended to be observable in production. If you
strip it, you'd also strip the ``/metrics`` route and lose SLO visibility,
which is a worse tradeoff.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)


class Metrics:
    """Holds all daemon metrics and the registry that serves /metrics."""

    def __init__(self) -> None:
        # Own registry — keeps cvedaemon metrics out of any caller's global
        # registry (matters for tests + when embedded).
        self.registry = CollectorRegistry()

        # Cycle-level metrics
        self.cycle_seconds = Histogram(
            "cvedaemon_cycle_seconds",
            "Wall-clock duration of one poll cycle.",
            buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1200),
            registry=self.registry,
        )
        self.cycle_timeout_total = Counter(
            "cvedaemon_cycle_timeouts_total",
            "Cycles that exceeded cycle_timeout_seconds and were cancelled.",
            registry=self.registry,
        )
        self.cycle_failure_total = Counter(
            "cvedaemon_cycle_failures_total",
            "Cycles that raised before completion.",
            registry=self.registry,
        )

        # Source-level metrics
        self.source_success_total = Counter(
            "cvedaemon_source_success_total",
            "Source fetches that returned without raising.",
            ["source"],
            registry=self.registry,
        )
        self.source_failure_total = Counter(
            "cvedaemon_source_failure_total",
            "Source fetches that raised.",
            ["source"],
            registry=self.registry,
        )
        self.advisories_fetched_total = Counter(
            "cvedaemon_source_fetched_advisories_total",
            "Advisories returned from a source (pre-dedupe).",
            ["source"],
            registry=self.registry,
        )

        # Pipeline-level metrics
        self.advisories_collected_total = Counter(
            "cvedaemon_advisories_collected_total",
            "Post-dedupe advisories handed to the scoring pipeline.",
            registry=self.registry,
        )
        self.advisory_failure_total = Counter(
            "cvedaemon_advisory_failures_total",
            "Advisories that raised inside _process_advisory.",
            registry=self.registry,
        )

        # Action-level metrics
        self.action_dispatch_total = Counter(
            "cvedaemon_action_dispatched_total",
            "Action invocations grouped by status (ok/error).",
            ["action", "status"],
            registry=self.registry,
        )
        self.action_skipped_total = Counter(
            "cvedaemon_action_skipped_total",
            "Action invocations skipped before dispatch.",
            ["action", "reason"],
            registry=self.registry,
        )

    def render(self) -> tuple[bytes, str]:
        """Return (body, content_type) for an HTTP /metrics response."""
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


__all__ = ["Metrics"]
