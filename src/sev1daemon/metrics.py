"""Prometheus metrics. Single-process model — no multiproc dir needed.

We expose:

* ``sev1daemon_cycle_seconds`` (Histogram) — wall time of each poll cycle.
* ``sev1daemon_cycle_timeouts_total`` — cycles killed by ``cycle_timeout``.
* ``sev1daemon_cycle_failures_total`` — cycles that raised before completion.
* ``sev1daemon_source_success_total{source}`` / ``..._failure_total{source}``.
* ``sev1daemon_source_fetched_advisories_total{source}``.
* ``sev1daemon_advisories_collected_total`` — post-dedupe count per cycle.
* ``sev1daemon_advisory_failures_total`` — advisories that raised in pipeline.
* ``sev1daemon_action_dispatched_total{action,status}``.
* ``sev1daemon_action_skipped_total{action,reason}`` — circuit/rate/ssrf/dry_run.

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
    Gauge,
    Histogram,
    generate_latest,
)


class Metrics:
    """Holds all daemon metrics and the registry that serves /metrics."""

    def __init__(self) -> None:
        # Own registry — keeps sev1daemon metrics out of any caller's global
        # registry (matters for tests + when embedded).
        self.registry = CollectorRegistry()

        # Cycle-level metrics
        self.cycle_seconds = Histogram(
            "sev1daemon_cycle_seconds",
            "Wall-clock duration of one poll cycle.",
            buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1200),
            registry=self.registry,
        )
        self.cycle_timeout_total = Counter(
            "sev1daemon_cycle_timeouts_total",
            "Cycles that exceeded cycle_timeout_seconds and were cancelled.",
            registry=self.registry,
        )
        self.cycle_failure_total = Counter(
            "sev1daemon_cycle_failures_total",
            "Cycles that raised before completion.",
            registry=self.registry,
        )

        # Source-level metrics
        self.source_success_total = Counter(
            "sev1daemon_source_success_total",
            "Source fetches that returned without raising.",
            ["source"],
            registry=self.registry,
        )
        self.source_failure_total = Counter(
            "sev1daemon_source_failure_total",
            "Source fetches that raised.",
            ["source"],
            registry=self.registry,
        )
        self.source_incomplete_total = Counter(
            "sev1daemon_source_incomplete_total",
            "Source fetches that only partly succeeded (checkpoint not advanced).",
            ["source"],
            registry=self.registry,
        )
        self.source_last_success_timestamp = Gauge(
            "sev1daemon_source_last_success_timestamp_seconds",
            "Unix time of the last complete fetch per source.",
            ["source"],
            registry=self.registry,
        )
        self.advisories_fetched_total = Counter(
            "sev1daemon_source_fetched_advisories_total",
            "Advisories returned from a source (pre-dedupe).",
            ["source"],
            registry=self.registry,
        )

        # Pipeline-level metrics
        self.advisories_collected_total = Counter(
            "sev1daemon_advisories_collected_total",
            "Post-dedupe advisories handed to the scoring pipeline.",
            registry=self.registry,
        )
        self.advisory_failure_total = Counter(
            "sev1daemon_advisory_failures_total",
            "Advisories that raised inside _process_advisory.",
            registry=self.registry,
        )

        self.advisories_requeued_total = Counter(
            "sev1daemon_advisories_requeued_total",
            "Unfinished advisories from earlier cycles picked up again.",
            registry=self.registry,
        )
        self.advisories_given_up_total = Counter(
            "sev1daemon_advisories_given_up_total",
            "Advisories abandoned after advisory_max_attempts unfinished cycles.",
            registry=self.registry,
        )
        self.duplicates_skipped_total = Counter(
            "sev1daemon_duplicate_alerts_skipped_total",
            "Package alerts skipped because a record sharing an id/alias already fired.",
            registry=self.registry,
        )

        # Action-level metrics
        self.action_dispatch_total = Counter(
            "sev1daemon_action_dispatched_total",
            "Action invocations grouped by status (ok/error).",
            ["action", "status"],
            registry=self.registry,
        )
        self.action_skipped_total = Counter(
            "sev1daemon_action_skipped_total",
            "Action invocations skipped before dispatch.",
            ["action", "reason"],
            registry=self.registry,
        )

    def render(self) -> tuple[bytes, str]:
        """Return (body, content_type) for an HTTP /metrics response."""
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


__all__ = ["Metrics"]
