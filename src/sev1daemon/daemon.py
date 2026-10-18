"""Daemon: lifecycle, poll loop and source collection.

The daemon owns:

* the poll loop (``run``), which fires ``_run_cycle`` every
  ``poll_interval_seconds`` until SIGTERM/SIGINT.
* source collection (``_collect``) with per-source checkpoints, and the
  housekeeping that runs after each cycle.
* lifecycle of shared clients: HTTP, SQLite state store, action dispatcher,
  health server, and Prometheus metrics.

Scoring and dispatch live in ``pipeline.AlertPipeline``.

Signal handling: SIGTERM and SIGINT set ``_stop_evt``. The in-flight cycle
races the stop event and ``cycle_timeout_seconds``; whichever comes first
cancels it, so shutdown takes seconds rather than waiting out a long fetch
(systemd/Docker would SIGKILL first). Anything the cancelled cycle didn't
finish stays ``processed=0`` and is re-queued on the next start.

Delivery guarantees:

* A source's checkpoint only advances after a complete fetch, to the time the
  fetch started; queries overlap the previous window (dedupe makes that free).
* Every advisory a cycle collected is stored (``processed=0``) before any
  checkpoint moves. A cycle cancelled or killed at any point therefore leaves
  each advisory either still inside some source's next query window or in the
  re-queue; nothing fetched is lost.
* An advisory is marked processed only once every matching action for every
  package crossing the threshold has succeeded. Unfinished advisories are
  re-queued each cycle, up to ``advisory_max_attempts`` cycles.
* Alerts are at-least-once: a cycle cancelled mid-dispatch can re-send.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import signal
import sqlite3
import tempfile
import time
import traceback
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sev1daemon.actions.dispatcher import ActionDispatcher
from sev1daemon.config import Config
from sev1daemon.enrich import DepsDevClient, GithubStarsClient, RegistryClient
from sev1daemon.health import HealthState, start_health_server
from sev1daemon.http import HttpClient
from sev1daemon.log import get_logger
from sev1daemon.metrics import Metrics
from sev1daemon.models import Advisory
from sev1daemon.pipeline import AlertPipeline
from sev1daemon.scoring import Scorer
from sev1daemon.sources import (
    GithubSource,
    NvdSource,
    OsvSource,
    RssSource,
    Source,
    SourceFetchIncomplete,
)
from sev1daemon.state import StateStore

log = get_logger("daemon")

# Bound on parallel source fetches. Most CVE feeds rate-limit aggressively
# and we want to be a polite consumer; 2 concurrent fetches is a good
# tradeoff between freshness and back-pressure.
_SOURCE_FETCH_CONCURRENCY = 2

# How long shutdown waits for a cancelled cycle to unwind before giving up.
_CANCEL_GRACE_SECONDS = 10.0


@dataclass
class _Collected:
    """One cycle's fetch results, and the checkpoints the complete fetches earned.

    The checkpoints are written only after the advisories are stored, so a
    cycle that dies in between never moves a window past an unstored record.
    """

    advisories: list[Advisory] = field(default_factory=list)
    checkpoints: list[tuple[str, datetime]] = field(default_factory=list)  # (source, fetch start)


class Daemon:
    def __init__(self, cfg: Config, *, dry_run: bool = False, serve_health: bool = True):
        """``dry_run``: score and log but never run actions. Pair it with
        ``dry_run_config`` so state writes land in a throwaway DB snapshot.

        ``serve_health``: bind the health/metrics port. One-shot commands
        (``check``, ``replay``) pass False so they can run next to the daemon,
        which already holds that port."""
        self._cfg = cfg
        self._dry_run = dry_run
        self._serve_health = serve_health
        self._http = HttpClient(
            cache_dir=cfg.http_cache_dir,
            cache_ttl_seconds=cfg.http_cache_ttl_seconds,
        )
        self._state = StateStore(cfg.state_db)
        self._sources: list[Source] = []
        self._scorer = Scorer(cfg.blast_radius)
        self._stars: GithubStarsClient | None = None
        self._registry = RegistryClient(self._http)
        self._depsdev = DepsDevClient(self._http)
        self._dispatcher: ActionDispatcher | None = None
        self._pipeline: AlertPipeline | None = None
        self._stop_evt = asyncio.Event()
        self._health_shutdown: Callable[[], None] | None = None
        self._metrics = Metrics()
        # healthz fails once no source has fetched completely for the stale
        # window, so a liveness probe restarts a wedged or blind daemon. Both
        # windows must outlast one full (possibly slow) cycle, or the probe
        # kills a healthy daemon in the middle of its first poll.
        cycle_timeout = int(cfg.effective_cycle_timeout())
        stale_seconds = max(3 * cfg.poll_interval_seconds, cycle_timeout + cfg.poll_interval_seconds, 300)
        grace_seconds = max(cfg.startup_grace_seconds, cycle_timeout)
        self._health_state = HealthState(grace_seconds, stale_seconds)

    # ---------- lifecycle ----------

    async def setup(self) -> None:
        await self._state.open()
        self._stars = GithubStarsClient(self._http, self._cfg.sources.github.token)
        self._build_sources()
        self._dispatcher = ActionDispatcher(
            self._cfg.actions,
            self._http,
            self._state,
            self._cfg.blast_radius.score_threshold,
            circuit_failures=self._cfg.action_circuit_failures,
            circuit_window_seconds=self._cfg.action_circuit_window_seconds,
            rate_per_second=self._cfg.action_rate_per_second,
            rate_burst=self._cfg.action_rate_burst,
            allow_private_urls=self._cfg.allow_private_urls,
            metrics=self._metrics,
        )
        if self._dry_run:
            self._dispatcher.dry_run = True
            log.info("daemon.dry_run_enabled")
        self._pipeline = AlertPipeline(
            self._cfg,
            self._state,
            self._dispatcher,
            self._scorer,
            self._registry,
            self._depsdev,
            self._stars,
            self._metrics,
        )
        if self._serve_health:
            self._health_shutdown = start_health_server(
                self._cfg.health_host,
                self._cfg.health_port,
                self._health_state,
                self._metrics,
            )
        log.info(
            "daemon.setup",
            sources=[s.name for s in self._sources],
            actions=self._dispatcher.runner_count,
            health=f"{self._cfg.health_host}:{self._cfg.health_port}" if self._serve_health else "off",
            cycle_timeout=self._cfg.effective_cycle_timeout(),
        )

    async def shutdown(self) -> None:
        if self._health_shutdown is not None:
            try:
                self._health_shutdown()
            except Exception as exc:
                log.warning("health.shutdown_failed", error=str(exc))
        await self._http.aclose()
        await self._state.close()
        log.info("daemon.stopped")

    def _build_sources(self) -> None:
        src_cfg = self._cfg.sources
        if src_cfg.osv.enabled:
            self._sources.append(
                OsvSource(
                    http=self._http,
                    base_url=src_cfg.osv.base_url,
                    ecosystems=src_cfg.osv.ecosystems,
                    min_cvss=self._cfg.min_cvss,
                )
            )
        if src_cfg.nvd.enabled:
            self._sources.append(
                NvdSource(
                    http=self._http,
                    base_url=src_cfg.nvd.base_url,
                    api_key=src_cfg.nvd.api_key,
                    results_per_page=src_cfg.nvd.results_per_page,
                    min_cvss=self._cfg.min_cvss,
                )
            )
        if src_cfg.github.enabled:
            self._sources.append(
                GithubSource(
                    http=self._http,
                    base_url=src_cfg.github.base_url,
                    token=src_cfg.github.token,
                    severities=src_cfg.github.severity,
                    min_cvss=self._cfg.min_cvss,
                )
            )
        if src_cfg.rss.enabled and src_cfg.rss.feeds:
            self._sources.append(
                RssSource(
                    http=self._http,
                    feeds=[f.model_dump() for f in src_cfg.rss.feeds],
                    keywords=src_cfg.rss.keywords,
                )
            )

    # ---------- run loop ----------

    async def run(self) -> None:
        self._install_signal_handlers()
        cycle_timeout = self._cfg.effective_cycle_timeout()
        try:
            while not self._stop_evt.is_set():
                started = datetime.now(timezone.utc)
                cycle_task = asyncio.create_task(self._run_cycle())
                stop_task = asyncio.create_task(self._stop_evt.wait())
                done, _ = await asyncio.wait(
                    {cycle_task, stop_task},
                    timeout=cycle_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                stop_task.cancel()
                if cycle_task not in done:
                    # Stop requested, or the cycle overran its timeout (a
                    # wedged HTTP read). Cancel it either way; unfinished
                    # advisories stay processed=0 and are re-queued.
                    await self._cancel_cycle(cycle_task)
                    if self._stop_evt.is_set():
                        log.info("poll.cycle_cancelled_for_shutdown")
                        break
                    log.error("poll.cycle_timeout", timeout=cycle_timeout)
                    self._metrics.cycle_timeout_total.inc()
                elif (exc := cycle_task.exception()) is not None:
                    log.error(
                        "poll.cycle_failed",
                        error_type=type(exc).__name__,
                        error=str(exc),
                        traceback="".join(traceback.format_exception(exc)),
                    )
                    self._metrics.cycle_failure_total.inc()
                elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                sleep_for = max(1.0, self._cfg.poll_interval_seconds - elapsed)
                try:
                    await asyncio.wait_for(self._stop_evt.wait(), timeout=sleep_for)
                except asyncio.TimeoutError:
                    pass
            log.info("daemon.stop_signal_received")
        finally:
            await self.shutdown()

    async def _cancel_cycle(self, cycle_task: asyncio.Task[int]) -> None:
        cycle_task.cancel()
        try:
            await asyncio.wait_for(cycle_task, timeout=_CANCEL_GRACE_SECONDS)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        except Exception as exc:
            log.warning("poll.cycle_cancel_error", error_type=type(exc).__name__, error=str(exc))

    async def run_once(self) -> int:
        """One-shot poll. Returns number of alerts fired."""
        return await self._run_cycle()

    async def replay(self, advisory_id: str) -> int | None:
        """Re-process a stored advisory from scratch; None if it isn't stored.

        Clears its processed flag, retry count, per-package scores and dedupe
        keys so every package is scored and dispatched again against the
        current config. Actions that already succeeded are still skipped.
        """
        assert self._pipeline is not None, "call setup() first"
        adv = await self._state.get_advisory(advisory_id)
        if adv is None:
            return None
        await self._state.reset_for_replay(advisory_id)
        return await self._pipeline.process(adv)

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop_evt.set)
            except NotImplementedError:
                # Windows fallback — signals are delivered to the main thread
                # via the default handler; the daemon exits on KeyboardInterrupt.
                pass

    # ---------- cycle ----------

    async def _run_cycle(self) -> int:
        assert self._pipeline is not None, "call setup() first"
        self._health_state.mark_poll_start()
        cycle_started = time.monotonic()
        try:
            collected = await self._collect()
            advisories = await self._pipeline.new_advisories(collected.advisories)
            # Store first, then move the checkpoints: from here on a cancelled
            # or crashed cycle re-queues these rows instead of losing them.
            await self._pipeline.store(advisories)
            await self._commit_checkpoints(collected.checkpoints)
            advisories += await self._pipeline.requeued(exclude={a.id for a in advisories})
            log.info("poll.collected", count=len(advisories))
            self._metrics.advisories_collected_total.inc(len(advisories))
            fired = 0
            for adv in advisories:
                fired += await self._pipeline.process(adv)
            await self._housekeeping()
            return fired
        finally:
            self._health_state.mark_poll_end()
            self._metrics.cycle_seconds.observe(time.monotonic() - cycle_started)

    async def _housekeeping(self) -> None:
        """Retention pruning + cache eviction; cheap when nothing is due."""
        pruned_actions = await self._state.prune_action_log(
            self._cfg.action_log_retention_days
        )
        if pruned_actions:
            log.info("housekeeping.pruned", action_log_rows=pruned_actions)
        pruned_pkgs = await self._state.prune_processed_packages(
            self._cfg.processed_packages_retention_days
        )
        if pruned_pkgs:
            log.info("housekeeping.pruned_packages", rows=pruned_pkgs)
        pruned_advs = await self._state.prune_advisories(self._cfg.advisory_retention_days)
        if pruned_advs:
            log.info("housekeeping.pruned_advisories", rows=pruned_advs)
        evicted = await self._http.evict_expired()
        if evicted:
            log.info("housekeeping.cache_evicted", files=evicted)

    async def _collect(self) -> _Collected:
        # Bounded concurrency: be polite to upstream feeds, but don't serialize
        # entirely — a slow NVD pull no longer blocks GHSA.
        sem = asyncio.Semaphore(_SOURCE_FETCH_CONCURRENCY)
        collected = _Collected()
        results = collected.advisories

        async def _one(src: Source) -> None:
            async with sem:
                since = await self._since_for(src.name)
                fetch_started = datetime.now(timezone.utc)
                try:
                    advs = await src.fetch(since)
                except SourceFetchIncomplete as exc:
                    # Use what came back, but keep the checkpoint where it is so
                    # the missing part of the window is queried again.
                    await self._source_failed(src.name, f"incomplete: {exc}", incomplete=True)
                    self._metrics.advisories_fetched_total.labels(source=src.name).inc(
                        len(exc.advisories)
                    )
                    results.extend(exc.advisories)
                    return
                except Exception as exc:
                    await self._source_failed(src.name, f"{type(exc).__name__}: {exc}")
                    return
                log.info("poll.source_ok", source=src.name, advisories=len(advs))
                self._metrics.source_success_total.labels(source=src.name).inc()
                self._metrics.advisories_fetched_total.labels(source=src.name).inc(len(advs))
                self._metrics.source_last_success_timestamp.labels(source=src.name).set(
                    fetch_started.timestamp()
                )
                results.extend(advs)
                # The checkpoint is earned, but written by _run_cycle once the
                # advisories are stored (see _Collected).
                collected.checkpoints.append((src.name, fetch_started))

        await asyncio.gather(*(_one(s) for s in self._sources))
        return collected

    async def _commit_checkpoints(self, checkpoints: list[tuple[str, datetime]]) -> None:
        for name, fetch_started in checkpoints:
            await self._state.set_poll_success(name, at=fetch_started)
            self._health_state.mark_source(name, ok=True)

    async def _source_failed(self, name: str, error: str, *, incomplete: bool = False) -> None:
        """Record a failed or partial fetch; the checkpoint stays where it was."""
        log.warning(
            "poll.source_incomplete" if incomplete else "poll.source_failed",
            source=name,
            error=error,
        )
        counter = (
            self._metrics.source_incomplete_total if incomplete else self._metrics.source_failure_total
        )
        counter.labels(source=name).inc()
        await self._state.set_poll_failure(name, error)
        self._health_state.mark_source(name, ok=False, error=error)

    async def _since_for(self, source_name: str) -> datetime:
        last = await self._state.get_last_success(source_name)
        if last is None:
            return datetime.now(timezone.utc) - timedelta(
                minutes=self._cfg.lookback_minutes_on_start
            )
        # Overlap the previous window generously: upstream indexes lag behind
        # their "modified" timestamps, and dedupe makes re-reading free.
        overlap = max(timedelta(minutes=10), timedelta(seconds=2 * self._cfg.poll_interval_seconds))
        return last - overlap


# ---------- top-level entry helpers ----------


async def run_daemon(cfg: Config) -> None:
    d = Daemon(cfg)
    try:
        await d.setup()
    except Exception:
        await d.shutdown()
        raise
    await d.run()  # run() owns shutdown in its finally clause


@contextlib.asynccontextmanager
async def dry_run_config(cfg: Config, enabled: bool) -> AsyncIterator[Config]:
    """Point the state DB at a throwaway snapshot when ``enabled``.

    A dry run still scores and marks advisories processed; doing that on the
    production DB would suppress the real alerts afterwards.
    """
    if not enabled:
        yield cfg
        return
    tmp = Path(tempfile.mkdtemp(prefix="sev1daemon-dryrun-"))
    snapshot = tmp / "state.db"
    try:
        # sqlite backup API: consistent copy even with a live WAL writer.
        await asyncio.to_thread(_sqlite_snapshot, Path(cfg.state_db), snapshot)
        log.info("daemon.dry_run_snapshot", path=str(snapshot))
        yield cfg.model_copy(update={"state_db": str(snapshot)})
    finally:
        await asyncio.to_thread(shutil.rmtree, tmp, True)


def _sqlite_snapshot(src: Path, dst: Path) -> None:
    if not src.exists():
        return  # first run: the dry run starts from an empty DB
    with (
        contextlib.closing(sqlite3.connect(f"file:{src}?mode=ro", uri=True)) as source,
        contextlib.closing(sqlite3.connect(dst)) as target,
    ):
        source.backup(target)


async def run_one_shot(cfg: Config, *, dry_run: bool = False) -> int:
    """Run one poll cycle. ``dry_run`` disables action dispatch and uses a DB snapshot."""
    async with dry_run_config(cfg, dry_run) as run_cfg:
        # No health server: the daemon usually holds that port already.
        d = Daemon(run_cfg, dry_run=dry_run, serve_health=False)
        try:
            await d.setup()
        except Exception:
            await d.shutdown()
            raise
        try:
            return await d.run_once()
        finally:
            await d.shutdown()
