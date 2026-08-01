"""Daemon poll loop + pipeline orchestration.

The daemon owns:

* the poll loop (``run``), which fires ``_run_cycle`` every
  ``poll_interval_seconds`` until SIGTERM/SIGINT.
* the pipeline (``_run_cycle`` → ``_collect`` → ``_dedupe_and_filter``
  → ``_process_advisory``) that turns raw advisories into action dispatches.
* lifecycle of shared clients: HTTP, SQLite state store, action dispatcher,
  health server, and Prometheus metrics.

Signal handling: SIGTERM and SIGINT set ``_stop_evt``. The current cycle
is wrapped in ``asyncio.wait_for`` against ``cycle_timeout_seconds`` so a
hung source download cannot block the shutdown indefinitely. After the
inflight cycle returns or times out, the loop exits and ``shutdown`` runs
through its ``finally`` block.
"""

from __future__ import annotations

import asyncio
import signal
import time
import traceback
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from cvedaemon.actions.dispatcher import ActionDispatcher
from cvedaemon.config import Config
from cvedaemon.enrich import DepsDevClient, GithubStarsClient, RegistryClient
from cvedaemon.health import HealthState, start_health_server
from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger
from cvedaemon.metrics import Metrics
from cvedaemon.models import (
    Advisory,
    AffectedPackage,
    Alert,
)
from cvedaemon.scoring import Scorer
from cvedaemon.sources import (
    GithubSource,
    NvdSource,
    OsvSource,
    RssSource,
    Source,
)
from cvedaemon.state import StateStore

log = get_logger("daemon")

# Bound on parallel source fetches. Most CVE feeds rate-limit aggressively
# and we want to be a polite consumer; 2 concurrent fetches is a good
# tradeoff between freshness and back-pressure.
_SOURCE_FETCH_CONCURRENCY = 2


class Daemon:
    def __init__(self, cfg: Config):
        self._cfg = cfg
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
        self._stop_evt = asyncio.Event()
        self._health_shutdown: Callable[[], None] | None = None
        self._metrics = Metrics()
        # Stale window = max(3 * poll_interval, 300s). After this, healthz fails
        # so k8s liveness probe restarts a wedged daemon.
        stale_seconds = max(3 * cfg.poll_interval_seconds, 300)
        self._health_state = HealthState(cfg.startup_grace_seconds, stale_seconds)

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
            health=f"{self._cfg.health_host}:{self._cfg.health_port}",
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
                try:
                    await asyncio.wait_for(asyncio.shield(cycle_task), timeout=cycle_timeout)
                    self._health_state.mark_success()
                except asyncio.TimeoutError:
                    # Hard kill the cycle if it overran the timeout. Without
                    # this a wedged HTTP read holds the poll loop hostage
                    # past SIGTERM's grace period.
                    cycle_task.cancel()
                    try:
                        await cycle_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    log.error("poll.cycle_timeout", timeout=cycle_timeout)
                    self._metrics.cycle_timeout_total.inc()
                except Exception as exc:
                    log.error(
                        "poll.cycle_failed",
                        error_type=type(exc).__name__,
                        error=str(exc),
                        traceback=traceback.format_exc(),
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

    async def run_once(self) -> int:
        """One-shot poll. Returns number of alerts fired."""
        return await self._run_cycle()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop_evt.set)
            except NotImplementedError:
                # Windows fallback — signals are delivered to the main thread
                # via the default handler; the daemon exits on KeyboardInterrupt.
                pass

    # ---------- pipeline ----------

    async def _run_cycle(self) -> int:
        self._health_state.mark_poll_start()
        cycle_started = time.monotonic()
        try:
            advisories = await self._collect()
            advisories = await self._dedupe_and_filter(advisories)
            log.info("poll.collected", count=len(advisories))
            self._metrics.advisories_collected_total.inc(len(advisories))
            fired = 0
            for adv in advisories:
                fired += await self._process_advisory(adv)
            # Housekeeping. Run unconditionally; both prunes are cheap when
            # nothing is over the retention window.
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
            return fired
        finally:
            self._health_state.mark_poll_end()
            self._metrics.cycle_seconds.observe(time.monotonic() - cycle_started)

    async def _collect(self) -> list[Advisory]:
        # Bounded concurrency: be polite to upstream feeds, but don't serialize
        # entirely — a slow NVD pull no longer blocks GHSA.
        sem = asyncio.Semaphore(_SOURCE_FETCH_CONCURRENCY)
        results: list[Advisory] = []

        async def _one(src: Source) -> None:
            async with sem:
                since = await self._since_for(src.name)
                try:
                    advs = await src.fetch(since)
                except Exception as exc:
                    log.warning(
                        "poll.source_failed",
                        source=src.name,
                        error_type=type(exc).__name__,
                        error=str(exc),
                    )
                    self._metrics.source_failure_total.labels(source=src.name).inc()
                    await self._state.set_poll_failure(src.name, str(exc))
                    return
                log.info("poll.source_ok", source=src.name, advisories=len(advs))
                self._metrics.source_success_total.labels(source=src.name).inc()
                self._metrics.advisories_fetched_total.labels(source=src.name).inc(len(advs))
                await self._state.set_poll_success(src.name)
                results.extend(advs)

        await asyncio.gather(*(_one(s) for s in self._sources))
        return results

    async def _since_for(self, source_name: str) -> datetime:
        last = await self._state.get_last_success(source_name)
        if last is None:
            return datetime.now(timezone.utc) - timedelta(
                minutes=self._cfg.lookback_minutes_on_start
            )
        # 1-min overlap to avoid edge-misses.
        return last - timedelta(minutes=1)

    async def _dedupe_and_filter(self, advisories: list[Advisory]) -> list[Advisory]:
        # Merge by id across sources.
        merged: dict[str, Advisory] = {}
        for adv in advisories:
            existing = merged.get(adv.id)
            merged[adv.id] = existing.merge(adv) if existing else adv
        # Drop already-processed.
        out: list[Advisory] = []
        for adv in merged.values():
            if await self._state.advisory_seen(adv.id):
                continue
            out.append(adv)
        return out

    async def _process_advisory(self, adv: Advisory) -> int:
        await self._state.upsert_advisory(adv)
        try:
            if adv.is_supply_chain:
                fired = await self._process_supply_chain(adv)
            else:
                fired = await self._process_cve(adv)
        except Exception as exc:
            # Leave processed=0 so next cycle retries. Per-package idempotency
            # in record_package_score+package_fired prevents already-fired
            # actions from re-running.
            log.warning(
                "poll.advisory_failed",
                advisory=adv.id,
                error_type=type(exc).__name__,
                error=str(exc),
                traceback=traceback.format_exc(),
            )
            self._metrics.advisory_failure_total.inc()
            return 0
        await self._state.mark_processed(adv.id)
        return fired

    async def _process_cve(self, adv: Advisory) -> int:
        if not self._dispatcher:
            return 0
        fired = 0
        for pkg in adv.affected:
            # CPE-derived "packages" (from NVD-only ingestion) don't map to
            # any registry — stars/downloads/deps.dev all return 0 and the
            # advisory could never cross threshold. Skip them; rely on cross-
            # ref via aliases against OSV/GHSA records that have real
            # ecosystem entries.
            if pkg.ecosystem.startswith("cpe:"):
                continue
            # Idempotency: if a prior cycle already dispatched actions for
            # this (advisory, package) pair, a mid-batch retry must not
            # re-fire. The advisory row stays at processed=0 only if a later
            # package raised — but earlier packages must remain "done".
            if await self._state.package_fired(adv.id, pkg.ecosystem, pkg.name):
                continue
            stars, downloads, depsdev = await self._enrich(pkg)
            breakdown = self._scorer.score(pkg, stars, downloads, depsdev)
            score = breakdown.total
            crosses = self._scorer.crosses_threshold(score)
            await self._state.record_package_score(
                adv.id, pkg.ecosystem, pkg.name, score, breakdown.as_dict(), crosses
            )
            if not crosses:
                continue
            alert = Alert(advisory=adv, package=pkg, score=score, breakdown=breakdown)
            results = await self._dispatcher.dispatch(alert)
            if any(r.status == "ok" for r in results):
                fired += 1
        return fired

    async def _process_supply_chain(self, adv: Advisory) -> int:
        if not self._dispatcher:
            return 0
        packages = adv.affected or [AffectedPackage(ecosystem="(any)", name="(unspecified)")]
        fired = 0
        for pkg in packages:
            if await self._state.package_fired(adv.id, pkg.ecosystem, pkg.name):
                continue
            alert = Alert(advisory=adv, package=pkg, score=100.0, breakdown=None)
            await self._state.record_package_score(
                adv.id, pkg.ecosystem, pkg.name, 100.0, None, True
            )
            results = await self._dispatcher.dispatch(alert)
            if any(r.status == "ok" for r in results):
                fired += 1
        return fired

    async def _enrich(self, pkg: AffectedPackage) -> tuple[int | None, int | None, int | None]:
        # Gather all signal lookups; per-signal failure → None, never propagate.
        downloads_r, depsdev_r, repo_url_r = await asyncio.gather(
            self._registry.downloads(pkg.ecosystem, pkg.name),
            self._depsdev.dependents(pkg.ecosystem, pkg.name),
            self._depsdev.repo_url(pkg.ecosystem, pkg.name),
            return_exceptions=True,
        )
        downloads_raw = self._unwrap_signal("downloads", pkg, downloads_r)
        depsdev_raw = self._unwrap_signal("depsdev", pkg, depsdev_r)
        repo_url = self._unwrap_signal("repo_url", pkg, repo_url_r)
        downloads = downloads_raw if isinstance(downloads_raw, int) else None
        depsdev = depsdev_raw if isinstance(depsdev_raw, int) else None
        if self._stars and isinstance(repo_url, str) and repo_url:
            try:
                stars = await self._stars.stars_for_repo_url(repo_url)
            except Exception as exc:
                log.warning(
                    "enrich.stars_failed",
                    ecosystem=pkg.ecosystem,
                    package=pkg.name,
                    error=str(exc),
                )
                stars = None
        else:
            stars = None
        return stars, downloads, depsdev

    @staticmethod
    def _unwrap_signal(
        name: str,
        pkg: AffectedPackage,
        result: int | str | None | BaseException,
    ) -> int | str | None:
        if isinstance(result, BaseException):
            log.warning(
                "enrich.signal_failed",
                signal=name,
                ecosystem=pkg.ecosystem,
                package=pkg.name,
                error=str(result),
            )
            return None
        return result


# ---------- top-level entry helpers ----------


async def run_daemon(cfg: Config) -> None:
    d = Daemon(cfg)
    try:
        await d.setup()
    except Exception:
        await d.shutdown()
        raise
    await d.run()  # run() owns shutdown in its finally clause


async def run_one_shot(cfg: Config, *, dry_run: bool = False) -> int:
    """Run one poll cycle. ``dry_run`` disables action dispatch (state only)."""
    d = Daemon(cfg)
    try:
        await d.setup()
    except Exception:
        await d.shutdown()
        raise
    # Flip dry-run after setup so the dispatcher (built in setup) exists.
    if dry_run and d._dispatcher is not None:
        d._dispatcher.dry_run = True
        log.info("daemon.dry_run_enabled")
    try:
        return await d.run_once()
    finally:
        await d.shutdown()
