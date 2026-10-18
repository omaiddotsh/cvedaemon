"""Alert pipeline: turns collected advisories into action dispatches.

For each advisory, every affected package is scored and dispatched:

* **Supply chain** advisories skip enrichment and score 100 (popularity is
  irrelevant for an active compromise). With no package listed they alert
  once against a ``(any)/(unspecified)`` placeholder.
* **Everything else** (CVEs, malicious-package records) is enriched (stars,
  downloads, deps.dev dependents), scored, and dispatched only above the
  threshold.

Delivery bookkeeping lives here too: a package is recorded as fired only once
every matching action succeeded; an advisory is marked processed only when
none of its packages is left unfinished, otherwise the attempt is counted and
the daemon re-queues it next cycle (up to ``advisory_max_attempts``).
Records for the same vulnerability from different sources share an id/alias
and alert once per package (``fired_keys``).
"""

from __future__ import annotations

import asyncio
import traceback
from dataclasses import dataclass
from typing import Any

from sev1daemon.actions.base import ActionResult
from sev1daemon.actions.dispatcher import ActionDispatcher
from sev1daemon.config import Config
from sev1daemon.enrich import DepsDevClient, GithubStarsClient, RegistryClient
from sev1daemon.log import get_logger
from sev1daemon.metrics import Metrics
from sev1daemon.models import Advisory, AffectedPackage, Alert, ScoreBreakdown
from sev1daemon.scoring import Scorer
from sev1daemon.state import StateStore

log = get_logger("pipeline")

_UNSPECIFIED = AffectedPackage(ecosystem="(any)", name="(unspecified)")


@dataclass
class _PackageOutcome:
    """Result of dispatching one package's alert."""

    done: bool  # nothing left to retry for this package
    sent: bool  # at least one action ran OK in this attempt
    matched: bool  # at least one action matched (score / ecosystem filters)
    detail: str = ""


def _outcome(results: list[ActionResult]) -> _PackageOutcome:
    if not results:
        return _PackageOutcome(done=True, sent=False, matched=False)
    pending = [r for r in results if r.status != "ok"]
    sent = any(r.status == "ok" and r.detail != "already_succeeded" for r in results)
    detail = ", ".join(f"{r.status}:{r.detail}"[:120] for r in pending)
    return _PackageOutcome(done=not pending, sent=sent, matched=True, detail=detail)


class AlertPipeline:
    def __init__(
        self,
        cfg: Config,
        state: StateStore,
        dispatcher: ActionDispatcher,
        scorer: Scorer,
        registry: RegistryClient,
        depsdev: DepsDevClient,
        stars: GithubStarsClient | None,
        metrics: Metrics,
    ):
        self._cfg = cfg
        self._state = state
        self._dispatcher = dispatcher
        self._scorer = scorer
        self._registry = registry
        self._depsdev = depsdev
        self._stars = stars
        self._metrics = metrics

    # ---------- queue ----------

    async def new_advisories(self, advisories: list[Advisory]) -> list[Advisory]:
        """Merge records sharing an id across sources; drop already-processed ones.

        A processed advisory comes back when upstream has modified it and the
        new record lists packages this daemon never scored: OSV and GHSA
        routinely add affected packages after publication, and a popular one
        added later must still alert.
        """
        merged: dict[str, Advisory] = {}
        for adv in advisories:
            existing = merged.get(adv.id)
            merged[adv.id] = existing.merge(adv) if existing else adv
        out: list[Advisory] = []
        for adv in merged.values():
            if not await self._state.advisory_seen(adv.id) or await self._reopened(adv):
                out.append(adv)
        return out

    async def _reopened(self, adv: Advisory) -> bool:
        """Queue a processed advisory again if upstream added packages to it."""
        if adv.modified is None:
            return False
        stored = await self._state.stored_modified(adv.id)
        if stored is not None and adv.modified <= stored:
            return False
        packages = [
            (p.ecosystem, p.name) for p in adv.affected if not p.ecosystem.startswith("cpe:")
        ]
        missing = await self._state.unscored_packages(adv.id, packages)
        if not missing:
            return False
        log.info(
            "poll.reopened",
            advisory=adv.id,
            new_packages=[f"{eco}/{name}" for eco, name in missing],
        )
        await self._state.reopen(adv.id)
        return True

    async def store(self, advisories: list[Advisory]) -> None:
        """Persist collected advisories (``processed=0``) so a cycle that dies
        before processing them re-queues them instead of losing them."""
        await self._state.upsert_advisories(advisories)

    async def requeued(self, exclude: set[str]) -> list[Advisory]:
        """Advisories an earlier cycle stored but never finished."""
        pending = await self._state.pending_advisories(
            self._cfg.advisory_max_attempts, exclude=exclude
        )
        if pending:
            log.info("poll.requeued", count=len(pending))
            self._metrics.advisories_requeued_total.inc(len(pending))
        return pending

    # ---------- processing ----------

    async def process(self, adv: Advisory) -> int:
        """Score and dispatch one advisory. Returns the number of alerts sent."""
        await self._state.upsert_advisory(adv)
        try:
            fired, unfinished = await self._process_packages(adv)
        except Exception as exc:
            # Leave processed=0 so the next cycle retries. Per-package and
            # per-action idempotency keep finished work from re-running.
            log.warning(
                "poll.advisory_failed",
                advisory=adv.id,
                error_type=type(exc).__name__,
                error=str(exc),
                traceback=traceback.format_exc(),
            )
            self._metrics.advisory_failure_total.inc()
            await self._record_unfinished(adv, f"{type(exc).__name__}: {exc}")
            return 0
        if unfinished:
            await self._record_unfinished(adv, "; ".join(unfinished))
        else:
            await self._state.mark_processed(adv.id)
        return fired

    async def _process_packages(self, adv: Advisory) -> tuple[int, list[str]]:
        """Returns (alerts sent, reasons for packages still unfinished)."""
        packages = adv.affected
        if adv.is_supply_chain and not packages:
            packages = [_UNSPECIFIED]
        fired = 0
        unfinished: list[str] = []
        for pkg in packages:
            # CPE-derived "packages" (NVD) don't map to any registry, so they
            # can never cross the threshold; NVD-only CVEs never alert.
            if pkg.ecosystem.startswith("cpe:") and not adv.is_supply_chain:
                continue
            # Idempotency: a prior cycle already finished this package.
            if await self._state.package_fired(adv.id, pkg.ecosystem, pkg.name):
                continue
            if await self._already_alerted(adv, pkg):
                continue
            score, breakdown = await self._score(adv, pkg)
            breakdown_dict = breakdown.as_dict() if breakdown else None
            await self._state.record_package_score(
                adv.id, pkg.ecosystem, pkg.name, score, breakdown_dict, False
            )
            alerting = adv.is_supply_chain or self._scorer.crosses_threshold(score)
            log.info(
                "package.scored",
                advisory=adv.id,
                ecosystem=pkg.ecosystem,
                package=pkg.name,
                score=round(score, 2),
                alert=alerting,
                dry_run=self._dispatcher.dry_run,
            )
            if not alerting:
                continue
            alert = Alert(advisory=adv, package=pkg, score=score, breakdown=breakdown)
            outcome = await self._dispatch(alert, breakdown_dict)
            if outcome.sent:
                fired += 1
            if not outcome.done:
                unfinished.append(f"{pkg.ecosystem}/{pkg.name}: {outcome.detail}")
        return fired, unfinished

    async def _score(
        self, adv: Advisory, pkg: AffectedPackage
    ) -> tuple[float, ScoreBreakdown | None]:
        if adv.is_supply_chain:
            return 100.0, None
        stars, downloads, depsdev = await self._enrich(pkg)
        breakdown = self._scorer.score(pkg, stars, downloads, depsdev)
        return breakdown.total, breakdown

    async def _record_unfinished(self, adv: Advisory, error: str) -> None:
        if self._dispatcher.dry_run:
            return
        attempts = await self._state.record_attempt(adv.id, error)
        if attempts >= self._cfg.advisory_max_attempts:
            log.error("advisory.gave_up", advisory=adv.id, attempts=attempts, last_error=error)
            self._metrics.advisories_given_up_total.inc()
            await self._state.give_up(adv.id, error)
        else:
            log.warning("advisory.unfinished", advisory=adv.id, attempts=attempts, error=error)

    async def _already_alerted(self, adv: Advisory, pkg: AffectedPackage) -> bool:
        """Another record for the same vulnerability (shared id/alias) already fired."""
        other = await self._state.any_key_fired([adv.id, *adv.aliases], pkg.ecosystem, pkg.name)
        if other is None or other == adv.id:
            return False
        log.info(
            "poll.duplicate_skipped",
            advisory=adv.id,
            already_fired_as=other,
            ecosystem=pkg.ecosystem,
            package=pkg.name,
        )
        self._metrics.duplicates_skipped_total.inc()
        return True

    async def _dispatch(
        self, alert: Alert, breakdown: dict[str, Any] | None
    ) -> _PackageOutcome:
        """Dispatch, then record the package as fired only once every action succeeded."""
        outcome = _outcome(await self._dispatcher.dispatch(alert))
        # "Fired" means every matching action succeeded. When no action matched
        # there's nothing to retry, but nothing went out either: don't record
        # it as fired or other records for the same vuln would be suppressed.
        if outcome.done and outcome.matched and not self._dispatcher.dry_run:
            adv, pkg = alert.advisory, alert.package
            await self._state.record_package_score(
                adv.id, pkg.ecosystem, pkg.name, alert.score, breakdown, True
            )
            await self._state.record_fired_keys(
                [adv.id, *adv.aliases], pkg.ecosystem, pkg.name, adv.id
            )
        return outcome

    # ---------- enrichment ----------

    async def _enrich(self, pkg: AffectedPackage) -> tuple[int | None, int | None, int | None]:
        """(stars, downloads, dependents); a failed lookup is None, never an error."""
        downloads_r, depsdev_r, repo_url_r = await asyncio.gather(
            self._registry.downloads(pkg.ecosystem, pkg.name),
            self._depsdev.dependents(pkg.ecosystem, pkg.name),
            self._depsdev.repo_url(pkg.ecosystem, pkg.name),
            return_exceptions=True,
        )
        downloads = _signal("downloads", pkg, downloads_r)
        depsdev = _signal("depsdev", pkg, depsdev_r)
        repo_url = _signal("repo_url", pkg, repo_url_r)
        stars = None
        if self._stars and isinstance(repo_url, str) and repo_url:
            try:
                stars = await self._stars.stars_for_repo_url(repo_url)
            except Exception as exc:
                log.warning(
                    "enrich.stars_failed", ecosystem=pkg.ecosystem, package=pkg.name, error=str(exc)
                )
        return (
            stars,
            downloads if isinstance(downloads, int) else None,
            depsdev if isinstance(depsdev, int) else None,
        )


def _signal(
    name: str, pkg: AffectedPackage, result: int | str | None | BaseException
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
