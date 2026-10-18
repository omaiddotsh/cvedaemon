"""Delivery guarantees of the poll pipeline: nothing fetched is silently lost,
nothing is marked alerted unless an action actually succeeded, shutdown is
prompt, and duplicate records for one vulnerability alert once.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from sev1daemon.actions.base import ActionResult
from sev1daemon.config import WebhookAction
from sev1daemon.daemon import Daemon, run_one_shot
from sev1daemon.health import HealthState
from sev1daemon.models import Advisory, AdvisoryClass, AffectedPackage, SourceKind
from sev1daemon.sources.base import Source, SourceFetchIncomplete

from .support import minimal_config

pytestmark = [pytest.mark.asyncio, pytest.mark.usefixtures("stub_enrich")]


def _adv(
    adv_id: str,
    *,
    aliases: list[str] | None = None,
    pkg: tuple[str, str] = ("npm", "left-pad"),
    cls: AdvisoryClass = AdvisoryClass.CVE,
) -> Advisory:
    now = datetime.now(timezone.utc)
    return Advisory(
        id=adv_id,
        source=SourceKind.OSV,
        advisory_class=cls,
        cvss=9.8,
        summary="x",
        published=now,
        modified=now,
        affected=[AffectedPackage(ecosystem=pkg[0], name=pkg[1])],
        aliases=aliases or [],
    )


class _Source(Source):
    """Returns each queued batch once, then nothing (like a real since-window)."""

    def __init__(self, name: str, *batches: list[Advisory]):
        self.name = name
        self._batches = list(batches)
        self.since_seen: list[datetime] = []

    async def fetch(self, since: datetime) -> list[Advisory]:
        self.since_seen.append(since)
        return self._batches.pop(0) if self._batches else []


class _ScriptedRunner:
    """Fake action; returns the scripted statuses in order, then "ok"."""

    type = "webhook"

    def __init__(self, name: str, *statuses: str):
        self.name = name
        self._statuses = list(statuses)
        self.calls: list[Any] = []

    async def run(self, alert) -> ActionResult:
        self.calls.append(alert)
        status = self._statuses.pop(0) if self._statuses else "ok"
        return ActionResult(status=status, detail=f"scripted {status}")


async def _daemon(tmp_path, sources: list[Source], runners: list[_ScriptedRunner], **cfg_overrides):
    cfg = minimal_config(tmp_path)
    if cfg_overrides:
        cfg = cfg.model_copy(update=cfg_overrides)
    d = Daemon(cfg)
    await d.setup()
    d._sources = sources
    assert d._dispatcher is not None
    d._dispatcher._runners = [
        (WebhookAction(name=r.name, type="webhook", url="https://example.test/hook"), r)
        for r in runners
    ]
    return d


async def _processed(d: Daemon, adv_id: str) -> bool:
    return await d._state.advisory_seen(adv_id)


async def test_failed_action_is_retried_on_a_later_cycle(tmp_path):
    hook = _ScriptedRunner("hook", "error")
    d = await _daemon(tmp_path, [_Source("s", [_adv("CVE-2099-1")])], [hook])
    try:
        assert await d._run_cycle() == 0
        assert len(hook.calls) == 1
        assert not await _processed(d, "CVE-2099-1"), "failed alert must stay pending"

        # The source returns nothing now (its window moved on); the advisory
        # comes back from the pending queue and the retry succeeds.
        assert await d._run_cycle() == 1
        assert len(hook.calls) == 2
        assert await _processed(d, "CVE-2099-1")

        await d._run_cycle()
        assert len(hook.calls) == 2, "finished advisories are not re-sent"
    finally:
        await d.shutdown()


async def test_only_the_failed_action_reruns(tmp_path):
    slack = _ScriptedRunner("slack")  # ok first time
    issue = _ScriptedRunner("issue", "error")  # fails once
    d = await _daemon(tmp_path, [_Source("s", [_adv("CVE-2099-2")])], [slack, issue])
    try:
        await d._run_cycle()
        assert (len(slack.calls), len(issue.calls)) == (1, 1)
        await d._run_cycle()
        assert (len(slack.calls), len(issue.calls)) == (1, 2), "slack must not be re-sent"
        assert await _processed(d, "CVE-2099-2")
    finally:
        await d.shutdown()


async def test_skipped_dispatch_is_not_marked_fired(tmp_path):
    hook = _ScriptedRunner("hook")
    d = await _daemon(tmp_path, [_Source("s", [_adv("CVE-2099-3")])], [hook])
    try:
        assert d._dispatcher is not None

        async def _always_open(_name: str) -> bool:
            return True

        d._dispatcher._breaker.is_open = _always_open  # type: ignore[method-assign]
        await d._run_cycle()
        assert hook.calls == []
        assert not await _processed(d, "CVE-2099-3")
        assert not await d._state.package_fired("CVE-2099-3", "npm", "left-pad")
    finally:
        await d.shutdown()


async def test_gives_up_after_max_attempts(tmp_path):
    hook = _ScriptedRunner("hook", "error", "error", "error", "error")
    d = await _daemon(
        tmp_path, [_Source("s", [_adv("CVE-2099-4")])], [hook], advisory_max_attempts=3
    )
    try:
        for _ in range(5):
            await d._run_cycle()
        assert len(hook.calls) == 3
        assert await _processed(d, "CVE-2099-4")  # given up, no longer re-queued
    finally:
        await d.shutdown()


async def test_alias_duplicates_alert_once_either_order(tmp_path):
    hook = _ScriptedRunner("hook")
    ghsa = _adv("GHSA-aaaa-bbbb-cccc", aliases=["CVE-2099-5"])
    pysec = _adv("PYSEC-2099-5", aliases=["CVE-2099-5", "GHSA-aaaa-bbbb-cccc"])
    go = _adv("GO-2099-5", aliases=["CVE-2099-5"])
    d = await _daemon(tmp_path, [_Source("s", [ghsa], [pysec], [go])], [hook])
    try:
        for _ in range(3):
            await d._run_cycle()
        assert len(hook.calls) == 1
        for adv_id in ("GHSA-aaaa-bbbb-cccc", "PYSEC-2099-5", "GO-2099-5"):
            assert await _processed(d, adv_id)
    finally:
        await d.shutdown()


async def test_supply_chain_item_not_suppressed_by_cve_record(tmp_path):
    hook = _ScriptedRunner("hook")
    cve = _adv("CVE-2024-3094", pkg=("cpe:2.3:a:tukaani:xz", "xz"))  # NVD-style, never alerts
    rss = _adv(
        "rss:0123456789abcdef",
        aliases=["CVE-2024-3094"],
        cls=AdvisoryClass.SUPPLY_CHAIN,
    )
    rss.affected = []
    d = await _daemon(tmp_path, [_Source("s", [cve], [rss])], [hook])
    try:
        await d._run_cycle()
        await d._run_cycle()
        assert len(hook.calls) == 1
        assert hook.calls[0].advisory.id == "rss:0123456789abcdef"
    finally:
        await d.shutdown()


async def test_incomplete_fetch_processes_results_but_keeps_checkpoint(tmp_path):
    class _Partial(Source):
        name = "partial"

        async def fetch(self, since):
            raise SourceFetchIncomplete("page 2 returned 503", [_adv("CVE-2099-6")])

    hook = _ScriptedRunner("hook")
    d = await _daemon(tmp_path, [_Partial()], [hook])
    try:
        await d._run_cycle()
        assert len(hook.calls) == 1
        assert await d._state.get_last_success("partial") is None
        assert not d._health_state.readyz_ok()
    finally:
        await d.shutdown()


async def test_checkpoint_is_fetch_start_and_window_overlaps(tmp_path):
    class _Slow(_Source):
        async def fetch(self, since):
            await asyncio.sleep(0.2)
            return await super().fetch(since)

    src = _Slow("slow")
    d = await _daemon(tmp_path, [src], [_ScriptedRunner("hook")])
    try:
        before = datetime.now(timezone.utc)
        await d._run_cycle()
        last = await d._state.get_last_success("slow")
        assert last is not None and last <= before + timedelta(seconds=0.1)
        await d._run_cycle()
        overlap = last - src.since_seen[1]
        assert overlap >= timedelta(minutes=10)
    finally:
        await d.shutdown()


async def test_all_sources_failing_is_not_healthy(tmp_path):
    class _Broken(Source):
        name = "broken"

        async def fetch(self, since):
            raise RuntimeError("401 bad credentials")

    d = await _daemon(tmp_path, [_Broken()], [_ScriptedRunner("hook")])
    try:
        await d._run_cycle()
        assert not d._health_state.readyz_ok()
        snap = d._health_state.snapshot()
        assert "401" in str(snap["sources"])
    finally:
        await d.shutdown()


async def test_healthz_tracks_source_success():
    state = HealthState(grace_seconds=0, stale_seconds=60)
    state.mark_source("osv", ok=False, error="boom")
    assert not state.healthz_ok()
    state.mark_source("osv", ok=True)
    assert state.healthz_ok() and state.readyz_ok()


async def test_sigterm_cancels_a_running_cycle(tmp_path):
    class _Hang(Source):
        name = "hang"

        async def fetch(self, since):
            await asyncio.sleep(3600)
            return []

    d = await _daemon(tmp_path, [_Hang()], [_ScriptedRunner("hook")])
    # run() owns shutdown(); don't call it again.
    task = asyncio.create_task(d.run())
    await asyncio.sleep(0.3)
    started = time.monotonic()
    d._stop_evt.set()
    await asyncio.wait_for(task, timeout=5)
    assert time.monotonic() - started < 5


async def test_dry_run_does_not_touch_production_state(tmp_path, monkeypatch):
    adv = _adv("CVE-2099-7")
    hook = _ScriptedRunner("hook")
    cfg = minimal_config(tmp_path)

    def _wire(d: Daemon) -> None:
        d._sources = [_Source("s", [adv])]
        assert d._dispatcher is not None
        d._dispatcher._runners = [
            (WebhookAction(name="hook", type="webhook", url="https://example.test/hook"), hook)
        ]

    original_setup = Daemon.setup

    async def _setup_and_wire(self):
        await original_setup(self)
        _wire(self)

    monkeypatch.setattr(Daemon, "setup", _setup_and_wire)
    assert await run_one_shot(cfg, dry_run=True) == 0
    assert hook.calls == []
    # The real run afterwards still alerts: the dry run left no trace.
    assert await run_one_shot(cfg, dry_run=False) == 1
    assert len(hook.calls) == 1


async def test_cancel_during_collect_moves_no_checkpoint(tmp_path):
    """One source answers at once, a sibling hangs, and the cycle is cancelled
    (cycle_timeout or SIGTERM). The fast source's advisory was never stored, so
    its checkpoint must not move either: the next cycle re-fetches and alerts."""

    class _Hang(Source):
        name = "hang"

        async def fetch(self, since):
            await asyncio.sleep(3600)
            return []

    adv = _adv("CVE-2099-20")
    fast = _Source("fast", [adv], [adv])
    hook = _ScriptedRunner("hook")
    d = await _daemon(tmp_path, [fast, _Hang()], [hook])
    try:
        cycle = asyncio.create_task(d._run_cycle())
        await asyncio.sleep(0.3)
        await d._cancel_cycle(cycle)
        assert await d._state.get_last_success("fast") is None
        assert await d._state.pending_advisories(48) == []
        d._sources = [fast]
        await d._run_cycle()
        assert len(hook.calls) == 1
        assert await d._state.get_last_success("fast") is not None
    finally:
        await d.shutdown()


async def test_collected_advisories_are_stored_before_processing(tmp_path, monkeypatch):
    """Three advisories collected, enrichment of the first one slow, cycle
    cancelled: every collected advisory is already in the DB as pending and the
    checkpoint has moved, so the next cycle re-queues all of them."""
    from sev1daemon import pipeline as pipeline_mod

    async def _slow_enrich(self, pkg):
        await asyncio.sleep(3600)
        return (None, None, None)

    monkeypatch.setattr(pipeline_mod.AlertPipeline, "_enrich", _slow_enrich)
    advs = [_adv(f"CVE-2099-3{i}") for i in range(3)]
    hook = _ScriptedRunner("hook")
    d = await _daemon(tmp_path, [_Source("s", advs)], [hook])
    try:
        cycle = asyncio.create_task(d._run_cycle())
        await asyncio.sleep(0.3)
        await d._cancel_cycle(cycle)
        pending = {a.id for a in await d._state.pending_advisories(48)}
        assert pending == {a.id for a in advs}
        assert await d._state.get_last_success("s") is not None

        async def _instant_enrich(self, pkg):
            return (None, None, None)

        monkeypatch.setattr(pipeline_mod.AlertPipeline, "_enrich", _instant_enrich)
        await d._run_cycle()  # the source has nothing new; the re-queue carries them
        assert sorted(a.advisory.id for a in hook.calls) == sorted(a.id for a in advs)
        assert await d._state.pending_advisories(48) == []
    finally:
        await d.shutdown()


async def test_one_shot_runs_next_to_a_daemon_holding_the_health_port(tmp_path, monkeypatch):
    """``check`` and ``replay`` must not bind the health port: the daemon is
    normally running and already holds it."""
    import socket

    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    port = taken.getsockname()[1]
    try:
        cfg = minimal_config(tmp_path).model_copy(update={"health_port": port})
        hook = _ScriptedRunner("hook")
        original_setup = Daemon.setup

        async def _setup_and_wire(self):
            await original_setup(self)
            self._sources = [_Source("s", [_adv("CVE-2099-40")])]
            self._dispatcher._runners = [
                (WebhookAction(name="hook", type="webhook", url="https://example.test/hook"), hook)
            ]

        monkeypatch.setattr(Daemon, "setup", _setup_and_wire)
        assert await run_one_shot(cfg, dry_run=False) == 1  # no EADDRINUSE
        # replay goes through the same path
        from sev1daemon.cli import _replay

        await _replay(cfg, "CVE-2099-40", dry_run=True)
    finally:
        taken.close()


async def test_modified_advisory_with_a_new_package_is_processed_again(tmp_path):
    """OSV/GHSA add affected packages after publication. A processed advisory
    that comes back modified with a package this daemon never scored is queued
    again; the packages that already alerted are not sent twice."""
    first = _adv("CVE-2099-50", pkg=("npm", "left-pad"))
    later = Advisory(
        id="CVE-2099-50",
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="x",
        published=first.published,
        modified=first.modified + timedelta(hours=1),
        affected=[
            AffectedPackage(ecosystem="npm", name="left-pad"),
            AffectedPackage(ecosystem="npm", name="lodash"),
        ],
    )
    unchanged_again = first  # the overlap re-reads the same record: not reopened
    hook = _ScriptedRunner("hook")
    d = await _daemon(tmp_path, [_Source("s", [first], [unchanged_again], [later], [later])], [hook])
    try:
        await d._run_cycle()
        await d._run_cycle()
        assert [a.package.name for a in hook.calls] == ["left-pad"]
        await d._run_cycle()
        assert [a.package.name for a in hook.calls] == ["left-pad", "lodash"]
        assert await _processed(d, "CVE-2099-50")
        await d._run_cycle()  # same modified record again: nothing more
        assert len(hook.calls) == 2
    finally:
        await d.shutdown()


async def test_dry_run_logs_every_dispatch_decision(tmp_path, monkeypatch):
    """``check --dry-run`` promises to log dispatch decisions: each package's
    score and each action that would have fired must be in the log."""
    from sev1daemon import pipeline as pipeline_mod
    from sev1daemon.actions import dispatcher as dispatcher_mod

    class _Rec:
        def __init__(self):
            self.events: list[tuple[str, dict]] = []

        def __getattr__(self, _level):
            def _log(event, **kw):
                self.events.append((event, kw))

            return _log

    pipe_log, disp_log = _Rec(), _Rec()
    monkeypatch.setattr(pipeline_mod, "log", pipe_log)
    monkeypatch.setattr(dispatcher_mod, "log", disp_log)
    hook = _ScriptedRunner("hook")
    d = await _daemon(tmp_path, [_Source("s", [_adv("CVE-2099-60")])], [hook])
    try:
        d._dispatcher.dry_run = True
        await d._run_cycle()
        assert hook.calls == []
        scored = [kw for ev, kw in pipe_log.events if ev == "package.scored"]
        assert scored and scored[0]["advisory"] == "CVE-2099-60" and scored[0]["alert"] is True
        decisions = [kw for ev, kw in disp_log.events if ev == "action.dry_run"]
        assert decisions == [
            {
                "action": "hook",
                "type": "webhook",
                "advisory": "CVE-2099-60",
                "ecosystem": "npm",
                "package": "left-pad",
                "score": 0.0,
            }
        ]
    finally:
        await d.shutdown()


async def test_replay_redispatches_only_missing_actions(tmp_path):
    slack = _ScriptedRunner("slack")
    d = await _daemon(tmp_path, [_Source("s", [_adv("CVE-2099-8")])], [slack])
    try:
        await d._run_cycle()
        assert len(slack.calls) == 1
        # A new action added later: replay sends only to it, not to slack again.
        issue = _ScriptedRunner("issue")
        assert d._dispatcher is not None
        d._dispatcher._runners.append(
            (WebhookAction(name="issue", type="webhook", url="https://example.test/i"), issue)
        )
        assert await d.replay("CVE-2099-8") == 1
        assert (len(slack.calls), len(issue.calls)) == (1, 1)
        assert await d.replay("CVE-0000-0000") is None
    finally:
        await d.shutdown()
