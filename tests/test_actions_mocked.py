"""Mocked action runner tests. No network."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from cvedaemon.actions.dispatcher import ActionDispatcher
from cvedaemon.actions.github_issue import GithubIssueRunner
from cvedaemon.actions.webhook import WebhookRunner
from cvedaemon.config import GithubIssueAction, WebhookAction
from cvedaemon.http import HttpClient
from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    Alert,
    SourceKind,
)
from cvedaemon.state import StateStore

pytestmark = pytest.mark.asyncio


def make_alert(score: float = 100.0) -> Alert:
    return Alert(
        advisory=Advisory(
            id="CVE-2099-0001",
            source=SourceKind.NVD,
            advisory_class=AdvisoryClass.CVE,
            cvss=9.8,
            summary="rce",
            published=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            affected=[AffectedPackage("npm", "x")],
            aliases=["CVE-2099-0001"],
            references=["https://example.test/r"],
        ),
        package=AffectedPackage("npm", "x"),
        score=score,
        breakdown=None,
    )


@respx.mock
async def test_webhook_action_posts_payload(tmp_path):
    route = respx.post("https://hooks.example.test/in").mock(
        return_value=httpx.Response(200, text="ok")
    )
    http = HttpClient(cache_dir=tmp_path / "cache")
    try:
        runner = WebhookRunner(
            WebhookAction(name="hook", url="https://hooks.example.test/in"), http
        )
        res = await runner.run(make_alert())
    finally:
        await http.aclose()

    assert res.status == "ok"
    assert route.called
    req = route.calls.last.request
    assert b"CVE-2099-0001" in req.content


@respx.mock
async def test_webhook_action_reports_error_on_5xx(tmp_path):
    respx.post("https://hooks.example.test/in").mock(
        return_value=httpx.Response(503, text="down")
    )
    http = HttpClient(cache_dir=tmp_path / "cache")
    try:
        runner = WebhookRunner(
            WebhookAction(name="hook", url="https://hooks.example.test/in"), http
        )
        res = await runner.run(make_alert())
    finally:
        await http.aclose()

    assert res.status == "error"
    assert "503" in res.detail


@respx.mock
async def test_github_issue_action_creates_issue(tmp_path):
    route = respx.post("https://api.github.com/repos/foo/bar/issues").mock(
        return_value=httpx.Response(201, json={"number": 42})
    )
    http = HttpClient(cache_dir=tmp_path / "cache")
    try:
        cfg = GithubIssueAction(
            name="issue",
            repo="foo/bar",
            token="ghp_dummy",
            labels=["security"],
            assignees=["alice"],
        )
        runner = GithubIssueRunner(cfg, http)
        res = await runner.run(make_alert())
    finally:
        await http.aclose()

    assert res.status == "ok"
    assert "#42" in res.detail
    assert route.called


async def test_dispatcher_skips_below_min_score(tmp_path):
    http = HttpClient(cache_dir=tmp_path / "cache")
    state = StateStore(tmp_path / "state.db")
    await state.open()
    try:
        cfg = WebhookAction(
            name="hook",
            url="https://hooks.example.test/in",
            min_score=80,
        )
        # global_threshold=50, action.min_score=80 → effective 80
        dispatcher = ActionDispatcher([cfg], http, state, global_threshold=50)
        results = await dispatcher.dispatch(make_alert(score=70.0))
        assert results == []
    finally:
        await state.close()
        await http.aclose()


async def test_dispatcher_filters_by_ecosystem(tmp_path):
    http = HttpClient(cache_dir=tmp_path / "cache")
    state = StateStore(tmp_path / "state.db")
    await state.open()
    try:
        cfg = WebhookAction(
            name="hook",
            url="https://hooks.example.test/in",
            min_score=0,
            ecosystems=["PyPI"],
        )
        dispatcher = ActionDispatcher([cfg], http, state, global_threshold=0)
        results = await dispatcher.dispatch(make_alert(score=100.0))
        assert results == []
    finally:
        await state.close()
        await http.aclose()
