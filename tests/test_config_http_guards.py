"""Tests for config validation, the HTTP client, star enrichment, the SSRF guard
and the shell action.

No network: HTTP is mocked with respx and DNS with a patched getaddrinfo.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx
from pydantic import ValidationError

from sev1daemon.actions.guards import CircuitBreaker, is_safe_url, is_safe_url_async
from sev1daemon.actions.shell import ShellRunner, _render_argv
from sev1daemon.config import Config, RssSourceConfig, ShellAction
from sev1daemon.enrich import github_stars as stars_mod
from sev1daemon.enrich.github_stars import GithubStarsClient
from sev1daemon.http import HttpClient
from sev1daemon.models import Advisory, AdvisoryClass, AffectedPackage, Alert, SourceKind


def _load(tmp_path: Path, text: str) -> Config:
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return Config.load(p)


@pytest.fixture
def fast_sleep(monkeypatch):
    """Make sleeps instant; records the requested durations."""
    real_sleep = asyncio.sleep
    calls: list[float] = []

    async def _sleep(seconds: float, *args: Any, **kwargs: Any) -> None:
        calls.append(seconds)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    return calls


# ======================================================================
# config
# ======================================================================


def test_config_rejects_unknown_top_level_key(tmp_path):
    with pytest.raises(ValidationError) as exc:
        _load(tmp_path, "poll_interval_secs: 60\n")
    assert "extra_forbidden" in str(exc.value) or "Extra inputs" in str(exc.value)


def test_config_rejects_unknown_nested_key(tmp_path):
    with pytest.raises(ValidationError):
        _load(tmp_path, "sources:\n  osv:\n    enabeld: false\n")


def test_action_typo_enable_does_not_leave_action_enabled(tmp_path):
    # `enable: false` (typo) used to be ignored, leaving the action enabled.
    with pytest.raises(ValidationError):
        _load(
            tmp_path,
            """
actions:
  - name: hook
    type: webhook
    enable: false
    url: "https://example.test/hook"
""",
        )


def test_disabled_action_still_rejects_unknown_keys(tmp_path):
    with pytest.raises(ValidationError):
        _load(
            tmp_path,
            """
actions:
  - name: hook
    type: webhook
    enabled: false
    urll: ""
""",
        )


def test_disabled_action_without_name_is_a_clear_error(tmp_path):
    with pytest.raises(ValueError, match="action.name required"):
        _load(
            tmp_path,
            """
actions:
  - type: webhook
    enabled: false
    url: ""
""",
        )


def test_disabled_placeholder_action_still_tolerated(tmp_path):
    cfg = _load(
        tmp_path,
        """
actions:
  - name: hook-off
    type: webhook
    enabled: false
    url: ""
""",
    )
    assert [(a.name, a.enabled) for a in cfg.actions] == [("hook-off", False)]


def test_non_mapping_action_is_a_clear_error(tmp_path):
    with pytest.raises(ValueError, match="mapping"):
        _load(tmp_path, "actions:\n  - just-a-string\n")


def test_env_expansion_still_works_with_strict_models(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDEN_NVD_KEY", "k-123")
    cfg = _load(tmp_path, 'sources:\n  nvd:\n    api_key: "${HARDEN_NVD_KEY}"\n')
    assert cfg.sources.nvd.api_key == "k-123"


def test_rss_enabled_requires_feeds(tmp_path):
    with pytest.raises(ValidationError, match="at least one feed"):
        _load(
            tmp_path,
            """
sources:
  osv: {enabled: false}
  nvd: {enabled: false}
  github: {enabled: false}
  rss: {enabled: true}
""",
        )


def test_rss_enabled_requires_keywords():
    with pytest.raises(ValidationError, match="at least one keyword"):
        RssSourceConfig(
            enabled=True, feeds=[{"name": "f", "url": "https://f.example/rss"}], keywords=[]
        )


def test_rss_blank_keyword_rejected():
    with pytest.raises(ValidationError, match="blank"):
        RssSourceConfig(keywords=["supply chain", "  "])


def test_rss_feed_url_must_be_http():
    with pytest.raises(ValidationError):
        RssSourceConfig(enabled=True, feeds=[{"name": "f", "url": "file:///etc/passwd"}])


def test_rss_with_feeds_counts_as_the_only_source(tmp_path):
    cfg = _load(
        tmp_path,
        """
sources:
  osv: {enabled: false}
  nvd: {enabled: false}
  github: {enabled: false}
  rss:
    enabled: true
    feeds:
      - {name: f, url: "https://f.example/rss"}
""",
    )
    assert cfg.sources.rss.enabled


def test_advisory_max_attempts_default_and_bounds(tmp_path):
    assert Config().advisory_max_attempts == 48
    assert _load(tmp_path, "advisory_max_attempts: 3\n").advisory_max_attempts == 3
    with pytest.raises(ValidationError):
        _load(tmp_path, "advisory_max_attempts: 0\n")


def test_example_config_sets_advisory_max_attempts_and_specific_keywords():
    example = Path(__file__).resolve().parent.parent / "config.example.yaml"
    cfg = Config.load(example)
    assert cfg.advisory_max_attempts == 48
    assert "malware" not in cfg.sources.rss.keywords
    assert cfg.sources.rss.keywords == RssSourceConfig().keywords


def test_shell_command_must_split_at_load_time():
    with pytest.raises(ValidationError, match="shell-style argv"):
        ShellAction(name="s", type="shell", command='/bin/echo "unterminated')


# ======================================================================
# http — Retry-After ceiling
# ======================================================================

URL = "https://api.example.test/thing"


@respx.mock
async def test_retry_after_within_ceiling_is_honoured_in_full(fast_sleep):
    route = respx.get(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "90"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    http = HttpClient()
    try:
        status, body, _ = await http.get_json(URL, cache=False)
    finally:
        await http.aclose()
    assert (status, body) == (200, {"ok": True})
    assert route.call_count == 2
    assert fast_sleep == [90.0]  # previously clamped to 30s


@respx.mock
async def test_retry_after_over_ceiling_returns_429_without_sleeping(fast_sleep):
    route = respx.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "3600"}))
    http = HttpClient()
    try:
        status, _, headers = await http.get_json(URL, cache=False)
    finally:
        await http.aclose()
    assert status == 429
    assert headers["retry-after"] == "3600"
    assert route.call_count == 1
    assert fast_sleep == []


@respx.mock
async def test_secondary_rate_limit_403_with_retry_after_is_retried(fast_sleep):
    route = respx.get(URL).mock(
        side_effect=[
            httpx.Response(403, headers={"Retry-After": "60"}),
            httpx.Response(200, json=[]),
        ]
    )
    http = HttpClient()
    try:
        status, _, _ = await http.get_json(URL, cache=False)
    finally:
        await http.aclose()
    assert status == 200
    assert route.call_count == 2
    assert fast_sleep == [60.0]


@respx.mock
async def test_plain_403_is_not_retried(fast_sleep):
    route = respx.get(URL).mock(return_value=httpx.Response(403, json={"message": "forbidden"}))
    http = HttpClient()
    try:
        status, _, _ = await http.get_json(URL, cache=False)
    finally:
        await http.aclose()
    assert status == 403
    assert route.call_count == 1


@respx.mock
async def test_per_call_retry_after_ceiling(fast_sleep):
    route = respx.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "30"}))
    http = HttpClient()
    try:
        status, _, _ = await http.get_json(URL, cache=False, max_retry_after=5.0)
    finally:
        await http.aclose()
    assert status == 429
    assert route.call_count == 1
    assert fast_sleep == []


# ======================================================================
# http — cache eviction
# ======================================================================


def _age(path: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(path, (t, t))


async def test_evict_expired_removes_stale_entries_and_temp_files(tmp_path):
    cache = tmp_path / "cache"
    http = HttpClient(cache_dir=cache, cache_ttl_seconds=60)
    try:
        old_ts = time.time() - 3600
        (cache / "expired.json").write_text(json.dumps({"_ts": old_ts, "body": {}}))
        (cache / "fresh.json").write_text(json.dumps({"_ts": time.time(), "body": {}}))
        (cache / "corrupt.json").write_text("{not json")
        # Legacy OSV all.zip cache: nothing uses it any more, so even a fresh
        # entry is reclaimed.
        (cache / "bytes-aaa.meta.json").write_text(json.dumps({"_ts": old_ts}))
        (cache / "bytes-aaa.bin").write_bytes(b"zip")
        (cache / "bytes-bbb.meta.json").write_text(json.dumps({"_ts": time.time()}))
        (cache / "bytes-bbb.bin").write_bytes(b"zip")
        (cache / "bytes-ccc.bin").write_bytes(b"zip")
        stale_tmp = cache / ".cache.dead.tmp"
        stale_tmp.write_text("partial")
        _age(stale_tmp, 3600)
        stale_meta_tmp = cache / ".bytes.dead.meta.tmp"
        stale_meta_tmp.write_text("partial")
        _age(stale_meta_tmp, 3600)
        (cache / ".cache.inflight.tmp").write_text("being written")

        removed = await http.evict_expired()

        remaining = sorted(p.name for p in cache.iterdir())
        assert remaining == [".cache.inflight.tmp", "fresh.json"]
        assert removed == 9
        # Idempotent.
        assert await http.evict_expired() == 0
    finally:
        await http.aclose()


async def test_evict_expired_without_cache_dir_is_noop():
    http = HttpClient()
    try:
        assert await http.evict_expired() == 0
    finally:
        await http.aclose()


async def test_init_still_evicts(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "expired.json").write_text(json.dumps({"_ts": 0, "body": {}}))
    http = HttpClient(cache_dir=cache, cache_ttl_seconds=60)
    try:
        assert not (cache / "expired.json").exists()
    finally:
        await http.aclose()


# ======================================================================
# http — streamed line reads (OSV change index), cache refresh, timeouts
# ======================================================================

CSV_URL = "https://feed.example.test/modified_id.csv"


class _ChunkStream(httpx.AsyncByteStream):
    """Response body served chunk by chunk; records how much of it was read."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.served = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.served += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@respx.mock
async def test_stream_lines_reads_lazily_and_closes_on_early_exit():
    early = _ChunkStream([b"a,1\r\nb,2\n", b"c,3\n", b"d,4\n"])
    full = _ChunkStream([b"a,1\nb,", b"2\nc,3"])
    respx.get(CSV_URL).mock(
        side_effect=[httpx.Response(200, stream=early), httpx.Response(200, stream=full)]
    )
    http = HttpClient()
    try:
        got: list[str] = []
        async with http.stream_lines(CSV_URL) as (status, lines):
            assert status == 200
            async for line in lines:
                got.append(line)
                if line.startswith("b"):
                    break
        assert got == ["a,1", "b,2"]
        assert early.served == 1  # the rest of the body was never pulled
        assert early.closed

        async with http.stream_lines(CSV_URL) as (status, lines):
            assert [line async for line in lines] == ["a,1", "b,2", "c,3"]
        assert full.closed
    finally:
        await http.aclose()


@respx.mock
async def test_stream_lines_retries_retryable_status_then_streams(fast_sleep):
    route = respx.get(CSV_URL).mock(
        side_effect=[
            httpx.Response(503, headers={"Retry-After": "2"}),
            httpx.Response(200, text="x,1\n"),
        ]
    )
    http = HttpClient()
    try:
        async with http.stream_lines(CSV_URL) as (status, lines):
            assert status == 200
            assert [line async for line in lines] == ["x,1"]
    finally:
        await http.aclose()
    assert route.call_count == 2
    assert fast_sleep == [2.0]


@respx.mock
async def test_stream_lines_hands_back_long_retry_after_and_errors(fast_sleep):
    respx.get(CSV_URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "3600"}))
    down_url = "https://down.example.test/modified_id.csv"
    broken = respx.get(down_url).mock(side_effect=httpx.ConnectError("down"))
    http = HttpClient()
    try:
        async with http.stream_lines(CSV_URL) as (status, _):
            assert status == 429
        assert fast_sleep == []
        with pytest.raises(httpx.ConnectError):
            async with http.stream_lines(down_url):
                pass
    finally:
        await http.aclose()
    assert broken.call_count == 3


@respx.mock
async def test_get_json_refresh_replaces_the_cached_copy(tmp_path):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(200, json={"v": 1}), httpx.Response(200, json={"v": 2})]
    )
    http = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        assert (await http.get_json(URL))[1] == {"v": 1}
        assert (await http.get_json(URL))[1] == {"v": 1}  # cached
        assert route.call_count == 1
        assert (await http.get_json(URL, refresh=True))[1] == {"v": 2}
        assert (await http.get_json(URL))[1] == {"v": 2}  # the refreshed copy is stored
        assert route.call_count == 2
    finally:
        await http.aclose()


@respx.mock
async def test_omitted_timeout_uses_the_client_default_not_no_timeout():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={}))
    csv = respx.get(CSV_URL).mock(return_value=httpx.Response(200, text=""))
    http = HttpClient(default_timeout=7.0)
    try:
        await http.get_json(URL, cache=False)
        async with http.stream_lines(CSV_URL):
            pass
        await http.get_json(URL, cache=False, timeout=3.0)
    finally:
        await http.aclose()
    default = {"connect": 7.0, "read": 7.0, "write": 7.0, "pool": 7.0}
    assert route.calls[0].request.extensions["timeout"] == default
    assert csv.calls[0].request.extensions["timeout"] == default
    assert route.calls[1].request.extensions["timeout"]["read"] == 3.0


# ======================================================================
# github stars — rate-limit back-off
# ======================================================================

REPO_API = "https://api.github.com/repos/foo/bar"
REPO_URL = "https://github.com/foo/bar"


class _RecordingLog:
    def __init__(self) -> None:
        self.events: list[str] = []

    def __getattr__(self, _level: str):
        def _log(event: str, **_kw: Any) -> None:
            self.events.append(event)

        return _log


@pytest.fixture
def stars_log(monkeypatch):
    rec = _RecordingLog()
    monkeypatch.setattr(stars_mod, "log", rec)
    return rec


@respx.mock
async def test_stars_403_rate_limit_backs_off_until_reset(stars_log):
    reset = int(time.time()) + 600
    route = respx.get(REPO_API).mock(
        return_value=httpx.Response(
            403,
            json={"message": "API rate limit exceeded"},
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)},
        )
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        for _ in range(5):
            assert await client.stars_for_repo_url(REPO_URL) is None
        assert route.call_count == 1, "no API calls while backing off"
        assert stars_log.events.count("stars.rate_limited") == 1, "logged once"
        assert client._blocked_until == pytest.approx(reset, abs=1)
    finally:
        await http.aclose()


@respx.mock
async def test_stars_429_retry_after_backs_off_then_resumes(stars_log, fast_sleep):
    route = respx.get(REPO_API).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "120"}),
            httpx.Response(200, json={"stargazers_count": 7}),
        ]
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        before = time.time()
        assert await client.stars_for_repo_url(REPO_URL) is None
        assert fast_sleep == [], "long Retry-After is not slept through inline"
        assert client._blocked_until >= before + 119
        assert await client.stars_for_repo_url(REPO_URL) is None
        assert route.call_count == 1

        client._blocked_until = time.time() - 1  # reset time has passed
        assert await client.stars_for_repo_url(REPO_URL) == 7
        assert route.call_count == 2
    finally:
        await http.aclose()


@respx.mock
async def test_stars_remaining_zero_backs_off_proactively(stars_log):
    reset = int(time.time()) + 300
    route = respx.get(REPO_API).mock(
        return_value=httpx.Response(
            200,
            json={"stargazers_count": 42},
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)},
        )
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        assert await client.stars_for_repo_url(REPO_URL) == 42  # this answer is still used
        assert await client.stars_for_repo_url("https://github.com/foo/other") is None
        assert route.call_count == 1
        assert stars_log.events.count("stars.rate_limited") == 1
    finally:
        await http.aclose()


@respx.mock
async def test_stars_plain_403_does_not_back_off(stars_log):
    route = respx.get(REPO_API).mock(
        return_value=httpx.Response(403, json={"message": "Repository access blocked"})
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        assert await client.stars_for_repo_url(REPO_URL) is None
        assert await client.stars_for_repo_url(REPO_URL) is None
        assert route.call_count == 2
        assert "stars.rate_limited" not in stars_log.events
    finally:
        await http.aclose()


@respx.mock
async def test_stars_backoff_is_capped(stars_log):
    respx.get(REPO_API).mock(
        return_value=httpx.Response(429, headers={"X-RateLimit-Reset": str(int(time.time()) + 10**7)})
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        assert await client.stars_for_repo_url(REPO_URL) is None
        assert client._blocked_until <= time.time() + stars_mod._MAX_BACKOFF_SECONDS + 1
    finally:
        await http.aclose()


# ======================================================================
# SSRF guard — all addresses, IPv6, async variant
# ======================================================================


def _addrinfo(*ips: str) -> list[tuple]:
    return [
        (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
        for ip in ips
    ]


ADDRESS_CASES = [
    (("93.184.216.34",), (True, "ok")),
    (("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"), (True, "ok")),
    # Public A record but a private AAAA record: blocked (any address counts).
    (("93.184.216.34", "fd00::1"), (False, "private_ip_v6")),
    (("2606:2800:220:1:248:1893:25c8:1946", "10.1.2.3"), (False, "private_ip_v4")),
    (("::1",), (False, "private_ip_v6")),
    (("fe80::1%en0",), (False, "private_ip_v6")),
    (("ff02::1",), (False, "private_ip_v6")),
    (("::ffff:127.0.0.1",), (False, "private_ip_v4")),
    (("::ffff:169.254.169.254",), (False, "private_ip_v4")),
    (("100.64.0.1",), (False, "private_ip_v4")),
    (("240.0.0.1",), (False, "private_ip_v4")),
    (("0.0.0.0",), (False, "private_ip_v4")),
    (("::",), (False, "private_ip_v6")),
]


@pytest.mark.parametrize(("ips", "expected"), ADDRESS_CASES)
def test_is_safe_url_checks_every_resolved_address(ips, expected):
    with patch.object(socket, "getaddrinfo", return_value=_addrinfo(*ips)) as gai:
        assert is_safe_url("https://hook.example/x") == expected
    # AF_UNSPEC so AAAA records are returned too.
    assert gai.call_args.args[2] == socket.AF_UNSPEC


@pytest.mark.parametrize(("ips", "expected"), ADDRESS_CASES)
async def test_is_safe_url_async_matches_sync(ips, expected, monkeypatch):
    loop = asyncio.get_running_loop()
    seen: dict[str, Any] = {}

    async def _fake_getaddrinfo(host, port, *, family=0, type=0, proto=0, flags=0):
        seen.update(host=host, family=family)
        return _addrinfo(*ips)

    monkeypatch.setattr(loop, "getaddrinfo", _fake_getaddrinfo)
    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("blocking lookup")):
        assert await is_safe_url_async("https://hook.example/x") == expected
    assert seen == {"host": "hook.example", "family": socket.AF_UNSPEC}


async def test_is_safe_url_async_dns_failure_and_prechecks(monkeypatch):
    loop = asyncio.get_running_loop()

    async def _fail(*_a: Any, **_kw: Any):
        raise socket.gaierror("nxdomain")

    monkeypatch.setattr(loop, "getaddrinfo", _fail)
    assert await is_safe_url_async("https://nope.invalid/x") == (False, "dns_resolution_failed")
    assert await is_safe_url_async("ftp://x.example/") == (False, "bad_scheme")
    assert await is_safe_url_async("http://x.example/") == (False, "http_disallowed")
    assert await is_safe_url_async("https:///nohost") == (False, "missing_host")
    assert await is_safe_url_async("https://10.0.0.1/", allow_private=True) == (
        True,
        "private_allowed",
    )


def test_is_safe_url_empty_resolution_is_refused():
    with patch.object(socket, "getaddrinfo", return_value=[]):
        assert is_safe_url("https://hook.example/x") == (False, "dns_resolution_failed")


# ======================================================================
# circuit breaker — 0 disables
# ======================================================================


class _FakeState:
    def __init__(self, failures: int) -> None:
        self._failures = failures

    async def recent_action_failures(self, _name: str, _since: datetime) -> int:
        return self._failures


async def test_circuit_breaker_zero_threshold_is_disabled():
    breaker = CircuitBreaker(_FakeState(failures=50), failures=0, window_seconds=60)  # type: ignore[arg-type]
    assert await breaker.is_open("hook") is False


async def test_circuit_breaker_trips_at_threshold():
    assert await CircuitBreaker(_FakeState(2), failures=3, window_seconds=60).is_open("h") is False  # type: ignore[arg-type]
    assert await CircuitBreaker(_FakeState(3), failures=3, window_seconds=60).is_open("h") is True  # type: ignore[arg-type]


# ======================================================================
# shell action — argv boundaries
# ======================================================================

MALICIOUS_ID = 'CVE-2099-0001" "--evil" \'$(touch /tmp/pwned)\'; rm -rf / #'


def _alert(adv_id: str = MALICIOUS_ID, package: str = "left pad") -> Alert:
    adv = Advisory(
        id=adv_id,
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="s",
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        affected=[AffectedPackage(ecosystem="npm", name=package)],
    )
    return Alert(advisory=adv, package=AffectedPackage("npm", package), score=99.0, breakdown=None)


def test_render_argv_keeps_argv_count_for_malicious_advisory_id():
    template = '/usr/local/bin/page-oncall "{{advisory_id}}" {{ecosystem}} --pkg={{package}}'
    benign = _render_argv(template, _alert("CVE-2099-0001", "leftpad"))
    hostile = _render_argv(template, _alert())
    assert len(hostile) == len(benign) == 4
    assert hostile == ["/usr/local/bin/page-oncall", MALICIOUS_ID, "npm", "--pkg=left pad"]


def test_render_argv_does_not_expand_placeholders_inside_values():
    argv = _render_argv("cmd {{advisory_id}} {{package}}", _alert("{{package}}", "real"))
    assert argv == ["cmd", "{{package}}", "real"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only test")
async def test_shell_runner_passes_malicious_id_as_one_argument():
    script = "import sys, json; print(json.dumps(sys.argv[1:]))"
    command = f'{shlex.quote(sys.executable)} -c {shlex.quote(script)} "{{{{advisory_id}}}}" {{{{package}}}}'
    runner = ShellRunner(ShellAction(name="t", type="shell", command=command, timeout_seconds=20))
    res = await runner.run(_alert())
    assert res.status == "ok", res.detail
    printed = res.detail.split("out=", 1)[1].strip()
    assert json.loads(printed) == [MALICIOUS_ID, "left pad"]


def test_shell_placeholder_cannot_be_the_executable():
    import pytest as _pytest

    from sev1daemon.config import ShellAction

    with _pytest.raises(ValueError):
        ShellAction(name="x", type="shell", command="{{package}} --flag")
    ShellAction(name="ok", type="shell", command="/usr/local/bin/page {{package}}")


def test_nvd_cvss_v40_is_scored():
    from sev1daemon.sources.nvd import _highest_cvss

    metrics = {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3}}]}
    assert _highest_cvss(metrics) == 9.3



async def test_retry_after_zero_still_backs_off(tmp_path, monkeypatch):
    """A 429 with Retry-After: 0 must not be retried instantly."""
    import httpx as _httpx
    import respx as _respx

    from sev1daemon import http as http_mod
    from sev1daemon.http import HttpClient

    slept: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(http_mod.asyncio, "sleep", _fake_sleep)
    url = "https://api.npmjs.org/downloads/point/last-week/x"
    client = HttpClient(cache_dir=tmp_path / "cache", cache_ttl_seconds=60)
    try:
        with _respx.mock:
            _respx.get(url).mock(
                side_effect=[
                    _httpx.Response(429, headers={"Retry-After": "0"}),
                    _httpx.Response(429, headers={"Retry-After": "0"}),
                    _httpx.Response(200, json={"downloads": 5}),
                ]
            )
            status, body, _ = await client.get_json(url, cache=False)
    finally:
        await client.aclose()
    assert status == 200 and body == {"downloads": 5}
    assert slept == [1.0, 2.0]
