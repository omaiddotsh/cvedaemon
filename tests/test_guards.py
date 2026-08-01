"""Tests for action guards: TokenBucket, CircuitBreaker, is_safe_url."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import patch

import pytest

from cvedaemon.actions.guards import (
    CircuitBreaker,
    TokenBucket,
    host_of,
    is_safe_url,
)
from cvedaemon.state import StateStore

# ---------- TokenBucket ----------


@pytest.mark.asyncio
async def test_bucket_allows_burst_then_throttles():
    b = TokenBucket(rate=1.0, burst=2)
    # Burst-2: first two immediate, third blocks until refill.
    assert await b.acquire("k", timeout=0.1) is True
    assert await b.acquire("k", timeout=0.1) is True
    # Third within burst window — wait roughly 1s for one token to regen.
    started = asyncio.get_event_loop().time()
    ok = await b.acquire("k", timeout=2.0)
    elapsed = asyncio.get_event_loop().time() - started
    assert ok is True
    assert elapsed >= 0.5, "should have waited for token refill"


@pytest.mark.asyncio
async def test_bucket_timeout_returns_false():
    b = TokenBucket(rate=0.1, burst=1)
    assert await b.acquire("k", timeout=0.0) is True  # first burst token
    # Wanted next token in 0.05s, but rate=0.1/s → ~10s wait; we don't wait.
    assert await b.acquire("k", timeout=0.05) is False


@pytest.mark.asyncio
async def test_bucket_rate_zero_disables_limit():
    b = TokenBucket(rate=0.0, burst=1)
    # Should always succeed instantly.
    for _ in range(5):
        assert await b.acquire("k", timeout=0.0) is True


@pytest.mark.asyncio
async def test_bucket_keys_independent():
    b = TokenBucket(rate=1.0, burst=1)
    assert await b.acquire("a", timeout=0.0) is True
    # b is a fresh key — should also get a token immediately.
    assert await b.acquire("b", timeout=0.0) is True


# ---------- CircuitBreaker ----------


@pytest.mark.asyncio
async def test_breaker_open_after_threshold(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        for _ in range(3):
            await store.log_action("A", "hk", "webhook", "error", "fail")
        breaker = CircuitBreaker(store, failures=3, window_seconds=60)
        assert await breaker.is_open("hk") is True
        # Different action name not affected.
        assert await breaker.is_open("other") is False
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_breaker_below_threshold_stays_closed(tmp_path):
    store = StateStore(tmp_path / "s.db")
    await store.open()
    try:
        for _ in range(2):
            await store.log_action("A", "hk", "webhook", "error", "fail")
        # 5-failure threshold not reached → breaker stays closed.
        breaker = CircuitBreaker(store, failures=5, window_seconds=60)
        assert await breaker.is_open("hk") is False
    finally:
        await store.close()


# ---------- is_safe_url ----------


def test_is_safe_url_rejects_non_http():
    ok, reason = is_safe_url("file:///etc/passwd")
    assert not ok
    assert reason == "bad_scheme"


def test_is_safe_url_rejects_http_when_strict():
    ok, reason = is_safe_url("http://example.com/hook", allow_private=False)
    assert not ok
    assert reason == "http_disallowed"


def test_is_safe_url_accepts_https_public():
    # Patch resolution to return a public IP without hitting real DNS.
    with patch.object(socket, "gethostbyname_ex", return_value=("h", [], ["93.184.216.34"])):
        ok, reason = is_safe_url("https://example.com/hook")
    assert ok is True
    assert reason == "ok"


def test_is_safe_url_rejects_private_ipv4():
    with patch.object(socket, "gethostbyname_ex", return_value=("h", [], ["10.0.0.1"])):
        ok, reason = is_safe_url("https://internal.lan/hook")
    assert not ok
    assert reason == "private_ip_v4"


def test_is_safe_url_rejects_metadata_endpoint():
    with patch.object(
        socket, "gethostbyname_ex", return_value=("h", [], ["169.254.169.254"])
    ):
        ok, reason = is_safe_url("https://metadata.aws/hook")
    assert not ok
    assert reason == "private_ip_v4"


def test_is_safe_url_allow_private_short_circuits():
    ok, reason = is_safe_url("https://10.0.0.1/hook", allow_private=True)
    assert ok is True
    assert reason == "private_allowed"


def test_host_of_url():
    assert host_of("https://api.example.com/x/y") == "api.example.com"
    assert host_of("not a url") == "unknown"


def test_is_safe_url_rejects_dns_failure():
    with patch.object(socket, "gethostbyname_ex", side_effect=socket.gaierror):
        ok, reason = is_safe_url("https://does-not-exist.invalid/hook")
    assert not ok
    assert reason == "dns_resolution_failed"
