"""Outbound action guards: token-bucket rate limit, circuit breaker, SSRF.

These keep cvedaemon from becoming a noisy neighbour or a relay for
attacker-controlled URLs:

* :class:`TokenBucket` — per-key bucket; ``acquire()`` blocks until a token
  is available (or non-blocking ``try_acquire()`` returns False). One bucket
  per ``(action_name, host)`` so a busy Slack target doesn't starve PagerDuty.
* :class:`CircuitBreaker` — counts recent action_log error rows; if a host
  has tripped the threshold inside the window, skip dispatch until the
  window passes. Persisted via ``StateStore`` so it survives restarts.
* :func:`is_safe_url` — SSRF guard. Rejects schemes other than http/https,
  rejects RFC1918 / loopback / link-local / metadata endpoints unless the
  config explicitly opts in via ``allow_private_urls``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from cvedaemon.log import get_logger
from cvedaemon.state import StateStore

log = get_logger("action.guards")


class TokenBucket:
    """Async token bucket. Tokens regenerate at ``rate`` per second up to ``burst``.

    Per-key buckets are created lazily; an unbounded number of keys is fine
    in practice because keys are derived from ``(action_name, host)`` which
    has a small cardinality. Memory cost: ~80 bytes per key.
    """

    def __init__(self, rate: float, burst: int):
        self._rate = max(rate, 0.0)
        self._burst = max(burst, 1)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    def _refill(self, key: str, now: float) -> float:
        tokens, last = self._buckets.get(key, (float(self._burst), now))
        if self._rate > 0:
            tokens = min(self._burst, tokens + (now - last) * self._rate)
        self._buckets[key] = (tokens, now)
        return tokens

    async def acquire(self, key: str, *, timeout: float = 5.0) -> bool:
        """Wait up to ``timeout`` seconds for a token. Returns True on success."""
        if self._rate <= 0:
            return True
        deadline = time.monotonic() + timeout
        while True:
            async with self._lock:
                now = time.monotonic()
                tokens = self._refill(key, now)
                if tokens >= 1:
                    self._buckets[key] = (tokens - 1, now)
                    return True
                # Sleep until at least one token regenerates, but never past
                # the caller's deadline.
                deficit = 1 - tokens
                sleep_for = min(deficit / self._rate, max(0.0, deadline - now))
            if sleep_for <= 0:
                return False
            await asyncio.sleep(sleep_for)


class CircuitBreaker:
    """State-store-backed breaker. Trips per action_name on consecutive failures.

    Why persist in SQLite instead of in-memory? Restart cycles are short
    (systemd may flap) and we don't want a freshly-flapped action to be
    hammered for another N tries just because the daemon restarted.
    """

    def __init__(self, state: StateStore, failures: int, window_seconds: int):
        self._state = state
        self._failures = max(failures, 1)
        self._window = max(window_seconds, 1)

    async def is_open(self, action_name: str) -> bool:
        if self._failures <= 0:
            return False
        since = datetime.now(timezone.utc) - timedelta(seconds=self._window)
        recent = await self._state.recent_action_failures(action_name, since)
        return recent >= self._failures


# RFC1918 + loopback + link-local + multicast + reserved + carrier-grade NAT.
# Plus IPv6 unique-local + loopback + link-local. ``ip_address.is_private``
# covers most but not 100.64.0.0/10 (CGNAT) or 169.254.169.254 metadata.
_BLOCKED_V4_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
]
_BLOCKED_V6_NETWORKS = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def is_safe_url(url: str, *, allow_private: bool = False) -> tuple[bool, str]:
    """Validate a webhook target URL.

    Returns ``(ok, reason)``. ``ok=False`` means the URL must not be fetched;
    ``reason`` is a short slug suitable for log/metric labels.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "url_parse_failed"
    if parsed.scheme not in ("http", "https"):
        return False, "bad_scheme"
    if not parsed.hostname:
        return False, "missing_host"
    if parsed.scheme == "http" and not allow_private:
        # Plain HTTP is rejected in the default safe profile — webhooks carry
        # secrets (auth headers, signed payloads) and must be TLS-only.
        return False, "http_disallowed"
    if allow_private:
        return True, "private_allowed"
    # Resolve host → IPs. We block if any returned IP is in a private range.
    # gethostbyname_ex returns (canonical, aliases, [ips]); DNS lookup is
    # blocking but only runs at action time, not on each cycle.
    try:
        _, _, ips = socket.gethostbyname_ex(parsed.hostname)
    except (socket.gaierror, UnicodeError):
        # If we can't resolve, refuse rather than risk DNS rebinding.
        return False, "dns_resolution_failed"
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "bad_ip"
        if isinstance(ip, ipaddress.IPv4Address):
            for net in _BLOCKED_V4_NETWORKS:
                if ip in net:
                    return False, "private_ip_v4"
        else:
            for net in _BLOCKED_V6_NETWORKS:
                if ip in net:
                    return False, "private_ip_v6"
    return True, "ok"


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or "unknown"
    except ValueError:
        return "unknown"


__all__ = ["TokenBucket", "CircuitBreaker", "is_safe_url", "host_of"]
