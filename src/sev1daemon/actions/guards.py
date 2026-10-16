"""Outbound action guards: token-bucket rate limit, circuit breaker, SSRF.

These keep sev1daemon from becoming a noisy neighbour or a relay for
attacker-controlled URLs:

* :class:`TokenBucket` — per-key bucket; ``acquire()`` blocks until a token
  is available (or non-blocking ``try_acquire()`` returns False). One bucket
  per ``(action_name, host)`` so a busy Slack target doesn't starve PagerDuty.
* :class:`CircuitBreaker` — counts recent action_log error rows; if a host
  has tripped the threshold inside the window, skip dispatch until the
  window passes. Persisted via ``StateStore`` so it survives restarts.
* :func:`is_safe_url` / :func:`is_safe_url_async` — SSRF guard. Rejects
  schemes other than http/https, and rejects hosts where ANY resolved address
  (A or AAAA) is private / loopback / link-local / reserved / multicast /
  metadata, unless the config explicitly opts in via ``allow_private_urls``.
  The async variant resolves via ``loop.getaddrinfo`` so DNS never blocks the
  event loop; both share the same checking logic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sev1daemon.log import get_logger
from sev1daemon.state import StateStore

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
        # 0 disables the breaker (is_open always False), mirroring
        # TokenBucket(rate=0). Clamping to 1 would trip it on the first error.
        self._failures = max(failures, 0)
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


# Marker returned by _precheck when the URL passed the static checks and the
# verdict depends on what the host resolves to.
_NEEDS_DNS = "needs_dns"

# getaddrinfo result: (family, type, proto, canonname, sockaddr).
_AddrInfo = tuple[Any, Any, Any, Any, Any]


def _precheck(url: str, *, allow_private: bool) -> tuple[bool, str, str]:
    """Checks that need no DNS. Returns ``(ok, reason, hostname)``.

    ``ok and reason == _NEEDS_DNS`` means the host still has to be resolved
    and every address checked; any other result is final.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except ValueError:
        return False, "url_parse_failed", ""
    if parsed.scheme not in ("http", "https"):
        return False, "bad_scheme", ""
    if not hostname:
        return False, "missing_host", ""
    if parsed.scheme == "http" and not allow_private:
        # Plain HTTP is rejected in the default safe profile — webhooks carry
        # secrets (auth headers, signed payloads) and must be TLS-only.
        return False, "http_disallowed", hostname
    if allow_private:
        return True, "private_allowed", hostname
    return True, _NEEDS_DNS, hostname


def _blocked_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Reason slug when ``ip`` must not be contacted, else None."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # ::ffff:10.0.0.1 reaches 10.0.0.1 — judge it as the IPv4 address.
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        nets: list[Any] = _BLOCKED_V4_NETWORKS
        reason = "private_ip_v4"
    else:
        nets = _BLOCKED_V6_NETWORKS
        reason = "private_ip_v6"
    if any(ip in net for net in nets):
        return reason
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return reason
    return None


def _check_addrinfo(infos: Iterable[_AddrInfo]) -> tuple[bool, str]:
    """Verdict over every resolved address: blocked if ANY one is non-public.

    Checking all of them (A and AAAA) matters because the HTTP client may
    connect to any address the resolver hands back.
    """
    seen = False
    for info in infos:
        sockaddr = info[4]
        try:
            # IPv6 sockaddrs may carry a zone id ("fe80::1%en0").
            ip = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        except (ValueError, IndexError, TypeError):
            return False, "bad_ip"
        seen = True
        reason = _blocked_reason(ip)
        if reason is not None:
            return False, reason
    if not seen:
        return False, "dns_resolution_failed"
    return True, "ok"


def is_safe_url(url: str, *, allow_private: bool = False) -> tuple[bool, str]:
    """Validate a webhook target URL (blocking DNS lookup).

    Returns ``(ok, reason)``. ``ok=False`` means the URL must not be fetched;
    ``reason`` is a short slug suitable for log/metric labels. Prefer
    :func:`is_safe_url_async` from coroutines.
    """
    ok, reason, hostname = _precheck(url, allow_private=allow_private)
    if not ok or reason != _NEEDS_DNS:
        return ok, reason
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        # socket.gaierror is an OSError. If we can't resolve, refuse rather
        # than risk DNS rebinding.
        return False, "dns_resolution_failed"
    return _check_addrinfo(infos)


async def is_safe_url_async(url: str, *, allow_private: bool = False) -> tuple[bool, str]:
    """Async :func:`is_safe_url`: resolves via ``loop.getaddrinfo`` (non-blocking)."""
    ok, reason, hostname = _precheck(url, allow_private=allow_private)
    if not ok or reason != _NEEDS_DNS:
        return ok, reason
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError):
        return False, "dns_resolution_failed"
    return _check_addrinfo(infos)


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or "unknown"
    except ValueError:
        return "unknown"


__all__ = ["TokenBucket", "CircuitBreaker", "is_safe_url", "is_safe_url_async", "host_of"]
