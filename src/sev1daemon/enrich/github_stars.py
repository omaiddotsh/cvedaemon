"""GitHub stargazer fetch — looks up the repo url for a package and reads stars.

Rate limits: once GitHub answers 403/429 as rate limited (or a response
reports ``X-RateLimit-Remaining: 0``), the client stops calling the API until
the reset time and returns None for lookups in the meantime. Unknown stars
score 0 points, so backing off never inflates a score.
"""

from __future__ import annotations

import time

from sev1daemon.enrich.repo import parse_github_repo
from sev1daemon.http import HttpClient, _parse_retry_after
from sev1daemon.log import get_logger

log = get_logger("stars")


# Back-off used when a rate-limited response carries no usable reset hint.
_DEFAULT_BACKOFF_SECONDS = 60.0
# Upper bound on a back-off, so a bogus reset header can't disable star
# enrichment for days. GitHub's primary window resets hourly.
_MAX_BACKOFF_SECONDS = 3600.0
# Short Retry-After waits are slept through by HttpClient; anything longer
# comes straight back here so enrichment backs off instead of stalling.
_MAX_INLINE_RETRY_AFTER = 5.0


class GithubStarsClient:
    def __init__(self, http: HttpClient, token: str):
        self._http = http
        self._token = token
        # Epoch seconds until which the API must not be called (0 = not limited).
        self._blocked_until = 0.0

    async def stars_for_repo_url(self, repo_url: str) -> int | None:
        # Accepts https/git+https/git/ssh/scp-style GitHub URLs, dotted repo
        # names (handlebars.js), and drops ".git", "/issues", "#readme", etc.
        parsed = parse_github_repo(repo_url)
        if parsed is None:
            return None
        if time.time() < self._blocked_until:
            return None
        owner, name = parsed
        url = f"https://api.github.com/repos/{owner}/{name}"
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        status, body, resp_headers = await self._http.get_json(
            url,
            headers=headers,
            cache=True,
            timeout=20.0,
            max_retry_after=_MAX_INLINE_RETRY_AFTER,
        )
        rate_limited = _is_rate_limited(status, resp_headers)
        if rate_limited or _header(resp_headers, "x-ratelimit-remaining") == "0":
            # On a 200 this is proactive: the quota is spent, so the next
            # call would be refused anyway.
            self._back_off(status, resp_headers)
        if status != 200:
            if rate_limited:
                return None
            # 404 commonly means the repo was renamed/deleted. 401/403 likely
            # means the GHSA token is invalid. Distinguishing at the call site
            # helps operators triage auth failures fast.
            log.info(
                "stars.no_data",
                owner=owner,
                name=name,
                status=status,
            )
            return None
        try:
            return int(body.get("stargazers_count", 0))
        except (AttributeError, TypeError, ValueError):
            log.info("stars.unparseable", owner=owner, name=name)
            return None

    def _back_off(self, status: int, headers: dict[str, str]) -> None:
        now = time.time()
        until = _reset_epoch(headers, now)
        until = min(until, now + _MAX_BACKOFF_SECONDS)
        if until <= self._blocked_until:
            return
        already_blocked = self._blocked_until > now
        self._blocked_until = until
        if not already_blocked:
            # Logged once per back-off window, not once per skipped lookup.
            log.warning(
                "stars.rate_limited",
                status=status,
                resume_in_seconds=round(until - now),
            )


def _header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup on the plain dict HttpClient returns."""
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _is_rate_limited(status: int, headers: dict[str, str]) -> bool:
    if status == 429:
        return True
    # 403 is also GitHub's answer for a bad token or a blocked repo; only the
    # rate-limit flavours (spent quota, or a secondary limit with Retry-After)
    # mean "stop calling".
    return status == 403 and (
        _header(headers, "x-ratelimit-remaining") == "0"
        or _header(headers, "retry-after") is not None
    )


def _reset_epoch(headers: dict[str, str], now: float) -> float:
    """When calls may resume: X-RateLimit-Reset (epoch) or Retry-After, else a default."""
    reset = _header(headers, "x-ratelimit-reset")
    if reset:
        try:
            reset_at = float(reset)
        except ValueError:
            reset_at = 0.0
        # A reset already in the past (clock skew) falls through to the
        # Retry-After / default back-off rather than not backing off at all.
        if reset_at > now:
            return reset_at
    retry_after = _header(headers, "retry-after")
    if retry_after:
        return now + _parse_retry_after(retry_after)
    return now + _DEFAULT_BACKOFF_SECONDS
