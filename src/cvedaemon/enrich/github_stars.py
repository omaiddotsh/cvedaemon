"""GitHub stargazer fetch — looks up the repo url for a package and reads stars."""

from __future__ import annotations

import re

from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger

log = get_logger("stars")


_GITHUB_HOST_RE = re.compile(r"(?i)^(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/.#]+)")


class GithubStarsClient:
    def __init__(self, http: HttpClient, token: str):
        self._http = http
        self._token = token

    async def stars_for_repo_url(self, repo_url: str) -> int | None:
        m = _GITHUB_HOST_RE.search(repo_url or "")
        if not m:
            return None
        owner, name = m.group(1), m.group(2)
        # strip ".git" if appended
        name = name.removesuffix(".git")
        url = f"https://api.github.com/repos/{owner}/{name}"
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        status, body, _ = await self._http.get_json(
            url, headers=headers, cache=True, timeout=20.0
        )
        if status != 200:
            # 404 commonly means the repo was renamed/deleted. 401/403 likely
            # means the GHSA token is invalid or rate-limited. Distinguishing
            # at the call site helps operators triage auth failures fast.
            log.info(
                "stars.no_data",
                owner=owner,
                name=name,
                status=status,
            )
            return None
        try:
            return int(body.get("stargazers_count", 0))
        except (TypeError, ValueError):
            log.info("stars.unparseable", owner=owner, name=name)
            return None
