"""Source-repository resolution: GitHub URL parsing and per-ecosystem repo lookups.

Three ways a package's GitHub repo is found, cheapest first:

* the package name already is the repo (Go ``github.com/...`` modules,
  SwiftURL URLs, GitHub Actions ``owner/repo``): ``repo_url_from_name``;
* the registry's own metadata, for ecosystems deps.dev does not index
  (Packagist, Hex, Pub): ``registry_repo_url``;
* deps.dev version metadata, for everything else (``DepsDevClient.repo_url``).

Every helper returns the canonical ``https://github.com/<owner>/<repo>`` form
or None, so the stars lookup sees one URL shape whatever the source.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from sev1daemon.http import HttpClient
from sev1daemon.log import get_logger

log = get_logger("repo")

# github.com in any of the forms package metadata uses:
#   https://github.com/o/r, http://www.github.com/o/r, github.com/o/r (Go, GHSA swift)
#   git+https://github.com/o/r.git, git://github.com/o/r.git (npm)
#   ssh://git@github.com/o/r.git, git+ssh://git@github.com/o/r.git
#   git@github.com:o/r.git (scp-like), scm:git:https://github.com/o/r.git (Maven)
# Owner follows GitHub's login rules (alphanumerics and hyphens). The repo
# segment allows dots (handlebars.js) and stops at the first character a repo
# name cannot contain, which drops "/issues", "#readme", "/tree/main/x", "?q".
_GITHUB_RE = re.compile(
    r"""
    ^\s*
    (?:scm:git:)?
    (?:git\+)?
    (?:
        (?:https?|git|ssh)://(?:[^@/\s]+@)?(?:www\.)?github\.com(?::\d+)?/
      | git@github\.com:
      | (?:www\.)?github\.com/
    )
    (?P<owner>[A-Za-z0-9][A-Za-z0-9-]*)
    /
    (?P<repo>[A-Za-z0-9._-]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# github.com/<x>/... paths that are site pages, not repos (FUNDING links such
# as github.com/sponsors/<user> show up in package metadata).
_RESERVED_OWNERS = frozenset(
    {
        "about", "apps", "collections", "enterprise", "features", "marketplace",
        "orgs", "settings", "sponsors", "topics", "users",
    }
)

# A bare "owner/repo[/path]" GitHub Actions package name.
_ACTION_NAME_RE = re.compile(r"^(?P<owner>[A-Za-z0-9][A-Za-z0-9-]*)/(?P<repo>[A-Za-z0-9._-]+)")

# Ecosystems whose package name identifies the GitHub repo directly.
NAME_IS_REPO_ECOSYSTEMS = frozenset({"Go", "SwiftURL", "GitHub Actions"})
# Ecosystems deps.dev does not index, whose registry API carries the repo URL.
REGISTRY_REPO_ECOSYSTEMS = frozenset({"Packagist", "Hex", "Pub"})


def parse_github_repo(url: str | None) -> tuple[str, str] | None:
    """``(owner, repo)`` for a GitHub repository URL in any common form, else None."""
    m = _GITHUB_RE.match(url or "")
    if not m:
        return None
    return _owner_repo(m.group("owner"), m.group("repo"))


def github_repo_url(url: str | None) -> str | None:
    """Canonical ``https://github.com/<owner>/<repo>`` for a GitHub URL, else None."""
    parsed = parse_github_repo(url)
    if parsed is None:
        return None
    owner, repo = parsed
    return f"https://github.com/{owner}/{repo}"


def repo_url_from_name(ecosystem: str, name: str) -> str | None:
    """Repo URL when the package name itself is a GitHub repo; no network.

    * Go: ``github.com/<owner>/<repo>[/subpath][/vN]`` (other hosts → None)
    * SwiftURL: ``https://github.com/<owner>/<repo>.git`` or ``github.com/<owner>/<repo>``
    * GitHub Actions: ``<owner>/<repo>[/path]``
    """
    if ecosystem in ("Go", "SwiftURL"):
        return github_repo_url(name)
    if ecosystem == "GitHub Actions":
        direct = github_repo_url(name)
        if direct:
            return direct
        m = _ACTION_NAME_RE.match(name.strip())
        if not m:
            return None
        parsed = _owner_repo(m.group("owner"), m.group("repo"))
        return f"https://github.com/{parsed[0]}/{parsed[1]}" if parsed else None
    return None


async def registry_repo_url(http: HttpClient, ecosystem: str, name: str) -> str | None:
    """GitHub repo from Packagist / Hex / Pub package metadata."""
    if ecosystem == "Packagist":
        url = f"https://packagist.org/packages/{quote(name, safe='/')}.json"
    elif ecosystem == "Hex":
        url = f"https://hex.pm/api/packages/{quote(name, safe='')}"
    elif ecosystem == "Pub":
        url = f"https://pub.dev/api/packages/{quote(name, safe='')}"
    else:
        return None
    status, body, _ = await http.get_json(url, cache=True, timeout=20.0)
    if status != 200 or not isinstance(body, dict):
        log.info("repo.no_data", ecosystem=ecosystem, name=name, status=status)
        return None
    return first_github_url(_registry_candidates(ecosystem, body))


def first_github_url(candidates: list[Any]) -> str | None:
    """First candidate that parses as a GitHub repo, canonicalized."""
    for candidate in candidates:
        if isinstance(candidate, str):
            found = github_repo_url(candidate)
            if found:
                return found
    return None


def _registry_candidates(ecosystem: str, body: dict[str, Any]) -> list[Any]:
    """Repo-ish URLs from a registry response, most authoritative first."""
    if ecosystem == "Packagist":
        # {"package": {"repository": "https://github.com/Seldaek/monolog", ...}}
        pkg = body.get("package")
        return [pkg.get("repository")] if isinstance(pkg, dict) else []
    if ecosystem == "Hex":
        # {"meta": {"links": {"GitHub": "https://github.com/phoenixframework/phoenix"}}}
        meta = body.get("meta")
        links = meta.get("links") if isinstance(meta, dict) else None
        if not isinstance(links, dict):
            return []
        preferred = [v for k, v in links.items() if str(k).lower() in ("github", "source", "repository")]
        return preferred + list(links.values())
    # Pub: {"latest": {"pubspec": {"repository": ..., "homepage": ..., "issue_tracker": ...}}}
    latest = body.get("latest")
    pubspec = latest.get("pubspec") if isinstance(latest, dict) else None
    if not isinstance(pubspec, dict):
        return []
    return [pubspec.get(k) for k in ("repository", "homepage", "issue_tracker")]


def _owner_repo(owner: str, repo: str) -> tuple[str, str] | None:
    repo = repo.removesuffix(".git")
    if not repo or repo in (".", "..") or owner.lower() in _RESERVED_OWNERS:
        return None
    return owner, repo
