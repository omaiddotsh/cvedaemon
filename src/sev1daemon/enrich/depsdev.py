"""deps.dev dependents count + source repo URL lookup.

deps.dev only has dependents at version level, on the v3alpha API:
``GET /v3alpha/systems/{system}/packages/{name}/versions/{version}:dependents``
→ ``{"dependentCount": int, "directDependentCount": int, "indirectDependentCount": int}``.
The version comes from the package's version list (``GET /v3/.../packages/{name}``),
which ``repo_url`` needs as well; the two share one in-flight request.
"""

from __future__ import annotations

import asyncio
import functools
import re
from typing import Any, ClassVar
from urllib.parse import quote

from sev1daemon.enrich.repo import (
    REGISTRY_REPO_ECOSYSTEMS,
    first_github_url,
    github_repo_url,
    registry_repo_url,
    repo_url_from_name,
)
from sev1daemon.http import HttpClient
from sev1daemon.log import get_logger

log = get_logger("depsdev")

_BASE = "https://api.deps.dev/v3"
_ALPHA_BASE = "https://api.deps.dev/v3alpha"

# deps.dev "system" per ecosystem: the systems deps.dev indexes. Packagist,
# Pub, Hex, SwiftURL and GitHub Actions answer "package not found" (checked
# live 2026-10), so they are not looked up here.
_SYSTEM = {
    "npm": "npm",
    "PyPI": "pypi",
    "RubyGems": "rubygems",
    "crates.io": "cargo",
    "NuGet": "nuget",
    "Maven": "maven",
    "Go": "go",
}

# Ecosystems deps.dev computes dependents for. Go, RubyGems and NuGet are
# indexed but answer "dependents not found" for every version, even for
# gin / x/net, rails / rack and Newtonsoft.Json / Serilog (checked live
# 2026-10), so asking would only spend a request on a 404.
_DEPENDENTS_ECOSYSTEMS = frozenset({"npm", "PyPI", "crates.io", "Maven"})

# A release version: dotted numbers, optionally with a Maven release
# qualifier or Go's "+incompatible". Anything else (beta, rc, -SNAPSHOT,
# a1, dev, ...) counts as a prerelease.
_STABLE_VERSION_RE = re.compile(
    r"^v?\d+(?:\.\d+)*(?:[.-](?:final|release|ga))?(?:\+incompatible)?$", re.IGNORECASE
)

_TIMEOUT = 20.0


class DepsDevClient:
    # Ecosystems with a deps.dev dependents signal, for score renormalization.
    SUPPORTED: ClassVar[frozenset[str]] = _DEPENDENTS_ECOSYSTEMS

    def __init__(self, http: HttpClient):
        self._http = http
        # Package lookups in flight, keyed by URL. dependents() and repo_url()
        # run concurrently for the same package and both need the version
        # list; the HttpClient disk cache only helps once the first has
        # landed, so concurrent callers share one request here instead.
        self._inflight: dict[str, asyncio.Task[dict[str, Any] | None]] = {}

    @classmethod
    def supports(cls, ecosystem: str) -> bool:
        """Whether deps.dev has dependents data for this ecosystem at all."""
        return ecosystem in cls.SUPPORTED

    async def dependents(self, ecosystem: str, name: str) -> int | None:
        """Total (direct + indirect, deduplicated) dependents, or None if unknown.

        Counted on the default version. When that is a prerelease (Maven
        picks the highest version, e.g. log4j-core 3.0.0-beta3) the newest
        stable release is asked as well and the larger count is used: each
        is a real per-version count, so the larger is still a lower bound on
        the package's dependents.

        Known limit: deps.dev counts dependents against the version each
        dependent resolved to when deps.dev last walked its graph, so a
        package that releases often can show 0 on every recent version
        (cargo serde 1.0.215 to 1.0.229 all answer 0 while 1.0.210 answers
        44,518; checked live 2026-10). That under-scores by at most the
        signal's weight and never over-scores, which is the conservative
        side; walking back far enough to find the counted version would
        cost one request per release.
        """
        if not self.supports(ecosystem) or not name:
            return None
        system = _SYSTEM[ecosystem]
        pkg = await self._package(system, name)
        if pkg is None:
            return None
        default, newest_stable = _default_and_newest_stable(pkg)
        if default and _is_stable(default):
            candidates = [default]
        else:
            candidates = [v for v in (default, newest_stable) if v]
        counts: list[int] = []
        for version in dict.fromkeys(candidates):  # dedupe, keep order
            count = await self._version_dependents(system, name, version)
            if count is not None:
                counts.append(count)
        return max(counts) if counts else None

    async def repo_url(self, ecosystem: str, name: str) -> str | None:
        """Canonical GitHub URL of the package's source repo, or None.

        Name-derived for Go/SwiftURL/GitHub Actions, registry metadata for
        Packagist/Hex/Pub, deps.dev version metadata for everything else
        (and for Go modules not hosted on GitHub).
        """
        if not name:
            return None
        direct = repo_url_from_name(ecosystem, name)
        if direct:
            return direct
        if ecosystem in REGISTRY_REPO_ECOSYSTEMS:
            return await registry_repo_url(self._http, ecosystem, name)
        system = _SYSTEM.get(ecosystem)
        if not system:
            return None
        pkg = await self._package(system, name)
        if pkg is None:
            return None
        default, newest_stable = _default_and_newest_stable(pkg)
        version = default or newest_stable
        if not version:
            return None
        url = f"{_package_url(system, name)}/versions/{quote(version, safe='')}"
        vbody = await self._get(url, endpoint="version", system=system, name=name)
        if vbody is None:
            return None
        return _repo_from_version(vbody)

    # ---------- deps.dev requests ----------

    async def _package(self, system: str, name: str) -> dict[str, Any] | None:
        url = _package_url(system, name)
        task = self._inflight.get(url)
        if task is None:
            task = asyncio.create_task(
                self._get(url, endpoint="package", system=system, name=name)
            )
            self._inflight[url] = task
            task.add_done_callback(functools.partial(self._forget, url))
        # shield: one caller being cancelled must not cancel the lookup the
        # other caller is still waiting on.
        return await asyncio.shield(task)

    def _forget(self, url: str, task: asyncio.Task[dict[str, Any] | None]) -> None:
        if self._inflight.get(url) is task:
            del self._inflight[url]
        if not task.cancelled():
            # Mark any exception retrieved: if every waiter was cancelled,
            # nobody else will, and asyncio would log it as unhandled.
            task.exception()

    async def _version_dependents(self, system: str, name: str, version: str) -> int | None:
        url = (
            f"{_ALPHA_BASE}/systems/{system}/packages/{quote(name, safe='')}"
            f"/versions/{quote(version, safe='')}:dependents"
        )
        body = await self._get(url, endpoint="dependents", system=system, name=name)
        if body is None:
            return None
        # Not synthesized from direct + indirect: a package can be both, so
        # their sum overcounts (handlebars 4.7.10: 15648 + 41140 > 56395).
        return _non_negative_int(body.get("dependentCount"))

    async def _get(self, url: str, *, endpoint: str, system: str, name: str) -> dict[str, Any] | None:
        status, body, _ = await self._http.get_json(url, cache=True, timeout=_TIMEOUT)
        if status != 200 or not isinstance(body, dict):
            log.info("depsdev.no_data", endpoint=endpoint, system=system, name=name, status=status)
            return None
        return body


def _package_url(system: str, name: str) -> str:
    # quote(safe="") also encodes Maven's "group:artifact" colon and Go's slashes.
    return f"{_BASE}/systems/{system}/packages/{quote(name, safe='')}"


def _is_stable(version: str) -> bool:
    return bool(_STABLE_VERSION_RE.match(version))


def _default_and_newest_stable(pkg: dict[str, Any]) -> tuple[str | None, str | None]:
    """(default version, most recently published stable version).

    With no default flagged, the last listed version stands in for it.
    """
    versions: list[tuple[str, str, bool]] = []  # (version, publishedAt, isDefault)
    for entry in pkg.get("versions") or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("versionKey")
        version = key.get("version") if isinstance(key, dict) else None
        if isinstance(version, str) and version:
            versions.append((version, str(entry.get("publishedAt") or ""), bool(entry.get("isDefault"))))
    if not versions:
        return None, None
    default = next((v for v, _, is_default in versions if is_default), versions[-1][0])
    # publishedAt is RFC 3339 UTC ("2024-12-10T10:51:48Z"), so it sorts as text.
    stable = [(published, v) for v, published, _ in versions if _is_stable(v)]
    newest_stable = max(stable)[1] if stable else None
    return default, newest_stable


def _repo_from_version(vbody: dict[str, Any]) -> str | None:
    """GitHub repo from deps.dev version metadata, most specific signal first.

    1. the SOURCE_REPO link (npm's ``git+https://...git`` included);
    2. a relatedProjects entry on github.com, SOURCE_REPO relation first;
    3. any other link on github.com (ISSUE_TRACKER ``.../issues``, HOMEPAGE).
    """
    links = [link for link in vbody.get("links") or [] if isinstance(link, dict)]
    projects = [p for p in vbody.get("relatedProjects") or [] if isinstance(p, dict)]

    source_links = [link.get("url") for link in links if link.get("label") == "SOURCE_REPO"]
    found = first_github_url(source_links)
    if found:
        return found

    def _project_url(project: dict[str, Any]) -> str | None:
        key = project.get("projectKey")
        pid = key.get("id") if isinstance(key, dict) else None
        # Project ids are "github.com/<owner>/<repo>"; other hosts are skipped.
        return github_repo_url(pid) if isinstance(pid, str) else None

    ranked = sorted(projects, key=lambda p: p.get("relationType") != "SOURCE_REPO")
    for project in ranked:
        found = _project_url(project)
        if found:
            return found

    return first_github_url([link.get("url") for link in links])


def _non_negative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None
