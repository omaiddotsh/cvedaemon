"""Blast-radius signal fixes: repo resolution, deps.dev dependents, Hex/Pub
downloads, and score renormalization over each ecosystem's supported signals.

HTTP is mocked with respx; response bodies mirror the live API shapes
(deps.dev v3 / v3alpha, hex.pm, pub.dev, packagist) as of 2026-10.
"""

from __future__ import annotations

import asyncio

import pytest
import respx
from httpx import Response

from sev1daemon.config import (
    ECOSYSTEMS,
    BlastRadiusConfig,
    DepsDevConfig,
    DownloadsConfig,
    StarsConfig,
)
from sev1daemon.enrich import depsdev as depsdev_mod
from sev1daemon.enrich.depsdev import DepsDevClient
from sev1daemon.enrich.github_stars import GithubStarsClient
from sev1daemon.enrich.registry import RegistryClient
from sev1daemon.enrich.repo import (
    NAME_IS_REPO_ECOSYSTEMS,
    REGISTRY_REPO_ECOSYSTEMS,
    github_repo_url,
    parse_github_repo,
    repo_url_from_name,
)
from sev1daemon.http import HttpClient
from sev1daemon.models import AffectedPackage
from sev1daemon.scoring import Scorer

DD = "https://api.deps.dev/v3/systems"
DD_ALPHA = "https://api.deps.dev/v3alpha/systems"
LOG4J_PKG = f"{DD}/maven/packages/org.apache.logging.log4j%3Alog4j-core"
LOG4J_ALPHA = f"{DD_ALPHA}/maven/packages/org.apache.logging.log4j%3Alog4j-core"


@pytest.fixture
async def http():
    client = HttpClient()  # no cache_dir: every lookup is a real (mocked) request
    try:
        yield client
    finally:
        await client.aclose()


def _versions(*entries: tuple[str, str, bool]) -> dict:
    return {
        "versions": [
            {"versionKey": {"version": v}, "publishedAt": published, "isDefault": default}
            for v, published, default in entries
        ]
    }


def _dependents(total: int, direct: int, indirect: int) -> dict:
    return {
        "dependentCount": total,
        "directDependentCount": direct,
        "indirectDependentCount": indirect,
    }


# deps.dev npm/handlebars: the last listed version (4.7.9) is NOT the default.
HANDLEBARS_PKG = _versions(
    ("4.7.10", "2026-03-27T00:00:00Z", True),
    ("4.7.9", "2026-03-26T20:46:39Z", False),
)
HANDLEBARS_VERSION = {
    "links": [
        {"label": "HOMEPAGE", "url": "https://handlebarsjs.com/"},
        {"label": "ISSUE_TRACKER", "url": "https://github.com/handlebars-lang/handlebars.js/issues"},
        {"label": "ORIGIN", "url": "https://registry.npmjs.org/handlebars/4.7.10"},
        {"label": "SOURCE_REPO", "url": "git+https://github.com/handlebars-lang/handlebars.js.git"},
    ],
    "relatedProjects": [
        {
            "projectKey": {"id": "github.com/handlebars-lang/handlebars.js"},
            "relationProvenance": "UNVERIFIED_METADATA",
            "relationType": "SOURCE_REPO",
        }
    ],
}

# deps.dev maven/log4j-core: default is a 3.0 beta; stable 2.x carries the dependents.
LOG4J_VERSIONS = _versions(
    ("2.24.3", "2024-12-10T10:51:48Z", False),
    ("2.26.1", "2026-06-29T07:44:25Z", False),
    ("2.25.5", "2026-07-01T10:49:54Z", False),
    ("3.0.0-beta3", "2024-11-09T05:54:31Z", True),
)


# ---------- GitHub URL parsing ----------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/handlebars-lang/handlebars.js", ("handlebars-lang", "handlebars.js")),
        ("git+https://github.com/handlebars-lang/handlebars.js.git", ("handlebars-lang", "handlebars.js")),
        ("https://github.com/handlebars-lang/handlebars.js/issues", ("handlebars-lang", "handlebars.js")),
        ("https://github.com/foo/bar#readme", ("foo", "bar")),
        ("https://github.com/foo/bar.git#v1.2.3", ("foo", "bar")),
        ("https://github.com/dart-lang/http/tree/master/pkgs/http", ("dart-lang", "http")),
        ("http://www.github.com/Foo/Bar?tab=readme", ("Foo", "Bar")),
        ("git://github.com/foo/bar.git", ("foo", "bar")),
        ("ssh://git@github.com/foo/bar.git", ("foo", "bar")),
        ("git+ssh://git@github.com/foo/bar.git", ("foo", "bar")),
        ("git@github.com:foo/bar.git", ("foo", "bar")),
        ("scm:git:https://github.com/apache/logging-log4j2.git", ("apache", "logging-log4j2")),
        ("github.com/gin-gonic/gin/binding/v2", ("gin-gonic", "gin")),
        ("  https://github.com/foo/under_score.dots-1  ", ("foo", "under_score.dots-1")),
    ],
)
def test_parse_github_repo_accepts_common_forms(url, expected):
    assert parse_github_repo(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "https://gitlab.com/foo/bar",
        "https://github.com/foo",
        "https://github.com/foo/.git",
        "https://github.com/sponsors/ljharb",
        "https://github.com.evil.example/foo/bar",
        "https://evil.example/?next=github.com/foo/bar",
        "notgithub.com/foo/bar",
    ],
)
def test_parse_github_repo_rejects_non_repos(url):
    assert parse_github_repo(url) is None


def test_github_repo_url_is_canonical():
    assert (
        github_repo_url("git+https://github.com/handlebars-lang/handlebars.js.git")
        == "https://github.com/handlebars-lang/handlebars.js"
    )


@respx.mock
async def test_stars_for_dotted_repo_name(http):
    # Previously truncated to ".../handlebars" (a 404).
    route = respx.get("https://api.github.com/repos/handlebars-lang/handlebars.js").mock(
        return_value=Response(200, json={"stargazers_count": 18_500})
    )
    client = GithubStarsClient(http, token="")
    url = "git+https://github.com/handlebars-lang/handlebars.js.git"
    assert await client.stars_for_repo_url(url) == 18_500
    assert route.call_count == 1


# ---------- repo from the package name ----------


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("Go", "github.com/gin-gonic/gin", "https://github.com/gin-gonic/gin"),
        ("Go", "github.com/hashicorp/vault/api/v2", "https://github.com/hashicorp/vault"),
        ("Go", "golang.org/x/net", None),
        ("SwiftURL", "https://github.com/apple/swift-nio.git", "https://github.com/apple/swift-nio"),
        ("SwiftURL", "github.com/vapor/vapor", "https://github.com/vapor/vapor"),
        ("GitHub Actions", "actions/checkout", "https://github.com/actions/checkout"),
        ("GitHub Actions", "github/codeql-action/init", "https://github.com/github/codeql-action"),
        ("GitHub Actions", "not a repo", None),
        ("npm", "github.com/foo/bar", None),
    ],
)
def test_repo_url_from_name(ecosystem, name, expected):
    assert repo_url_from_name(ecosystem, name) == expected


@respx.mock  # no routes: any request fails the test
async def test_depsdev_repo_url_uses_name_without_network(http):
    client = DepsDevClient(http)
    assert await client.repo_url("Go", "github.com/gin-gonic/gin/v2") == (
        "https://github.com/gin-gonic/gin"
    )
    assert await client.repo_url("GitHub Actions", "tj-actions/changed-files") == (
        "https://github.com/tj-actions/changed-files"
    )
    assert await client.repo_url("SwiftURL", "https://github.com/apple/swift-nio.git") == (
        "https://github.com/apple/swift-nio"
    )


@respx.mock
async def test_depsdev_repo_url_go_off_github_falls_back_to_depsdev(http):
    respx.get(f"{DD}/go/packages/golang.org%2Fx%2Fnet").mock(
        return_value=Response(200, json=_versions(("v0.61.0", "2026-09-01T00:00:00Z", True)))
    )
    respx.get(f"{DD}/go/packages/golang.org%2Fx%2Fnet/versions/v0.61.0").mock(
        return_value=Response(
            200,
            json={
                "links": [{"label": "SOURCE_REPO", "url": "https://go.googlesource.com/net"}],
                "relatedProjects": [
                    {"projectKey": {"id": "github.com/golang/net"}, "relationType": "SOURCE_REPO"}
                ],
            },
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("Go", "golang.org/x/net") == "https://github.com/golang/net"


# ---------- repo from deps.dev version metadata ----------


@respx.mock
async def test_depsdev_repo_url_prefers_source_repo_on_default_version(http):
    respx.get(f"{DD}/npm/packages/handlebars").mock(return_value=Response(200, json=HANDLEBARS_PKG))
    respx.get(f"{DD}/npm/packages/handlebars/versions/4.7.10").mock(
        return_value=Response(200, json=HANDLEBARS_VERSION)
    )
    client = DepsDevClient(http)
    assert await client.repo_url("npm", "handlebars") == (
        "https://github.com/handlebars-lang/handlebars.js"
    )


@respx.mock
async def test_depsdev_repo_url_related_project_beats_issue_tracker_link(http):
    respx.get(f"{DD}/pypi/packages/foo").mock(
        return_value=Response(200, json=_versions(("1.0", "2026-01-01T00:00:00Z", True)))
    )
    respx.get(f"{DD}/pypi/packages/foo/versions/1.0").mock(
        return_value=Response(
            200,
            json={
                "links": [
                    {"label": "HOMEPAGE", "url": "https://foo.example"},
                    {"label": "ISSUE_TRACKER", "url": "https://github.com/wrong/tracker/issues"},
                ],
                "relatedProjects": [
                    {"projectKey": {"id": "gitlab.com/x/y"}, "relationType": "SOURCE_REPO"},
                    {"projectKey": {"id": "github.com/other/thing"}, "relationType": "ISSUE_TRACKER"},
                    {"projectKey": {"id": "github.com/right/repo"}, "relationType": "SOURCE_REPO"},
                ],
            },
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("PyPI", "foo") == "https://github.com/right/repo"


@respx.mock
async def test_depsdev_repo_url_falls_back_to_issue_tracker_link(http):
    respx.get(f"{DD}/cargo/packages/foo").mock(
        return_value=Response(200, json=_versions(("1.0.0", "2026-01-01T00:00:00Z", True)))
    )
    respx.get(f"{DD}/cargo/packages/foo/versions/1.0.0").mock(
        return_value=Response(
            200,
            json={
                "links": [
                    {"label": "SOURCE_REPO", "url": "https://gitbox.apache.org/repos/asf/foo.git"},
                    {"label": "ISSUE_TRACKER", "url": "https://github.com/a/b/issues"},
                ]
            },
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("crates.io", "foo") == "https://github.com/a/b"


@respx.mock
async def test_depsdev_repo_url_maven_name_is_url_encoded(http):
    respx.get(LOG4J_PKG).mock(return_value=Response(200, json=LOG4J_VERSIONS))
    respx.get(f"{LOG4J_PKG}/versions/3.0.0-beta3").mock(
        return_value=Response(
            200,
            json={"links": [{"label": "SOURCE_REPO", "url": "https://github.com/apache/logging-log4j2"}]},
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("Maven", "org.apache.logging.log4j:log4j-core") == (
        "https://github.com/apache/logging-log4j2"
    )


# ---------- repo from registry metadata (not in deps.dev) ----------


@respx.mock
async def test_repo_url_packagist(http):
    respx.get("https://packagist.org/packages/monolog/monolog.json").mock(
        return_value=Response(
            200, json={"package": {"repository": "https://github.com/Seldaek/monolog"}}
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("Packagist", "monolog/monolog") == (
        "https://github.com/Seldaek/monolog"
    )


@respx.mock
async def test_repo_url_hex(http):
    respx.get("https://hex.pm/api/packages/phoenix").mock(
        return_value=Response(
            200,
            json={
                "meta": {
                    "links": {
                        "Changelog": "https://phoenix.hexdocs.pm/changelog.html",
                        "GitHub": "https://github.com/phoenixframework/phoenix",
                    }
                }
            },
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("Hex", "phoenix") == "https://github.com/phoenixframework/phoenix"


@respx.mock
async def test_repo_url_pub_strips_tree_path(http):
    respx.get("https://pub.dev/api/packages/http").mock(
        return_value=Response(
            200,
            json={
                "latest": {
                    "pubspec": {
                        "homepage": None,
                        "repository": "https://github.com/dart-lang/http/tree/master/pkgs/http",
                    }
                }
            },
        )
    )
    client = DepsDevClient(http)
    assert await client.repo_url("Pub", "http") == "https://github.com/dart-lang/http"


@respx.mock
async def test_repo_url_registry_404_is_none(http):
    respx.get("https://hex.pm/api/packages/nope").mock(
        return_value=Response(404, json={"message": "Page not found", "status": 404})
    )
    client = DepsDevClient(http)
    assert await client.repo_url("Hex", "nope") is None


# ---------- deps.dev dependents ----------


@respx.mock
async def test_dependents_uses_default_version_not_last_listed(http):
    respx.get(f"{DD}/npm/packages/handlebars").mock(return_value=Response(200, json=HANDLEBARS_PKG))
    # Only the default (and stable) 4.7.10 is asked; 4.7.9 has no route.
    route = respx.get(f"{DD_ALPHA}/npm/packages/handlebars/versions/4.7.10:dependents").mock(
        return_value=Response(200, json=_dependents(56_395, 15_648, 41_140))
    )
    client = DepsDevClient(http)
    assert await client.dependents("npm", "handlebars") == 56_395
    assert route.call_count == 1


@respx.mock
async def test_dependents_prerelease_default_also_asks_newest_stable(http):
    respx.get(LOG4J_PKG).mock(return_value=Response(200, json=LOG4J_VERSIONS))
    beta = respx.get(f"{LOG4J_ALPHA}/versions/3.0.0-beta3:dependents").mock(
        return_value=Response(200, json=_dependents(239, 99, 144))
    )
    # Newest stable by publish date is the 2.25.5 backport, not 2.26.1.
    stable = respx.get(f"{LOG4J_ALPHA}/versions/2.25.5:dependents").mock(
        return_value=Response(200, json=_dependents(2_689, 289, 2_407))
    )
    client = DepsDevClient(http)
    assert await client.dependents("Maven", "org.apache.logging.log4j:log4j-core") == 2_689
    assert beta.call_count == 1 and stable.call_count == 1


@respx.mock
async def test_dependents_one_version_missing_still_uses_the_other(http):
    respx.get(LOG4J_PKG).mock(return_value=Response(200, json=LOG4J_VERSIONS))
    respx.get(f"{LOG4J_ALPHA}/versions/3.0.0-beta3:dependents").mock(
        return_value=Response(200, json=_dependents(239, 99, 144))
    )
    respx.get(f"{LOG4J_ALPHA}/versions/2.25.5:dependents").mock(
        return_value=Response(404, text="dependents not found")
    )
    client = DepsDevClient(http)
    assert await client.dependents("Maven", "org.apache.logging.log4j:log4j-core") == 239


@respx.mock
async def test_dependents_404_is_none(http):
    respx.get(f"{DD}/npm/packages/handlebars").mock(return_value=Response(200, json=HANDLEBARS_PKG))
    respx.get(f"{DD_ALPHA}/npm/packages/handlebars/versions/4.7.10:dependents").mock(
        return_value=Response(404, text="dependents not found")
    )
    client = DepsDevClient(http)
    assert await client.dependents("npm", "handlebars") is None


@respx.mock  # no routes: unsupported ecosystems must not spend a request
@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("Go", "github.com/gin-gonic/gin"),
        ("RubyGems", "rails"),
        ("NuGet", "Newtonsoft.Json"),
        ("Packagist", "monolog/monolog"),
        ("Hex", "phoenix"),
        ("SwiftURL", "https://github.com/apple/swift-nio.git"),
        ("GitHub Actions", "actions/checkout"),
    ],
)
async def test_dependents_unsupported_ecosystem_is_none_without_request(http, ecosystem, name):
    assert await DepsDevClient(http).dependents(ecosystem, name) is None


@respx.mock
async def test_dependents_and_repo_url_share_one_package_lookup(http):
    pkg = respx.get(f"{DD}/npm/packages/handlebars").mock(
        return_value=Response(200, json=HANDLEBARS_PKG)
    )
    respx.get(f"{DD}/npm/packages/handlebars/versions/4.7.10").mock(
        return_value=Response(200, json=HANDLEBARS_VERSION)
    )
    respx.get(f"{DD_ALPHA}/npm/packages/handlebars/versions/4.7.10:dependents").mock(
        return_value=Response(200, json=_dependents(56_395, 15_648, 41_140))
    )
    client = DepsDevClient(http)
    # Same concurrency as the daemon's enrichment gather.
    deps, repo = await asyncio.gather(
        client.dependents("npm", "handlebars"), client.repo_url("npm", "handlebars")
    )
    assert deps == 56_395
    assert repo == "https://github.com/handlebars-lang/handlebars.js"
    assert pkg.call_count == 1
    assert client._inflight == {}


@respx.mock
async def test_shared_lookup_survives_one_caller_being_cancelled(http):
    gate = asyncio.Event()

    async def slow_package(request):
        await gate.wait()
        return Response(200, json=HANDLEBARS_PKG)

    respx.get(f"{DD}/npm/packages/handlebars").mock(side_effect=slow_package)
    respx.get(f"{DD}/npm/packages/handlebars/versions/4.7.10").mock(
        return_value=Response(200, json=HANDLEBARS_VERSION)
    )
    client = DepsDevClient(http)
    doomed = asyncio.create_task(client.dependents("npm", "handlebars"))
    survivor = asyncio.create_task(client.repo_url("npm", "handlebars"))
    await asyncio.sleep(0.01)
    doomed.cancel()
    gate.set()
    assert await survivor == "https://github.com/handlebars-lang/handlebars.js"
    with pytest.raises(asyncio.CancelledError):
        await doomed


@pytest.mark.parametrize(
    ("version", "stable"),
    [
        ("4.7.10", True),
        ("v1.12.0", True),
        ("2.0", True),
        ("5.6.15.Final", True),
        ("4.3.0.RELEASE", True),
        ("v2.0.0+incompatible", True),
        ("3.0.0-beta3", False),
        ("2.0.0rc1", False),
        ("1.0.0-SNAPSHOT", False),
        ("8.0.0.beta1", False),
        ("1.0.dev3", False),
        ("v0.0.0-20240101000000-abcdef123456", False),
    ],
)
def test_stable_version_detection(version, stable):
    assert depsdev_mod._is_stable(version) is stable


# ---------- Hex / Pub downloads ----------


@respx.mock
async def test_hex_downloads_uses_recent_90d(http):
    respx.get("https://hex.pm/api/packages/phoenix").mock(
        return_value=Response(
            200,
            json={
                "downloads": {"all": 157_309_523, "day": 87_573, "recent": 5_337_845, "week": 539_593}
            },
        )
    )
    assert await RegistryClient(http).downloads("Hex", "phoenix") == 5_337_845


@respx.mock
async def test_pub_downloads_uses_30d_count(http):
    respx.get("https://pub.dev/api/packages/http/score").mock(
        return_value=Response(
            200,
            json={
                "grantedPoints": 160,
                "maxPoints": 160,
                "likeCount": 8477,
                "downloadCount30Days": 12_992_646,
            },
        )
    )
    assert await RegistryClient(http).downloads("Pub", "http") == 12_992_646


@respx.mock
async def test_hex_and_pub_missing_package_is_none(http):
    respx.get("https://hex.pm/api/packages/nope").mock(
        return_value=Response(404, json={"message": "Page not found", "status": 404})
    )
    # pub.dev answers a missing package's score with an XML error body.
    respx.get("https://pub.dev/api/packages/nope/score").mock(
        return_value=Response(404, text="<?xml version='1.0'?><Error><Code>NoSuchKey</Code></Error>")
    )
    client = RegistryClient(http)
    assert await client.downloads("Hex", "nope") is None
    assert await client.downloads("Pub", "nope") is None


@respx.mock
async def test_hex_without_download_counts_is_none(http):
    respx.get("https://hex.pm/api/packages/new_pkg").mock(
        return_value=Response(200, json={"name": "new_pkg"})
    )
    assert await RegistryClient(http).downloads("Hex", "new_pkg") is None


# ---------- support matrix ----------

SUPPORT_MATRIX = {
    "npm": ("stars", "downloads", "depsdev"),
    "PyPI": ("stars", "downloads", "depsdev"),
    "crates.io": ("stars", "downloads", "depsdev"),
    "RubyGems": ("stars", "downloads"),
    "NuGet": ("stars", "downloads"),
    "Packagist": ("stars", "downloads"),
    "Hex": ("stars", "downloads"),
    "Pub": ("stars", "downloads"),
    "Maven": ("stars", "depsdev"),
    "Go": ("stars",),
    "SwiftURL": ("stars",),
    "GitHub Actions": ("stars",),
}


def test_support_matrix_covers_every_configured_ecosystem():
    assert set(SUPPORT_MATRIX) == set(ECOSYSTEMS)


@pytest.mark.parametrize(("ecosystem", "signals"), sorted(SUPPORT_MATRIX.items()))
def test_supported_signals_per_ecosystem(ecosystem, signals):
    assert Scorer.supported_signals(ecosystem) == signals
    assert RegistryClient.supports(ecosystem) is ("downloads" in signals)
    assert DepsDevClient.supports(ecosystem) is ("depsdev" in signals)


def test_every_ecosystem_has_a_repo_route_for_stars():
    # Stars count as supported everywhere, which needs a repo URL route.
    routes = set(depsdev_mod._SYSTEM) | NAME_IS_REPO_ECOSYSTEMS | REGISTRY_REPO_ECOSYSTEMS
    assert set(ECOSYSTEMS) <= routes


def test_downloads_support_has_a_configured_threshold():
    thresholds = DownloadsConfig().thresholds
    for ecosystem in RegistryClient.SUPPORTED:
        assert thresholds.get(ecosystem, 0) > 0, ecosystem


# ---------- renormalized scoring ----------


def _score(ecosystem, stars=None, downloads=None, depsdev=None, cfg=None):
    scorer = Scorer(cfg or BlastRadiusConfig())
    pkg = AffectedPackage(ecosystem=ecosystem, name="pkg")
    return scorer, scorer.score(pkg, stars=stars, downloads=downloads, depsdev=depsdev)


def test_fully_supported_ecosystem_is_not_rescaled():
    _, brk = _score("npm", stars=5_000, downloads=100_000, depsdev=1_000)
    assert brk.scale == 1.0
    assert (brk.stars_points, brk.downloads_points, brk.depsdev_points) == (40.0, 40.0, 20.0)
    assert brk.total == 100.0


def test_maven_full_signal_reaches_100():
    scorer, brk = _score("Maven", stars=50_000, depsdev=5_000)
    assert brk.total == 100.0
    assert brk.downloads_points == 0.0
    assert scorer.crosses_threshold(brk.total)


def test_maven_log4j_core_realistic_signals_cross_threshold():
    # ~3.4k stars (27.2 raw) + 2689 dependents (20 raw) = 47.2 of 60 → 78.67.
    scorer, brk = _score("Maven", stars=3_400, depsdev=2_689)
    assert brk.scale == pytest.approx(100 / 60, abs=1e-4)
    assert brk.total == pytest.approx(78.67, abs=0.02)
    assert scorer.crosses_threshold(brk.total)


def test_maven_missing_dependents_stays_conservative():
    # Supported signal came back None: it still scores 0 and stays in the
    # denominator, so saturated stars alone (40/60) cannot alert.
    scorer, brk = _score("Maven", stars=999_999, depsdev=None)
    assert brk.total == pytest.approx(66.67, abs=0.01)
    assert not scorer.crosses_threshold(brk.total)


def test_npm_missing_downloads_is_not_renormalized_away():
    scorer, brk = _score("npm", stars=999_999, downloads=None, depsdev=999_999)
    assert brk.scale == 1.0
    assert brk.total == 60.0
    assert not scorer.crosses_threshold(brk.total)


@pytest.mark.parametrize("ecosystem", ["Go", "SwiftURL", "GitHub Actions"])
def test_stars_only_ecosystems_alert_at_3500_stars(ecosystem):
    scorer, at = _score(ecosystem, stars=3_500)
    _, below = _score(ecosystem, stars=3_499)
    assert at.scale == 2.5
    assert at.total == 70.0 and scorer.crosses_threshold(at.total)
    assert not scorer.crosses_threshold(below.total)


def test_go_gin_scores_100_on_stars_alone():
    scorer, brk = _score("Go", stars=80_000)
    assert brk.total == 100.0


def test_two_signal_registry_ecosystem_scale():
    # RubyGems: stars + downloads, deps.dev has no dependents → 100 / 80.
    _, brk = _score("RubyGems", stars=5_000, downloads=10_000_000)
    assert brk.scale == 1.25
    assert brk.total == 100.0


def test_unsupported_signal_values_never_score():
    # Maven has no download source; a value passed anyway must not add points
    # (it would push the renormalized total past 100).
    _, brk = _score("Maven", stars=5_000, downloads=10**9, depsdev=5_000)
    assert brk.downloads_points == 0.0
    assert brk.total == 100.0


def test_zero_weights_do_not_divide_by_zero():
    cfg = BlastRadiusConfig(
        score_threshold=0,
        stars=StarsConfig(weight=0, saturate_at=1),
        downloads=DownloadsConfig(weight=0, thresholds={"npm": 1}),
        depsdev=DepsDevConfig(weight=0, saturate_at=1),
    )
    for ecosystem in ("npm", "Maven", "Go"):
        scorer, brk = _score(ecosystem, stars=10, downloads=10, depsdev=10, cfg=cfg)
        assert brk.total == 0.0
        assert scorer.crosses_threshold(brk.total)


def test_breakdown_dict_reports_scale_and_supported_signals():
    _, brk = _score("Maven", stars=2_500, depsdev=500)
    out = brk.as_dict()
    assert out["supported_signals"] == ["stars", "depsdev"]
    assert out["scale"] == pytest.approx(1.6667)
    assert out["total"] == brk.total == round(
        out["stars_points"] + out["downloads_points"] + out["depsdev_points"], 2
    )
    assert out["stars_raw"] == 2_500 and out["downloads_raw"] is None


# ---------- end to end: live-shaped responses → score ----------


async def _enrich_and_score(http, ecosystem, name, stars_client):
    registry, deps = RegistryClient(http), DepsDevClient(http)
    downloads, dependents, repo = await asyncio.gather(
        registry.downloads(ecosystem, name),
        deps.dependents(ecosystem, name),
        deps.repo_url(ecosystem, name),
    )
    stars = await stars_client.stars_for_repo_url(repo or "")
    scorer = Scorer(BlastRadiusConfig())
    brk = scorer.score(AffectedPackage(ecosystem, name), stars, downloads, dependents)
    return scorer, brk


@respx.mock
async def test_e2e_handlebars_scores_100(http):
    respx.get("https://api.npmjs.org/downloads/point/last-week/handlebars").mock(
        return_value=Response(200, json={"downloads": 25_000_000, "package": "handlebars"})
    )
    respx.get(f"{DD}/npm/packages/handlebars").mock(return_value=Response(200, json=HANDLEBARS_PKG))
    respx.get(f"{DD}/npm/packages/handlebars/versions/4.7.10").mock(
        return_value=Response(200, json=HANDLEBARS_VERSION)
    )
    respx.get(f"{DD_ALPHA}/npm/packages/handlebars/versions/4.7.10:dependents").mock(
        return_value=Response(200, json=_dependents(56_395, 15_648, 41_140))
    )
    respx.get("https://api.github.com/repos/handlebars-lang/handlebars.js").mock(
        return_value=Response(200, json={"stargazers_count": 18_500})
    )
    scorer, brk = await _enrich_and_score(
        http, "npm", "handlebars", GithubStarsClient(http, token="")
    )
    assert (brk.stars_raw, brk.downloads_raw, brk.depsdev_raw) == (18_500, 25_000_000, 56_395)
    assert brk.total == 100.0
    assert scorer.crosses_threshold(brk.total)


@respx.mock
async def test_e2e_log4j_core_crosses_threshold(http):
    respx.get(LOG4J_PKG).mock(return_value=Response(200, json=LOG4J_VERSIONS))
    respx.get(f"{LOG4J_PKG}/versions/3.0.0-beta3").mock(
        return_value=Response(
            200,
            json={"links": [{"label": "SOURCE_REPO", "url": "https://github.com/apache/logging-log4j2"}]},
        )
    )
    respx.get(f"{LOG4J_ALPHA}/versions/3.0.0-beta3:dependents").mock(
        return_value=Response(200, json=_dependents(239, 99, 144))
    )
    respx.get(f"{LOG4J_ALPHA}/versions/2.25.5:dependents").mock(
        return_value=Response(200, json=_dependents(2_689, 289, 2_407))
    )
    respx.get("https://api.github.com/repos/apache/logging-log4j2").mock(
        return_value=Response(200, json={"stargazers_count": 3_400})
    )
    scorer, brk = await _enrich_and_score(
        http, "Maven", "org.apache.logging.log4j:log4j-core", GithubStarsClient(http, token="")
    )
    assert brk.downloads_raw is None and brk.depsdev_raw == 2_689
    assert brk.total == pytest.approx(78.67, abs=0.02)
    assert scorer.crosses_threshold(brk.total)


def test_downloads_without_configured_threshold_is_unsupported():
    from sev1daemon.config import BlastRadiusConfig, DownloadsConfig
    from sev1daemon.models import AffectedPackage
    from sev1daemon.scoring import Scorer

    cfg = BlastRadiusConfig(downloads=DownloadsConfig(thresholds={"npm": 100_000}))
    # Hex has a download source, but this config has no Hex threshold: the
    # score is renormalized over stars alone rather than capped at 40/80.
    b = Scorer(cfg).score(AffectedPackage("Hex", "phoenix"), 5000, 10**7, None)
    assert "downloads" not in b.supported_signals
    assert b.total == 100.0
