"""Tests for the enrichment clients: registry, deps.dev, github stars."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from sev1daemon.enrich.depsdev import DepsDevClient
from sev1daemon.enrich.github_stars import GithubStarsClient
from sev1daemon.enrich.registry import RegistryClient
from sev1daemon.http import HttpClient

pytestmark = pytest.mark.asyncio


# ---------- registry ----------


@respx.mock
async def test_registry_npm_downloads():
    respx.get("https://api.npmjs.org/downloads/point/last-week/lodash").mock(
        return_value=Response(200, json={"downloads": 50_000_000, "package": "lodash"})
    )
    http = HttpClient()
    try:
        client = RegistryClient(http)
        assert await client.downloads("npm", "lodash") == 50_000_000
    finally:
        await http.aclose()


@respx.mock
async def test_registry_pypi_downloads():
    respx.get("https://pypistats.org/api/packages/requests/recent").mock(
        return_value=Response(
            200, json={"data": {"last_day": 1, "last_week": 7, "last_month": 30_000_000}}
        )
    )
    http = HttpClient()
    try:
        client = RegistryClient(http)
        assert await client.downloads("PyPI", "requests") == 30_000_000
    finally:
        await http.aclose()


@respx.mock
async def test_registry_handles_404():
    respx.get(
        "https://api.npmjs.org/downloads/point/last-week/this-pkg-does-not-exist"
    ).mock(return_value=Response(404))
    http = HttpClient()
    try:
        client = RegistryClient(http)
        # 404 → None, never propagates as exception.
        assert await client.downloads("npm", "this-pkg-does-not-exist") is None
    finally:
        await http.aclose()


async def test_registry_unknown_ecosystem_returns_none():
    http = HttpClient()
    try:
        client = RegistryClient(http)
        assert await client.downloads("MyMadeUpEcosystem", "name") is None
    finally:
        await http.aclose()


# ---------- deps.dev ----------


@respx.mock
async def test_depsdev_dependents_total():
    # Package-level :dependents does not exist (404); the count is per
    # version on v3alpha, read from the package's default version.
    respx.get("https://api.deps.dev/v3/systems/npm/packages/lodash").mock(
        return_value=Response(
            200,
            json={"versions": [{"versionKey": {"version": "4.17.21"}, "isDefault": True}]},
        )
    )
    respx.get(
        "https://api.deps.dev/v3alpha/systems/npm/packages/lodash/versions/4.17.21:dependents"
    ).mock(
        return_value=Response(
            200,
            json={"dependentCount": 1000, "directDependentCount": 100, "indirectDependentCount": 950},
        )
    )
    http = HttpClient()
    try:
        client = DepsDevClient(http)
        assert await client.dependents("npm", "lodash") == 1000
    finally:
        await http.aclose()


@respx.mock
async def test_depsdev_dependents_does_not_sum_overlapping_parts():
    # direct and indirect dependents overlap (a package can be both), so
    # summing them would inflate the count; without the total it is unknown.
    respx.get("https://api.deps.dev/v3/systems/npm/packages/foo").mock(
        return_value=Response(
            200,
            json={"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": True}]},
        )
    )
    respx.get(
        "https://api.deps.dev/v3alpha/systems/npm/packages/foo/versions/1.0.0:dependents"
    ).mock(
        return_value=Response(200, json={"directDependentCount": 5, "indirectDependentCount": 7})
    )
    http = HttpClient()
    try:
        client = DepsDevClient(http)
        assert await client.dependents("npm", "foo") is None
    finally:
        await http.aclose()


@respx.mock
async def test_depsdev_repo_url_finds_github():
    respx.get("https://api.deps.dev/v3/systems/npm/packages/foo").mock(
        return_value=Response(
            200,
            json={"versions": [{"versionKey": {"version": "1.0.0"}}]},
        )
    )
    respx.get("https://api.deps.dev/v3/systems/npm/packages/foo/versions/1.0.0").mock(
        return_value=Response(
            200,
            json={"links": [{"label": "SOURCE_REPO", "url": "https://github.com/foo/foo"}]},
        )
    )
    http = HttpClient()
    try:
        client = DepsDevClient(http)
        assert await client.repo_url("npm", "foo") == "https://github.com/foo/foo"
    finally:
        await http.aclose()


# ---------- github stars ----------


@respx.mock
async def test_stars_for_repo_url():
    respx.get("https://api.github.com/repos/foo/bar").mock(
        return_value=Response(200, json={"stargazers_count": 12345})
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        assert await client.stars_for_repo_url("https://github.com/foo/bar") == 12345
    finally:
        await http.aclose()


async def test_stars_with_non_github_url_returns_none():
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        assert await client.stars_for_repo_url("https://gitlab.com/foo/bar") is None
        assert await client.stars_for_repo_url("") is None
    finally:
        await http.aclose()


@respx.mock
async def test_stars_404_returns_none():
    respx.get("https://api.github.com/repos/foo/missing").mock(
        return_value=Response(404)
    )
    http = HttpClient()
    try:
        client = GithubStarsClient(http, token="")
        assert await client.stars_for_repo_url("https://github.com/foo/missing") is None
    finally:
        await http.aclose()
