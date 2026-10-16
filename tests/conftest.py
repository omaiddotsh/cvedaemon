"""Shared pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture
def stub_enrich(monkeypatch):
    """Stub enrichment HTTP so daemon-level tests don't hit real registries / deps.dev."""
    from sev1daemon.enrich import depsdev as dd
    from sev1daemon.enrich import github_stars as gs
    from sev1daemon.enrich import registry as reg

    async def _none(self, *a, **kw):
        return None

    monkeypatch.setattr(reg.RegistryClient, "downloads", _none)
    monkeypatch.setattr(dd.DepsDevClient, "dependents", _none)
    monkeypatch.setattr(dd.DepsDevClient, "repo_url", _none)
    monkeypatch.setattr(gs.GithubStarsClient, "stars_for_repo_url", _none)
