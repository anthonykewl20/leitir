"""Opt-in live gate for the package resolver (ADR-001 P4).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Verifies the pinned fixture data
still matches reality: registry APIs return the expected GitHub repos, and
GitHub tags still resolve to the pinned commit SHAs.
"""

from __future__ import annotations

import os

import fixtures_resolver as fx
import pytest

from leitir.resolver import (
    CratesResolver,
    Ecosystem,
    GitHubTagResolver,
    GoResolver,
    PackageRef,
    PyPIResolver,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
    )
]


def _token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def _tag_resolver() -> GitHubTagResolver:
    return GitHubTagResolver(token=_token())


def test_live_pypi_tag_resolves_to_pinned_commit():
    sha = _tag_resolver().resolve_tag_to_sha(fx.PYPI_SLUG, fx.PYPI_TAG)
    assert sha == fx.PYPI_COMMIT_SHA


def test_live_crates_tag_resolves_to_pinned_commit():
    sha = _tag_resolver().resolve_tag_to_sha(fx.CRATES_SLUG, fx.CRATES_TAG)
    assert sha == fx.CRATES_COMMIT_SHA


def test_live_go_tag_resolves_to_pinned_commit():
    sha = _tag_resolver().resolve_tag_to_sha(fx.GO_SLUG, fx.GO_TAG)
    assert sha == fx.GO_COMMIT_SHA


def test_live_pypi_full_resolution():
    resolver = PyPIResolver(tag_resolver=_tag_resolver())
    ref = PackageRef(Ecosystem.PYPI, fx.PYPI_NAME, fx.PYPI_VERSION)
    result = resolver.resolve(ref)
    assert result.scope.slug == fx.PYPI_SLUG
    assert result.scope.commit_sha == fx.PYPI_COMMIT_SHA


def test_live_crates_full_resolution():
    resolver = CratesResolver(tag_resolver=_tag_resolver())
    ref = PackageRef(Ecosystem.CRATES, fx.CRATES_NAME, fx.CRATES_VERSION)
    result = resolver.resolve(ref)
    assert result.scope.slug == fx.CRATES_SLUG
    assert result.scope.commit_sha == fx.CRATES_COMMIT_SHA


def test_live_go_full_resolution():
    resolver = GoResolver(tag_resolver=_tag_resolver())
    ref = PackageRef(Ecosystem.GO, fx.GO_MODULE, fx.GO_VERSION)
    result = resolver.resolve(ref)
    assert result.scope.slug == fx.GO_SLUG
    assert result.scope.commit_sha == fx.GO_COMMIT_SHA


def test_live_corrupted_tag_raises():
    from leitir.resolver import ResolutionError

    with pytest.raises(ResolutionError):
        _tag_resolver().resolve_tag_to_sha(fx.PYPI_SLUG, "v99.99.99")
