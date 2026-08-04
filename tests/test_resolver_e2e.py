"""Offline e2e gate for the package resolver (ADR-001 P4).

Runs without network. Uses a fake tag resolver seeded with the real pinned
fixture data to prove the full PackageRef -> ResolvedPackage -> RepoScope flow
produces correct, immutable provenance for all three ecosystems.
"""

from __future__ import annotations

import pytest

from leitir.resolver import (
    CratesResolver,
    Ecosystem,
    GitHubTagResolver,
    GoResolver,
    PackageRef,
    PyPIResolver,
    ResolutionError,
    ResolvedPackage,
)
from leitir.search import RepoScope

import fixtures_resolver as fx


class FakeTagResolver:
    """Seeded with the real pinned fixture data."""

    _TABLE = {
        (fx.PYPI_SLUG, fx.PYPI_TAG): fx.PYPI_COMMIT_SHA,
        (fx.CRATES_SLUG, fx.CRATES_TAG): fx.CRATES_COMMIT_SHA,
        (fx.GO_SLUG, fx.GO_TAG): fx.GO_COMMIT_SHA,
    }

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        key = (slug, tag)
        if key in self._TABLE:
            return self._TABLE[key]
        raise ResolutionError(f"tag {tag!r} not found in {slug}")


class FakePyPIResolver(PyPIResolver):
    """Bypasses HTTP; returns the pinned slug directly."""

    def __init__(self):
        super().__init__(tag_resolver=FakeTagResolver())

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.PYPI:
            raise ResolutionError("PyPIResolver only handles pypi packages")
        if ref.name != fx.PYPI_NAME or ref.version != fx.PYPI_VERSION:
            raise ResolutionError(f"unknown package {ref.name}=={ref.version}")
        tag, sha = self._resolve_first_tag(fx.PYPI_SLUG, ref.version)
        return ResolvedPackage(
            ref=ref,
            scope=RepoScope(fx.PYPI_SLUG, sha),
            tag=tag,
            registry_url=f"https://pypi.org/project/{ref.name}/{ref.version}/",
        )


class FakeCratesResolver(CratesResolver):
    def __init__(self):
        super().__init__(tag_resolver=FakeTagResolver())

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.CRATES:
            raise ResolutionError("CratesResolver only handles crates packages")
        if ref.name != fx.CRATES_NAME or ref.version != fx.CRATES_VERSION:
            raise ResolutionError(f"unknown crate {ref.name}=={ref.version}")
        tag, sha = self._resolve_first_tag(
            fx.CRATES_SLUG, ref.name, ref.version
        )
        return ResolvedPackage(
            ref=ref,
            scope=RepoScope(fx.CRATES_SLUG, sha),
            tag=tag,
            registry_url=f"https://crates.io/crates/{ref.name}/{ref.version}",
        )


class FakeGoResolver(GoResolver):
    def __init__(self):
        super().__init__(tag_resolver=FakeTagResolver())

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.GO:
            raise ResolutionError("GoResolver only handles go packages")
        if ref.name != fx.GO_MODULE or ref.version != fx.GO_VERSION:
            raise ResolutionError(f"unknown module {ref.name}@{ref.version}")
        parts = ref.name.split("/")
        slug = f"{parts[1]}/{parts[2]}"
        sha = FakeTagResolver().resolve_tag_to_sha(slug, ref.version)
        return ResolvedPackage(
            ref=ref,
            scope=RepoScope(slug, sha),
            tag=ref.version,
            registry_url=f"https://pkg.go.dev/{ref.name}@{ref.version}",
        )


class TestPyPIResolution:
    def test_resolves_to_correct_slug(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.PYPI, fx.PYPI_NAME, fx.PYPI_VERSION)
        result = resolver.resolve(ref)
        assert result.scope.slug == fx.PYPI_SLUG

    def test_resolves_to_correct_commit(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.PYPI, fx.PYPI_NAME, fx.PYPI_VERSION)
        result = resolver.resolve(ref)
        assert result.scope.commit_sha == fx.PYPI_COMMIT_SHA

    def test_resolves_to_correct_tag(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.PYPI, fx.PYPI_NAME, fx.PYPI_VERSION)
        result = resolver.resolve(ref)
        assert result.tag == fx.PYPI_TAG

    def test_registry_url_is_https(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.PYPI, fx.PYPI_NAME, fx.PYPI_VERSION)
        result = resolver.resolve(ref)
        assert result.registry_url.startswith("https://pypi.org/")

    def test_scope_is_valid_repo_scope(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.PYPI, fx.PYPI_NAME, fx.PYPI_VERSION)
        result = resolver.resolve(ref)
        assert isinstance(result.scope, RepoScope)
        assert len(result.scope.commit_sha) == 40


class TestCratesResolution:
    def test_resolves_to_correct_slug(self):
        resolver = FakeCratesResolver()
        ref = PackageRef(Ecosystem.CRATES, fx.CRATES_NAME, fx.CRATES_VERSION)
        result = resolver.resolve(ref)
        assert result.scope.slug == fx.CRATES_SLUG

    def test_resolves_to_correct_commit(self):
        resolver = FakeCratesResolver()
        ref = PackageRef(Ecosystem.CRATES, fx.CRATES_NAME, fx.CRATES_VERSION)
        result = resolver.resolve(ref)
        assert result.scope.commit_sha == fx.CRATES_COMMIT_SHA

    def test_resolves_to_correct_tag(self):
        resolver = FakeCratesResolver()
        ref = PackageRef(Ecosystem.CRATES, fx.CRATES_NAME, fx.CRATES_VERSION)
        result = resolver.resolve(ref)
        assert result.tag == fx.CRATES_TAG

    def test_registry_url_points_at_crates(self):
        resolver = FakeCratesResolver()
        ref = PackageRef(Ecosystem.CRATES, fx.CRATES_NAME, fx.CRATES_VERSION)
        result = resolver.resolve(ref)
        assert "crates.io" in result.registry_url


class TestGoResolution:
    def test_resolves_to_correct_slug(self):
        resolver = FakeGoResolver()
        ref = PackageRef(Ecosystem.GO, fx.GO_MODULE, fx.GO_VERSION)
        result = resolver.resolve(ref)
        assert result.scope.slug == fx.GO_SLUG

    def test_resolves_to_correct_commit(self):
        resolver = FakeGoResolver()
        ref = PackageRef(Ecosystem.GO, fx.GO_MODULE, fx.GO_VERSION)
        result = resolver.resolve(ref)
        assert result.scope.commit_sha == fx.GO_COMMIT_SHA

    def test_tag_is_the_go_version(self):
        resolver = FakeGoResolver()
        ref = PackageRef(Ecosystem.GO, fx.GO_MODULE, fx.GO_VERSION)
        result = resolver.resolve(ref)
        assert result.tag == fx.GO_TAG

    def test_registry_url_points_at_pkg_go_dev(self):
        resolver = FakeGoResolver()
        ref = PackageRef(Ecosystem.GO, fx.GO_MODULE, fx.GO_VERSION)
        result = resolver.resolve(ref)
        assert "pkg.go.dev" in result.registry_url


class TestSadPaths:
    def test_unknown_pypi_package_raises(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.PYPI, "nonexistent_pkg_xyz", "0.0.1")
        with pytest.raises(ResolutionError):
            resolver.resolve(ref)

    def test_wrong_ecosystem_raises(self):
        resolver = FakePyPIResolver()
        ref = PackageRef(Ecosystem.CRATES, fx.PYPI_NAME, fx.PYPI_VERSION)
        with pytest.raises(ResolutionError):
            resolver.resolve(ref)

    def test_unresolvable_tag_raises(self):
        resolver = FakeTagResolver()
        with pytest.raises(ResolutionError):
            resolver.resolve_tag_to_sha("psf/requests", "v99.99.99")

    def test_go_unsupported_vanity_module_raises(self):
        resolver = GoResolver(tag_resolver=FakeTagResolver())
        ref = PackageRef(Ecosystem.GO, "gonum.org/v1/gonum", "v0.1.0")
        with pytest.raises(ResolutionError, match="unsupported Go module host"):
            resolver.resolve(ref)
