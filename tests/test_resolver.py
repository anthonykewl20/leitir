"""Unit tests for the package resolver contracts (ADR-001 P4)."""

from __future__ import annotations

import io
import json

import pytest

from leitir.resolver import (
    CratesResolver,
    Ecosystem,
    GoResolver,
    GitHubTagResolver,
    MultiResolver,
    PackageRef,
    PackageResolver,
    PyPIResolver,
    ResolutionError,
    ResolvedPackage,
)
from leitir.search import RepoScope

SHA = "a" * 40


class TestPackageRef:
    def test_valid_pypi_ref(self):
        ref = PackageRef(Ecosystem.PYPI, "requests", "2.28.1")
        assert ref.ecosystem is Ecosystem.PYPI
        assert ref.name == "requests"
        assert ref.version == "2.28.1"

    def test_valid_crates_ref(self):
        ref = PackageRef(Ecosystem.CRATES, "serde", "1.0.152")
        assert ref.ecosystem is Ecosystem.CRATES

    def test_valid_go_ref(self):
        ref = PackageRef(Ecosystem.GO, "github.com/stretchr/testify", "v1.8.1")
        assert ref.ecosystem is Ecosystem.GO

    def test_go_requires_module_path(self):
        with pytest.raises(ValueError, match="module path"):
            PackageRef(Ecosystem.GO, "testify", "v1.8.1")

    def test_empty_name_rejected(self):
        with pytest.raises(ValueError):
            PackageRef(Ecosystem.PYPI, "", "1.0")

    def test_empty_version_rejected(self):
        with pytest.raises(ValueError):
            PackageRef(Ecosystem.PYPI, "requests", "")

    def test_bad_ecosystem_rejected(self):
        with pytest.raises(TypeError):
            PackageRef("npm", "express", "4.0.0")


class TestResolvedPackage:
    def test_valid(self):
        ref = PackageRef(Ecosystem.PYPI, "requests", "2.28.1")
        scope = RepoScope("psf/requests", SHA)
        resolved = ResolvedPackage(
            ref=ref,
            scope=scope,
            tag="v2.28.1",
            registry_url="https://pypi.org/project/requests/2.28.1/",
        )
        assert resolved.scope.slug == "psf/requests"
        assert resolved.tag == "v2.28.1"

    def test_empty_tag_rejected(self):
        ref = PackageRef(Ecosystem.PYPI, "requests", "2.28.1")
        scope = RepoScope("psf/requests", SHA)
        with pytest.raises(ValueError):
            ResolvedPackage(ref=ref, scope=scope, tag="", registry_url="https://x.com")

    def test_non_https_url_rejected(self):
        ref = PackageRef(Ecosystem.PYPI, "requests", "2.28.1")
        scope = RepoScope("psf/requests", SHA)
        with pytest.raises(ValueError):
            ResolvedPackage(
                ref=ref, scope=scope, tag="v1", registry_url="http://x.com"
            )


class TestResolverProtocol:
    def test_multi_resolver_satisfies_protocol(self):
        tag_resolver = GitHubTagResolver()
        multi = MultiResolver(
            pypi=PyPIResolver(tag_resolver),
            crates=CratesResolver(tag_resolver),
            go=GoResolver(tag_resolver),
        )
        assert isinstance(multi, PackageResolver)

    def test_multi_resolver_rejects_unknown_ecosystem(self):
        tag_resolver = GitHubTagResolver()
        multi = MultiResolver(
            pypi=PyPIResolver(tag_resolver),
            crates=CratesResolver(tag_resolver),
            go=GoResolver(tag_resolver),
        )
        ref = PackageRef(Ecosystem.PYPI, "requests", "2.28.1")
        multi._resolvers = {}
        with pytest.raises(ResolutionError):
            multi.resolve(ref)


class TestEcosystemEnum:
    def test_values(self):
        assert Ecosystem.PYPI.value == "pypi"
        assert Ecosystem.CRATES.value == "crates"
        assert Ecosystem.GO.value == "go"

    def test_from_string(self):
        assert Ecosystem("pypi") is Ecosystem.PYPI


@pytest.mark.parametrize(
    ("resolver_factory", "environment", "payload", "expected"),
    [
        (
            lambda tags: PyPIResolver(tags),
            {"PYPI_TOKEN": "pypi-secret"},
            {"info": {"version": "1.0"}},
            "Bearer pypi-secret",
        ),
        (
            lambda tags: PyPIResolver(tags),
            {"PIP_TOKEN": "pip-secret"},
            {"info": {"version": "1.0"}},
            "Bearer pip-secret",
        ),
        (
            lambda tags: CratesResolver(tags),
            {"CARGO_TOKEN": "cargo-secret"},
            {"crate": {"max_version": "1.0"}},
            "Bearer cargo-secret",
        ),
    ],
)
def test_registry_metadata_uses_optional_credentials(
    monkeypatch, resolver_factory, environment, payload, expected
):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(json.dumps(payload).encode())

    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert resolver_factory(GitHubTagResolver()).latest_version("demo") == "1.0"
    assert captured["Authorization"] == expected
