"""Unit tests for the package resolver contracts (ADR-001 P4)."""

from __future__ import annotations

import io
import json
import os

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
    TagAbsentError,
    resolve_corpus_spec,
)
from leitir.search import RepoScope
from leitir.spec import parse_corpus_spec

SHA = "a" * 40


@pytest.mark.parametrize(
    ("prefix", "owner", "scope_name"),
    [
        ("github", "owner", "owner/repo"),
        ("gitlab", "owner", "owner/repo"),
        ("bitbucket", "owner", "owner/repo"),
        ("codeberg", "owner", "owner/repo"),
        ("sourcehut", "~owner", "owner/repo"),
    ],
)
def test_full_sha_bypasses_ref_resolvers_for_every_git_host(
    tmp_path, prefix, owner, scope_name
):
    class NoNetwork:
        def __getattr__(self, name):
            raise AssertionError(f"SHA resolution must not call {name}")

    parsed = parse_corpus_spec(f"{prefix}:{owner}/repo@{SHA.upper()}")

    scope, tag, version_source, detection_source = resolve_corpus_spec(
        parsed, NoNetwork(), NoNetwork(), tmp_path
    )

    assert scope == RepoScope(scope_name, SHA)
    assert (tag, version_source, detection_source) == (None, None, None)


class RecordingRepoResolver:
    def __init__(
        self,
        *,
        missing: set[tuple[str, str]] | None = None,
        failures: dict[tuple[str, str], ResolutionError] | None = None,
    ):
        self.calls = []
        self.missing = missing or set()
        self.failures = failures or {}

    def resolve_tag_to_sha(self, slug, tag):
        self.calls.append(("tag", slug, tag))
        if (slug, tag) in self.failures:
            raise self.failures[(slug, tag)]
        if (slug, tag) in self.missing:
            raise TagAbsentError("not found")
        return SHA

    def resolve_commit_to_sha(self, slug, ref):
        self.calls.append(("commit", slug, ref))
        if (slug, ref) in self.failures:
            raise self.failures[(slug, ref)]
        if (slug, ref) in self.missing:
            raise TagAbsentError("not found")
        return SHA


def _go_resolver(monkeypatch, module, host_resolvers):
    requested = []

    def fake_urlopen(request, timeout):
        requested.append(request.full_url)
        return io.BytesIO(json.dumps({"Version": "v1.2.3"}).encode())

    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    github = host_resolvers.get("github.com", RecordingRepoResolver())
    resolver = GoResolver(
        github,
        base_url="https://proxy.test",
        repository_resolvers=host_resolvers,
    )
    result = resolver.resolve(PackageRef(Ecosystem.GO, module, "v1.2.3"))
    assert requested == [f"https://proxy.test/{module}/@v/v1.2.3.info"]
    return result


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


class TestGoMultiHostResolution:
    @pytest.mark.parametrize(
        ("module", "host", "slug", "subpath"),
        [
            ("github.com/owner/repo", "github.com", "owner/repo", None),
            ("gitlab.com/group/subgroup/repo", "gitlab.com", "group/subgroup/repo", None),
            ("bitbucket.org/owner/repo", "bitbucket.org", "owner/repo", None),
            ("golang.org/x/sync", "github.com", "golang/sync", None),
        ],
    )
    def test_dispatches_module_to_repository_host(
        self, monkeypatch, module, host, slug, subpath
    ):
        selected = RecordingRepoResolver()
        result = _go_resolver(monkeypatch, module, {host: selected})
        assert result.host == host
        assert result.scope == RepoScope(slug, SHA)
        assert result.subpath == subpath
        assert result.ref.name == module
        assert selected.calls == [("tag", slug, "v1.2.3")]

    def test_gitlab_submodule_falls_back_without_confusing_subgroups(self, monkeypatch):
        selected = RecordingRepoResolver(
            missing={("group/subgroup/repo/tools", "v1.2.3")}
        )
        result = _go_resolver(
            monkeypatch,
            "gitlab.com/group/subgroup/repo/tools",
            {"gitlab.com": selected},
        )
        assert result.scope.slug == "group/subgroup/repo"
        assert result.subpath == "tools"
        assert result.tag == "tools/v1.2.3"

    def test_gitlab_submodule_does_not_fallback_after_non_absence_failure(
        self, monkeypatch
    ):
        failure = ResolutionError("HTTP 503 after retries")
        selected = RecordingRepoResolver(
            failures={
                ("group/subgroup/repo/tools", "v1.2.3"): failure,
            }
        )

        with pytest.raises(ResolutionError) as error:
            _go_resolver(
                monkeypatch,
                "gitlab.com/group/subgroup/repo/tools",
                {"gitlab.com": selected},
            )

        assert error.value is failure
        assert selected.calls == [
            ("tag", "group/subgroup/repo/tools", "v1.2.3")
        ]

    @pytest.mark.parametrize(
        ("module", "host", "slug"),
        [
            ("github.com/owner/repo", "github.com", "owner/repo"),
            ("gitlab.com/group/subgroup/repo", "gitlab.com", "group/subgroup/repo"),
            ("bitbucket.org/owner/repo", "bitbucket.org", "owner/repo"),
        ],
    )
    def test_pseudo_version_expands_commit_on_selected_host(
        self, monkeypatch, module, host, slug
    ):
        selected = RecordingRepoResolver()

        def fake_urlopen(request, timeout):
            return io.BytesIO(b"{}")

        monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
        version = "v0.0.0-20240102030405-abcdef123456"
        resolver = GoResolver(
            selected,
            base_url="https://proxy.test",
            repository_resolvers={host: selected},
        )
        result = resolver.resolve(PackageRef(Ecosystem.GO, module, version))
        assert result.scope == RepoScope(slug, SHA)
        assert selected.calls == [("commit", slug, "abcdef123456")]

    def test_pseudo_version_advances_after_absent_repository_candidate(
        self, monkeypatch
    ):
        first = "group/repo/submodule"
        second = "group/repo"
        selected = RecordingRepoResolver(
            failures={(first, "abcdef123456"): TagAbsentError("missing")}
        )

        version = "v0.0.0-20240102030405-abcdef123456"
        monkeypatch.setattr(
            "leitir._http.safe_urlopen", lambda _request, timeout: io.BytesIO(b"{}")
        )
        resolver = GoResolver(
            selected,
            base_url="https://proxy.test",
            repository_resolvers={"gitlab.com": selected},
        )
        result = resolver.resolve(
            PackageRef(Ecosystem.GO, "gitlab.com/group/repo/submodule", version)
        )

        assert result.scope == RepoScope(second, SHA)
        assert result.subpath == "submodule"
        assert selected.calls == [
            ("commit", first, "abcdef123456"),
            ("commit", second, "abcdef123456"),
        ]

    @pytest.mark.parametrize("module", ["gopkg.in/yaml.v3", "gonum.org/v1/gonum"])
    def test_unsupported_vanity_host_fails_before_network(self, monkeypatch, module):
        def unexpected(*args, **kwargs):
            raise AssertionError("network must not be used")

        monkeypatch.setattr("leitir._http.safe_urlopen", unexpected)
        resolver = GoResolver(RecordingRepoResolver())
        with pytest.raises(ResolutionError, match="unsupported Go module host"):
            resolver.resolve(PackageRef(Ecosystem.GO, module, "v1.2.3"))


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)
def test_live_go_golang_x_module_resolves_to_pinned_github_commit():
    resolver = GoResolver(GitHubTagResolver())
    result = resolver.resolve(PackageRef(Ecosystem.GO, "golang.org/x/sync", "v0.7.0"))
    assert result.host == "github.com"
    assert result.scope == RepoScope(
        "golang/sync", "14be23e5b48bec28285f8a694875175ecacfddb3"
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


class ScriptedTagResolver:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.calls = []

    def resolve_tag_to_sha(self, slug, tag):
        self.calls.append((slug, tag))
        outcome = self.outcomes[tag]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.mark.parametrize(
    ("resolver_factory", "candidates"),
    [
        (lambda tags: PyPIResolver(tags), ("v1.2.3", "1.2.3")),
        (
            lambda tags: CratesResolver(tags),
            ("demo-1.2.3", "v1.2.3", "1.2.3"),
        ),
    ],
)
class TestCandidateTagFailures:
    def _resolve(self, resolver, candidates):
        if isinstance(resolver, CratesResolver):
            return resolver._resolve_first_tag("acme/demo", "demo", "1.2.3")
        return resolver._resolve_first_tag("acme/demo", "1.2.3")

    def test_non_absence_failure_does_not_try_fallback(
        self, resolver_factory, candidates
    ):
        failure = ResolutionError("HTTP 503 after retries")
        tags = ScriptedTagResolver(
            {candidates[0]: failure, **{tag: SHA for tag in candidates[1:]}}
        )

        with pytest.raises(ResolutionError) as error:
            self._resolve(resolver_factory(tags), candidates)

        assert error.value is failure
        assert tags.calls == [("acme/demo", candidates[0])]

    def test_absent_preferred_tag_uses_fallback(self, resolver_factory, candidates):
        tags = ScriptedTagResolver(
            {candidates[0]: TagAbsentError("HTTP 404"), candidates[1]: SHA}
        )

        assert self._resolve(resolver_factory(tags), candidates) == (candidates[1], SHA)
        assert tags.calls == [
            ("acme/demo", candidates[0]),
            ("acme/demo", candidates[1]),
        ]

    def test_all_absent_tags_raise_last_error(self, resolver_factory, candidates):
        failures = {tag: TagAbsentError(f"missing {tag}") for tag in candidates}
        tags = ScriptedTagResolver(failures)

        with pytest.raises(TagAbsentError) as error:
            self._resolve(resolver_factory(tags), candidates)

        assert error.value is failures[candidates[-1]]
        assert tags.calls == [("acme/demo", tag) for tag in candidates]


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
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert resolver_factory(GitHubTagResolver()).latest_version("demo") == "1.0"
    assert captured["Authorization"] == expected
