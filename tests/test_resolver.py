"""Unit tests for the package resolver contracts (ADR-001 P4)."""

from __future__ import annotations

import io
import json
import os
from dataclasses import replace

import _http_server as _hs
import pytest

from leitir.resolver import (
    CratesResolver,
    DegradedProvenanceError,
    Ecosystem,
    GitHubTagResolver,
    GoResolver,
    MultiResolver,
    NpmResolver,
    PackageRef,
    PackageResolver,
    PyPIResolver,
    ResolutionError,
    ResolvedPackage,
    TagAbsentError,
    TagLookupUnavailableError,
    _degraded_reason,
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

    def test_non_ascii_name_rejected_typed(self):
        # Audit 2026-08-23 P3: emoji/unicode specs must fail validation here,
        # not as a bare ``'ascii' codec can't encode`` error at request time.
        with pytest.raises(ValueError, match="printable ASCII"):
            PackageRef(Ecosystem.PYPI, "flask\U0001F389", "1.0")

    def test_non_ascii_version_rejected_typed(self):
        with pytest.raises(ValueError, match="printable ASCII"):
            PackageRef(Ecosystem.NPM, "express", "4.0\u00e9")

    def test_non_pypi_grammar_name_rejected(self):
        with pytest.raises(ValueError, match="invalid pypi package name"):
            PackageRef(Ecosystem.PYPI, "-leading-sep", "1.0")

    def test_non_crates_grammar_name_rejected(self):
        with pytest.raises(ValueError, match="invalid crates package name"):
            PackageRef(Ecosystem.CRATES, "-leading-dash", "1.0")


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

    def test_registry_timestamp_extractors_are_timezone_aware(self):
        timestamp = "2026-08-08T12:34:56Z"

        assert PyPIResolver._published_at(
            {"urls": [{"upload_time_iso_8601": timestamp}]}
        ) == timestamp
        assert NpmResolver._published_at(
            {"time": {"1.0.0": timestamp}}, "1.0.0"
        ) == timestamp
        assert CratesResolver._published_at(
            {"version": {"created_at": timestamp}}, "1.0.0"
        ) == timestamp

    def test_malformed_registry_timestamp_is_not_produced(self):
        assert PyPIResolver._published_at(
            {"urls": [{"upload_time_iso_8601": "2026-08-08T12:34:56"}]}
        ) is None

    @pytest.mark.parametrize(
        ("host", "go_module_zip", "go_proxy_url", "message"),
        [
            ("unsupported.example", False, None, "unsupported repository host"),
            ("github.com", True, None, "provenance must use"),
            ("go-module-zip", True, "ftp://proxy.example", "requires an HTTPS"),
            ("github.com", False, "https://proxy.example", "must not have"),
        ],
    )
    def test_go_zip_provenance_contract_rejects_inconsistent_fields(
        self, host, go_module_zip, go_proxy_url, message
    ):
        with pytest.raises(ValueError, match=message):
            ResolvedPackage(
                PackageRef(Ecosystem.GO, "example.com/demo", "v1.0.0"),
                RepoScope("example/demo", SHA),
                "v1.0.0",
                "https://pkg.go.dev/example.com/demo@v1.0.0",
                host=host,
                go_module_zip=go_module_zip,
                go_proxy_url=go_proxy_url,
            )


def test_github_commit_timestamp_comes_from_committer_metadata(monkeypatch):
    timestamp = "2026-08-08T12:34:56Z"

    def fake_urlopen(request, timeout):
        assert request.full_url == f"https://api.github.com/repos/acme/demo/commits/{SHA}"
        return io.BytesIO(
            json.dumps({"commit": {"committer": {"date": timestamp}}}).encode()
        )

    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)

    assert GitHubTagResolver().published_at_for_commit("acme/demo", SHA) == timestamp


class TestNetworkBaseUrlValidation:
    @pytest.mark.parametrize(
        "base_url",
        [
            "ftp://registry.example",
            "https:///missing-host",
            "https://user:password@registry.example",
            "https://registry.example/path#opaque-secret",
        ],
    )
    def test_npm_rejects_unsafe_configured_base_urls(self, base_url):
        with pytest.raises(ValueError, match="network base URL"):
            NpmResolver(RecordingRepoResolver(), base_url=base_url)

    def test_plaintext_base_url_with_credentials_is_rejected(self, monkeypatch):
        monkeypatch.setenv("NPM_TOKEN", "sentinel-registry-token")

        with pytest.raises(ValueError, match="must use HTTPS"):
            NpmResolver(
                RecordingRepoResolver(),
                base_url="http://registry.npmjs.org",
            )

    def test_plaintext_base_url_with_explicit_token_is_rejected(self):
        with pytest.raises(ValueError, match="must use HTTPS"):
            GitHubTagResolver(
                token="sentinel-explicit-token",
                base_url="http://github-mirror.example",
            )

    def test_anonymous_plaintext_base_url_is_allowed(self):
        resolver = NpmResolver(
            RecordingRepoResolver(),
            base_url="http://127.0.0.1:43210",
        )

        assert resolver._base_url == "http://127.0.0.1:43210"


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
    def test_vanity_host_uses_authenticated_proxy_zip_source(self, monkeypatch, module):
        result = _go_resolver(monkeypatch, module, {})

        assert result.host == "go-module-zip"
        assert result.go_module_zip is True
        assert result.go_proxy_url == "https://proxy.test"

    def test_github_major_suffix_is_not_a_subpath(self, monkeypatch):
        result = _go_resolver(
            monkeypatch,
            "github.com/lxc/incus/v6",
            {"github.com": RecordingRepoResolver()},
        )

        assert result.subpath is None

    def test_github_monorepo_subpath_is_preserved(self, monkeypatch):
        result = _go_resolver(
            monkeypatch,
            "github.com/owner/repo/sub",
            {"github.com": RecordingRepoResolver()},
        )

        assert result.subpath == "sub"


@pytest.mark.live
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


class TestDegradedClassificationRealTransport:
    """Issue #248: the *real* ``GitHubTagResolver`` transport must raise
    errors that ``_degraded_reason`` classifies as fallback-eligible.

    These tests deliberately avoid ``ScriptedTagResolver``: the original
    bug — bare, envelope-less ``ResolutionError``s on transport failure —
    was invisible to every fake-based test while both ADR-0023 headline
    scenarios (403 throttle, outage) failed closed in production."""

    @pytest.fixture(autouse=True)
    def _reset_rate_limit_notices(self):
        # The 403-with-headers scenarios touch the process-global notice
        # registry keyed by host; reset so notice-asserting tests in
        # test_http.py can never be affected by ordering (reviewer-qwen P3).
        from leitir._http import reset_rate_limit_notices

        reset_rate_limit_notices()
        yield
        reset_rate_limit_notices()

    @staticmethod
    def _real_tag_resolver(base_url: str) -> GitHubTagResolver:
        return GitHubTagResolver(
            base_url=base_url,
            allow_insecure_http_for_tests=True,
            max_attempts=1,
            sleeper=lambda _seconds: None,
        )

    def test_connection_refused_classifies_as_unavailable(self):
        resolver = self._real_tag_resolver("http://127.0.0.1:9")
        with pytest.raises(TagLookupUnavailableError) as excinfo:
            resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
        message = str(excinfo.value)
        assert "API call failed:" in message
        assert "not found" not in message  # transport failure, not absence
        assert _degraded_reason(excinfo.value) is not None

    def test_http_403_rate_limit_classifies_as_unavailable(self):
        with _hs.scripted_server(
            [(403, {"X-RateLimit-Remaining": "0", "Retry-After": "0"}, b"")]
        ) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(TagLookupUnavailableError) as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert "API call failed:" in str(excinfo.value)
            assert _degraded_reason(excinfo.value) is not None

    def test_http_404_stays_tag_absent_and_fail_closed(self):
        with _hs.scripted_server([(404, {}, b"")]) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(TagAbsentError) as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert _degraded_reason(excinfo.value) is None

    @pytest.mark.parametrize("status", [401, 451, 422])
    def test_permanent_client_error_stays_fail_closed(self, status):
        # reviewer-hy3 round 2 (issue #248): a fatal 4xx — bad credentials,
        # DMCA takedown, malformed query — is a configuration/access fact,
        # not an outage. It must NOT become fallback-eligible degraded
        # provenance; an expired token degrading forever would hide the
        # configuration error entirely.
        with _hs.scripted_server([(status, {}, b"")]) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(ResolutionError) as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert not isinstance(excinfo.value, TagLookupUnavailableError)
            assert _degraded_reason(excinfo.value) is None
            assert "API call failed:" not in str(excinfo.value)

    def test_plain_403_without_rate_limit_headers_stays_fail_closed(self):
        # GitHub permission denial (SAML/private repo/IP policy) sends 403
        # with no rate-limit headers: FATAL per _http.classify, so it fails
        # closed instead of degrading. Eligibility follows the same line
        # retry semantics draw (reviewer-hy3 round 2).
        with _hs.scripted_server([(403, {}, b"")]) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(ResolutionError) as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert not isinstance(excinfo.value, TagLookupUnavailableError)
            assert _degraded_reason(excinfo.value) is None

    def test_http_503_outage_classifies_as_unavailable(self):
        with _hs.scripted_server([(503, {}, b"")]) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(TagLookupUnavailableError) as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert "API call failed:" in str(excinfo.value)
            assert _degraded_reason(excinfo.value) is not None

    @pytest.mark.parametrize(
        ("status", "body"),
        [(200, b"<html>not json</html>"), (200, b"{}"), (200, b"[]")],
    )
    def test_malformed_200_body_wraps_as_typed_error(self, status, body):
        # Parity with _HostedRepoResolver._get_json: malformed forge data is
        # a provenance fact (fail-closed ResolutionError), never a raw
        # JSONDecodeError/KeyError leak and never fallback-eligible
        # (reviewer round 2, both reviewers).
        with _hs.scripted_server([(status, {"Content-Type": "application/json"}, body)]) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(ResolutionError, match="malformed") as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert not isinstance(excinfo.value, TagLookupUnavailableError)
            assert _degraded_reason(excinfo.value) is None

    def test_dereference_malformed_200_wraps_typed(self):
        # reviewer-qwen round 2: pin the annotated-tag dereference path's
        # malformed-body wrap (ref lookup 200 + dereference garbage), which
        # probe coverage held but no in-suite test pinned.
        with _hs.scripted_server(
            [
                (
                    200,
                    {"Content-Type": "application/json"},
                    _hs.json_body({"object": {"type": "tag", "sha": "d" * 40}}),
                ),
                (200, {"Content-Type": "application/json"}, b"<html>nope</html>"),
            ]
        ) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(ResolutionError, match="malformed") as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert not isinstance(excinfo.value, TagLookupUnavailableError)
            assert _degraded_reason(excinfo.value) is None

    def test_dereference_fatal_401_stays_fail_closed(self):
        # reviewer-qwen round 2: pin the dereference path's FATAL branch —
        # a 401 while dereferencing must not become degraded provenance.
        with _hs.scripted_server(
            [
                (
                    200,
                    {"Content-Type": "application/json"},
                    _hs.json_body({"object": {"type": "tag", "sha": "d" * 40}}),
                ),
                (401, {}, b""),
            ]
        ) as server:
            resolver = self._real_tag_resolver(server.base_url)
            with pytest.raises(ResolutionError, match="dereferencing") as excinfo:
                resolver.resolve_tag_to_sha("pallets/flask", "v3.0.3")
            assert not isinstance(excinfo.value, TagLookupUnavailableError)
            assert _degraded_reason(excinfo.value) is None
            assert "API call failed:" not in str(excinfo.value)

    def test_pypi_resolution_degrades_over_real_transport(self):
        # Both sides drive the REAL transport through a real local server:
        # request 1 serves PyPI metadata, request 2 is the tag lookup and
        # answers 403 rate-limited, exactly the ADR-0023 headline scenario.
        sleeps: list[float] = []
        script = [
            (
                200,
                {"Content-Type": "application/json"},
                _hs.json_body(TestRegistryOnlyFallback._pypi_payload()),
            ),
            (403, {"X-RateLimit-Remaining": "0", "Retry-After": "0"}, b""),
        ]
        with _hs.scripted_server(script) as server:
            tags = GitHubTagResolver(
                base_url=server.base_url,
                sleeper=sleeps.append,
                base_delay=1.0,
                max_attempts=1,
                allow_insecure_http_for_tests=True,
            )
            resolver = PyPIResolver(
                tag_resolver=tags,
                base_url=server.base_url,
                sleeper=sleeps.append,
                base_delay=1.0,
                allow_insecure_http_for_tests=True,
            )
            result = resolver.resolve(PackageRef(Ecosystem.PYPI, "demo", "1.2.3"))

        assert result.degraded_provenance is not None
        assert "unavailable" in result.degraded_provenance
        assert result.tag is None
        assert result.scope.slug == "registry/demo"
        assert result.artifact is not None
        with pytest.raises(DegradedProvenanceError, match="registry-only"):
            result.require_full_provenance()


class TestRegistryOnlyFallback:
    """Audit 2026-08-23 P1(b): throttled/down GitHub tag lookups degrade to
    a checksum-verified registry-only resolution instead of hard-failing,
    while genuinely absent tags keep failing closed."""

    @staticmethod
    def _pypi_payload():
        return {
            "info": {
                "version": "1.2.3",
                "project_url": "https://github.com/acme/demo",
                "project_urls": {"Source": "https://github.com/acme/demo"},
            },
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.example/demo-1.2.3.tar.gz",
                    "digests": {
                        "sha256": "b" * 64,
                        "md5": "0" * 32,
                    },
                    "upload_time_iso_8601": "2024-01-01T00:00:00+00:00",
                }
            ],
        }

    def _resolve_pypi(self, monkeypatch, tag_outcome, payload=None):
        payload = payload or self._pypi_payload()

        def fake_urlopen(request, timeout):
            return io.BytesIO(json.dumps(payload).encode())

        monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
        tags = ScriptedTagResolver(
            {"v1.2.3": tag_outcome, "1.2.3": tag_outcome}
        )
        return PyPIResolver(tags).resolve(PackageRef(Ecosystem.PYPI, "demo", "1.2.3")), tags

    def test_throttled_tag_lookup_degrades_to_registry_only(self, monkeypatch):
        throttle = ResolutionError(
            "github.com API call failed: HTTP 403 rate limit exceeded"
        )
        result, tags = self._resolve_pypi(monkeypatch, throttle)

        assert result.degraded_provenance is not None
        assert "unavailable" in result.degraded_provenance
        assert result.tag is None
        assert result.scope.slug == "registry/demo"
        assert len(result.scope.commit_sha) == 40
        assert result.artifact is not None
        assert result.artifact.digest == "b" * 64
        with pytest.raises(DegradedProvenanceError, match="registry-only"):
            result.require_full_provenance()

    def test_absent_tag_still_fails_closed(self, monkeypatch):
        absent = TagAbsentError("tag 'v1.2.3' not found in acme/demo: 404")
        with pytest.raises(TagAbsentError):
            self._resolve_pypi(monkeypatch, absent)

    def test_npm_throttled_tag_lookup_degrades_to_registry_only(self, monkeypatch):
        import base64

        # 64 raw bytes -> valid sha512 integrity token, as npm serves.
        digest_bytes = bytes(range(64))
        integrity = "sha512-" + base64.b64encode(digest_bytes).decode()
        payload = {
            "versions": {
                "1.0.0": {
                    "repository": {"type": "git", "url": "https://github.com/acme/demo"},
                    "dist": {
                        "tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                        "integrity": integrity,
                    },
                }
            },
            "time": {"1.0.0": "2024-01-01T00:00:00.000Z"},
        }

        def fake_urlopen(request, timeout):
            return io.BytesIO(json.dumps(payload).encode())

        monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
        throttle = ResolutionError("github.com API call failed: HTTP 503")
        tags = ScriptedTagResolver(
            {
                "demo@1.0.0": throttle,
                "v1.0.0": throttle,
                "1.0.0": throttle,
            }
        )
        result = NpmResolver(tags).resolve(PackageRef(Ecosystem.NPM, "demo", "1.0.0"))

        assert result.degraded_provenance is not None
        assert result.scope.slug == "registry/demo"
        assert len(result.scope.commit_sha) == 40
        assert result.artifact is not None
        assert result.artifact.digest == digest_bytes.hex()

    def test_fallback_scope_is_deterministic(self, monkeypatch):
        throttle = ResolutionError("github.com API call failed: HTTP 403")
        first, _ = self._resolve_pypi(monkeypatch, throttle)
        second, _ = self._resolve_pypi(monkeypatch, throttle)
        assert first.scope == second.scope

    def test_malformed_metadata_is_not_transport_and_still_fails_closed(self, monkeypatch):
        # reviewer-qwen 2026-08-23: only the transport envelope is
        # fallback-eligible; malformed forge data must keep failing closed.
        malformed = ResolutionError("github.com returned malformed metadata")
        with pytest.raises(ResolutionError, match="malformed"):
            self._resolve_pypi(monkeypatch, malformed)

    def test_scoped_npm_name_degrades_to_a_grammar_safe_slug(self, monkeypatch):
        import base64

        digest_bytes = bytes(range(64))
        integrity = "sha512-" + base64.b64encode(digest_bytes).decode()
        payload = {
            "versions": {
                "1.0.0": {
                    "repository": {"type": "git", "url": "https://github.com/babel/babel"},
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@babel/core/-/core-1.0.0.tgz",
                        "integrity": integrity,
                    },
                }
            },
            "time": {"1.0.0": "2024-01-01T00:00:00.000Z"},
        }

        def fake_urlopen(request, timeout):
            return io.BytesIO(json.dumps(payload).encode())

        monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
        throttle = ResolutionError("github.com API call failed: HTTP 503")
        tags = ScriptedTagResolver(
            {
                "@babel/core@1.0.0": throttle,
                "v1.0.0": throttle,
                "1.0.0": throttle,
            }
        )
        # Candidate tags for the scoped name include the scoped form.
        tags.outcomes["@babel/core@1.0.0"] = throttle
        tags.outcomes["babel--core@1.0.0"] = throttle
        result = NpmResolver(tags).resolve(
            PackageRef(Ecosystem.NPM, "@babel/core", "1.0.0")
        )

        assert result.degraded_provenance is not None
        assert result.scope.slug == "registry/babel--core"
        assert len(result.scope.commit_sha) == 40
        # The shelf SHA still hashes the original scoped name, so two
        # packages that flatten to the same slug never share a shelf.
        flat = NpmResolver(tags).resolve(
            PackageRef(Ecosystem.NPM, "babel--core", "1.0.0")
        )
        assert flat.scope.slug == result.scope.slug
        assert flat.scope.commit_sha != result.scope.commit_sha

    def test_no_artifact_means_no_fallback(self, monkeypatch):
        payload = {
            "info": {
                "version": "1.2.3",
                "project_url": "https://github.com/acme/demo",
            },
            "urls": [],
        }
        throttle = ResolutionError("github.com API call failed: HTTP 403")
        with pytest.raises(ResolutionError):
            self._resolve_pypi(monkeypatch, throttle, payload=payload)

    def test_degraded_result_requires_marker_scope(self):
        good = ResolvedPackage(
            ref=PackageRef(Ecosystem.PYPI, "demo", "1.2.3"),
            scope=RepoScope("acme/demo", SHA),
            tag="v1.2.3",
            registry_url="https://pypi.org/project/demo/1.2.3/",
        )
        with pytest.raises(ValueError, match="registry/"):
            replace(good, degraded_provenance="repository tag lookup unavailable")


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
            {candidates[0]: failure, **dict.fromkeys(candidates[1:], SHA)}
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
