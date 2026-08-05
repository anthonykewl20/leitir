"""Real, iterative resolver retry tests against a live local HTTP server.

Drives ``GitHubTagResolver``, ``PyPIResolver``, ``CratesResolver``, and
``GoResolver`` through real sockets. Registry and GitHub-tag endpoints are both
pointed at the same local server with a combined scripted sequence. Each
scenario is looped to prove determinism under sustained use.
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
    TagAbsentError,
)

import _http_server as hs

SHA = "c" * 40
TAG_SHA = "d" * 40
SLUG = "python/cpython"
ITERATIONS = 8


def _tag_resolver(base_url, sleeper):
    return GitHubTagResolver(base_url=base_url, sleeper=sleeper, base_delay=1.0)


def _tag_ref_commit() -> dict:
    return {"object": {"type": "commit", "sha": SHA}}


def _tag_ref_annotated() -> dict:
    return {"object": {"type": "tag", "sha": TAG_SHA}}


def _tag_deref_commit() -> dict:
    return {"object": {"type": "commit", "sha": SHA}}


class TestGitHubTagResolverReal:
    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_502_retried_then_commit_sha(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_commit())),
        ]) as h:
            r = _tag_resolver(h.base_url, sleeps.append)
            assert r.resolve_tag_to_sha(SLUG, "v3.11.0") == SHA
        assert sleeps == [1.0, 2.0]
        assert h.state.served_count == 3

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_404_fatal(self, iteration):
        sleeps = []
        with hs.scripted_server([(404, {}, b"")]) as h:
            r = _tag_resolver(h.base_url, sleeps.append)
            with pytest.raises(TagAbsentError, match="HTTP 404"):
                r.resolve_tag_to_sha(SLUG, "v9.9.9")
        assert sleeps == []
        assert h.state.served_count == 1

    def test_exhausted_503_is_not_tag_absence(self):
        sleeps = []
        with hs.scripted_server([(503, {}, b"")] * 4) as h:
            r = _tag_resolver(h.base_url, sleeps.append)
            with pytest.raises(ResolutionError, match="HTTP 503") as error:
                r.resolve_tag_to_sha(SLUG, "v3.11.0")
        assert not isinstance(error.value, TagAbsentError)
        assert h.state.served_count == 4

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_annotated_tag_dereferences_via_second_call(self, iteration):
        sleeps = []
        # ref points to an annotated tag object, then git/tags derefs to commit.
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_annotated())),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_deref_commit())),
        ]) as h:
            r = _tag_resolver(h.base_url, sleeps.append)
            assert r.resolve_tag_to_sha(SLUG, "v3.11.0") == SHA
        assert sleeps == []
        assert h.state.served_count == 2
        assert "/git/ref/tags/" in h.state.request_paths[0]
        assert "/git/tags/" in h.state.request_paths[1]

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_dereference_retries_502(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_annotated())),
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_deref_commit())),
        ]) as h:
            r = _tag_resolver(h.base_url, sleeps.append)
            assert r.resolve_tag_to_sha(SLUG, "v3.11.0") == SHA
        assert sleeps == [1.0]

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_dereference_fatal_failure_wrapped_and_does_not_leak(self, iteration):
        """H2: a fatal failure in _dereference_annotated_tag must surface as a
        ResolutionError (not a raw HTTPError) so the candidate-tag loop in
        _resolve_first_tag can decide what to do with it."""
        sleeps = []
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_annotated())),
            (404, {}, b""),  # dereference fails fatally
        ]) as h:
            r = _tag_resolver(h.base_url, sleeps.append)
            with pytest.raises(ResolutionError, match="dereference") as error:
                r.resolve_tag_to_sha(SLUG, "v3.11.0")
        assert not isinstance(error.value, TagAbsentError)
        assert sleeps == []
        assert h.state.served_count == 2

    @pytest.mark.parametrize("iteration", range(4))
    def test_socket_timeout_wrapped_not_leaked(self, iteration):
        """H1 (resolver side): a read timeout must be wrapped into
        ResolutionError, not escape as a bare TimeoutError."""
        sleeps = []
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_commit()), 3.0),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_commit()), 3.0),
        ]) as h:
            r = GitHubTagResolver(
                base_url=h.base_url, sleeper=sleeps.append,
                timeout=1, max_attempts=2, base_delay=0.1,
            )
            with pytest.raises(ResolutionError) as exc_info:
                r.resolve_tag_to_sha(SLUG, "v3.11.0")
        assert isinstance(exc_info.value.__cause__, OSError)
        assert sleeps == [0.1]


def _pypi_payload() -> dict:
    return {"info": {"project_url": f"https://github.com/{SLUG}"}}


def _crates_payload() -> dict:
    return {"version": {"repository": f"https://github.com/{SLUG}"}}


def _go_payload() -> dict:
    return {"Version": "v3.11.0", "Time": "2022-10-24T00:00:00Z"}


class TestPyPIResolverReal:
    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_registry_502_retried_then_full_resolve(self, iteration):
        sleeps = []
        # registry (PyPI) and tag resolver share the server; sequence:
        # 1. pypi -> 502 transient
        # 2. pypi -> 200 with github slug
        # 3. github tag ref -> 200 commit sha
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(_pypi_payload())),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_commit())),
        ]) as h:
            tag_r = _tag_resolver(h.base_url, sleeps.append)
            resolver = PyPIResolver(
                tag_resolver=tag_r, base_url=h.base_url, sleeper=sleeps.append, base_delay=1.0
            )
            result = resolver.resolve(PackageRef(Ecosystem.PYPI, "requests", "2.31.0"))
        assert result.scope.slug == SLUG
        assert result.scope.commit_sha == SHA
        assert result.tag == "v2.31.0"
        assert sleeps == [1.0]
        assert h.state.served_count == 3

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_registry_404_fatal(self, iteration):
        sleeps = []
        with hs.scripted_server([(404, {}, b"")]) as h:
            tag_r = _tag_resolver(h.base_url, sleeps.append)
            resolver = PyPIResolver(
                tag_resolver=tag_r, base_url=h.base_url, sleeper=sleeps.append
            )
            with pytest.raises(ResolutionError, match="PyPI lookup failed"):
                resolver.resolve(PackageRef(Ecosystem.PYPI, "nope", "9.9.9"))
        assert sleeps == []
        assert h.state.served_count == 1


class TestCratesResolverReal:
    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_registry_502_retried_then_full_resolve(self, iteration):
        sleeps = []
        # crates candidate tags: {name}-{version}, v{version}, {version}
        # First two candidate tags must 404, third resolves. Script:
        # 1. crates -> 502 transient
        # 2. crates -> 200 with slug
        # 3. tag "name-version" -> 404 fatal-but-retried-as-resolution-error
        # 4. tag "vversion" -> 404
        # 5. tag "version" -> 200 commit sha
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(_crates_payload())),
            (404, {}, b""),
            (404, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_commit())),
        ]) as h:
            tag_r = _tag_resolver(h.base_url, sleeps.append)
            resolver = CratesResolver(
                tag_resolver=tag_r, base_url=h.base_url, sleeper=sleeps.append, base_delay=1.0
            )
            result = resolver.resolve(PackageRef(Ecosystem.CRATES, "serde", "1.0.0"))
        assert result.scope.slug == SLUG
        assert result.scope.commit_sha == SHA
        assert sleeps == [1.0]  # only the crates 502 sleeps; 404s are fatal (no sleep)
        assert h.state.served_count == 5

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_registry_404_fatal(self, iteration):
        sleeps = []
        with hs.scripted_server([(404, {}, b"")]) as h:
            tag_r = _tag_resolver(h.base_url, sleeps.append)
            resolver = CratesResolver(
                tag_resolver=tag_r, base_url=h.base_url, sleeper=sleeps.append
            )
            with pytest.raises(ResolutionError, match="crates.io lookup failed"):
                resolver.resolve(PackageRef(Ecosystem.CRATES, "nope", "9.9.9"))
        assert sleeps == []
        assert h.state.served_count == 1


class TestGoResolverReal:
    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_proxy_502_retried_then_full_resolve(self, iteration):
        sleeps = []
        # 1. go proxy -> 502
        # 2. go proxy -> 200 info
        # 3. github tag ref -> 200 commit sha (Go uses version verbatim as tag)
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(_go_payload())),
            (200, {"Content-Type": "application/json"}, hs.json_body(_tag_ref_commit())),
        ]) as h:
            tag_r = _tag_resolver(h.base_url, sleeps.append)
            resolver = GoResolver(
                tag_resolver=tag_r, base_url=h.base_url, sleeper=sleeps.append, base_delay=1.0
            )
            result = resolver.resolve(
                PackageRef(Ecosystem.GO, "github.com/python/cpython", "v3.11.0")
            )
        assert result.scope.slug == SLUG
        assert result.scope.commit_sha == SHA
        assert sleeps == [1.0]
        assert h.state.served_count == 3

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_proxy_404_fatal(self, iteration):
        sleeps = []
        with hs.scripted_server([(404, {}, b"")]) as h:
            tag_r = _tag_resolver(h.base_url, sleeps.append)
            resolver = GoResolver(
                tag_resolver=tag_r, base_url=h.base_url, sleeper=sleeps.append
            )
            with pytest.raises(ResolutionError, match="Go proxy lookup failed"):
                resolver.resolve(
                    PackageRef(Ecosystem.GO, "github.com/python/cpython", "v9.9.9")
                )
        assert sleeps == []
        assert h.state.served_count == 1
