"""Offline npm registry resolution coverage."""

from __future__ import annotations

import io

import pytest
from _http_server import json_body, routed_server

from leitir.resolver import (
    Ecosystem,
    NpmResolver,
    PackageRef,
    ResolutionError,
    TagAbsentError,
)

SHA = "c" * 40


class Tags:
    def __init__(self, hits=("v1.2.0",)):
        self.hits = set(hits)
        self.calls = []

    def resolve_tag_to_sha(self, slug, tag):
        self.calls.append((slug, tag))
        if tag not in self.hits:
            raise TagAbsentError(f"missing {tag}")
        return SHA


def _payload(repository="git+https://github.com/acme/demo.git", *, version_repo=None):
    version = {}
    if version_repo is not None:
        version["repository"] = version_repo
    return {
        "dist-tags": {"latest": "1.2.0"},
        "versions": {"1.0.0": {}, "1.1.0": {}, "1.2.0": version},
        "repository": repository,
    }


def _resolve(payload, *, version="1.2.0", tags=None, name="demo"):
    path = "/%40scope%2Fdemo" if name.startswith("@") else f"/{name}"
    with routed_server({path: (200, {}, json_body(payload))}) as server:
        resolver = NpmResolver(tags or Tags(), base_url=server.base_url, max_attempts=1)
        result = resolver.resolve(PackageRef(Ecosystem.NPM, name, version))
        assert server.state.request_paths == [path]
        return result


def test_latest_and_explicit_resolution():
    payload = _payload()
    with routed_server({"/demo": (200, {}, json_body(payload))}) as server:
        tags = Tags()
        resolver = NpmResolver(tags, base_url=server.base_url, max_attempts=1)
        assert resolver.latest_version("demo") == "1.2.0"
        resolved = resolver.resolve(PackageRef(Ecosystem.NPM, "demo", "1.2.0"))
    assert resolved.scope.slug == "acme/demo"
    assert resolved.scope.commit_sha == SHA
    assert resolved.tag == "v1.2.0"


@pytest.mark.parametrize(
    "repo_url",
    [
        "git+https://github.com/acme/demo.git",
        "git+ssh://git@github.com/acme/demo.git",
        "ssh://git@github.com/acme/demo.git",
        "git://github.com/acme/demo.git",
        "github:acme/demo",
        "git@github.com:acme/demo.git",
        "https://github.com/acme/demo.git/",
    ],
)
def test_repository_url_rewriting(repo_url):
    assert _resolve(_payload(repo_url)).scope.slug == "acme/demo"


def test_version_repository_preferred_and_directory_carried_for_scoped_name():
    payload = _payload(
        "https://github.com/wrong/top",
        version_repo={"url": "github:acme/demo", "directory": "packages/core"},
    )
    resolved = _resolve(payload, name="@scope/demo")
    assert resolved.scope.slug == "acme/demo"
    assert resolved.subpath == "packages/core"


def test_missing_version_lists_recent_versions():
    payload = _payload()
    with routed_server({"/demo": (200, {}, json_body(payload))}) as server:
        resolver = NpmResolver(Tags(), base_url=server.base_url, max_attempts=1)
        with pytest.raises(ResolutionError, match="recent versions: 1.0.0, 1.1.0, 1.2.0"):
            resolver.resolve(PackageRef(Ecosystem.NPM, "demo", "9.0.0"))


def test_non_github_repository_rejected():
    with pytest.raises(ResolutionError, match="only github.com"):
        _resolve(_payload("https://gitlab.com/acme/demo.git"))


def test_attacker_host_rejected():
    with pytest.raises(ResolutionError, match="only github.com"):
        _resolve(_payload("https://github.com.attacker.example/acme/demo.git"))


def test_tag_miss_is_hard_error_without_default_branch_fallback():
    tags = Tags(hits=())
    with pytest.raises(ResolutionError, match="no default-branch fallback") as error:
        _resolve(_payload(), tags=tags)
    assert "'demo@1.2.0', 'v1.2.0', '1.2.0'" in str(error.value)
    assert tags.calls == [
        ("acme/demo", "demo@1.2.0"),
        ("acme/demo", "v1.2.0"),
        ("acme/demo", "1.2.0"),
    ]


@pytest.mark.parametrize(
    ("name", "hit", "expected_calls"),
    [
        ("@scope/demo", "@scope/demo@1.2.0", ["@scope/demo@1.2.0"]),
        ("demo", "v1.2.0", ["demo@1.2.0", "v1.2.0"]),
        ("demo", "1.2.0", ["demo@1.2.0", "v1.2.0", "1.2.0"]),
    ],
)
def test_npm_tag_candidates_are_tried_in_order_and_stop_at_first_success(
    name, hit, expected_calls
):
    tags = Tags(hits=(hit,))
    resolved = _resolve(_payload(), name=name, tags=tags)
    assert resolved.tag == hit
    assert tags.calls == [("acme/demo", tag) for tag in expected_calls]


def test_npm_non_absence_failure_does_not_try_fallback():
    failure = ResolutionError("HTTP 503 after retries")

    class FailingTags(Tags):
        def resolve_tag_to_sha(self, slug, tag):
            self.calls.append((slug, tag))
            raise failure

    tags = FailingTags(hits=("v1.2.0",))
    with pytest.raises(ResolutionError) as error:
        _resolve(_payload(), tags=tags)
    assert error.value is failure
    assert tags.calls == [("acme/demo", "demo@1.2.0")]


def test_npm_absent_preferred_tag_uses_fallback():
    tags = Tags(hits=("v1.2.0",))
    resolved = _resolve(_payload(), tags=tags)
    assert resolved.tag == "v1.2.0"
    assert tags.calls == [
        ("acme/demo", "demo@1.2.0"),
        ("acme/demo", "v1.2.0"),
    ]


def test_npm_token_authenticates_default_registry_metadata(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(json_body(_payload()))

    monkeypatch.setenv("NPM_TOKEN", "npm-secret")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert NpmResolver(Tags()).latest_version("demo") == "1.2.0"
    assert captured["Authorization"] == "Bearer npm-secret"
