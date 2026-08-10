from __future__ import annotations

import io
import os

import _http_server as hs
import fixtures_resolver as fx
import pytest

from leitir.resolver import (
    Ecosystem,
    GitLabResolver,
    GoResolver,
    PackageRef,
    ResolutionError,
    TagAbsentError,
)

SHA = "a" * 40


def _resolver(base_url, **kwargs):
    return GitLabResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def test_resolves_ref_to_lowercase_commit_sha():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA.upper()}))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "release/1") == SHA
    assert server.state.request_paths == ["/projects/owner%2Frepo/repository/commits/release%2F1"]


def test_resolves_subgroup_project_ref_with_encoded_full_path():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA.upper()}))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha(
            "group/subgroup/project", "main"
        ) == SHA
    assert server.state.request_paths == [
        "/projects/group%2Fsubgroup%2Fproject/repository/commits/main"
    ]


def test_commit_sha_input_is_verified_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_ref_to_sha("owner/repo", SHA) == SHA
    assert server.state.served_count == 1


def test_pseudo_version_commit_prefix_is_expanded_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_commit_to_sha(
            "owner/repo", "abcdef123456"
        ) == SHA
    assert server.state.request_paths == [
        "/projects/owner%2Frepo/repository/commits/abcdef123456"
    ]


def test_404_is_wrapped_without_retry():
    sleeps = []
    with hs.scripted_server([(404, {}, b"")]) as server:
        resolver = GitLabResolver(base_url=server.base_url, sleeper=sleeps.append)
        with pytest.raises(TagAbsentError, match="HTTP 404"):
            resolver.resolve_tag_to_sha("owner/repo", "missing")
    assert sleeps == []


def test_non_404_stays_resolution_error():
    with hs.scripted_server([(500, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match="HTTP 500") as caught:
            _resolver(server.base_url, max_attempts=1).resolve_tag_to_sha(
                "owner/repo", "main"
            )
    assert not isinstance(caught.value, TagAbsentError)


def test_go_nested_module_advances_after_absent_repository_candidate():
    responses = [
        (404, {}, b""),
        (200, {}, hs.json_body({"id": SHA})),
    ]
    with hs.scripted_server(responses) as repository, hs.scripted_server(
        [(200, {}, hs.json_body({}))]
    ) as proxy:
        hosted = _resolver(repository.base_url)
        resolver = GoResolver(
            hosted,
            base_url=proxy.base_url,
            repository_resolvers={"gitlab.com": hosted},
        )
        result = resolver.resolve(
            PackageRef(
                Ecosystem.GO,
                "gitlab.com/group/project/submodule",
                "v1.0.0",
            )
        )

    assert result.scope.slug == "group/project"
    assert result.subpath == "submodule"
    assert repository.state.served_count == 2


def test_rate_limit_retries():
    sleeps = []
    responses = [
        (429, {"Retry-After": "0"}, b""),
        (200, {}, hs.json_body({"id": SHA})),
    ]
    with hs.scripted_server(responses) as server:
        resolver = GitLabResolver(base_url=server.base_url, sleeper=sleeps.append)
        assert resolver.resolve_tag_to_sha("owner/repo", "main") == SHA
    assert sleeps == [0.0]


@pytest.mark.parametrize("payload", [{}, {"id": "short"}, [], {"id": 1}])
def test_malformed_commit_metadata_is_honest(payload):
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(ResolutionError, match="malformed commit metadata"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")


def test_archive_url_uses_project_api_and_pinned_sha():
    url = GitLabResolver().archive_url("owner/repo", SHA)
    assert url == "https://gitlab.com/api/v4/projects/owner%2Frepo/repository/archive.tar.gz?sha=" + SHA


def test_tree_listing_maps_gitlab_blobs():
    payload = [{"id": "b" * 40, "path": "src/a.py", "type": "blob", "mode": "100644"}]
    responses = [
        (200, {}, hs.json_body(payload)),
        (200, {}, hs.json_body({"size": 7})),
    ]
    with hs.scripted_server(responses) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [(entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries] == [
        ("src/a.py", "b" * 40, 7, "100644")
    ]


def test_environment_token_uses_private_token_only_for_https_host(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body({"id": SHA}))

    monkeypatch.setenv("GITLAB_TOKEN", "secret-value")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert GitLabResolver().resolve_tag_to_sha("owner/repo", "main") == SHA
    assert captured["Private-token"] == "secret-value"


def test_token_is_never_rendered_on_failure(monkeypatch, capsys):
    monkeypatch.setenv("GITLAB_TOKEN", "never-print-this")
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(ResolutionError) as caught:
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")
    assert "never-print-this" not in str(caught.value)
    assert "never-print-this" not in capsys.readouterr().err


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)
def test_live_ref_resolves_to_pinned_commit():
    resolver = GitLabResolver()
    assert resolver.resolve_tag_to_sha(fx.GITLAB_SLUG, fx.GITLAB_REF) == fx.GITLAB_COMMIT_SHA


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)
def test_live_subgroup_ref_resolves_to_pinned_commit():
    resolver = GitLabResolver()
    assert resolver.resolve_tag_to_sha(
        fx.GITLAB_SUBGROUP_SLUG, fx.GITLAB_SUBGROUP_REF
    ) == fx.GITLAB_SUBGROUP_COMMIT_SHA
