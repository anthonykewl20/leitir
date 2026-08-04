from __future__ import annotations

import io
import os

import pytest

import _http_server as hs
import fixtures_resolver as fx
from leitir.resolver import BitbucketResolver, ResolutionError


SHA = "a" * 40


def _resolver(base_url, **kwargs):
    return BitbucketResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def test_resolves_ref_to_lowercase_commit_sha():
    with hs.scripted_server([(200, {}, hs.json_body({"hash": SHA.upper()}))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "release/1") == SHA
    assert server.state.request_paths == ["/repositories/owner/repo/commit/release%2F1"]


def test_commit_sha_input_is_verified_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"hash": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_ref_to_sha("owner/repo", SHA) == SHA
    assert server.state.served_count == 1


def test_404_is_wrapped_without_retry():
    sleeps = []
    with hs.scripted_server([(404, {}, b"")]) as server:
        resolver = BitbucketResolver(base_url=server.base_url, sleeper=sleeps.append)
        with pytest.raises(ResolutionError, match="HTTP 404"):
            resolver.resolve_tag_to_sha("owner/repo", "missing")
    assert sleeps == []


def test_rate_limit_retries():
    sleeps = []
    responses = [
        (429, {"Retry-After": "0"}, b""),
        (200, {}, hs.json_body({"hash": SHA})),
    ]
    with hs.scripted_server(responses) as server:
        resolver = BitbucketResolver(base_url=server.base_url, sleeper=sleeps.append)
        assert resolver.resolve_tag_to_sha("owner/repo", "main") == SHA
    assert sleeps == [0.0]


@pytest.mark.parametrize("payload", [{}, {"hash": "short"}, [], {"hash": 1}])
def test_malformed_commit_metadata_is_honest(payload):
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(ResolutionError, match="malformed commit metadata"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")


def test_archive_url_uses_download_endpoint_and_pinned_sha():
    url = BitbucketResolver().archive_url("owner/repo", SHA)
    assert url == f"https://bitbucket.org/owner/repo/get/{SHA}.tar.gz"


def test_tree_listing_hashes_host_native_file_content():
    payload = {"values": [{"type": "commit_file", "path": "a.py", "size": 5}]}
    responses = [
        (200, {}, hs.json_body(payload)),
        (200, {}, b"hello"),
    ]
    with hs.scripted_server(responses) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [(entry.path, entry.size, entry.mode) for entry in entries] == [("a.py", 5, "100644")]
    assert entries[0].blob_sha == "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"


def test_environment_token_uses_bearer_only_for_https_api_host(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body({"hash": SHA}))

    monkeypatch.setenv("BITBUCKET_TOKEN", "secret-value")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert BitbucketResolver().resolve_tag_to_sha("owner/repo", "main") == SHA
    assert captured["Authorization"] == "Bearer secret-value"


def test_token_is_never_rendered_on_failure(monkeypatch, capsys):
    monkeypatch.setenv("BITBUCKET_TOKEN", "never-print-this")
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
    resolver = BitbucketResolver()
    assert resolver.resolve_tag_to_sha(fx.BITBUCKET_SLUG, fx.BITBUCKET_REF) == fx.BITBUCKET_COMMIT_SHA
