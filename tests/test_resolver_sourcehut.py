from __future__ import annotations

import io
import os
from urllib.error import HTTPError

import pytest

import _http_server as hs
from leitir.resolver import ResolutionError, SourcehutResolver, TagAbsentError


SHA = "a" * 40
HEAD_SHA = "1" * 40
TAG_SHA = "2" * 40


def _pkt(payload: bytes) -> bytes:
    return f"{len(payload) + 4:04x}".encode("ascii") + payload


def _info_refs() -> bytes:
    return b"".join(
        (
            _pkt(b"# service=git-upload-pack\n"),
            b"0000",
            _pkt(f"{HEAD_SHA} HEAD\0symref=HEAD:refs/heads/main\n".encode()),
            _pkt(f"{HEAD_SHA} refs/heads/main\n".encode()),
            _pkt(f"{TAG_SHA.upper()} refs/tags/v1.0\n".encode()),
            b"0000",
        )
    )


def _resolver(base_url, **kwargs):
    return SourcehutResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def test_anonymous_info_refs_parsing_and_resolution_avoids_graphql():
    with hs.scripted_server([(200, {}, _info_refs())]) as server:
        resolver = _resolver(server.base_url)
        assert resolver._info_refs("~user/repo") == {
            "HEAD": HEAD_SHA,
            "refs/heads/main": HEAD_SHA,
            "refs/tags/v1.0": TAG_SHA,
        }
        assert resolver.resolve_tag_to_sha("~user/repo", "v1.0") == TAG_SHA
        assert resolver.resolve_tag_to_sha("~user/repo", "main") == HEAD_SHA
    assert len(server.state.request_paths) == 3
    assert all(
        path == "/~user/repo/info/refs?service=git-upload-pack"
        for path in server.state.request_paths
    )


def test_private_info_refs_uses_graphql_fallback_with_token():
    payload = {"data": {"user": {"repository": {"revparse_single": {"id": SHA.upper()}}}}}
    with hs.scripted_server([(401, {}, b""), (200, {}, hs.json_body(payload))]) as server:
        assert _resolver(server.base_url, token="token").resolve_tag_to_sha("~user/repo", "refs/heads/main") == SHA
    assert server.state.request_paths[0].startswith("/~user/repo/info/refs?")
    assert server.state.request_paths[1].startswith("/?query=")


def test_private_info_refs_without_token_is_clear_resolution_error():
    with hs.scripted_server([(401, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match=r"Sourcehut refs.*HTTP 401"):
            _resolver(server.base_url).resolve_tag_to_sha("~user/repo", "main")
    assert server.state.served_count == 1


def test_null_revparse_result_is_tag_absence():
    payload = {"data": {"user": {"repository": {"revparse_single": None}}}}
    with hs.scripted_server([(401, {}, b""), (200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(TagAbsentError) as error:
            _resolver(server.base_url, token="token").resolve_tag_to_sha("~user/repo", "missing")
    assert error.value.__cause__ is not None


@pytest.mark.parametrize(
    "message", ["revision 'missing' not found", "no such ref: missing"]
)
def test_graphql_missing_revision_error_is_tag_absence(message):
    payload = {"errors": [{"message": message}], "data": None}
    with hs.scripted_server([(401, {}, b""), (200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(TagAbsentError) as error:
            _resolver(server.base_url, token="token").resolve_tag_to_sha("~user/repo", "missing")
    assert error.value.__cause__ is not None


@pytest.mark.parametrize(
    "payload",
    [
        {"data": {"user": {"repository": {}}}},
        {"errors": [{"message": "authentication required"}], "data": None},
    ],
)
def test_malformed_or_auth_graphql_response_is_not_tag_absence(payload):
    with hs.scripted_server([(401, {}, b""), (200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(ResolutionError) as error:
            _resolver(server.base_url, token="token").resolve_tag_to_sha("~user/repo", "missing")
    assert not isinstance(error.value, TagAbsentError)


def test_slug_is_strict_and_404_fails_closed():
    with pytest.raises(ResolutionError, match="invalid Sourcehut"):
        SourcehutResolver().archive_url("user/repo", SHA)
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match="HTTP 404"):
            _resolver(server.base_url).resolve_tag_to_sha("~user/repo", "missing")


def test_archive_and_tree_endpoints():
    root = {"data": {"user": {"repository": {"revparse_single": {"tree": {"id": "c" * 40}}}}}}
    page = {"data": {"user": {"repository": {"object": {"entries": {"results": [{"name": "a.py", "mode": 420, "object": {"type": "BLOB", "id": "b" * 40, "size": 3, "content": "https://git.sr.ht/blob/a"}}], "cursor": None}}}}}}
    with hs.scripted_server([(200, {}, hs.json_body(root)), (200, {}, hs.json_body(page))]) as server:
        entries = _resolver(server.base_url, token="token").list_blobs("~user/repo", SHA)
    assert SourcehutResolver().archive_url("~user/repo", SHA) == f"https://git.sr.ht/~user/repo/archive/{SHA}.tar.gz"
    assert entries[0].path == "a.py"
    assert all(path.startswith("/?query=") for path in server.state.request_paths)


def test_environment_token_is_bearer_and_redacted(monkeypatch, capsys):
    captured = {}
    calls = 0

    def fake_urlopen(request, timeout):
        nonlocal calls
        calls += 1
        captured.update(request.header_items())
        if calls == 1:
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)
        return io.BytesIO(hs.json_body({"data": {"user": {"repository": {"revparse_single": {"id": SHA}}}}}))

    monkeypatch.setenv("SRHT_TOKEN", "never-print-this")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert SourcehutResolver().resolve_tag_to_sha("~user/repo", "main") == SHA
    assert captured["Authorization"] == "Bearer never-print-this"
    assert calls == 2
    assert "never-print-this" not in capsys.readouterr().err


@pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification")
def test_live_pinned_commit_resolves():
    sha = "24be30ef17d5ca0162f11b35258c8fa2413d556a"
    assert SourcehutResolver().resolve_tag_to_sha("~sircmpwn/scdoc", "HEAD") == sha
