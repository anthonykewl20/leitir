from __future__ import annotations

import io
import os

import pytest

import _http_server as hs
from leitir.resolver import ResolutionError, SourcehutResolver


SHA = "a" * 40


def _resolver(base_url, **kwargs):
    return SourcehutResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def test_resolves_ref_through_sourcehut_log_api():
    payload = {"data": {"user": {"repository": {"revparse_single": {"id": SHA.upper()}}}}}
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("~user/repo", "refs/heads/main") == SHA
    assert server.state.request_paths[0].startswith("/?query=")


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
        entries = _resolver(server.base_url).list_blobs("~user/repo", SHA)
    assert SourcehutResolver().archive_url("~user/repo", SHA) == f"https://git.sr.ht/~user/repo/archive/{SHA}.tar.gz"
    assert entries[0].path == "a.py"
    assert all(path.startswith("/?query=") for path in server.state.request_paths)


def test_environment_token_is_bearer_and_redacted(monkeypatch, capsys):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body({"data": {"user": {"repository": {"revparse_single": {"id": SHA}}}}}))

    monkeypatch.setenv("SRHT_TOKEN", "never-print-this")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert SourcehutResolver().resolve_tag_to_sha("~user/repo", "main") == SHA
    assert captured["Authorization"] == "Bearer never-print-this"
    assert "never-print-this" not in capsys.readouterr().err


@pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification")
def test_live_pinned_commit_resolves():
    if not os.environ.get("SRHT_TOKEN"):
        pytest.skip("Sourcehut GraphQL requires SRHT_TOKEN")
    sha = "24be30ef17d5ca0162f11b35258c8fa2413d556a"
    assert SourcehutResolver().resolve_tag_to_sha("~sircmpwn/scdoc", sha) == sha
