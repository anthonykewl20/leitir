from __future__ import annotations

import io
import os

import pytest

import _http_server as hs
from leitir.resolver import CodebergResolver, ResolutionError


SHA = "a" * 40


def _resolver(base_url, **kwargs):
    return CodebergResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def test_resolves_ref_and_commit_through_gitea_api():
    with hs.scripted_server([(200, {}, hs.json_body([{"sha": SHA.upper()}]))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "release/1") == SHA
    assert server.state.request_paths == ["/repos/owner/repo/commits?sha=release%2F1&limit=1"]


def test_404_and_malformed_metadata_fail_closed():
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match="HTTP 404"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "missing")
    with hs.scripted_server([(200, {}, hs.json_body([{"sha": "short"}]))]) as server:
        with pytest.raises(ResolutionError, match="malformed commit metadata"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")


def test_archive_and_recursive_tree_endpoints():
    payload = {"tree": [{"type": "blob", "path": "a.py", "sha": "b" * 40, "size": 3, "mode": "100644"}]}
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert CodebergResolver().archive_url("owner/repo", SHA) == f"https://codeberg.org/owner/repo/archive/{SHA}.tar.gz"
    assert entries[0].path == "a.py"
    assert server.state.request_paths == [f"/repos/owner/repo/git/trees/{SHA}?recursive=true"]


def test_environment_token_is_bearer_and_redacted(monkeypatch, capsys):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body([{"sha": SHA}]))

    monkeypatch.setenv("CODEBERG_TOKEN", "never-print-this")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert CodebergResolver().resolve_tag_to_sha("owner/repo", "main") == SHA
    assert captured["Authorization"] == "Bearer never-print-this"
    assert "never-print-this" not in capsys.readouterr().err


@pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification")
def test_live_pinned_commit_resolves():
    sha = "db760a61d52ac179f8f308f089b4741c072f17ce"
    assert CodebergResolver().resolve_tag_to_sha("forgejo/forgejo", sha) == sha
