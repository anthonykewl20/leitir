from __future__ import annotations

import io
import json
import tarfile

import _http_server as hs
import pytest

from leitir.materialize import MaterializationError, materialize_repo
from leitir.resolver import SourcehutResolver
from leitir.search import RepoScope
from leitir.tree import GitHubTreeSource

SHA = "b" * 40
CONTENT = b"sourcehut proof\n"


def _tarball(content=CONTENT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("repo/README.md")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _resolver(server, *, token="test-token"):
    resolver = SourcehutResolver(
        token=token,
        base_url=server.base_url,
        max_attempts=1,
        allow_insecure_http_for_tests=True,
    )
    resolver.archive_url = lambda *_: f"{server.base_url}/archive"  # type: ignore[method-assign]
    return resolver


def _tree_responses():
    root = {"data": {"user": {"repository": {"revparse_single": {"tree": {"id": "c" * 40}}}}}}
    page = {"data": {"user": {"repository": {"object": {"entries": {"results": [{"name": "README.md", "mode": 420, "object": {"type": "BLOB", "id": GitHubTreeSource.git_blob_sha(CONTENT), "size": len(CONTENT), "content": "https://git.sr.ht/blob/readme"}}], "cursor": None}}}}}}
    return [(200, {}, hs.json_body(root)), (200, {}, hs.json_body(page))]


def test_materializes_fully_verified_sourcehut_tree(tmp_path):
    with hs.scripted_server([(200, {}, _tarball()), *_tree_responses()]) as server:
        target = materialize_repo(tmp_path, f"sourcehut:~user/repo@{SHA}", RepoScope("user/repo", SHA), host="git.sr.ht", resolver=_resolver(server))
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert target == tmp_path / "repos/git.sr.ht/~user/repo" / SHA
    assert manifest["repo_url"] == "https://git.sr.ht/~user/repo"
    assert (manifest["fetch_method"], manifest["verified"]) == ("sourcehut-archive", True)


def test_anonymous_materialization_records_archive_only(tmp_path, monkeypatch):
    monkeypatch.delenv("SRHT_TOKEN", raising=False)
    with hs.scripted_server([(200, {}, _tarball())]) as server:
        target = materialize_repo(
            tmp_path,
            f"sourcehut:~user/repo@{SHA}",
            RepoScope("user/repo", SHA),
            host="git.sr.ht",
            resolver=_resolver(server, token=None),
        )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["verified"] == "archive-only"
    assert manifest["verified"] is not True
    assert manifest["verified_at"]
    assert server.state.served_count == 1


def test_sourcehut_mismatch_fails_closed(tmp_path):
    with hs.scripted_server([(200, {}, _tarball(b"tampered")), *_tree_responses()]) as server:
        resolver = _resolver(server)
        original = resolver._get_bytes
        resolver._get_bytes = lambda url: CONTENT if url == "https://git.sr.ht/blob/readme" else original(url)  # type: ignore[method-assign]
        with pytest.raises(MaterializationError, match="VerificationError"):
            materialize_repo(tmp_path, "x", RepoScope("user/repo", SHA), host="git.sr.ht", resolver=resolver)
    assert not (tmp_path / "repos/git.sr.ht/~user/repo" / SHA).exists()


def test_sourcehut_archive_404_cleans_target_and_redacts_token(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SRHT_TOKEN", "never-print-this")
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(MaterializationError, match="HTTP 404") as caught:
            materialize_repo(tmp_path, "x", RepoScope("user/repo", SHA), host="git.sr.ht", resolver=_resolver(server))
    assert "never-print-this" not in str(caught.value)
    assert "never-print-this" not in capsys.readouterr().err
    assert not (tmp_path / "repos/git.sr.ht/~user/repo" / SHA).exists()
