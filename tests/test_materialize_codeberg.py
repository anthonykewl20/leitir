from __future__ import annotations

import io
import json
import tarfile

import pytest

import _http_server as hs
from leitir.materialize import MaterializationError, materialize_repo
from leitir.resolver import CodebergResolver
from leitir.search import RepoScope


SHA = "b" * 40
CONTENT = b"host-native proof\n"


def _tarball(content=CONTENT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"demo/{'README.md'}")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _resolver(server):
    resolver = CodebergResolver(base_url=server.base_url, max_attempts=1)
    resolver.archive_url = lambda *_: f"{server.base_url}/archive"  # type: ignore[method-assign]
    return resolver


def _tree():
    from leitir.tree import GitHubTreeSource
    return {"tree": [{"type": "blob", "path": "README.md", "sha": GitHubTreeSource.git_blob_sha(CONTENT), "size": len(CONTENT), "mode": "100644"}]}


def test_materializes_fully_verified_codeberg_tree(tmp_path):
    with hs.scripted_server([(200, {}, _tarball()), (200, {}, hs.json_body(_tree()))]) as server:
        target = materialize_repo(tmp_path, f"codeberg:owner/demo@{SHA}", RepoScope("owner/demo", SHA), host="codeberg.org", resolver=_resolver(server))
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert target == tmp_path / "repos/codeberg.org/owner/demo" / SHA
    assert (manifest["fetch_method"], manifest["verified"]) == ("codeberg-archive", True)


def test_verification_mismatch_and_archive_404_fail_closed(tmp_path):
    with hs.scripted_server([(200, {}, _tarball(b"tampered")), (200, {}, hs.json_body(_tree())), (200, {}, hs.json_body({"content": "aG9zdC1uYXRpdmUgcHJvb2YK", "encoding": "base64"}))]) as server:
        with pytest.raises(MaterializationError, match="VerificationError"):
            materialize_repo(tmp_path, "x", RepoScope("owner/demo", SHA), host="codeberg.org", resolver=_resolver(server))
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(MaterializationError, match="HTTP 404"):
            materialize_repo(tmp_path, "x", RepoScope("owner/demo", SHA), host="codeberg.org", resolver=_resolver(server))
