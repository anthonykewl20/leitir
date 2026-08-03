"""Offline end-to-end tests for corpus roots, indexing, and removal."""

from __future__ import annotations

import io
import json
import tarfile

from leitir.corpus import load_sources, materialize_source, remove_source, resolve_root
from leitir.search import RepoScope

from _http_server import scripted_server

SHA = "b" * 40


def _tarball() -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        content = b"hello\n"
        member = tarfile.TarInfo(f"demo-{SHA}/README.md")
        member.size = len(content)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _add(root, server, spec="example/demo"):
    return materialize_source(
        spec,
        RepoScope("example/demo", SHA),
        root=root,
        base_url=server.base_url,
        max_attempts=1,
        verify=False,
    )


def test_root_resolution_precedence(tmp_path, monkeypatch):
    home = tmp_path / "home"
    env_root = tmp_path / "from-env"
    explicit = tmp_path / "explicit"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("LEITIR_HOME", str(env_root))

    assert resolve_root(explicit) == explicit
    assert resolve_root() == env_root
    monkeypatch.delenv("LEITIR_HOME")
    assert resolve_root() == home / ".leitir"


def test_materialize_updates_atomic_index_and_leaves_no_temp_file(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _add(tmp_path, server)

    entries = json.loads((tmp_path / "sources.json").read_text())
    assert entries == [
        {
            "commit_sha": SHA,
            "fetched_at": entries[0]["fetched_at"],
            "host": "github.com",
            "name": "example/demo",
            "owner": "example",
            "path": f"repos/github.com/example/demo/{SHA}",
            "repo": "demo",
            "verified": False,
        }
    ]
    assert target.is_dir()
    assert not list(tmp_path.glob(".sources.json.tmp-*"))


def test_corrupt_index_is_backed_up_and_rebuilt(tmp_path):
    tmp_path.joinpath("sources.json").write_text("not json")
    with scripted_server([(200, {}, _tarball())]) as server:
        _add(tmp_path, server)

    assert (tmp_path / "sources.json.bak").read_text() == "not json"
    assert len(load_sources(tmp_path)) == 1


def test_structurally_corrupt_index_is_backed_up(tmp_path):
    malformed = '[{"name": "missing provenance"}]\n'
    tmp_path.joinpath("sources.json").write_text(malformed)

    assert load_sources(tmp_path) == []
    assert (tmp_path / "sources.json.bak").read_text() == malformed


def test_two_specs_for_same_repo_sha_are_deduplicated(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        first = _add(tmp_path, server, "npm:demo@1.0")
        second = _add(tmp_path, server, "pypi:demo@1.0")

    assert first == second
    assert server.state.served_count == 1
    assert len(load_sources(tmp_path)) == 1


def test_remove_one_sha_updates_index_and_prunes_empty_parents(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _add(tmp_path, server)

    assert remove_source(tmp_path, "example", "demo", SHA)
    assert not target.exists()
    assert not (tmp_path / "repos").exists()
    assert load_sources(tmp_path) == []


def test_remove_whole_repo_preserves_sibling_repositories(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        _add(tmp_path, server)
    sibling = tmp_path / "repos/github.com/example/other" / ("c" * 40)
    sibling.mkdir(parents=True)

    assert remove_source(tmp_path, "example", "demo")
    assert sibling.is_dir()
    assert not (tmp_path / "repos/github.com/example/demo").exists()


def test_import_does_not_resolve_or_create_default_root(tmp_path, monkeypatch):
    root = tmp_path / "unused"
    monkeypatch.setenv("LEITIR_HOME", str(root))
    __import__("leitir.corpus")
    assert not root.exists()
