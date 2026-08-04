"""Offline tests for SHA-pinned codeload materialization."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from leitir.materialize import MaterializationError, materialize_github_repo

from _http_server import scripted_server

SHA = "a" * 40


def _tarball(*, traversal: bool = False) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}/")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        content = b"pinned source\n"
        source = tarfile.TarInfo(f"demo-{SHA}/src/example.py")
        source.size = len(content)
        source.mode = 0o644
        archive.addfile(source, io.BytesIO(content))
        if traversal:
            evil = tarfile.TarInfo("../evil.txt")
            evil.size = 4
            archive.addfile(evil, io.BytesIO(b"evil"))
    return data.getvalue()


def _materialize(root: Path, base_url: str, **options: object) -> Path:
    return materialize_github_repo(
        root,
        "example/demo#v1",
        "example",
        "demo",
        SHA,
        tag="v1",
        base_url=base_url,
        max_attempts=1,
        verify=False,
        **options,  # type: ignore[arg-type]
    )


def test_download_extracts_directly_into_sha_directory(tmp_path):
    with scripted_server([(200, {"Content-Type": "application/gzip"}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)

    assert target == tmp_path / "repos/github.com/example/demo" / SHA
    assert (target / "src/example.py").read_text() == "pinned source\n"
    assert not (target / f"demo-{SHA}").exists()
    assert server.state.request_paths == [f"/example/demo/tar.gz/{SHA}"]


def test_manifest_records_immutable_provenance(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    assert manifest == {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": manifest["fetched_at"],
        "has_tests": False,
        "host": "github.com",
        "owner": "example",
        "repo": "demo",
        "repo_url": "https://github.com/example/demo",
        "source": "git-commit",
        "spec": "example/demo#v1",
        "subpath": None,
        "tag": "v1",
        "verified": False,
        "verified_at": None,
        "verification_notes": [],
    }
    assert manifest["fetched_at"].endswith("Z")
    assert manifest["verified"] is False
    assert manifest["verified_at"] is None


def test_existing_valid_manifest_is_idempotent(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        first = _materialize(tmp_path, server.base_url)
        second = _materialize(tmp_path, server.base_url)

    assert second == first
    assert server.state.served_count == 1


def test_http_failure_cleans_partial_target_and_uses_domain_error(tmp_path):
    with scripted_server([(404, {}, b"missing")]) as server:
        with pytest.raises(MaterializationError, match="HTTP 404"):
            _materialize(tmp_path, server.base_url)

    target = tmp_path / "repos/github.com/example/demo" / SHA
    assert not target.exists()
    assert not list(target.parent.glob(f".{SHA}.tmp-*"))


def test_transient_http_failure_is_retried(tmp_path):
    with scripted_server([(500, {}, b"retry"), (200, {}, _tarball())]) as server:
        target = materialize_github_repo(
            tmp_path,
            "example/demo",
            "example",
            "demo",
            SHA,
            base_url=server.base_url,
            max_attempts=2,
            sleeper=lambda _delay: None,
            verify=False,
        )

    assert (target / "src/example.py").is_file()
    assert server.state.served_count == 2


def test_invalid_tarball_cleans_partial_target(tmp_path):
    with scripted_server([(200, {}, b"not a tarball")]) as server:
        with pytest.raises(MaterializationError, match="ReadError"):
            _materialize(tmp_path, server.base_url)
    assert not (tmp_path / "repos/github.com/example/demo" / SHA).exists()


def test_path_traversal_member_is_rejected(tmp_path):
    with scripted_server([(200, {}, _tarball(traversal=True))]) as server:
        with pytest.raises(MaterializationError, match="UnsafeArchiveError"):
            _materialize(tmp_path, server.base_url)

    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "repos/github.com/example/demo" / SHA).exists()


def test_device_file_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        device = tarfile.TarInfo(f"demo-{SHA}/device")
        device.type = tarfile.CHRTYPE
        archive.addfile(device)
    with scripted_server([(200, {}, data.getvalue())]) as server:
        with pytest.raises(MaterializationError, match="UnsafeArchiveError"):
            _materialize(tmp_path, server.base_url)


def test_escaping_symlink_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        link = tarfile.TarInfo(f"demo-{SHA}/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        archive.addfile(link)
    with scripted_server([(200, {}, data.getvalue())]) as server:
        with pytest.raises(MaterializationError, match="UnsafeArchiveError"):
            _materialize(tmp_path, server.base_url)
