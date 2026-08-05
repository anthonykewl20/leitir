"""Offline tests for SHA-pinned codeload materialization."""

from __future__ import annotations

import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

import leitir.materialize as materialize_module
from leitir.materialize import (
    MaterializationError,
    UnsafeArchiveError,
    _extract_tarball,
    materialize_github_repo,
)

from _http_server import scripted_server

SHA = "a" * 40


def _snapshot(path: Path) -> set[str]:
    return {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
    }


def _extract_then_clean(data: bytes, staging: Path) -> None:
    try:
        _extract_tarball(data, staging, "pkg", SHA)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


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
        "materialized_tree_hash": "h1:cOO2Q95wvMIfJHy3T7u15v8K/y5EH8GT0x24FCEgzEU=",
        "materialized_tree_hash_algorithm": "dirhash-h1-sha256-v1",
        "materialized_tree_hash_scope": "full",
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
    # Failed materialization must not leave orphan empty parent directories.
    assert not (tmp_path / "repos").exists()


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


def test_chained_symlink_escape_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, target in (
            ("a", "."),
            ("b", "a/.."),
            ("c", "b/.."),
            ("leak.py", "c/etc/passwd"),
        ):
            link = tarfile.TarInfo(f"demo-{SHA}/{name}")
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)

    with pytest.raises(UnsafeArchiveError, match="symbolic link escapes its target"):
        _extract_tarball(data.getvalue(), tmp_path / "out", "demo", SHA)


def test_chained_symlink_escape_creates_nothing_outside_staging(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo("pkg/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, target in (("a", "."), ("b", "a/.."), ("b/payload", "owned")):
            link = tarfile.TarInfo(f"pkg/{name}")
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)

    parent = tmp_path / "parent"
    parent.mkdir()
    before = _snapshot(parent)
    with pytest.raises(UnsafeArchiveError, match="symbolic link escapes its target"):
        _extract_then_clean(data.getvalue(), parent / "staging")

    assert _snapshot(parent) == before
    assert not (parent / "payload").exists()


def test_relocated_nested_symlink_escape_creates_nothing_outside_staging(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        inside = tarfile.TarInfo("pkg/inside/")
        inside.type = tarfile.DIRTYPE
        inside.mode = 0o755
        archive.addfile(inside)
        for name, target in (
            ("x/y/a", "../../inside"),
            ("x/y/a/b", "../../outside"),
            ("x/y/a/b/pwn", "marker"),
        ):
            link = tarfile.TarInfo(f"pkg/{name}")
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)

    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "outside").mkdir()
    before = _snapshot(parent)
    with pytest.raises(UnsafeArchiveError, match="symbolic link escapes its target"):
        _extract_then_clean(data.getvalue(), parent / "staging")

    assert _snapshot(parent) == before
    assert not (parent / "outside/pwn").exists()


def test_benign_symlink_extracts_within_target(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        content = b"safe"
        member = tarfile.TarInfo(f"demo-{SHA}/realfile")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
        link = tarfile.TarInfo(f"demo-{SHA}/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "realfile"
        archive.addfile(link)

    destination = tmp_path / "out"
    _extract_tarball(data.getvalue(), destination, "demo", SHA)

    assert (destination / "link").is_symlink()
    assert (destination / "link").read_bytes() == b"safe"


def test_oversized_archive_member_is_rejected(tmp_path, monkeypatch):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"demo-{SHA}/large")
        member.size = 2
        archive.addfile(member, io.BytesIO(b"xx"))
    monkeypatch.setattr(materialize_module, "ARCHIVE_MAX_MEMBER_BYTES", 1)

    with pytest.raises(UnsafeArchiveError, match="archive member exceeds size limit"):
        _extract_tarball(data.getvalue(), tmp_path / "out", "demo", SHA)


def test_archive_member_count_is_enforced_during_iteration(tmp_path, monkeypatch):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name in ("one", "two"):
            member = tarfile.TarInfo(f"demo-{SHA}/{name}")
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
    monkeypatch.setattr(materialize_module, "ARCHIVE_MAX_MEMBERS", 1)

    with pytest.raises(UnsafeArchiveError, match="archive contains too many members"):
        _extract_tarball(data.getvalue(), tmp_path / "out", "demo", SHA)


def test_compressed_download_size_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(materialize_module, "ARCHIVE_MAX_COMPRESSED_BYTES", 4)
    with scripted_server([(200, {}, b"12345")]) as server:
        with pytest.raises(MaterializationError, match="compressed size limit"):
            _materialize(tmp_path, server.base_url)


class _ShortReadResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def read(self, _size: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""


def test_bounded_read_accepts_streaming_short_reads_under_limit():
    response = _ShortReadResponse([b"ab", b"c", b"de"])
    assert materialize_module._read_bounded(response, 5) == b"abcde"


def test_bounded_read_rejects_streaming_short_reads_over_limit():
    response = _ShortReadResponse([b"ab", b"cd", b"ef"])
    with pytest.raises(MaterializationError, match="compressed size limit"):
        materialize_module._read_bounded(response, 5)


@pytest.mark.parametrize("token", ["bad\x00token", "bad\x7ftoken"])
def test_codeload_token_control_character_is_rejected_without_disclosure(
    tmp_path, token
):
    with pytest.raises(ValueError) as error:
        materialize_github_repo(
            tmp_path,
            "example/demo",
            "example",
            "demo",
            SHA,
            token=token,
            verify=False,
        )
    assert token not in str(error.value)
