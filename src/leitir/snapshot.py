"""Deterministic, offline corpus snapshot export and import."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from leitir.corpus import (
    enumerate_shelved_sources,
    resolve_root,
    shelve_imported_sources,
)
from leitir.docpointers import POINTERS_NAME
from leitir.materialize import MANIFEST_NAME, _extract_tarball, read_valid_manifest
from leitir.tree import GitHubTreeSource

FORMAT_VERSION = 2
CORPUS_VERSION = 2
ARCHIVE_ROOT = "leitir-corpus-v1"


class SnapshotError(Exception):
    """A corpus snapshot is malformed or cannot be rehydrated safely."""


class SnapshotVerificationError(SnapshotError):
    """Snapshot bytes do not match their lock metadata."""


def _tree_entries(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_symlink() or path.is_file()
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def tree_sha(root: str | os.PathLike[str]) -> str:
    """Return SHA-256 of sorted ``mode path NUL git-blob-sha LF`` records.

    Regular files use Git modes 100644 or 100755 and symlinks use 120000 with
    their link target as blob bytes. Directories do not contribute records.
    """
    source = Path(root)
    digest = hashlib.sha256()
    for path in _tree_entries(source):
        relative = path.relative_to(source).as_posix()
        if path.is_symlink():
            mode = "120000"
            data = os.fsencode(os.readlink(path))
        else:
            executable = bool(path.stat().st_mode & 0o111)
            mode = "100755" if executable else "100644"
            data = path.read_bytes()
        blob_sha = GitHubTreeSource.git_blob_sha(data)
        digest.update(f"{mode} {relative}\0{blob_sha}\n".encode("utf-8"))
    return digest.hexdigest()


def _tarball_path(lock_path: Path) -> Path:
    return lock_path.with_suffix(".tar.gz")


def _tar_info(name: str, mode: int, *, kind: bytes, size: int = 0, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode & 0o777
    info.size = size
    info.linkname = linkname
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _archive_paths(sources: list[tuple[dict[str, Any], dict[str, object], Path]]) -> list[tuple[PurePosixPath, Path]]:
    paths: list[tuple[PurePosixPath, Path]] = []
    for entry, _manifest, target in sources:
        base = PurePosixPath(entry["path"])
        paths.append((base, target))
        for path in target.rglob("*"):
            paths.append((base / path.relative_to(target).as_posix(), path))
    return sorted(paths, key=lambda item: item[0].as_posix())


def _write_tarball(
    output: Path,
    sources: list[tuple[dict[str, Any], dict[str, object], Path]],
    pointers: bytes,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.tmp-", dir=output.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with temporary.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
            archive.addfile(_tar_info(ARCHIVE_ROOT, 0o755, kind=tarfile.DIRTYPE))
            for relative, path in _archive_paths(sources):
                name = f"{ARCHIVE_ROOT}/{relative.as_posix()}"
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    archive.addfile(_tar_info(name, metadata.st_mode, kind=tarfile.DIRTYPE))
                elif stat.S_ISREG(metadata.st_mode):
                    info = _tar_info(name, metadata.st_mode, kind=tarfile.REGTYPE, size=metadata.st_size)
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)
                elif stat.S_ISLNK(metadata.st_mode):
                    archive.addfile(_tar_info(name, metadata.st_mode, kind=tarfile.SYMTYPE, linkname=os.readlink(path)))
                else:
                    raise SnapshotError(f"source contains a special file: {relative}")
            pointer_info = _tar_info(
                f"{ARCHIVE_ROOT}/{POINTERS_NAME}",
                0o644,
                kind=tarfile.REGTYPE,
                size=len(pointers),
            )
            import io

            archive.addfile(pointer_info, io.BytesIO(pointers))
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def export_corpus(
    output: str | os.PathLike[str] = "corpus.lock",
    *,
    root: str | os.PathLike[str] | None = None,
) -> tuple[Path, Path]:
    """Write a deterministic lock and gzip tarball for one corpus."""
    corpus_root = resolve_root(root)
    lock_path = Path(output).expanduser().absolute()
    tarball_path = _tarball_path(lock_path)
    sources = enumerate_shelved_sources(corpus_root)
    for _entry, _manifest, target in sources:
        if lock_path.is_relative_to(target) or tarball_path.is_relative_to(target):
            raise SnapshotError("snapshot output cannot be inside a shelved source")
    records: list[dict[str, object]] = []
    for entry, manifest, target in sources:
        records.append(
            {
                "format_version": FORMAT_VERSION,
                "corpus_version": CORPUS_VERSION,
                **entry,
                "spec": manifest["spec"],
                "version_source": manifest.get("version_source"),
                "artifact_kind": manifest.get("artifact_kind"),
                "artifact_checksum": manifest.get("artifact_checksum"),
                "tree_sha": tree_sha(target),
            }
        )
    try:
        pointers = (corpus_root / POINTERS_NAME).read_bytes()
    except FileNotFoundError:
        pointers = b""
    _write_tarball(tarball_path, sources, pointers)
    tarball_sha256 = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
    payload = {
        "format_version": FORMAT_VERSION,
        "corpus_version": CORPUS_VERSION,
        "tarball": tarball_path.name,
        "tarball_sha256": tarball_sha256,
        "pointers_sha256": hashlib.sha256(pointers).hexdigest(),
        "sources": records,
    }
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{lock_path.name}.tmp-", dir=lock_path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, lock_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return lock_path, tarball_path


def _load_lock(
    path: Path, expected_sha256: str | None = None
) -> tuple[dict[str, object], list[dict[str, Any]]]:
    try:
        lock_bytes = path.read_bytes()
        if expected_sha256 is not None:
            if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                raise SnapshotError("trusted lock SHA-256 must be 64 lowercase hex characters")
            if not secrets.compare_digest(hashlib.sha256(lock_bytes).hexdigest(), expected_sha256):
                raise SnapshotVerificationError("snapshot lock SHA-256 mismatch")
        payload = json.loads(lock_bytes.decode("utf-8"))
    except FileNotFoundError:
        raise SnapshotError(f"snapshot lock not found: {path}") from None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read snapshot lock: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("format_version") != FORMAT_VERSION or payload.get("corpus_version") != CORPUS_VERSION:
        raise SnapshotError("unsupported snapshot lock format")
    sources = payload.get("sources")
    if not isinstance(sources, list) or not all(isinstance(item, dict) for item in sources):
        raise SnapshotError("snapshot sources must be a list of objects")
    return payload, sources


def _validate_membership(staging: Path, records: list[dict[str, Any]]) -> None:
    declared = sorted((PurePosixPath(record["path"]) for record in records), key=str)
    for path in sorted(staging.rglob("*"), key=lambda item: item.relative_to(staging).as_posix()):
        relative = PurePosixPath(path.relative_to(staging).as_posix())
        if relative == PurePosixPath(POINTERS_NAME):
            if path.is_symlink() or not path.is_file():
                raise SnapshotVerificationError(f"snapshot has invalid {POINTERS_NAME}")
            continue
        inside = any(relative == shelf or relative.is_relative_to(shelf) for shelf in declared)
        ancestor = any(shelf.is_relative_to(relative) for shelf in declared)
        if inside:
            continue
        if ancestor and path.is_dir() and not path.is_symlink():
            continue
        raise SnapshotVerificationError(
            f"snapshot archive member is not declared by corpus.lock: {relative}"
        )


def _validate_record(record: dict[str, Any], staging: Path) -> dict[str, Any]:
    required = {
        "format_version": int, "corpus_version": int, "name": str, "host": str,
        "owner": str, "repo": str, "commit_sha": str, "path": str,
        "fetched_at": str, "spec": str, "tree_sha": str,
    }
    if any(not isinstance(record.get(field), expected) for field, expected in required.items()):
        raise SnapshotError("snapshot source record has invalid fields")
    if record["format_version"] != FORMAT_VERSION or record["corpus_version"] != CORPUS_VERSION:
        raise SnapshotError("snapshot source record has an unsupported version")
    relative = PurePosixPath(record["path"])
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.parts
        or relative.as_posix() != record["path"]
    ):
        raise SnapshotError(f"invalid snapshot shelf path: {record['path']!r}")
    target = staging.joinpath(*relative.parts)
    if target.is_symlink() or not target.is_dir():
        raise SnapshotVerificationError(f"invalid imported source tree: {record['path']}")
    manifest = read_valid_manifest(
        target, record["owner"], record["repo"], record["commit_sha"], host=record["host"]
    )
    if manifest is None:
        raise SnapshotVerificationError(f"invalid imported manifest: {record['path']}")
    for field in ("spec", "version_source", "artifact_kind", "artifact_checksum"):
        if record.get(field) != manifest.get(field):
            raise SnapshotVerificationError(f"snapshot {field} mismatch: {record['path']}")
    actual_tree_sha = tree_sha(target)
    if actual_tree_sha != record["tree_sha"]:
        raise SnapshotVerificationError(f"snapshot tree SHA mismatch: {record['path']}")
    return {
        field: record[field]
        for field in ("name", "host", "owner", "repo", "commit_sha", "path", "fetched_at")
    } | ({"verified": record["verified"]} if "verified" in record else {})


def import_corpus(
    lock: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
    expected_lock_sha256: str | None = None,
    allow_unverified_lock: bool = False,
) -> list[dict[str, Any]]:
    """Verify every snapshot source before installing any of them.

    The lock file itself must normally be bound to an externally trusted
    SHA-256 digest.  Callers deliberately accepting an untrusted lock must opt
    out explicitly with ``allow_unverified_lock=True``.
    """
    if not isinstance(allow_unverified_lock, bool):
        raise TypeError("allow_unverified_lock must be a bool")
    if expected_lock_sha256 is None and not allow_unverified_lock:
        raise SnapshotVerificationError(
            "expected_lock_sha256 is required unless allow_unverified_lock=True"
        )
    lock_path = Path(lock).expanduser().absolute()
    payload, records = _load_lock(lock_path, expected_lock_sha256)
    tarball_name = payload.get("tarball")
    if not isinstance(tarball_name, str) or Path(tarball_name).name != tarball_name:
        raise SnapshotError("snapshot tarball must be an adjacent file name")
    tarball = lock_path.parent / tarball_name
    try:
        data = tarball.read_bytes()
    except FileNotFoundError:
        raise SnapshotError(f"snapshot tarball not found: {tarball}") from None
    expected_tarball_sha256 = payload.get("tarball_sha256")
    if not isinstance(expected_tarball_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_tarball_sha256
    ):
        raise SnapshotVerificationError("snapshot lock has no valid tarball_sha256")
    if not secrets.compare_digest(hashlib.sha256(data).hexdigest(), expected_tarball_sha256):
        raise SnapshotVerificationError("snapshot tarball SHA-256 mismatch")
    staging = Path(tempfile.mkdtemp(prefix="leitir-snapshot-import-"))
    try:
        _extract_tarball(data, staging, "snapshot", "0" * 40, archive_root=ARCHIVE_ROOT)
        pointers_hash = payload.get("pointers_sha256")
        pointers_path = staging / POINTERS_NAME
        if not isinstance(pointers_hash, str) or not pointers_path.is_file():
            raise SnapshotVerificationError(f"snapshot is missing valid {POINTERS_NAME} metadata")
        if hashlib.sha256(pointers_path.read_bytes()).hexdigest() != pointers_hash:
            raise SnapshotVerificationError(f"snapshot {POINTERS_NAME} checksum mismatch")
        entries = [_validate_record(record, staging) for record in records]
        paths = [entry["path"] for entry in entries]
        if len(paths) != len(set(paths)):
            raise SnapshotError("snapshot contains duplicate shelf paths")
        path_parts = [PurePosixPath(path).parts for path in paths]
        if any(
            left != right and left == right[: len(left)]
            for left in path_parts
            for right in path_parts
        ):
            raise SnapshotError("snapshot contains overlapping shelf paths")
        _validate_membership(staging, records)
        shelve_imported_sources(staging, root, entries, pointers_name=POINTERS_NAME)
        return entries
    finally:
        shutil.rmtree(staging, ignore_errors=True)
