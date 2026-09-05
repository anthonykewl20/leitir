"""Fail-closed verification and lock lifetime for local index shelves."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from leitir.materialize import VerificationError, _target_lock, read_valid_manifest, target_path

SCHEMA_VERSION = 1
INDEX_ROOT_NAME = ".search-index"


@dataclass(frozen=True, slots=True, order=True)
class ShelfRef:
    host: str
    owner: str
    repo: str
    commit: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True, slots=True)
class IndexDocument:
    host: str
    owner: str
    repo: str
    commit: str
    path: str
    blob_sha: str
    size: int

    def identity(self) -> tuple[str, str, str, str, str, str]:
        return (self.host, self.owner, self.repo, self.commit, self.path, self.blob_sha)

    def to_dict(self) -> dict[str, object]:
        return {
            "blob_sha": self.blob_sha,
            "commit": self.commit,
            "host": self.host,
            "owner": self.owner,
            "path": self.path,
            "repo": self.repo,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class VerifiedIndexShelf:
    shelf: ShelfRef
    target: Path
    documents: tuple[IndexDocument, ...]
    postings: dict[str, tuple[int, ...]]

    def read_document(self, document: IndexDocument) -> bytes:
        data = _read_source_blob(self.target, document.path)
        if len(data) != document.size or _git_blob_sha(data) != document.blob_sha:
            raise VerificationError(f"indexed source bytes changed: {document.path}")
        return data


def _read_source_blob(target: Path, relative: str) -> bytes:
    """Read Git blob bytes: a symbolic link's bytes are its link text.

    Never traverse a link, including a parent component. The verified source
    tree and document digest bind these bytes, as for regular documents.
    """
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or ".." in parts:
        raise VerificationError("unsafe indexed source path")
    path = target
    try:
        for component in parts[:-1]:
            path /= component
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise VerificationError("indexed source parent is not a directory")
        path /= parts[-1]
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            data = os.fsencode(os.readlink(path))
            after = path.lstat()
            if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise VerificationError("indexed symbolic link changed while reading")
            return data
        return _read_regular(path)
    except OSError as exc:
        raise VerificationError(f"cannot read indexed source: {relative}") from exc


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()


def index_shelf_path(root: Path, shelf: ShelfRef) -> Path:
    # target_path performs the repository identity validation used by materialization.
    root = root.expanduser().absolute()
    target_path(root, shelf.owner, shelf.repo, shelf.commit, host=shelf.host)
    candidate = root / INDEX_ROOT_NAME / shelf.host / shelf.owner / shelf.repo / shelf.commit
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise VerificationError(f"index path contains a symbolic link: {current}")
    return candidate


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def require_eligible(manifest: Mapping[str, object]) -> None:
    if not (
        manifest.get("source") == "git-commit"
        and manifest.get("parity") == "exact"
        and manifest.get("materialized_tree_hash_scope") == "full"
    ):
        raise VerificationError("materialized shelf is not eligible for indexed search")


def _read_regular(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise VerificationError(f"index artifact is not a regular file: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            current = os.fstat(fd)
            if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise VerificationError(f"index artifact changed while opening: {path}")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                return handle.read()
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError as exc:
        raise VerificationError(f"cannot safely read index artifact: {path}") from exc


def _object(payload: object, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return payload


def _documents(payload: object, shelf: ShelfRef) -> tuple[IndexDocument, ...]:
    if not isinstance(payload, list):
        raise VerificationError("index document table must be a list")
    documents: list[IndexDocument] = []
    for raw in payload:
        item = _object(raw, "index document")
        if set(item) != {"blob_sha", "commit", "host", "owner", "path", "repo", "size"}:
            raise VerificationError("index document has an invalid shape")
        if (
            any(not isinstance(item[field], str) for field in ("host", "owner", "repo", "commit", "path", "blob_sha"))
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
        ):
            raise VerificationError("index document has invalid field types")
        document = IndexDocument(
            host=item["host"], owner=item["owner"], repo=item["repo"], commit=item["commit"],
            path=item["path"], blob_sha=item["blob_sha"], size=item["size"],
        )
        relative = Path(document.path)
        if (
            document.identity()[:4] != (shelf.host, shelf.owner, shelf.repo, shelf.commit)
            or not isinstance(document.path, str)
            or not document.path
            or "\0" in document.path
            or relative.is_absolute()
            or ".." in relative.parts
            or not isinstance(document.blob_sha, str)
            or len(document.blob_sha) != 40
            or any(char not in "0123456789abcdef" for char in document.blob_sha)
            or document.size < 0
        ):
            raise VerificationError("index document identity is invalid")
        documents.append(document)
    if tuple(document.identity() for document in documents) != tuple(sorted(document.identity() for document in documents)):
        raise VerificationError("index document table is not deterministically sorted")
    if len({document.identity() for document in documents}) != len(documents):
        raise VerificationError("index document table contains duplicates")
    return tuple(documents)


def _postings(payload: object, document_count: int) -> dict[str, tuple[int, ...]]:
    if not isinstance(payload, dict):
        raise VerificationError("postings must be an object")
    result: dict[str, tuple[int, ...]] = {}
    if list(payload) != sorted(payload):
        raise VerificationError("postings keys are not sorted")
    for gram, values in payload.items():
        if not isinstance(gram, str) or len(gram) != 6 or any(char not in "0123456789abcdef" for char in gram):
            raise VerificationError("postings contains an invalid trigram")
        if not isinstance(values, list) or any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise VerificationError("posting list contains an invalid document id")
        if values != sorted(set(values)) or any(value < 0 or value >= document_count for value in values):
            raise VerificationError("posting list is not sorted, unique, and in range")
        result[gram] = tuple(values)
    return result


@contextmanager
def open_verified_shelf(root: Path, shelf: ShelfRef) -> Iterator[VerifiedIndexShelf]:
    """Yield a shelf while retaining its materialization lock for all reads."""
    root = root.expanduser().absolute()
    target = target_path(root, shelf.owner, shelf.repo, shelf.commit, host=shelf.host)
    with _target_lock(root, target, shelf.commit):
        source_manifest = read_valid_manifest(target, shelf.owner, shelf.repo, shelf.commit, host=shelf.host)
        if source_manifest is None:
            raise VerificationError("materialized shelf failed load-time verification")
        require_eligible(source_manifest)
        directory = index_shelf_path(root, shelf)
        manifest_bytes = _read_regular(directory / "manifest.json")
        index_bytes = _read_regular(directory / "index.json")
        try:
            metadata = _object(json.loads(manifest_bytes), "index manifest")
            index = _object(json.loads(index_bytes), "index")
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise VerificationError("index artifact is malformed JSON") from exc
        if metadata.get("schema_version") != SCHEMA_VERSION or index.get("schema_version") != SCHEMA_VERSION:
            raise VerificationError("unsupported index schema_version")
        identity = {"host": shelf.host, "owner": shelf.owner, "repo": shelf.repo, "commit": shelf.commit}
        if metadata.get("shelf") != identity:
            raise VerificationError("index shelf identity mismatch")
        try:
            catalog = _object(
                json.loads(_read_regular(root / INDEX_ROOT_NAME / "manifest.json")),
                "top-level index manifest",
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise VerificationError("top-level index manifest is malformed JSON") from exc
        if catalog.get("schema_version") != SCHEMA_VERSION or not isinstance(catalog.get("shelves"), list):
            raise VerificationError("unsupported top-level index schema_version")
        catalog_records = [
            item
            for item in catalog["shelves"]
            if isinstance(item, dict) and item.get("shelf") == identity
        ]
        if len(catalog_records) != 1 or catalog_records[0].get("index_sha256") != metadata.get("index_sha256"):
            raise VerificationError("top-level index manifest binding mismatch")
        documents = _documents(index.get("documents"), shelf)
        postings = _postings(index.get("postings"), len(documents))
        source_bytes = _read_regular(target / "leitir-manifest.json")
        checks = (
            (metadata.get("source_manifest_sha256"), hashlib.sha256(source_bytes).hexdigest()),
            (metadata.get("source_tree_hash"), source_manifest.get("materialized_tree_hash")),
            (metadata.get("document_table_sha256"), _digest(index.get("documents"))),
            (metadata.get("postings_sha256"), _digest(index.get("postings"))),
            (metadata.get("index_sha256"), hashlib.sha256(index_bytes).hexdigest()),
            (metadata.get("index_byte_length"), len(index_bytes)),
            (metadata.get("build_parameters"), {"gram_bytes": 3, "path_encoding": "utf-8"}),
        )
        if any(actual != expected for actual, expected in checks):
            raise VerificationError("index manifest binding mismatch")
        yield VerifiedIndexShelf(shelf, target, documents, postings)
