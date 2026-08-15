"""Explicit deterministic construction of local trigram index shelves."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from leitir.index.postings import build_postings
from leitir.index.verify import (
    INDEX_ROOT_NAME,
    SCHEMA_VERSION,
    IndexDocument,
    ShelfRef,
    _digest,
    _git_blob_sha,
    _read_regular,
    canonical_json,
    index_shelf_path,
    require_eligible,
)
from leitir.materialize import (
    VerificationError,
    _file_lock,
    _fsync_directory,
    _target_lock,
    read_valid_manifest,
    target_path,
)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        raise


def _source_documents(target: Path, shelf: ShelfRef) -> tuple[tuple[IndexDocument, bytes], ...]:
    records: list[tuple[IndexDocument, bytes]] = []
    try:
        paths = sorted(target.rglob("*"), key=lambda path: path.relative_to(target).as_posix())
        for path in paths:
            relative = path.relative_to(target).as_posix()
            metadata = path.lstat()
            if path == target / "leitir-manifest.json":
                continue
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"source tree contains unsafe index document: {relative}")
            if not path.resolve().is_relative_to(target.resolve()):
                raise VerificationError(f"source document escapes shelf: {relative}")
            data = path.read_bytes()
            records.append(
                (
                    IndexDocument(
                        shelf.host, shelf.owner, shelf.repo, shelf.commit, relative, _git_blob_sha(data), len(data)
                    ),
                    data,
                )
            )
    except OSError as exc:
        raise VerificationError("cannot safely enumerate materialized shelf") from exc
    records.sort(key=lambda item: item[0].identity())
    return tuple(records)


def _update_catalog(root: Path, shelf: ShelfRef, metadata: dict[str, object]) -> None:
    index_root = root / INDEX_ROOT_NAME
    index_root.mkdir(parents=True, exist_ok=True)
    catalog_path = index_root / "manifest.json"
    with _file_lock(index_root / ".manifest.lock"):
        shelves: list[dict[str, object]] = []
        try:
            payload = json.loads(catalog_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION or not isinstance(payload.get("shelves"), list):
                raise VerificationError("unsupported or malformed top-level index manifest")
            shelves = [dict(item) for item in payload["shelves"] if isinstance(item, dict)]
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise VerificationError("cannot read top-level index manifest") from exc
        identity = metadata["shelf"]
        shelves = [item for item in shelves if item.get("shelf") != identity]
        shelves.append({"index_sha256": metadata["index_sha256"], "shelf": identity})
        shelves.sort(key=lambda item: tuple(str(item["shelf"][key]) for key in ("host", "owner", "repo", "commit")))  # type: ignore[index]
        _atomic_write(catalog_path, canonical_json({"schema_version": SCHEMA_VERSION, "shelves": shelves}))


def build_shelf_index(root: Path, shelf: ShelfRef) -> Path:
    """Build or explicitly replace one index shelf while holding its target lock."""
    root = root.expanduser().absolute()
    target = target_path(root, shelf.owner, shelf.repo, shelf.commit, host=shelf.host)
    with _target_lock(root, target, shelf.commit):
        source_manifest = read_valid_manifest(target, shelf.owner, shelf.repo, shelf.commit, host=shelf.host)
        if source_manifest is None:
            raise VerificationError("materialized shelf failed load-time verification")
        require_eligible(source_manifest)
        records = _source_documents(target, shelf)
        documents = [document.to_dict() for document, _data in records]
        postings = build_postings(data for _document, data in records)
        index_payload = {"documents": documents, "postings": postings, "schema_version": SCHEMA_VERSION}
        index_bytes = canonical_json(index_payload)
        source_manifest_bytes = _read_regular(target / "leitir-manifest.json")
        identity = {"host": shelf.host, "owner": shelf.owner, "repo": shelf.repo, "commit": shelf.commit}
        metadata: dict[str, object] = {
            "build_parameters": {"gram_bytes": 3, "path_encoding": "utf-8"},
            "document_table_sha256": _digest(documents),
            "index_byte_length": len(index_bytes),
            "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
            "postings_sha256": _digest(postings),
            "schema_version": SCHEMA_VERSION,
            "shelf": identity,
            "source_manifest_sha256": hashlib.sha256(source_manifest_bytes).hexdigest(),
            "source_tree_hash": source_manifest["materialized_tree_hash"],
        }
        directory = index_shelf_path(root, shelf)
        directory.mkdir(parents=True, exist_ok=True)
        # Recheck every parent after creation so a pre-existing symlink cannot
        # redirect atomic publication outside the corpus index root.
        directory = index_shelf_path(root, shelf)
        _atomic_write(directory / "index.json", index_bytes)
        _atomic_write(directory / "manifest.json", canonical_json(metadata))
        _update_catalog(root, shelf, metadata)
        return directory / "index.json"


def ineligible_shelf_conditions(root: Path, shelf: ShelfRef) -> tuple[str, ...]:
    """Return the named eligibility conditions a verified shelf does not meet.

    A missing or invalid manifest is an operational error rather than an
    eligibility result: callers must not turn failed load-time verification into
    a skippable shelf.
    """

    root = root.expanduser().absolute()
    target = target_path(root, shelf.owner, shelf.repo, shelf.commit, host=shelf.host)
    with _target_lock(root, target, shelf.commit):
        manifest = read_valid_manifest(
            target, shelf.owner, shelf.repo, shelf.commit, host=shelf.host
        )
    if manifest is None:
        raise VerificationError("materialized shelf failed load-time verification")
    conditions: list[str] = []
    if manifest.get("source") != "git-commit":
        conditions.append("source")
    if manifest.get("parity") != "exact":
        conditions.append("parity")
    if manifest.get("materialized_tree_hash_scope") != "full":
        conditions.append("scope")
    return tuple(conditions)


def shelves_from_corpus(root: Path, selectors: tuple[str, ...] = ()) -> tuple[ShelfRef, ...]:
    """Resolve deterministic shelf identities from the corpus source catalog."""
    from leitir.corpus import load_sources

    selected: list[ShelfRef] = []
    for entry in load_sources(root):
        shelf = ShelfRef(entry["host"], entry["owner"], entry["repo"], entry["commit_sha"])
        aliases = {
            str(entry.get("name", "")), str(entry.get("spec", "")), shelf.slug,
            f"{shelf.slug}@{shelf.commit}", f"{shelf.host}:{shelf.slug}@{shelf.commit}",
        }
        if not selectors or any(selector in aliases for selector in selectors):
            selected.append(shelf)
    result = tuple(sorted(set(selected)))
    if selectors and len(result) == 0:
        raise VerificationError("no materialized shelves match the requested index scope")
    return result


__all__ = [
    "ShelfRef",
    "build_shelf_index",
    "ineligible_shelf_conditions",
    "shelves_from_corpus",
]
