"""Deterministic materialized-tree hashing for load-time cache verification.

The corpus-on-disk model in :mod:`leitir.materialize` writes an immutable
provenance manifest per shelved source, but the original implementation only
verified the *downloaded archive* (registry checksum) or *fetched Git tree* at
write time.  On every subsequent cache hit it returned the shelved bytes as
``verified`` without re-hashing them, so any post-materialization mutation
(bit rot, accidental edit, sync conflict, attacker with cache write access)
was silently served as a trusted source.

This module implements a load-time integrity check using the Go ``Hash1`` line
format (``h1:`` directory hash from ``golang.org/x/mod/sumdb/dirhash``). Leitir
hashes paths relative to the shelf root, equivalent to ``HashDir(dir, "",
Hash1)``, so digests are NOT equal to ``go mod verify`` output for the same
files. This is by design: leitir's digest is an internal cache-integrity anchor,
not a Go interoperability token. We compute a single SHA-256 over a
deterministic summary of every regular file and symbolic link under the shelf
root, excluding the manifest itself.  The digest is stored in the
manifest as ``materialized_tree_hash`` and recomputed on every load.  Any
mismatch, malformed digest, or unsupported entry type causes
``verify_materialized_tree_hash`` to raise and the caller treats the entry as
an invalid cache (fail-closed).

Regular files use the Go ``Hash1`` line format. Symbolic links use a distinct
extension: ``hex(sha256(linkname_bytes)) + " -> " + linkname + "  " + path +
"\\n"``. Both path and link target must be strict UTF-8 and may not contain a
newline. Hashing the link target itself (without following it) makes link loops
irrelevant and prevents links from colliding with regular-file records.

Algorithm (matches Go ``Hash1`` line format for regular files):

    summary = b""
    for path in sorted(regular_files_under(root), key=posix_form):
        summary += hex(sha256(file_bytes)).encode("ascii")
        summary += b"  "                # two spaces (U+0020 U+0020)
        summary += posix_form(path).encode("utf-8")
        summary += b"\n"               # one LF (U+000A)
    digest = sha256(summary)
    materialized_tree_hash = "h1:" + base64.standard(digest)

Bounds and sampling
-------------------
Trees of at most :data:`MAX_FILES` files/links and :data:`MAX_BYTES` bytes
are hashed in full. A single entry is also full even when it alone exceeds the
byte cap, since the required at-least-one sample necessarily hashes it. Above
either cap otherwise, each entry's content (or symlink target) digest is used
with its POSIX path to form a deterministic SHA-256 ordering key. Entries are
selected greedily in that order while both caps permit, with at least one entry
selected from a non-empty tree, then summarized in path order. The manifest
records ``sampled`` separately from ``full`` so partial verification is never
represented as complete.

Per-file digest map (issue #194)
--------------------------------
Sampling bounds the *legacy aggregate* anchor, not load-time coverage.
Manifests written since issue #194 additionally carry
``materialized_file_digests`` — a flat Cargo-``.cargo-checksum.json``-style
map of POSIX path to the same per-entry SHA-256 digests the aggregate
summarizes — and their ``materialized_tree_hash`` is recorded at scope
``full`` regardless of the caps: every entry's digest enters the stored
aggregate, so the stored digest is a digest *of the map*. At load,
:func:`verify_file_digest_map` streams the tree once, compares every entry's
recomputed digest to the map, and compares the aggregate rebuilt from the
verified map to the stored anchor. A tampered map that is made consistent
with tampered bytes therefore still breaks the stored aggregate (which the
existing tree-hash and detached manifest-auth chains already protect), while
a tampered map alone fails the per-file comparison. The caps keep bounding
only ingest-time re-enumeration heuristics; they never bound the load-time
trust level of a map-carrying shelf.

Verified shelves must carry this digest. Legacy shelves can be upgraded with
``leitir upgrade-cache`` before they are loaded by normal corpus operations.

Residual I/O cost
-----------------
The content-derived ordering used for sampling requires reading each candidate
file once to compute its per-file SHA-256. The selected *summary* is bounded
by ``MAX_BYTES``, but the *initial scan* is O(total tree bytes). For a tree
of 100k files at 1 GiB total, verify cost is ~1 GiB of reads even though only
~64 MiB enters the summary. This is accepted for prototype-scale corpora; the
alternatives (path-derived ordering, signed sidecar index, trusted-mtime cache)
each weaken the threat model or add complexity that is not yet justified. Issue
#20 was closed with this cost deferred; a follow-up will be filed if benchmarks
at production scale show it matters in practice.

References
----------
* Go ``Hash1``: ``sumdb/dirhash/hash.go`` of ``golang.org/x/mod``
  (verbatim source fetched via ``leitir get go:golang.org/x/mod``).
* npm ``ssri``: integrity-string parsing for archive digests.
* pip ``Hashes.check_against_chunks``: streamed re-hash of cached downloads.
* Cargo directory source ``.cargo-checksum.json``: per-file map verified on
  every build (adopted for load-time full coverage by issue #194; see
  ``materialized_file_digests`` below — the aggregate remains the anchor).

Stdlib-only, deterministic, PYTHONHASHSEED-independent, fails closed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import BinaryIO

# Public algorithm identifier stored alongside the digest so future formats
# (e.g. one that includes modes or empty directories) can coexist.
TREE_HASH_ALGORITHM = "dirhash-h1-sha256-v1"

# Algorithm identifier of the flat per-file SHA-256 digest map (issue #194).
# Map values are exactly the per-entry digests that feed the full-scope
# aggregate: sha256(content) for regular files, sha256(linkname_bytes) for
# symbolic links. The stored full-scope ``materialized_tree_hash`` is a
# digest over the map's records, which anchors the map in the existing
# tree-hash (and detached manifest-auth) chain.
FILE_DIGEST_ALGORITHM = "per-file-sha256-v1"

# Wire prefix; intentionally matches Go's ``h1:`` so anyone reading the manifest
# can recognize the format without leitir-specific documentation.
TREE_HASH_PREFIX = "h1:"

MAX_FILES = 1_000
MAX_BYTES = 64 * 1024 * 1024  # 64 MiB
SAMPLED = "sampled"
FULL = "full"

# Streaming chunk size; bounded memory regardless of file size.
_CHUNK = 1024 * 1024

# Root-level manifest file name excluded from digests (and from the map).
_ROOT_MANIFEST_NAME = "leitir-manifest.json"

_HEX64 = re.compile(r"[0-9a-f]{64}")

# One scanned entry: (relative path, relative bytes, hex digest, linkname
# bytes or None for regular files, size in bytes).
_Entry = tuple[str, bytes, str, bytes | None, int]


class TreeHashError(Exception):
    """Base class for materialized-tree hash failures."""


class TreeHashFormatError(TreeHashError):
    """The stored ``materialized_tree_hash`` is missing or malformed."""


class TreeHashMismatchError(TreeHashError):
    """The recomputed digest does not equal the stored digest."""


class TreeHashStructureError(TreeHashError):
    """The tree is unreadable or contains an unsupported entry."""


def _scan_entries(root: Path) -> list[_Entry]:
    """One sorted streaming scan returning per-entry digests and metadata.

    Regular files contribute ``sha256(content)``; symbolic links contribute
    ``sha256(linkname_bytes)``.  Raises :class:`TreeHashStructureError` for
    unreadable trees and entries the line format cannot represent.
    """
    entries: list[_Entry] = []
    for relative, absolute, is_symlink, metadata in _sorted_regular_files(root):
        relative_bytes = _strict_utf8(relative)
        entry_digest = hashlib.sha256()
        linkname_bytes: bytes | None = None
        if is_symlink:
            try:
                # A bytes path makes os.readlink return the exact on-disk
                # bytes instead of decoding first with platform rules.
                raw_linkname = os.readlink(os.fsencode(absolute))
                linkname_bytes = _linkname_bytes(raw_linkname)
                if os.name == "nt":
                    # Windows exposes the NT substitution path for absolute
                    # links; hash the user-visible target used to create it.
                    if linkname_bytes.startswith(b"\\\\?\\UNC\\"):
                        linkname_bytes = b"\\\\" + linkname_bytes[8:]
                    elif linkname_bytes.startswith(b"\\\\?\\"):
                        linkname_bytes = linkname_bytes[4:]
                linkname = linkname_bytes.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise TreeHashStructureError(
                    "path or linkname contains non-UTF-8 bytes "
                    f"(unsupported): {relative!r}"
                ) from exc
            except OSError as exc:
                raise TreeHashStructureError(
                    f"cannot read entry in materialized tree: {relative} ({exc})"
                ) from exc
            if "\n" in linkname:
                raise TreeHashStructureError(
                    f"linkname contains a newline (unsupported): {relative!r}"
                )
            entry_digest.update(linkname_bytes)
            size = len(linkname_bytes)
        else:
            size = 0
            try:
                with _open_checked_regular_file(absolute, metadata) as handle:
                    while True:
                        chunk = handle.read(_CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        entry_digest.update(chunk)
            except OSError as exc:
                raise TreeHashStructureError(
                    f"cannot read entry in materialized tree: {relative} ({exc})"
                ) from exc
        entries.append(
            (relative, relative_bytes, entry_digest.hexdigest(), linkname_bytes, size)
        )
    return entries


def _summary_digest(entries: Iterable[_Entry]) -> str:
    """Hash sorted entries with the Go ``Hash1`` line format."""
    summary = hashlib.sha256()
    for _relative, relative_bytes, digest_hex, linkname_bytes, _size in sorted(
        entries, key=lambda entry: entry[0]
    ):
        summary.update(digest_hex.encode("ascii"))
        if linkname_bytes is not None:
            summary.update(b" -> ")
            summary.update(linkname_bytes)
        summary.update(b"  ")
        summary.update(relative_bytes)
        summary.update(b"\n")
    return TREE_HASH_PREFIX + base64.standard_b64encode(summary.digest()).decode(
        "ascii"
    )


def compute_materialized_tree_hash(
    root: Path, *, _force_full: bool = False
) -> tuple[str, str]:
    """Return the canonical ``h1:`` hash and sampling scope for ``root``.

    The manifest file (``leitir-manifest.json``) at the root is excluded so the
    digest can be stored *inside* the manifest without self-reference.  Sub-
    directory manifests of the same name are included.

    Raises
    ------
    TreeHashStructureError
        If the tree is unreadable, contains a special file, or has a path/link
        target that cannot be represented unambiguously in the line format.
    """
    try:
        root = Path(root)
        if not root.is_dir():
            raise TreeHashStructureError(f"not a directory: {root}")
        entries = _scan_entries(root)
        total_bytes = sum(entry[4] for entry in entries)

        natural_scope = (
            FULL
            if len(entries) <= MAX_FILES
            and (total_bytes <= MAX_BYTES or len(entries) <= 1)
            else SAMPLED
        )
        scope = FULL if _force_full else natural_scope
        selected = entries
        if scope == SAMPLED:
            ordered = sorted(
                entries,
                key=lambda entry: hashlib.sha256(
                    entry[2].encode("ascii") + b"\0" + entry[1]
                ).digest(),
            )
            selected = []
            selected_bytes = 0
            for entry in ordered:
                if len(selected) >= MAX_FILES:
                    break
                if selected_bytes + entry[4] <= MAX_BYTES:
                    selected.append(entry)
                    selected_bytes += entry[4]
            if not selected and ordered:
                selected.append(ordered[0])

        return _summary_digest(selected), scope
    except TreeHashError:
        raise
    except Exception as exc:
        raise TreeHashStructureError(
            f"cannot hash materialized tree safely: {root} ({exc})"
        ) from exc


def compute_file_digest_map(root: Path) -> dict[str, str]:
    """Return the flat per-file SHA-256 digest map for ``root``.

    Values are the per-entry digests :func:`compute_materialized_tree_hash`
    summarizes: ``sha256(content)`` for regular files and
    ``sha256(linkname_bytes)`` for symbolic links.  The root-level manifest is
    excluded, matching the aggregate.  Raises :class:`TreeHashStructureError`
    for the same unsupported trees as the aggregate computation.
    """
    try:
        root = Path(root)
        if not root.is_dir():
            raise TreeHashStructureError(f"not a directory: {root}")
        return {
            relative: digest_hex
            for relative, _relative_bytes, digest_hex, _linkname, _size in _scan_entries(
                root
            )
        }
    except TreeHashError:
        raise
    except Exception as exc:
        raise TreeHashStructureError(
            f"cannot hash materialized tree safely: {root} ({exc})"
        ) from exc


def file_map_manifest_fields(mapping: Mapping[str, str]) -> dict[str, object]:
    """Build the manifest fields recording a per-file digest map."""
    return {
        "materialized_file_digests_algorithm": FILE_DIGEST_ALGORITHM,
        "materialized_file_digests": dict(mapping),
    }


def full_coverage_manifest_fields(root: Path) -> dict[str, object]:
    """Return map plus full-scope aggregate fields from a single scan.

    The aggregate is always recorded at scope ``full``: every entry's digest
    enters it through the map, so the stored ``materialized_tree_hash`` is a
    digest over the map's records and anchors the map in the existing
    tree-hash chain (issue #194).  Below-cap shelves get the same digest value
    the legacy natural-scope computation produced, byte-identically.
    """
    try:
        root = Path(root)
        if not root.is_dir():
            raise TreeHashStructureError(f"not a directory: {root}")
        entries = _scan_entries(root)
    except TreeHashError:
        raise
    except Exception as exc:
        raise TreeHashStructureError(
            f"cannot hash materialized tree safely: {root} ({exc})"
        ) from exc
    fields: dict[str, object] = file_map_manifest_fields(
        {relative: digest_hex for relative, _rb, digest_hex, _lb, _size in entries}
    )
    fields.update(manifest_digest_fields(_summary_digest(entries), scope=FULL))
    return fields


def _validated_h1_digest(expected: object) -> str:
    """Validate an ``h1:`` digest string and return it unchanged."""
    if not isinstance(expected, str) or not expected.startswith(TREE_HASH_PREFIX):
        raise TreeHashFormatError(
            "materialized_tree_hash must be an 'h1:'-prefixed base64 string"
        )
    encoded = expected[len(TREE_HASH_PREFIX) :]
    try:
        # Strict round-trip: standard_b64encode(b64decode(x, validate=True)) == x
        # enforces canonical alphabet (+ and /) and rejects embedded whitespace.
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TreeHashFormatError(
            f"materialized_tree_hash is not valid base64: {exc}"
        ) from exc
    if base64.standard_b64encode(decoded) != encoded.encode("ascii"):
        raise TreeHashFormatError(
            "materialized_tree_hash is not in canonical base64 form"
        )
    return expected


def _validated_file_digest_map(expected_map: object) -> Mapping[str, str]:
    """Validate the stored map's shape; return it when well-formed."""
    if not isinstance(expected_map, Mapping):
        raise TreeHashFormatError(
            "materialized_file_digests must be an object mapping paths to "
            "SHA-256 digests"
        )
    # Key types are checked before sorting so a programmatically supplied
    # non-string key is a typed format error, never a raw TypeError.
    for path in expected_map:
        if not isinstance(path, str):
            raise TreeHashFormatError(
                f"invalid materialized_file_digests path: {path!r}"
            )
    for path, digest in sorted(expected_map.items()):
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or "\n" in path
            or path.startswith("/")
            or path == _ROOT_MANIFEST_NAME
            or any(segment in ("", ".", "..") for segment in path.split("/"))
        ):
            raise TreeHashFormatError(
                f"invalid materialized_file_digests path: {path!r}"
            )
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise TreeHashFormatError(
                f"invalid materialized_file_digests digest for path: {path!r}"
            )
    return expected_map


def verify_file_digest_map(
    root: Path,
    expected_map: object,
    *,
    algorithm: object = None,
    expected_tree_hash: object = None,
    tree_hash_algorithm: object = None,
    tree_hash_scope: object = None,
) -> None:
    """Verify every entry of ``root`` against the stored per-file digest map.

    One streaming pass recomputes each entry's digest, checks the disk
    universe against the map, compares every digest, and finally rebuilds the
    full-scope aggregate from the verified map and compares it (constant-time)
    to the stored ``materialized_tree_hash``.  That last step anchors the map
    in the existing tree-hash chain: a map rewritten to agree with tampered
    bytes no longer matches the stored aggregate, and a tampered aggregate no
    longer matches the map.

    Raises
    ------
    TreeHashFormatError
        If the map, its algorithm, or the anchored aggregate is missing or
        malformed, or the stored scope is not ``full``.
    TreeHashStructureError
        If the tree on disk contains unsupported entries or is unreadable.
    TreeHashMismatchError
        If any file's digest differs from the map, the disk/map universes
        differ, or the map does not match the anchored aggregate.  Mismatches
        name the offending path.
    """
    if algorithm != FILE_DIGEST_ALGORITHM:
        raise TreeHashFormatError(
            f"unsupported materialized_file_digests_algorithm: {algorithm!r}"
        )
    if tree_hash_algorithm is not None and tree_hash_algorithm != TREE_HASH_ALGORITHM:
        raise TreeHashFormatError(
            f"unsupported materialized_tree_hash_algorithm: {tree_hash_algorithm!r}"
        )
    if tree_hash_scope != FULL:
        raise TreeHashFormatError(
            "a manifest carrying materialized_file_digests must anchor a "
            f"full-scope materialized_tree_hash (stored {tree_hash_scope!r})"
        )
    expected = _validated_h1_digest(expected_tree_hash)
    validated_map = _validated_file_digest_map(expected_map)
    try:
        root = Path(root)
        if not root.is_dir():
            raise TreeHashStructureError(f"not a directory: {root}")
        entries = _scan_entries(root)
    except TreeHashError:
        raise
    except Exception as exc:
        raise TreeHashStructureError(
            f"cannot hash materialized tree safely: {root} ({exc})"
        ) from exc

    disk = {
        relative: digest_hex
        for relative, _rb, digest_hex, _lb, _size in entries
    }
    missing = sorted(set(validated_map) - set(disk))
    if missing:
        raise TreeHashMismatchError(
            f"file listed in the digest map is absent from the shelf: {missing[0]}"
        )
    unexpected = sorted(set(disk) - set(validated_map))
    if unexpected:
        raise TreeHashMismatchError(
            f"unexpected file on disk is absent from the digest map: {unexpected[0]}"
        )
    for relative in sorted(disk):
        if not secrets.compare_digest(disk[relative], validated_map[relative]):
            raise TreeHashMismatchError(
                f"materialized file digest mismatch: {relative}"
            )
    if not secrets.compare_digest(_summary_digest(entries), expected):
        raise TreeHashMismatchError(
            "materialized file digest map does not match the anchored "
            "materialized_tree_hash; refusing to serve tampered bytes"
        )


def verify_materialized_tree_hash(
    root: Path, expected: object, *, algorithm: object = None, scope: object = FULL
) -> None:
    """Recompute the tree hash under ``root`` and compare to ``expected``.

    Fail-closed on every pathological input: ``None``, non-string, missing
    prefix, wrong algorithm, malformed base64, symlink/special file in the
    tree, or any byte mismatch.  Constant-time comparison guards against
    timing leakage of the digest on multi-tenant hosts.

    Raises
    ------
    TreeHashFormatError
        If ``expected`` is not a valid ``h1:`` digest string.
    TreeHashStructureError
        If the tree on disk contains unsupported entries.
    TreeHashMismatchError
        If the recomputed digest differs from ``expected``.
    """
    if algorithm is not None and algorithm != TREE_HASH_ALGORITHM:
        raise TreeHashFormatError(
            f"unsupported materialized_tree_hash_algorithm: {algorithm!r}"
        )
    if scope not in (FULL, SAMPLED):
        raise TreeHashFormatError(
            f"unsupported materialized_tree_hash_scope: {scope!r}"
        )
    expected = _validated_h1_digest(expected)

    actual, actual_scope = compute_materialized_tree_hash(root)
    if actual_scope != scope:
        # Scope-less v1 manifests are interpreted as FULL and may describe a
        # tree that now crosses the sampling caps. Preserve their full digest,
        # but reject a sampled digest falsely presented as full.
        if scope == FULL and actual_scope == SAMPLED:
            if secrets.compare_digest(actual, expected):
                raise TreeHashFormatError(
                    "a sampled materialized_tree_hash scope cannot be verified as full"
                )
            actual, _forced_scope = compute_materialized_tree_hash(
                root, _force_full=True
            )
        else:
            raise TreeHashFormatError(
                "materialized_tree_hash_scope does not match the deterministic "
                f"tree scope: stored {scope!r}, computed {actual_scope!r}"
            )
    if not secrets.compare_digest(actual, expected):
        raise TreeHashMismatchError(
            "materialized tree hash mismatch: cache contents do not match the "
            "pinned manifest digest; refusing to serve tampered bytes"
        )


def manifest_digest_fields(value: str, *, scope: str = FULL) -> dict[str, str]:
    """Build the algorithm, digest, and full-or-sampled manifest fields."""
    if scope not in (FULL, SAMPLED):
        raise ValueError(f"unsupported materialized tree hash scope: {scope!r}")
    return {
        "materialized_tree_hash_algorithm": TREE_HASH_ALGORITHM,
        "materialized_tree_hash": value,
        "materialized_tree_hash_scope": scope,
    }


def _open_checked_regular_file(path: Path, expected: os.stat_result) -> BinaryIO:
    """Open the exact regular inode previously inspected, without following links."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        actual = os.fstat(fd)
        if (
            not stat.S_ISREG(actual.st_mode)
            or actual.st_dev != expected.st_dev
            or actual.st_ino != expected.st_ino
        ):
            raise OSError("entry changed between lstat and open")
        handle = os.fdopen(fd, "rb")
        fd = -1
        return handle
    except Exception:
        if fd >= 0:
            os.close(fd)
        raise


def _sorted_regular_files(
    root: Path,
) -> Iterable[tuple[str, Path, bool, os.stat_result]]:
    """Yield sorted path entries, with a flag identifying symbolic links.

    Excludes only the root-level manifest.  Sorting happens on the POSIX form
    so the digest is identical on POSIX and Windows for the same tree.
    """
    entries: list[tuple[str, Path, bool, os.stat_result]] = []

    def walk_error(exc: OSError) -> None:
        raise TreeHashStructureError(
            f"cannot read entry in materialized tree: {exc.filename or root} ({exc})"
        ) from exc

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, onerror=walk_error, followlinks=False
    ):
        # Stabilize traversal order independent of filesystem enumeration.
        dirnames.sort()
        filenames.sort()

        # Symlinked directories are records, not traversal roots.
        for dirname in list(dirnames):
            full = Path(dirpath) / dirname
            if full.is_symlink():
                rel = _posix_relative(root, full)
                _validate_relative(rel)
                try:
                    metadata = full.lstat()
                except OSError as exc:
                    raise TreeHashStructureError(
                        f"cannot stat entry in materialized tree: {rel} ({exc})"
                    ) from exc
                entries.append((rel, full, True, metadata))
                dirnames.remove(dirname)

        for filename in filenames:
            full = Path(dirpath) / filename
            relative = _posix_relative(root, full)

            # Exclude only the root-level manifest.
            if relative == _ROOT_MANIFEST_NAME and Path(dirpath) == root:
                continue

            _validate_relative(relative)

            try:
                st = full.lstat()
            except OSError as exc:
                raise TreeHashStructureError(
                    f"cannot stat entry in materialized tree: {relative} ({exc})"
                ) from exc

            if stat.S_ISLNK(st.st_mode):
                entries.append((relative, full, True, st))
            elif not stat.S_ISREG(st.st_mode):
                raise TreeHashStructureError(
                    f"non-regular entry in materialized tree: {relative}"
                )
            else:
                entries.append((relative, full, False, st))

    entries.sort(key=lambda item: item[0])
    return entries


def _posix_relative(root: Path, path: Path) -> str:
    rel = Path(path).relative_to(root)
    return PurePosixPath(*rel.parts).as_posix()


def _strict_utf8(value: str) -> bytes:
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise TreeHashStructureError(
            f"path or linkname contains non-UTF-8 bytes (unsupported): {value!r}"
        ) from exc


def _linkname_bytes(value: str | bytes) -> bytes:
    """Preserve bytes-path readlink output and support injected test doubles."""
    return value.encode("utf-8", errors="strict") if isinstance(value, str) else value


def _validate_relative(relative: str) -> None:
    _strict_utf8(relative)
    if "\n" in relative:
        raise TreeHashStructureError(
            f"path contains a newline (unsupported): {relative!r}"
        )


if __name__ == "__main__":  # pragma: no cover - CLI smoke
    import sys

    target = Path(sys.argv[1])
    digest, scope = compute_materialized_tree_hash(target)
    print(digest, scope)
