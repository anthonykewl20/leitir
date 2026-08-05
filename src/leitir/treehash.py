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

Verified shelves must carry this digest. Legacy shelves can be upgraded with
``leitir upgrade-cache`` before they are loaded by normal corpus operations.

Residual I/O cost (tracked in issue #20)
---------------------------------------
The content-derived ordering used for sampling requires reading each candidate
file once to compute its per-file SHA-256. The selected *summary* is bounded
by ``MAX_BYTES``, but the *initial scan* is O(total tree bytes). For a tree
of 100k files at 1 GiB total, verify cost is ~1 GiB of reads even though only
~64 MiB enters the summary. This is accepted for prototype-scale corpora; the
alternatives (path-derived ordering, signed sidecar index, trusted-mtime cache)
each weaken the threat model or add complexity that is not yet justified.
Issue #20 tracks the revisit if benchmarks show this matters in practice.

References
----------
* Go ``Hash1``: ``sumdb/dirhash/hash.go`` of ``golang.org/x/mod``
  (verbatim source fetched via ``leitir get go:golang.org/x/mod``).
* npm ``ssri``: integrity-string parsing for archive digests.
* pip ``Hashes.check_against_chunks``: streamed re-hash of cached downloads.
* Cargo directory source ``.cargo-checksum.json``: per-file map verified on
  every build (we centralize on the cheaper aggregate form).

Stdlib-only, deterministic, PYTHONHASHSEED-independent, fails closed.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import stat
from pathlib import Path, PurePosixPath
from typing import Iterable

# Public algorithm identifier stored alongside the digest so future formats
# (e.g. one that includes modes or empty directories) can coexist.
TREE_HASH_ALGORITHM = "dirhash-h1-sha256-v1"

# Wire prefix; intentionally matches Go's ``h1:`` so anyone reading the manifest
# can recognize the format without leitir-specific documentation.
TREE_HASH_PREFIX = "h1:"

MAX_FILES = 1_000
MAX_BYTES = 64 * 1024 * 1024  # 64 MiB
SAMPLED = "sampled"
FULL = "full"

# Streaming chunk size; bounded memory regardless of file size.
_CHUNK = 1024 * 1024


class TreeHashError(Exception):
    """Base class for materialized-tree hash failures."""


class TreeHashFormatError(TreeHashError):
    """The stored ``materialized_tree_hash`` is missing or malformed."""


class TreeHashMismatchError(TreeHashError):
    """The recomputed digest does not equal the stored digest."""


class TreeHashStructureError(TreeHashError):
    """The tree is unreadable or contains an unsupported entry."""


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
        entries: list[tuple[str, bytes, str, bytes | None, int]] = []
        total_bytes = 0
        for relative, absolute, is_symlink in _sorted_regular_files(root):
            relative_bytes = _strict_utf8(relative)
            entry_digest = hashlib.sha256()
            linkname_bytes: bytes | None = None
            if is_symlink:
                try:
                    linkname = os.readlink(absolute)
                    linkname_bytes = linkname.encode("utf-8", errors="strict")
                except UnicodeEncodeError as exc:
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
                    with absolute.open("rb") as handle:
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
            digest_hex = entry_digest.hexdigest()
            total_bytes += size
            entries.append((relative, relative_bytes, digest_hex, linkname_bytes, size))

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

        summary = hashlib.sha256()
        for relative, relative_bytes, digest_hex, linkname_bytes, _size in sorted(
            selected, key=lambda entry: entry[0]
        ):
            summary.update(digest_hex.encode("ascii"))
            if linkname_bytes is not None:
                summary.update(b" -> ")
                summary.update(linkname_bytes)
            summary.update(b"  ")
            summary.update(relative_bytes)
            summary.update(b"\n")
        digest = TREE_HASH_PREFIX + base64.standard_b64encode(summary.digest()).decode("ascii")
        return digest, scope
    except TreeHashError:
        raise
    except Exception as exc:
        raise TreeHashStructureError(
            f"cannot hash materialized tree safely: {root} ({exc})"
        ) from exc


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
    if not isinstance(expected, str) or not expected.startswith(TREE_HASH_PREFIX):
        raise TreeHashFormatError(
            "materialized_tree_hash must be an 'h1:'-prefixed base64 string"
        )
    encoded = expected[len(TREE_HASH_PREFIX):]
    try:
        # Strict round-trip: standard_b64encode(b64decode(x, validate=True)) == x
        # enforces canonical alphabet (+ and /) and rejects embedded whitespace.
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise TreeHashFormatError(f"materialized_tree_hash is not valid base64: {exc}") from exc
    if base64.standard_b64encode(decoded) != encoded.encode("ascii"):
        raise TreeHashFormatError(
            "materialized_tree_hash is not in canonical base64 form"
        )

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


def _sorted_regular_files(root: Path) -> Iterable[tuple[str, Path, bool]]:
    """Yield sorted path entries, with a flag identifying symbolic links.

    Excludes only the root-level manifest.  Sorting happens on the POSIX form
    so the digest is identical on POSIX and Windows for the same tree.
    """
    entries: list[tuple[str, Path, bool]] = []

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
                entries.append((rel, full, True))
                dirnames.remove(dirname)

        for filename in filenames:
            full = Path(dirpath) / filename
            relative = _posix_relative(root, full)

            # Exclude only the root-level manifest.
            if relative == "leitir-manifest.json" and Path(dirpath) == root:
                continue

            _validate_relative(relative)

            try:
                st = full.lstat()
            except OSError as exc:
                raise TreeHashStructureError(
                    f"cannot stat entry in materialized tree: {relative} ({exc})"
                ) from exc

            if stat.S_ISLNK(st.st_mode):
                entries.append((relative, full, True))
            elif not stat.S_ISREG(st.st_mode):
                raise TreeHashStructureError(
                    f"non-regular entry in materialized tree: {relative}"
                )
            else:
                entries.append((relative, full, False))

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
            "path or linkname contains non-UTF-8 bytes "
            f"(unsupported): {value!r}"
        ) from exc


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
