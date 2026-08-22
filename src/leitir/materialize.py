"""Safely materialize and verify an immutable hosted source tree.

Verification hashes every extracted regular file when both the file count and
aggregate byte size are within :data:`VERIFY_MAX_FILES` and
:data:`VERIFY_MAX_BYTES`.  Above either cap, files are ordered by SHA-256 of
``<commit SHA>\0<path>``; in that order, files are selected greedily while both
caps permit (at least one file when the tree is non-empty). Sampled trees are
recorded distinctly so partial verification is never represented as complete.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import json
import logging
import os
import re
import shutil
import stat
import tarfile
import tempfile
import threading
import zipfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from leitir import _http
from leitir.safeio import atomic_write_bytes, fsync_directory, read_regular_file
from leitir.search import RepoScope
from leitir.treehash import (
    TreeHashError,
    compute_materialized_tree_hash,
    full_coverage_manifest_fields,
    manifest_digest_fields,
    verify_file_digest_map,
    verify_materialized_tree_hash,
)

logger = logging.getLogger(__name__)
_TARGET_LOCK_STATE = threading.local()

_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_CODELOAD = "https://codeload.github.com"
_HOST_METADATA = {
    "github.com": ("codeload-tarball", "https://github.com"),
    "gitlab.com": ("gitlab-archive", "https://gitlab.com"),
    "bitbucket.org": ("bitbucket-archive", "https://bitbucket.org"),
    "codeberg.org": ("codeberg-archive", "https://codeberg.org"),
    "git.sr.ht": ("sourcehut-archive", "https://git.sr.ht"),
    "go-module-zip": ("go-module-zip", ""),
}
MANIFEST_NAME = "leitir-manifest.json"
VERIFY_MAX_FILES = 1_000
VERIFY_MAX_BYTES = 64 * 1024 * 1024
# Manifests now embed the flat per-file digest map (issue #194), so the
# serialized-manifest bound must cover the worst-case map within the archive
# member limit (ARCHIVE_MAX_MEMBERS entries at ~12 + 64 + path bytes each)
# instead of the legacy 1 MiB provenance object.  Enforced on both the write
# side (_write_manifest) and every bounded read; breaches fail closed.
MANIFEST_MAX_BYTES = 96 * 1024 * 1024
ARCHIVE_MAX_MEMBERS = 500_000
ARCHIVE_MAX_MEMBER_BYTES = 1024 * 1024 * 1024
ARCHIVE_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
ARCHIVE_MAX_COMPRESSED_BYTES = 1024 * 1024 * 1024


class MaterializationError(Exception):
    """A pinned source tree could not be downloaded or safely extracted."""


class ManifestIntegrityError(MaterializationError):
    """A manifest update was refused because its shelf failed verification."""


class UnsafeArchiveError(Exception):
    """A tar archive contains a member that is unsafe to materialize."""


class VerificationError(Exception):
    """An extracted tree does not match its pinned Git tree listing."""


class ArtifactRetrievalError(MaterializationError):
    """A registry artifact could not be retrieved after retrying."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _assert_target_confinement(root: Path, target: Path) -> None:
    """Reject corpus-relative symlinks and paths resolving outside ``root``."""
    lexical_root = root.expanduser().absolute()
    lexical_target = target.expanduser().absolute()
    try:
        relative = lexical_target.relative_to(lexical_root)
    except ValueError as exc:
        raise MaterializationError(
            "materialization target escapes corpus root"
        ) from exc
    current = lexical_root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise MaterializationError(
                f"materialization target contains a symbolic link: {current}"
            )
    resolved_root = lexical_root.resolve(strict=False)
    resolved_parent = lexical_target.parent.resolve(strict=False)
    if resolved_parent != resolved_root and not resolved_parent.is_relative_to(
        resolved_root
    ):
        raise MaterializationError("materialization target parent escapes corpus root")


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Hold an interprocess exclusive lock without following a lock symlink."""
    path = Path(os.path.normcase(str(path.absolute())))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MaterializationError(
            f"cannot safely open materialization lock: {path}"
        ) from exc
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]  # Windows-only; typeshed lacks msvcrt.locking/LK_*
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]  # Windows-only; typeshed lacks msvcrt.locking/LK_*
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


@contextmanager
def _try_file_lock(path: Path) -> Iterator[bool]:
    """Try an exclusive lock without waiting for its current owner."""
    path = Path(os.path.normcase(str(path.absolute())))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MaterializationError(
            f"cannot safely open materialization lock: {path}"
        ) from exc
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
        else:
            import fcntl

        try:
            if os.name == "nt":
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]  # Windows-only; typeshed lacks msvcrt.locking/LK_*
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            if not isinstance(exc, BlockingIOError) and exc.errno not in {
                errno.EWOULDBLOCK,
                errno.EACCES,
                errno.EAGAIN,
            }:
                raise
        yield acquired
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]  # Windows-only; typeshed lacks msvcrt.locking/LK_*
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        else:
            os.close(fd)


def _sweep_target_debris(lock_path: Path, target: Path, commit_sha: str) -> None:
    """Sweep target debris only when its lock is immediately available."""
    with _try_file_lock(lock_path) as acquired:
        if not acquired or not target.parent.exists():
            return
        for stale in sorted(target.parent.glob(f".{commit_sha}.tmp-*")):
            _remove_path(stale)
        if target.exists():
            for stale in sorted(target.parent.glob(f".{commit_sha}.old-*")):
                _remove_path(stale)


@contextmanager
def _target_lock(root: Path, target: Path, commit_sha: str) -> Iterator[None]:
    root = root.expanduser().absolute()
    root.mkdir(parents=True, exist_ok=True)
    lock_root = root / ".locks"
    _assert_target_confinement(root, lock_root)
    lock_root.mkdir(exist_ok=True)
    _assert_target_confinement(root, lock_root)
    relative_target = target.absolute().relative_to(root)
    identity = os.path.normcase(str(relative_target)).encode("utf-8")
    lock_path = lock_root / f"{hashlib.sha256(identity).hexdigest()}.lock"
    held = getattr(_TARGET_LOCK_STATE, "held", None)
    if held is None or getattr(_TARGET_LOCK_STATE, "pid", None) != os.getpid():
        held = set()
        _TARGET_LOCK_STATE.held = held
        _TARGET_LOCK_STATE.pid = os.getpid()
    lock_identity = os.path.normcase(str(lock_path.absolute()))
    if lock_identity in held:
        yield
        return
    # Cleanup is opportunistic; the normal blocking lock below still
    # preserves writer serialization for the materialization itself.
    _sweep_target_debris(lock_path, target, commit_sha)
    with _file_lock(lock_path):
        held.add(lock_identity)
        try:
            _assert_target_confinement(root, target)
            yield
        finally:
            held.remove(lock_identity)


# Directory fsync is consolidated in leitir.safeio (issue #200); the
# historical ``_fsync_directory`` name is kept as an alias for existing
# importers (corpus.py, index/builder.py, cli.py).
_fsync_directory = fsync_directory


@contextmanager
def _open_new_regular_file(path: Path, root: Path) -> Iterator[BinaryIO]:
    """Create a regular extraction output without following a final symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise UnsafeArchiveError("archive output is not a regular file")
        _assert_confined(path, root)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            yield handle
    finally:
        if fd >= 0:
            os.close(fd)


def _failure_detail(exc: BaseException) -> str:
    current: BaseException | None = exc
    while current is not None:
        detail = _http.describe_failure(current)
        if detail.startswith("HTTP "):
            if current is exc:
                return detail
            return f"{type(exc).__name__}: {detail}"
        current = current.__cause__
    return _http.describe_failure(exc)


def _write_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    """Write a manifest atomically, including upgrades of cached manifests."""
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MANIFEST_MAX_BYTES:
        # A manifest that cannot be read back within the load-time bound
        # would strand the shelf: fail the write instead (issue #194, C-1).
        raise MaterializationError(
            "manifest exceeds the maximum serialized size; the per-file "
            "digest map would be unreadable at load time"
        )
    logger.debug("writing manifest path=%s", path)
    atomic_write_bytes(path, data)


def _manifest_has_file_map(payload: Mapping[str, object]) -> bool:
    """Return whether the manifest claims a per-file digest map."""
    return (
        "materialized_file_digests" in payload
        or "materialized_file_digests_algorithm" in payload
    )


def verify_materialized_integrity(
    target: str | os.PathLike[str], manifest: Mapping[str, object]
) -> None:
    """Verify a shelf's load-time integrity anchor (issue #194).

    Manifests carrying the per-file digest map are verified with full
    coverage in one streaming pass: every file's digest is compared to the
    map and the map is compared to the anchored full-scope tree hash.
    Legacy manifests without a map take the unchanged aggregate path.  Any
    malformed anchor, unreadable tree, per-file mismatch, or unanchored map
    raises :class:`VerificationError` (fail-closed, never load-and-warn);
    per-file mismatches name the offending path.

    Raises
    ------
    VerificationError
        If the shelf's bytes do not match the manifest's integrity anchor.
    """
    try:
        if _manifest_has_file_map(manifest):
            verify_file_digest_map(
                Path(target),
                manifest.get("materialized_file_digests"),
                algorithm=manifest.get("materialized_file_digests_algorithm"),
                expected_tree_hash=manifest.get("materialized_tree_hash"),
                tree_hash_algorithm=manifest.get("materialized_tree_hash_algorithm"),
                tree_hash_scope=manifest.get("materialized_tree_hash_scope"),
            )
        else:
            verify_materialized_tree_hash(
                Path(target),
                manifest.get("materialized_tree_hash"),
                algorithm=manifest.get("materialized_tree_hash_algorithm"),
                scope=manifest.get("materialized_tree_hash_scope", "full"),
            )
    except TreeHashError as exc:
        raise VerificationError(str(exc)) from exc


def update_manifest(
    target: str | os.PathLike[str], fields: Mapping[str, object]
) -> dict[str, object]:
    """Verify a shelf, then atomically merge fields into its manifest.

    The source manifest is read through the same bounded reader and
    duplicate-key-rejecting parser as the load gate (``_read_valid_manifest``),
    so no manifest shape that gate rejects can be laundered through this
    write path.  Raises :class:`ManifestIntegrityError` without writing if
    the source manifest is over-bound or malformed, or if its
    materialized-tree integrity anchor cannot be verified.
    """
    path = Path(target) / MANIFEST_NAME
    from leitir.manifest_auth import ManifestAuthMalformedError, _parse_json

    try:
        raw = read_regular_file(
            path, maximum_bytes=MANIFEST_MAX_BYTES, no_follow=False
        )
    except ValueError as exc:
        # An over-bound manifest cannot be re-read (let alone verified) at
        # load time; refuse the update with the typed error instead of the
        # bounded reader's raw ValueError (fail-closed stays).
        raise ManifestIntegrityError(
            f"source manifest for {target} exceeds the maximum serialized size"
        ) from exc
    try:
        payload = _parse_json(
            raw.decode("utf-8", "strict"), subject="materialized manifest"
        )
    except (UnicodeError, ManifestAuthMalformedError) as exc:
        # Matching the load gate's stated policy: a duplicate-key (or
        # otherwise unparseable) manifest is invalid, never last-wins
        # decoded and rewritten by this path.
        raise ManifestIntegrityError(
            f"source manifest for {target} is malformed and cannot be verified"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("source manifest must be an object")
    expected_hash = payload.get("materialized_tree_hash")
    if expected_hash is not None or _manifest_has_file_map(payload):
        # Map-carrying manifests are always written with their anchored
        # full-scope aggregate; a missing anchor on such a manifest means it
        # was tampered with, so it is rejected rather than backfilled.
        try:
            verify_materialized_integrity(Path(target), payload)
        except VerificationError as exc:
            logger.warning("load-time integrity verification failed for %s", target)
            raise ManifestIntegrityError(
                f"load-time integrity verification failed for {target}"
            ) from exc
    else:
        owner = payload.get("owner")
        repo = payload.get("repo")
        commit_sha = payload.get("commit_sha")
        host = payload.get("host", "github.com")
        target_parts = Path(target).parts
        try:
            _owner, _repo, identity_parts = _normalize_identity(
                owner if isinstance(owner, str) else "",
                repo if isinstance(repo, str) else "",
                commit_sha if isinstance(commit_sha, str) else "",
                host if isinstance(host, str) else "",
            )
        except ValueError:
            canonical_target = False
        else:
            suffix = ("repos", host, *identity_parts, commit_sha)
            canonical_target = target_parts[-len(suffix) :] == suffix
        provenance_valid = (
            canonical_target
            and isinstance(owner, str)
            and isinstance(repo, str)
            and isinstance(commit_sha, str)
            and isinstance(host, str)
            and _read_valid_manifest(
                target,
                owner,
                repo,
                commit_sha,
                host=host,
                allow_missing_tree_hash=True,
            )
            is not None
        )
        if not (
            payload.get("verified") in (True, "sampled", "archive-only")
            and provenance_valid
        ):
            raise ManifestIntegrityError(
                f"manifest has no valid materialized tree hash for {target}"
            )
        try:
            tree_digest, tree_scope = compute_materialized_tree_hash(Path(target))
        except TreeHashError as exc:
            logger.warning(
                "could not backfill materialized tree hash for %s: %s", target, exc
            )
            raise ManifestIntegrityError(
                f"could not backfill materialized tree hash for {target}"
            ) from exc
        payload.update(manifest_digest_fields(tree_digest, scope=tree_scope))
    payload.update(fields)
    _write_manifest(path, payload)
    return payload


def _refresh_license_manifest(target: Path, manifest: dict[str, object]) -> dict[str, object]:
    from leitir.sbom import license_manifest_fields

    fields = license_manifest_fields(manifest, target)
    if all(manifest.get(key) == value for key, value in fields.items()):
        return manifest
    return update_manifest(target, fields)


def has_top_level_tests(target: Path, subpath: str | None = None) -> bool:
    """Return whether the selected Git tree has a top-level tests directory."""
    tree = target / subpath if subpath else target
    if not tree.is_dir():
        return False
    return any(
        child.is_dir() and child.name.casefold() == "tests" for child in tree.iterdir()
    )


def _prune_empty(path: Path, stop: Path) -> None:
    """Remove empty parent directories created for a shelved source, up to stop."""
    while path != stop and path.is_dir():
        try:
            path.rmdir()
        except OSError:
            break
        path = path.parent


def _normalize_identity(
    owner: str, repo: str, commit_sha: str, host: str
) -> tuple[str, str, tuple[str, ...]]:
    parts = tuple(f"{owner}/{repo}".split("/"))
    if host != "gitlab.com" and len(parts) != 2:
        raise ValueError("repository identity must contain exactly two segments")
    valid_parts = parts
    if host == "git.sr.ht":
        if not parts[0].startswith("~") or len(parts[0]) == 1:
            raise ValueError("Sourcehut repository owner must start with '~'")
        valid_parts = (parts[0][1:], *parts[1:])
    if len(parts) < 2 or any(
        part in {".", ".."} or not _NAME.fullmatch(part) for part in valid_parts
    ):
        raise ValueError("repository identity contains an invalid path segment")
    if not _SHA1.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a 40-char lowercase hex SHA")
    return "/".join(parts[:-1]), parts[-1], parts


def _validate_identity(
    owner: str, repo: str, commit_sha: str, host: str = "github.com"
) -> None:
    _normalize_identity(owner, repo, commit_sha, host)


def target_path(
    root: str | os.PathLike[str],
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str = "github.com",
) -> Path:
    """Return the canonical target path for one pinned hosted repository."""
    if host not in _HOST_METADATA:
        raise ValueError(f"unsupported repository host {host!r}")
    _owner, _repo, parts = _normalize_identity(owner, repo, commit_sha, host)
    return Path(root).joinpath("repos", host, *parts, commit_sha)


def read_valid_manifest(
    target: str | os.PathLike[str],
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str = "github.com",
) -> dict[str, object] | None:
    """Read a manifest only when it identifies exactly the requested source."""
    return _read_valid_manifest(
        target,
        owner,
        repo,
        commit_sha,
        host=host,
        allow_missing_tree_hash=False,
    )


def _read_valid_manifest(
    target: str | os.PathLike[str],
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str,
    allow_missing_tree_hash: bool,
) -> dict[str, object] | None:
    """Validate a manifest, optionally permitting a legacy missing digest."""
    if Path(target).is_symlink():
        return None
    metadata = _HOST_METADATA.get(host)
    if metadata is None:
        return None
    try:
        owner, repo, _parts = _normalize_identity(owner, repo, commit_sha, host)
    except ValueError:
        return None
    fetch_method, canonical_base = metadata
    try:
        # Match detached-auth parsing: a duplicate field must never silently
        # select the last attacker-controlled value.  This remains a normal
        # invalid-manifest result rather than a new load-time exception.
        from leitir.manifest_auth import ManifestAuthMalformedError, _parse_json

        payload = _parse_json(
            # The parsed manifest is subsequently bound to its materialized
            # tree digest, so this digest-anchored cache input can support
            # platforms without O_NOFOLLOW.
            read_regular_file(Path(target) / MANIFEST_NAME, maximum_bytes=MANIFEST_MAX_BYTES, no_follow=False).decode("utf-8", "strict"),
            subject="materialized manifest",
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ManifestAuthMalformedError):
        return None
    if not isinstance(payload, dict):
        return None
    source = payload.get("source")
    fetch_method = (
        "registry-artifact" if source == "registry-artifact" else fetch_method
    )
    expected = {
        "host": host,
        "owner": owner,
        "repo": repo,
        "commit_sha": commit_sha,
        "fetch_method": fetch_method,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        return None
    if not isinstance(payload.get("spec"), str) or not payload["spec"]:
        return None
    expected_url = None if host == "go-module-zip" else f"{canonical_base}/{owner}/{repo}"
    if payload.get("repo_url") != expected_url:
        return None
    if not isinstance(payload.get("fetched_at"), str) or not payload["fetched_at"]:
        return None
    if "published_at" in payload and not _valid_timestamp(payload.get("published_at")):
        return None
    if payload.get("tag") is not None and not isinstance(payload.get("tag"), str):
        return None
    verified = payload.get("verified")
    if "verified" in payload and not (
        verified is True or verified is False or verified in ("sampled", "archive-only")
    ):
        return None
    if verified in (True, "sampled", "archive-only") and (
        not isinstance(payload.get("verified_at"), str) or not payload["verified_at"]
    ):
        return None
    if verified is False and payload.get("verified_at") is not None:
        return None
    if source is not None and source not in {"registry-artifact", "git-commit", "go-module-zip"}:
        return None
    if (
        "has_tests" in payload
        and payload.get("has_tests") is not None
        and not isinstance(payload.get("has_tests"), bool)
    ):
        return None
    artifact_fields = ("artifact_kind", "artifact_checksum")
    if source == "registry-artifact":
        if verified is not True:
            return None
        if payload.get("artifact_kind") not in {"npm-tarball", "sdist", "crate"}:
            return None
        if (
            not isinstance(payload.get("artifact_checksum"), str)
            or not payload["artifact_checksum"]
        ):
            return None
    elif any(field in payload for field in artifact_fields):
        return None
    if source == "go-module-zip":
        required = ("module_path", "module_version", "proxy_url", "zip_sha256", "sumdb_h1")
        if host != "go-module-zip" or fetch_method != "go-module-zip":
            return None
        if not all(isinstance(payload.get(field), str) and payload[field] for field in required):
            return None
        if not str(payload["proxy_url"]).startswith(("https://", "http://127.0.0.1", "http://localhost")):
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", str(payload["zip_sha256"])):
            return None
        if not str(payload["sumdb_h1"]).startswith("h1:"):
            return None
    if "parity" in payload and payload.get("parity") not in {
        "exact",
        "drift",
        "unknown",
    }:
        return None
    if "graph" in payload and payload.get("graph") not in {"complete", "direct-only"}:
        return None
    if "deps" in payload:
        deps = payload.get("deps")
        if not isinstance(deps, list):
            return None
        for dependency in deps:
            if not isinstance(dependency, dict) or set(dependency) != {
                "name",
                "version",
                "resolved_sha",
                "spec",
            }:
                return None
            if not all(
                isinstance(dependency.get(field), str) and bool(dependency[field])
                for field in ("name", "version", "spec")
            ):
                return None
            resolved_sha = dependency.get("resolved_sha")
            if resolved_sha is not None and (
                not isinstance(resolved_sha, str) or not resolved_sha
            ):
                return None
    for field in ("files_compared", "only_in_git", "only_in_artifact"):
        if field in payload and (
            not isinstance(payload[field], int)
            or isinstance(payload[field], bool)
            or payload[field] < 0
        ):
            return None
    if "trust_score" in payload and (
        not isinstance(payload["trust_score"], int)
        or isinstance(payload["trust_score"], bool)
        or not 0 <= payload["trust_score"] <= 100
    ):
        return None
    if "trust_breakdown" in payload:
        breakdown = payload["trust_breakdown"]
        if not isinstance(breakdown, list):
            return None
        for factor in breakdown:
            if not isinstance(factor, dict) or set(factor) != {
                "factor",
                "score",
                "weight",
                "evidence",
            }:
                return None
            if not isinstance(factor["factor"], str) or not factor["factor"]:
                return None
            for field in ("score", "weight"):
                if (
                    not isinstance(factor[field], int)
                    or isinstance(factor[field], bool)
                    or not 0 <= factor[field] <= 100
                ):
                    return None
            if not isinstance(factor["evidence"], dict):
                return None
    if payload.get("materialized_tree_hash") is not None or _manifest_has_file_map(
        payload
    ):
        try:
            verify_materialized_integrity(target, payload)
        except VerificationError:
            logger.warning("load-time integrity verification failed for %s", target)
            return None
    elif not allow_missing_tree_hash:
        # Every producer writes the anchor. Missing anchors are accepted only
        # by update_manifest's private, provenance-checked backfill path.
        # A map-carrying manifest without an aggregate is malformed and was
        # rejected above, never backfilled (issue #194, SP-2).
        return None
    return payload


def _archive_path(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise UnsafeArchiveError("invalid archive member path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise UnsafeArchiveError("archive member escapes its target")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        raise UnsafeArchiveError("invalid archive member path")
    return PurePosixPath(*parts)


def _stripped_member_path(
    member: tarfile.TarInfo, expected_root: str
) -> PurePosixPath | None:
    path = _archive_path(member.name)
    if path.parts[0] != expected_root:
        raise UnsafeArchiveError(
            "archive does not have the expected single top-level directory"
        )
    if len(path.parts) == 1:
        return None
    return PurePosixPath(*path.parts[1:])


def _symlink_destination(path: PurePosixPath, linkname: str) -> None:
    if not linkname or "\\" in linkname:
        raise UnsafeArchiveError("invalid symbolic-link target")
    target = PurePosixPath(linkname)
    if target.is_absolute():
        raise UnsafeArchiveError("symbolic link escapes its target")
    depth = 0
    for part in path.parent.parts + target.parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise UnsafeArchiveError("symbolic link escapes its target")
        else:
            depth += 1


def _hardlink_path(linkname: str, expected_root: str) -> PurePosixPath:
    path = _archive_path(linkname)
    if path.parts[0] != expected_root or len(path.parts) == 1:
        raise UnsafeArchiveError("hard link escapes its target")
    return PurePosixPath(*path.parts[1:])


def _assert_confined(output_path: Path, root: Path) -> None:
    if not Path(os.path.realpath(output_path)).is_relative_to(root):
        raise UnsafeArchiveError("symbolic link escapes its target")


def _resolve_planned_path(
    path: PurePosixPath, links: Mapping[PurePosixPath, PurePosixPath]
) -> PurePosixPath:
    """Resolve an archive path through already-planned links, lexically."""
    pending = list(path.parts)
    resolved: list[str] = []
    states: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    while pending:
        state = (tuple(resolved), tuple(pending))
        if state in states:
            raise UnsafeArchiveError("symbolic link escapes its target")
        states.add(state)
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise UnsafeArchiveError("symbolic link escapes its target")
            resolved.pop()
            continue
        resolved.append(part)
        current = PurePosixPath(*resolved)
        target = links.get(current)
        if target is not None:
            resolved.pop()
            pending[0:0] = target.parts
    return PurePosixPath(*resolved) if resolved else PurePosixPath(".")


def _validate_planned_symlinks(
    planned: list[tuple[tarfile.TarInfo, PurePosixPath | None]],
) -> None:
    """Reject chained escapes without relying on host symlink semantics."""
    links: dict[PurePosixPath, PurePosixPath] = {}
    for member, path in planned:
        if path is None or not member.issym():
            continue
        parent = _resolve_planned_path(path.parent, links)
        physical = parent / path.name
        if physical in links:
            raise UnsafeArchiveError("symbolic link escapes its target")
        links[physical] = PurePosixPath(member.linkname)
        _resolve_planned_path(physical, links)


def _read_bounded(response: object, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(limit + 1 - total)  # type: ignore[attr-defined]
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise MaterializationError("archive download exceeds compressed size limit")


def _cache_matches_source(
    manifest: Mapping[str, object],
    *,
    source: str,
    fetch_method: str,
    artifact_kind: str | None = None,
    artifact_checksum: str | None = None,
) -> bool:
    cached_source = manifest.get("source")
    if source == "git-commit" and cached_source is None:
        cached_source = "git-commit"
    if cached_source != source or manifest.get("fetch_method") != fetch_method:
        return False
    if source == "registry-artifact":
        return (
            manifest.get("artifact_kind") == artifact_kind
            and manifest.get("artifact_checksum") == artifact_checksum
        )
    return True


def _extract_tarball(
    data: bytes,
    destination: Path,
    repo: str,
    commit_sha: str,
    *,
    archive_root: str | None = None,
) -> None:
    expected_root = archive_root
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        planned: list[tuple[tarfile.TarInfo, PurePosixPath | None]] = []
        seen: set[PurePosixPath] = set()
        total_size = 0
        for member in archive:
            if len(planned) >= ARCHIVE_MAX_MEMBERS:
                raise UnsafeArchiveError("archive contains too many members")
            if member.size < 0 or member.size > ARCHIVE_MAX_MEMBER_BYTES:
                raise UnsafeArchiveError("archive member exceeds size limit")
            total_size += member.size
            if total_size > ARCHIVE_MAX_TOTAL_BYTES:
                raise UnsafeArchiveError("archive exceeds total size limit")
            if expected_root is None:
                expected_root = _archive_path(member.name).parts[0]
            path = _stripped_member_path(member, expected_root)
            if path is None and not member.isdir():
                raise UnsafeArchiveError("archive top-level member is not a directory")
            if path is not None:
                if path == PurePosixPath(MANIFEST_NAME):
                    raise UnsafeArchiveError(
                        "archive contains Leitir's reserved manifest path"
                    )
                if path in seen:
                    raise UnsafeArchiveError("archive contains duplicate member paths")
                seen.add(path)
            if not (
                member.isdir() or member.isreg() or member.issym() or member.islnk()
            ):
                raise UnsafeArchiveError(
                    "archive contains a device or other special file"
                )
            if member.issym() and path is not None:
                _symlink_destination(path, member.linkname)
            if member.islnk():
                _hardlink_path(member.linkname, expected_root)
            planned.append((member, path))

        if not planned:
            raise UnsafeArchiveError("archive is empty")
        if expected_root is None:
            raise UnsafeArchiveError("archive has no top-level directory")

        _validate_planned_symlinks(planned)

        destination.mkdir(parents=True, exist_ok=True)
        root = destination.resolve()
        regular_paths: set[PurePosixPath] = set()
        for member, path in planned:
            if path is None or not (member.isdir() or member.isreg()):
                continue
            output = destination.joinpath(*path.parts)
            if member.isdir():
                _assert_confined(output, root)
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(member.mode & 0o777)
                continue
            _assert_confined(output, root)
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise UnsafeArchiveError("regular archive member has no data")
            _assert_confined(output, root)
            with source, _open_new_regular_file(output, root) as handle:
                shutil.copyfileobj(source, handle)
            output.chmod(member.mode & 0o777)
            regular_paths.add(path)

        for member, path in planned:
            if path is None or not member.islnk():
                continue
            linked = _hardlink_path(member.linkname, expected_root)
            if linked not in regular_paths:
                raise UnsafeArchiveError(
                    "hard link does not target a regular archive member"
                )
            output = destination.joinpath(*path.parts)
            _assert_confined(output, root)
            output.parent.mkdir(parents=True, exist_ok=True)
            _assert_confined(output, root)
            os.link(destination.joinpath(*linked.parts), output)

        for member, path in planned:
            if path is None or not member.issym():
                continue
            output = destination.joinpath(*path.parts)
            _assert_confined(output, root)
            output.parent.mkdir(parents=True, exist_ok=True)
            _assert_confined(output, root)
            output.symlink_to(member.linkname)

        for _member, path in planned:
            if path is None:
                continue
            output = destination.joinpath(*path.parts)
            if output.is_symlink():
                resolved = Path(os.path.realpath(output))
                if not resolved.is_relative_to(root):
                    raise UnsafeArchiveError("symbolic link escapes its target")


def _verify_extracted_tree(
    staging: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    tree_source: object,
    *,
    max_files: int,
    max_bytes: int,
    excluded_paths: frozenset[str] = frozenset(),
) -> tuple[bool | str, int]:
    """Return verification status and the number of EOL-normalized files."""
    import hashlib

    from leitir.tree import GitHubTreeSource

    if max_files < 1:
        raise ValueError("verification_max_files must be >= 1")
    if max_bytes < 1:
        raise ValueError("verification_max_bytes must be >= 1")

    extracted_paths = list(staging.rglob("*"))
    extracted = {
        path.relative_to(staging).as_posix(): path
        for path in extracted_paths
        if (
            path.relative_to(staging).as_posix() not in excluded_paths
            and not path.is_symlink()
            and path.is_file()
        )
    }
    extracted_symlinks = {
        path.relative_to(staging).as_posix(): path
        for path in extracted_paths
        if path.relative_to(staging).as_posix() not in excluded_paths and path.is_symlink()
    }

    entries = tree_source.list_blobs(f"{owner}/{repo}", commit_sha)  # type: ignore[attr-defined]
    logger.debug(
        "verifying extracted tree repo=%s/%s blobs=%d", owner, repo, len(entries)
    )
    expected: dict[str, object] = {}
    for entry in entries:
        if entry.path in expected:
            raise VerificationError(f"duplicate blob path in Git tree: {entry.path}")
        expected[entry.path] = entry

    # GitHub's mode distinguishes regular blobs from symlinks (whose blob is
    # the link target). Injected legacy TreeSources may omit mode; in that case
    # retain compatibility by verifying the extracted regular-file universe.
    modes_available = all(getattr(entry, "mode", None) is not None for entry in entries)
    if modes_available:
        candidates = {
            path: entry
            for path, entry in expected.items()
            if getattr(entry, "mode", "").startswith("100")
        }
        expected_symlinks = {
            path: entry
            for path, entry in expected.items()
            if getattr(entry, "mode", "").startswith("120000")
        }
        unsupported = set(expected) - set(candidates) - set(expected_symlinks)
        if unsupported:
            raise VerificationError(
                f"unsupported Git blob mode: {min(unsupported)}"
            )
        # A mode-bearing listing pins the complete symlink universe, so a
        # symlink the archive added or dropped is a hard mismatch — never a
        # downgrade to "sampled". Mode-less legacy sources cannot make this
        # claim and stay on the sampled path below.
        if set(extracted_symlinks) != set(expected_symlinks):
            missing = sorted(set(expected_symlinks) - set(extracted_symlinks))
            extra = sorted(set(extracted_symlinks) - set(expected_symlinks))
            detail = missing[0] if missing else extra[0]
            kind = "missing" if missing else "unexpected"
            raise VerificationError(f"{kind} extracted symbolic link: {detail}")
        sizes = {path: entry.size for path, entry in candidates.items()}  # type: ignore[attr-defined]
    else:
        candidates = {path: expected.get(path) for path in extracted}
        expected_symlinks = {}
        sizes = {path: file.stat().st_size for path, file in extracted.items()}

    total_bytes = sum(sizes.values())
    sampled = (
        not modes_available
        or len(candidates) > max_files
        or total_bytes > max_bytes
    )
    selected = sorted(candidates)
    if not sampled and modes_available and set(extracted) != set(candidates):
        missing = sorted(set(candidates) - set(extracted))
        extra = sorted(set(extracted) - set(candidates))
        detail = missing[0] if missing else extra[0]
        kind = "missing" if missing else "unexpected"
        raise VerificationError(f"{kind} extracted regular file: {detail}")
    if sampled:
        selected = sorted(
            candidates,
            key=lambda path: hashlib.sha256(
                commit_sha.encode("ascii") + b"\0" + path.encode("utf-8")
            ).digest(),
        )
        bounded: list[str] = []
        selected_bytes = 0
        for path in selected:
            size = sizes[path]
            if len(bounded) >= max_files:
                break
            if selected_bytes + size <= max_bytes:
                bounded.append(path)
                selected_bytes += size
        if not bounded and selected:
            bounded.append(selected[0])
        selected = bounded

    text_normalized = 0
    for relative, entry in sorted(expected_symlinks.items()):
        if relative not in extracted_symlinks:
            continue
        try:
            extracted_bytes = os.readlink(os.fsencode(extracted_symlinks[relative]))
        except (OSError, UnicodeError) as exc:
            raise VerificationError(
                f"cannot read extracted symbolic link: {relative}"
            ) from exc
        actual = GitHubTreeSource.git_blob_sha(extracted_bytes)
        if actual != entry.blob_sha:  # type: ignore[attr-defined]
            # A mismatched digest on any host whose listing carries modes
            # triggers a commit-pinned re-read (read_blob_at_commit, then
            # read_blob). If the re-read equals the extracted bytes, the
            # mismatch is treated as an enumeration glitch and cleared. That
            # clearance binds the re-read channel to disk — it is not a
            # cryptographic match against entry.blob_sha — so it assumes the
            # re-read channel is honest (endpoint diversity / same-host
            # trust). A source offering neither re-read fails closed with a
            # typed error below.
            read_at_commit = getattr(tree_source, "read_blob_at_commit", None)
            read_blob = getattr(tree_source, "read_blob", None)
            if read_at_commit is not None:
                blob_bytes = read_at_commit(f"{owner}/{repo}", commit_sha, relative)
            elif read_blob is not None:
                blob_bytes = read_blob(
                    f"{owner}/{repo}",
                    entry.blob_sha,  # type: ignore[attr-defined]
                )
            else:
                # No way to re-read the pinned blob: a mismatch can never be
                # confirmed or cleared, so fail closed instead of guessing.
                raise VerificationError(
                    f"tree source cannot re-read symbolic link blob: {relative}"
                )
            if extracted_bytes != blob_bytes:
                raise VerificationError(
                    f"Git symbolic-link blob digest mismatch: {relative}"
                )
    for relative in selected:
        extracted_path = extracted.get(relative)
        entry = expected.get(relative)
        if extracted_path is None:
            raise VerificationError(f"missing extracted regular file: {relative}")
        if entry is None:
            raise VerificationError(
                f"extracted file is absent from Git tree: {relative}"
            )
        extracted_bytes = extracted_path.read_bytes()
        actual = GitHubTreeSource.git_blob_sha(extracted_bytes)
        if actual != entry.blob_sha:  # type: ignore[attr-defined]
            read_at_commit = getattr(tree_source, "read_blob_at_commit", None)
            if read_at_commit is not None:
                blob_bytes = read_at_commit(f"{owner}/{repo}", commit_sha, relative)
            else:
                # Compatibility for injected TreeSource implementations. The
                # blob SHA came from the pinned commit's tree listing.
                blob_bytes = tree_source.read_blob(  # type: ignore[attr-defined]
                    f"{owner}/{repo}",
                    entry.blob_sha,  # type: ignore[attr-defined]
                )
            if extracted_bytes not in (blob_bytes, blob_bytes.replace(b"\n", b"\r\n")):
                raise VerificationError(f"Git blob digest mismatch: {relative}")
            text_normalized += 1
    outcome: bool | str = "sampled" if sampled else True
    logger.debug(
        "tree verification outcome=%s normalized_files=%d", outcome, text_normalized
    )
    return outcome, text_normalized


def _github_git_parity(verified: bool | str, text_normalized: int) -> str:
    """Derive the GitHub Git-commit parity claim from a verification outcome."""
    if verified is not True:
        return "unknown"
    return "drift" if text_normalized else "exact"


def recompute_github_git_parity(
    root: str | os.PathLike[str],
    *,
    tree_source: object,
    dry_run: bool = False,
) -> tuple[int, int, int]:
    """Reprove cached GitHub Git-commit shelves and update their parity claims.

    Only an already fully verified Git-commit shelf is eligible. Incomplete
    enumeration or sampling leaves an existing claim untouched, so partial
    proof can never promote an unknown shelf.
    """
    root_path = Path(root).expanduser().absolute()
    updated = skipped = failed = 0
    for manifest_path in sorted(root_path.rglob(MANIFEST_NAME)):
        target = manifest_path.parent
        try:
            # The cache manifest is bound again by the verified tree hash below,
            # so this portable parity-recomputation input may omit O_NOFOLLOW.
            payload = json.loads(read_regular_file(manifest_path, maximum_bytes=MANIFEST_MAX_BYTES, no_follow=False).decode("utf-8", "strict"))
            if not isinstance(payload, dict):
                raise ValueError("manifest must be an object")
            owner = payload.get("owner")
            repo = payload.get("repo")
            commit_sha = payload.get("commit_sha")
            if not (
                payload.get("host") == "github.com"
                and payload.get("source") == "git-commit"
                and payload.get("verified") is True
                and isinstance(owner, str)
                and isinstance(repo, str)
                and isinstance(commit_sha, str)
            ):
                skipped += 1
                continue
            canonical_target = target_path(
                root_path, owner, repo, commit_sha, host="github.com"
            )
            if target != canonical_target:
                skipped += 1
                continue
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("could not load parity cache manifest %s: %s", manifest_path, exc)
            failed += 1
            continue

        with _target_lock(root_path, target, commit_sha):
            try:
                manifest = read_valid_manifest(
                    target, owner, repo, commit_sha, host="github.com"
                )
                if (
                    manifest is None
                    or manifest.get("source") != "git-commit"
                    or manifest.get("verified") is not True
                ):
                    skipped += 1
                    continue
                verified, text_normalized = _verify_extracted_tree(
                    target,
                    owner,
                    repo,
                    commit_sha,
                    tree_source,
                    max_files=VERIFY_MAX_FILES,
                    max_bytes=VERIFY_MAX_BYTES,
                    excluded_paths=frozenset({MANIFEST_NAME}),
                )
                if verified is not True:
                    skipped += 1
                    continue
                parity = _github_git_parity(verified, text_normalized)
                if manifest.get("parity") == parity:
                    skipped += 1
                    continue
                updated += 1
                if not dry_run:
                    update_manifest(target, {"parity": parity})
            except Exception as exc:
                logger.warning("could not recompute Git parity for %s: %s", target, exc)
                failed += 1
    return updated, skipped, failed


def materialize_github_repo(
    root: str | os.PathLike[str],
    spec: str,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    token: str | None = None,
    timeout: int = 60,
    base_url: str = _CODELOAD,
    max_attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    max_rate_limit_delay: float = 300.0,
    sleeper: Callable[[float], None] | None = None,
    verify: bool = True,
    tree_source: object | None = None,
    tree_base_url: str = "https://api.github.com",
    verification_max_files: int = VERIFY_MAX_FILES,
    verification_max_bytes: int = VERIFY_MAX_BYTES,
    on_fetch: Callable[[], None] | None = None,
) -> Path:
    """Download and safely extract an exact GitHub commit into the corpus."""
    from urllib.parse import urlsplit
    from urllib.request import Request

    retry = _http.make_retry(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        max_rate_limit_delay=max_rate_limit_delay,
        sleeper=sleeper,
    )
    url = f"{base_url.rstrip('/')}/{owner}/{repo}/tar.gz/{commit_sha}"
    logger.debug("materialize fetch method=codeload-tarball url=%s", url)
    headers = {"Accept": "application/gzip", "User-Agent": "leitir"}
    if token is None:
        from leitir.credentials import github_token_from_env

        github_token = github_token_from_env()
    else:
        github_token = token
    if github_token is not None:
        from leitir.credentials import validate_secret

        validate_secret(github_token, kind="token")
    endpoint = urlsplit(url)
    if (
        github_token
        and endpoint.scheme == "https"
        and endpoint.hostname == "codeload.github.com"
    ):
        headers["Authorization"] = f"Bearer {github_token}"

    def _fetch() -> bytes:
        with _http.safe_urlopen(
            Request(url, headers=headers), timeout=timeout
        ) as response:
            return _read_bounded(response, ARCHIVE_MAX_COMPRESSED_BYTES)

    if tree_source is None and verify:
        from leitir.tree import GitHubTreeSource

        tree_source = GitHubTreeSource(
            token=github_token,
            timeout=timeout,
            base_url=tree_base_url,
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )
    return _materialize_hosted_repo(
        root,
        spec,
        owner,
        repo,
        commit_sha,
        host="github.com",
        fetch_archive=lambda: retry(_fetch),
        tree_source=tree_source,
        tag=tag,
        subpath=subpath,
        manifest_fields=manifest_fields,
        verify=verify,
        verification_max_files=verification_max_files,
        verification_max_bytes=verification_max_bytes,
        on_fetch=on_fetch,
        archive_root=f"{repo}-{commit_sha}",
    )


def _materialize_hosted_repo(
    root: str | os.PathLike[str],
    spec: str,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str,
    fetch_archive: Callable[[], bytes],
    tree_source: object | None,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    verify: bool = True,
    verification_max_files: int = VERIFY_MAX_FILES,
    verification_max_bytes: int = VERIFY_MAX_BYTES,
    on_fetch: Callable[[], None] | None = None,
    archive_root: str | None = None,
) -> Path:
    owner, repo, _parts = _normalize_identity(owner, repo, commit_sha, host)
    root_path = Path(root).expanduser().absolute()
    target = target_path(root_path, owner, repo, commit_sha, host=host)
    with _target_lock(root_path, target, commit_sha):
        return _materialize_hosted_repo_locked(
            root_path,
            spec,
            owner,
            repo,
            commit_sha,
            host=host,
            fetch_archive=fetch_archive,
            tree_source=tree_source,
            tag=tag,
            subpath=subpath,
            manifest_fields=manifest_fields,
            verify=verify,
            verification_max_files=verification_max_files,
            verification_max_bytes=verification_max_bytes,
            on_fetch=on_fetch,
            archive_root=archive_root,
        )


def _materialize_hosted_repo_locked(
    root: str | os.PathLike[str],
    spec: str,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str,
    fetch_archive: Callable[[], bytes],
    tree_source: object | None,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    verify: bool = True,
    verification_max_files: int = VERIFY_MAX_FILES,
    verification_max_bytes: int = VERIFY_MAX_BYTES,
    on_fetch: Callable[[], None] | None = None,
    archive_root: str | None = None,
) -> Path:
    owner, repo, _parts = _normalize_identity(owner, repo, commit_sha, host)
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("spec must be non-empty")
    metadata = _HOST_METADATA.get(host)
    if metadata is None:
        raise ValueError(f"unsupported repository host {host!r}")
    fetch_method, canonical_base = metadata
    target = target_path(root, owner, repo, commit_sha, host=host)
    _assert_target_confinement(Path(root), target)
    existing = (
        read_valid_manifest(target, owner, repo, commit_sha, host=host)
        if target.is_dir()
        else None
    )
    if existing is not None and _cache_matches_source(
        existing, source="git-commit", fetch_method=fetch_method
    ):
        if existing.get("source") is None:
            existing["source"] = "git-commit"
            _write_manifest(target / MANIFEST_NAME, existing)
        existing = _refresh_license_manifest(target, existing)
        if not verify:
            if "verified" not in existing:
                existing.update(verified=False, verified_at=None)
                _write_manifest(target / MANIFEST_NAME, existing)
            _assert_target_confinement(Path(root), target)
            return target
        if existing.get("verified") in (True, "sampled"):
            _assert_target_confinement(Path(root), target)
            return target
        if (
            existing.get("verified") == "archive-only"
            and not getattr(
                tree_source, "full_tree_verification_available", lambda: True
            )()
        ):
            _assert_target_confinement(Path(root), target)
            return target
    if verify and tree_source is None:
        raise ValueError("tree_source is required when verification is enabled")
    if on_fetch is not None:
        on_fetch()
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_target_confinement(Path(root), target)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{commit_sha}.tmp-{os.getpid()}-", dir=target.parent)
    )
    try:
        data = fetch_archive()
        logger.debug(
            "materialize downloaded bytes=%d method=%s", len(data), fetch_method
        )
        if len(data) > ARCHIVE_MAX_COMPRESSED_BYTES:
            raise MaterializationError("archive download exceeds compressed size limit")
        _extract_tarball(
            data,
            staging,
            repo,
            commit_sha,
            archive_root=archive_root,
        )
        if verify:
            from leitir.resolver import ArchiveOnlyVerification

            try:
                verified, text_normalized = _verify_extracted_tree(
                    staging,
                    owner,
                    repo,
                    commit_sha,
                    tree_source,
                    max_files=verification_max_files,
                    max_bytes=verification_max_bytes,
                )
            except ArchiveOnlyVerification:
                verified, text_normalized = "archive-only", 0
            verified_at: str | None = _utc_now()
        else:
            verified = False
            verified_at = None
            text_normalized = 0
        verification_notes = (
            [f"text-normalized: {text_normalized} file(s)"] if text_normalized else []
        )
        fetched_at = _utc_now()
        manifest: dict[str, object] = dict(manifest_fields or {})
        if "published_at" in manifest and not _valid_timestamp(
            manifest["published_at"]
        ):
            raise MaterializationError(
                "published_at must be a timezone-aware ISO-8601 timestamp"
            )
        manifest.update(
            {
                "spec": spec,
                "host": host,
                "owner": owner,
                "repo": repo,
                "commit_sha": commit_sha,
                "tag": tag,
                "repo_url": f"{canonical_base}/{owner}/{repo}",
                "fetched_at": fetched_at,
                "fetch_method": fetch_method,
                "subpath": subpath,
                "verified": verified,
                "verified_at": verified_at,
                "verification_notes": verification_notes,
                "source": "git-commit",
                "has_tests": has_top_level_tests(staging, subpath),
                "parity": _github_git_parity(verified, text_normalized)
                if host == "github.com"
                else "unknown",
            }
        )
        # One scan yields the flat per-file digest map and the full-scope
        # aggregate that anchors it; load-time verification is full-coverage
        # for shelves of any size within the archive limits (issue #194).
        manifest.update(full_coverage_manifest_fields(staging))
        _write_manifest(staging / MANIFEST_NAME, manifest)
        _refresh_license_manifest(staging, manifest)
        _assert_target_confinement(Path(root), target)
        if target.exists():
            current = read_valid_manifest(target, owner, repo, commit_sha, host=host)
            if current is not None and _cache_matches_source(
                current, source="git-commit", fetch_method=fetch_method
            ):
                shutil.rmtree(staging)
                return target
            backup = Path(
                tempfile.mkdtemp(prefix=f".{commit_sha}.old-", dir=target.parent)
            )
            backup.rmdir()
            os.replace(target, backup)
        else:
            backup = None
        try:
            os.replace(staging, target)
        except Exception:
            if backup is not None and backup.exists() and not target.exists():
                os.replace(backup, target)
            raise
        _fsync_directory(target.parent)
        if backup is not None:
            _remove_path(backup)
        return target
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        _prune_empty(target.parent, Path(root))
        if isinstance(exc, MaterializationError):
            raise
        raise MaterializationError(
            f"materialization failed for {owner}/{repo}@{commit_sha}: "
            f"{_failure_detail(exc)}"
        ) from exc


def _go_zip_h1(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = sorted(
                (info for info in archive.infolist() if not info.is_dir()),
                key=lambda info: info.filename,
            )
            if (
                len(entries) > ARCHIVE_MAX_MEMBERS
                or len({info.filename for info in entries}) != len(entries)
            ):
                raise ValueError
            summary = hashlib.sha256()
            total_size = 0
            for info in entries:
                if "\n" in info.filename:
                    raise ValueError
                if info.file_size < 0 or info.file_size > ARCHIVE_MAX_MEMBER_BYTES:
                    raise ValueError
                total_size += info.file_size
                if total_size > ARCHIVE_MAX_TOTAL_BYTES:
                    raise ValueError
                with archive.open(info) as handle:
                    digest = hashlib.sha256()
                    while chunk := handle.read(64 * 1024):
                        digest.update(chunk)
                    digest_hex = digest.hexdigest()
                summary.update(f"{digest_hex}  {info.filename}\n".encode())
            return "h1:" + base64.b64encode(summary.digest()).decode("ascii")
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise VerificationError("Go module zip is malformed") from exc


def materialize_go_module_zip(
    root: str | os.PathLike[str],
    spec: str,
    scope: RepoScope,
    module: str,
    version: str,
    proxy_url: str,
    *,
    sumdb_url: str = "https://sum.golang.org",
    timeout: int = 30,
    manifest_fields: Mapping[str, object] | None = None,
    on_fetch: Callable[[], None] | None = None,
) -> Path:
    """Authenticate, download, and shelf a Go proxy module zip."""
    from urllib.request import Request

    from leitir.parity import extract_artifact
    from leitir.sumdb import SumDBClient, SumDBVerificationError

    if not proxy_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise ValueError("Go proxy URL must use HTTPS or a local test endpoint")
    owner, repo = scope.slug.split("/", 1)
    # A Go module's synthetic scope has the content hash as both its repository
    # name and commit. Do not expose that implementation detail as duplicate
    # shelf directories: module content belongs directly under its one hash.
    target = Path(root) / "repos" / "go-module-zip" / owner / scope.commit_sha
    with _target_lock(Path(root), target, scope.commit_sha):
        existing = read_valid_manifest(target, owner, repo, scope.commit_sha, host="go-module-zip") if target.is_dir() else None
        if existing is not None and existing.get("module_path") == module and existing.get("module_version") == version:
            _refresh_license_manifest(target, existing)
            return target
        from leitir.resolver import escape_go_module_path

        escaped_module = escape_go_module_path(module)
        url = f"{proxy_url.rstrip('/')}/{escaped_module}/@v/{version}.zip"
        if on_fetch is not None:
            on_fetch()
        try:
            with _http.safe_urlopen(Request(url, headers={"User-Agent": "leitir"}), timeout=timeout) as response:
                data = _read_bounded(response, ARCHIVE_MAX_COMPRESSED_BYTES)
            sum_hash = SumDBClient(Path(root), base_url=sumdb_url, timeout=timeout).verify(
                module, version, escaped_module=escaped_module
            )
        except SumDBVerificationError:
            raise
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ArtifactRetrievalError(f"Go module zip retrieval failed for {spec}: {_http.describe_failure(exc)}") from exc
        if _go_zip_h1(data) != sum_hash:
            raise VerificationError("Go module zip does not match sumdb h1 hash")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = [info.filename for info in archive.infolist() if info.filename]
        except zipfile.BadZipFile as exc:
            raise VerificationError("Go module zip is malformed") from exc
        # Proxy and lookup URLs use the escaped module path, while standard Go
        # proxy zips retain the canonical path in their member names. Accept the
        # escaped form too: it is covered by the authenticated h1 and is used by
        # compatible proxy implementations.
        archive_root = f"{module}@{version}"
        if not all(name.startswith(f"{archive_root}/") for name in names):
            archive_root = f"{escaped_module}@{version}"
        if not names or any(not name.startswith(f"{archive_root}/") for name in names):
            raise VerificationError("Go module zip has an unexpected module root")
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{scope.commit_sha}.tmp-{os.getpid()}-", dir=target.parent))
        try:
            extract_artifact(data, staging, archive_root=archive_root)
            now = _utc_now()
            manifest: dict[str, object] = dict(manifest_fields or {})
            manifest.update({
                "spec": spec,
                "host": "go-module-zip",
                "owner": owner,
                "repo": repo,
                "commit_sha": scope.commit_sha,
                "tag": version,
                "repo_url": None,
                "fetched_at": now,
                "fetch_method": "go-module-zip",
                "subpath": None,
                "verified": True,
                "verified_at": now,
                "verification_notes": [],
                "source": "go-module-zip",
                "has_tests": has_top_level_tests(staging),
                "module_path": module,
                "module_version": version,
                "proxy_url": proxy_url,
                "zip_sha256": hashlib.sha256(data).hexdigest(),
                "sumdb_h1": sum_hash,
            })
            # One scan yields the per-file digest map plus the full-scope
            # aggregate anchoring it (issue #194).
            manifest.update(full_coverage_manifest_fields(staging))
            _write_manifest(staging / MANIFEST_NAME, manifest)
            _refresh_license_manifest(staging, manifest)
            if target.exists():
                backup = Path(tempfile.mkdtemp(prefix=f".{scope.commit_sha}.old-", dir=target.parent))
                backup.rmdir()
                os.replace(target, backup)
            else:
                backup = None
            os.replace(staging, target)
            _fsync_directory(target.parent)
            if backup is not None:
                _remove_path(backup)
            return target
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            _prune_empty(target.parent, Path(root))
            raise


def materialize_artifact(
    root: str | os.PathLike[str],
    spec: str,
    scope: RepoScope,
    artifact: object,
    *,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    fetcher: object | None = None,
    on_fetch: Callable[[], None] | None = None,
) -> Path:
    if not isinstance(scope, RepoScope):
        raise TypeError("scope must be a RepoScope")
    owner, repo = scope.slug.split("/", 1)
    target = target_path(root, owner, repo, scope.commit_sha)
    with _target_lock(Path(root), target, scope.commit_sha):
        return _materialize_artifact_locked(
            root,
            spec,
            scope,
            artifact,
            tag=tag,
            subpath=subpath,
            manifest_fields=manifest_fields,
            fetcher=fetcher,
            on_fetch=on_fetch,
        )


def _materialize_artifact_locked(
    root: str | os.PathLike[str],
    spec: str,
    scope: RepoScope,
    artifact: object,
    *,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    fetcher: object | None = None,
    on_fetch: Callable[[], None] | None = None,
) -> Path:
    """Authenticate and safely materialize a registry source artifact."""
    import hashlib

    from leitir.parity import (
        ArtifactInfo,
        ChecksumMismatchError,
        RegistryArtifactFetcher,
        extract_artifact,
    )

    if not isinstance(artifact, ArtifactInfo):
        raise TypeError("artifact must be an ArtifactInfo")
    logger.debug(
        "materialize fetch method=registry-artifact kind=%s url=%s",
        artifact.artifact_kind,
        artifact.url,
    )
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("spec must be non-empty")
    owner, repo = scope.slug.split("/", 1)
    _validate_identity(owner, repo, scope.commit_sha)
    target = target_path(root, owner, repo, scope.commit_sha)
    _assert_target_confinement(Path(root), target)
    existing = (
        read_valid_manifest(target, owner, repo, scope.commit_sha)
        if target.is_dir()
        else None
    )
    if existing is not None and _cache_matches_source(
        existing,
        source="registry-artifact",
        fetch_method="registry-artifact",
        artifact_kind=artifact.artifact_kind,
        artifact_checksum=artifact.checksum,
    ):
        _refresh_license_manifest(target, existing)
        _assert_target_confinement(Path(root), target)
        return target

    client = fetcher or RegistryArtifactFetcher(max_bytes=ARCHIVE_MAX_COMPRESSED_BYTES)
    if on_fetch is not None:
        on_fetch()
    try:
        data = client.fetch(artifact)  # type: ignore[attr-defined]
    except Exception as exc:
        raise ArtifactRetrievalError(
            f"artifact retrieval failed for {spec}: {_failure_detail(exc)}"
        ) from exc
    if len(data) > ARCHIVE_MAX_COMPRESSED_BYTES:
        raise ArtifactRetrievalError("artifact download exceeds compressed size limit")
    actual = hashlib.new(artifact.algorithm, data).hexdigest()
    logger.debug("artifact checksum expected=%s actual=%s", artifact.digest, actual)
    if actual.lower() != artifact.digest.lower():
        raise ChecksumMismatchError(
            f"{artifact.artifact_kind} checksum mismatch: expected {artifact.checksum}"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_target_confinement(Path(root), target)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{scope.commit_sha}.tmp-{os.getpid()}-", dir=target.parent
        )
    )
    try:
        extract_artifact(data, staging)
        now = _utc_now()
        manifest: dict[str, object] = dict(manifest_fields or {})
        if "published_at" in manifest and not _valid_timestamp(
            manifest["published_at"]
        ):
            raise MaterializationError(
                "published_at must be a timezone-aware ISO-8601 timestamp"
            )
        manifest.update(
            {
                "spec": spec,
                "host": "github.com",
                "owner": owner,
                "repo": repo,
                "commit_sha": scope.commit_sha,
                "tag": tag,
                "repo_url": f"https://github.com/{owner}/{repo}",
                "fetched_at": now,
                "fetch_method": "registry-artifact",
                "subpath": subpath,
                "verified": True,
                "verified_at": now,
                "verification_notes": [],
                "source": "registry-artifact",
                "has_tests": None,
                "artifact_kind": artifact.artifact_kind,
                "artifact_checksum": artifact.checksum,
            }
        )
        # One scan yields the per-file digest map plus the full-scope
        # aggregate anchoring it (issue #194).
        manifest.update(full_coverage_manifest_fields(staging))
        _write_manifest(staging / MANIFEST_NAME, manifest)
        _refresh_license_manifest(staging, manifest)
        _assert_target_confinement(Path(root), target)
        if target.exists():
            current = read_valid_manifest(target, owner, repo, scope.commit_sha)
            if current is not None and _cache_matches_source(
                current,
                source="registry-artifact",
                fetch_method="registry-artifact",
                artifact_kind=artifact.artifact_kind,
                artifact_checksum=artifact.checksum,
            ):
                shutil.rmtree(staging)
                return target
            backup = Path(
                tempfile.mkdtemp(prefix=f".{scope.commit_sha}.old-", dir=target.parent)
            )
            backup.rmdir()
            os.replace(target, backup)
        else:
            backup = None
        try:
            os.replace(staging, target)
        except Exception:
            if backup is not None and backup.exists() and not target.exists():
                os.replace(backup, target)
            raise
        _fsync_directory(target.parent)
        if backup is not None:
            _remove_path(backup)
        return target
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        _prune_empty(target.parent, Path(root))
        raise


def materialize_repo(
    root: str | os.PathLike[str],
    spec: str,
    scope: RepoScope,
    *,
    host: str = "github.com",
    resolver: object | None = None,
    **kwargs: object,
) -> Path:
    """Materialize a :class:`RepoScope` through its host-native resolver."""
    slug = (
        f"~{scope.slug}"
        if host == "git.sr.ht" and not scope.slug.startswith("~")
        else scope.slug
    )
    owner, repo = slug.split("/", 1)
    owner, repo, _parts = _normalize_identity(owner, repo, scope.commit_sha, host)
    if host == "github.com":
        return materialize_github_repo(
            root,
            spec,
            owner,
            repo,
            scope.commit_sha,
            **kwargs,  # type: ignore[arg-type]
        )
    if host not in ("gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht"):
        raise ValueError(f"unsupported repository host {host!r}")
    if resolver is None:
        raise ValueError(f"a repository resolver is required for {host}")
    archive_url = resolver.archive_url(slug, scope.commit_sha)  # type: ignore[attr-defined]
    hosted_options = {
        key: kwargs.pop(key)
        for key in tuple(kwargs)
        if key
        in {
            "tag",
            "subpath",
            "manifest_fields",
            "verify",
            "verification_max_files",
            "verification_max_bytes",
            "on_fetch",
        }
    }
    for github_only in (
        "token",
        "timeout",
        "base_url",
        "max_attempts",
        "base_delay",
        "max_delay",
        "max_rate_limit_delay",
        "sleeper",
        "tree_source",
        "tree_base_url",
    ):
        kwargs.pop(github_only, None)
    if kwargs:
        unexpected = next(iter(kwargs))
        raise TypeError(f"unexpected materialization option {unexpected!r}")
    archive_fetcher = getattr(resolver, "_get_archive_bytes", None)
    if archive_fetcher is None:
        fetch_archive = lambda: resolver._get_bytes(archive_url)  # type: ignore[attr-defined]
    else:
        fetch_archive = lambda: archive_fetcher(
            archive_url, ARCHIVE_MAX_COMPRESSED_BYTES
        )
    return _materialize_hosted_repo(
        root,
        spec,
        owner,
        repo,
        scope.commit_sha,
        host=host,
        fetch_archive=fetch_archive,
        tree_source=resolver,
        **hosted_options,  # type: ignore[arg-type]
    )
