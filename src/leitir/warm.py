"""Task-bounded warm manifest verification (ADR-0035, epoch amendment).

One session supports one corpus root and is intended for one thread at a
time within an explicit :meth:`WarmSession.call` window.  A cached
verification is reused only while the writer-visible lock epoch and the
whole-tree stat signature recorded at verification time are both unchanged;
any ambiguity falls back to ADR-0006 full verification.  The session holds
no target locks: cross-writer visibility is the on-disk epoch's job, so
lock windows stay as short as a single writer transaction.  A failed
verification discards the memo and fails the touch; because a lock-free
failure cannot be attributed (a writer's swap-and-restore leaves
net-neutral evidence), later touches re-verify cold per touch — exactly
the cold path's per-invocation contract, never weaker.
"""

from __future__ import annotations

import copy
import logging
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from leitir import materialize
from leitir.materialize import MANIFEST_NAME

logger = logging.getLogger(__name__)

# (relative path, inode, mtime_ns, ctime_ns, size) per regular file.  ctime
# makes POSIX utime-based stat restoration observable; on platforms where
# ctime is creation time (Windows) the documented residual stands.
_FileStats = tuple[tuple[str, int, int, int, int], ...]
_ManifestStat = tuple[int, int, int, int]
_Sweep = tuple[_FileStats, _ManifestStat] | None


@dataclass(frozen=True)
class _WarmEntry:
    """A private, verified manifest with post-verification stat evidence."""

    manifest: dict[str, Any]
    file_stats: _FileStats
    manifest_stat: _ManifestStat
    epoch: bytes


def _stat_tuple(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_size


def _stat_sweep(target: Path) -> _Sweep:
    """Capture all regular-file stats, or ``None`` for ambiguous tree shape."""
    root_metadata = os.lstat(target)
    if not stat.S_ISDIR(root_metadata.st_mode):
        return None

    file_stats: list[tuple[str, int, int, int, int]] = []

    def raise_walk_error(error: OSError) -> None:
        raise error

    for directory, directories, filenames in os.walk(
        target, followlinks=False, onerror=raise_walk_error
    ):
        directories.sort()
        filenames.sort()
        current = Path(directory)
        for name in directories:
            metadata = os.lstat(current / name)
            if not stat.S_ISDIR(metadata.st_mode):
                return None
        for name in filenames:
            path = current / name
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode):
                return None
            relative = path.relative_to(target).as_posix()
            file_stats.append((relative, *_stat_tuple(metadata)))

    manifest_metadata = os.lstat(target / MANIFEST_NAME)
    if not stat.S_ISREG(manifest_metadata.st_mode):
        return None
    file_stats.sort(key=lambda item: item[0])
    return tuple(file_stats), _stat_tuple(manifest_metadata)


class WarmSession:
    """Thread-safe, corpus-root-scoped memo for one bounded task."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root).expanduser().resolve()
        self._lock = threading.RLock()
        self._entries: dict[str, _WarmEntry] = {}
        self._window_thread: int | None = None
        self._window_depth = 0
        self._closed = False
        self._degraded = False
        self._stats = {
            "hits": 0,
            "misses": 0,
            "revalidations": 0,
            "cold_fallbacks": 0,
        }

    def __enter__(self) -> WarmSession:
        with self._lock:
            self._require_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()

    @property
    def degraded(self) -> bool:
        """Whether all further reads must use the cold verification path."""
        with self._lock:
            return self._degraded

    @property
    def root(self) -> Path:
        """The resolved corpus root scoped by this session."""
        return self._root

    @contextmanager
    def call(self) -> Iterator[WarmSession]:
        """Open a reentrant per-tool-call window for this session.

        The window serializes memo use to one thread at a time; it holds no
        target locks.  Cross-writer invalidation is the on-disk lock
        epoch's responsibility, checked on every memoized read.
        """
        thread_id = threading.get_ident()
        foreign = False
        with self._lock:
            self._require_open()
            if self._window_depth == 0:
                self._window_thread = thread_id
                self._window_depth = 1
            elif self._window_thread == thread_id:
                self._window_depth += 1
            else:
                self._degrade()
                foreign = True
        try:
            yield self
        finally:
            if not foreign:
                with self._lock:
                    if not self._closed:
                        self._window_depth -= 1
                        if self._window_depth == 0:
                            self._window_thread = None

    def read_valid_manifest(
        self,
        target: Path,
        owner: str,
        repo: str,
        commit_sha: str,
        *,
        host: str = "github.com",
    ) -> dict[str, Any] | None:
        """Return a verified manifest, memoized across calls when provable.

        A memo is served only when the target's writer-visible epoch bytes
        and whole-tree stat signature are both unchanged since the recorded
        full verification.  Anything else — mismatch, absent entry, or
        ambiguous evidence — re-runs the unchanged cold gate.
        """
        target = target.expanduser().absolute()
        resolved = target.resolve(strict=False)
        target_key = os.path.normcase(str(resolved))
        with self._lock:
            self._require_open()
            if (
                self._degraded
                or self._window_depth == 0
                or self._window_thread != threading.get_ident()
            ):
                if self._window_depth and self._window_thread != threading.get_ident():
                    self._degrade()
                return self._cold_read(target, owner, repo, commit_sha, host=host)
            if not resolved.is_relative_to(self._root):
                return self._cold_read(target, owner, repo, commit_sha, host=host)

            entry = self._entries.get(target_key)
            if entry is not None and self._cache_identity_matches(
                entry.manifest, owner, repo, commit_sha, host
            ):
                sweep = self._sweep_or_degrade(target)
                if self.degraded:
                    return self._cold_read(target, owner, repo, commit_sha, host=host)
                if (
                    sweep is not None
                    and sweep[0] == entry.file_stats
                    and sweep[1] == entry.manifest_stat
                    and self._epoch_unchanged(target, entry)
                ):
                    self._stats["hits"] += 1
                    return copy.deepcopy(entry.manifest)

            was_cached = entry is not None
            self._stats["misses"] += 1
            if was_cached:
                self._stats["revalidations"] += 1
            # Bracket the whole verification with BOTH evidence kinds.  The
            # epoch brackets acquisitions, not mutations — a writer swaps the
            # shelf at the END of a long held interval, after its bump — so
            # only agreeing sweep+epoch pairs across the attempt prove the
            # hashed bytes and the pinned signature describe one shelf state
            # (review F1).  Agreement also distinguishes a torn read from
            # corruption for stickiness (review F3).
            epoch_before = self._read_epoch_or_none(target)
            sweep_before = self._sweep_or_degrade(target)
            status, manifest = materialize._read_valid_manifest_with_status(
                target,
                owner,
                repo,
                commit_sha,
                host=host,
                allow_missing_tree_hash=False,
            )
            epoch_after = self._read_epoch_or_none(target)
            sweep_after = self._sweep_or_degrade(target)
            writer_overlapped = (
                epoch_before is None
                or epoch_after is None
                or epoch_before != epoch_after
                or sweep_before is None
                or sweep_after is None
                or sweep_before != sweep_after
            )
            if status == "invalid":
                # A lock-free failure is attribution-ambiguous: a writer
                # that swapped and restored mid-verify leaves net-neutral
                # sweep/epoch evidence indistinguishable from corruption.
                # Drop the memo and fail this touch; every later touch
                # re-verifies cold (review F3) — the cold path's own
                # per-invocation contract, so no cached success ever
                # survives a failure and nothing unverified is served.
                self._entries.pop(target_key, None)
                return None
            if status != "ok" or manifest is None:
                return None

            if (
                not writer_overlapped
                and not self._degraded
                and sweep_after is not None
                and epoch_after is not None
            ):
                self._entries[target_key] = _WarmEntry(
                    manifest=copy.deepcopy(manifest),
                    file_stats=sweep_after[0],
                    manifest_stat=sweep_after[1],
                    epoch=epoch_after,
                )
            return copy.deepcopy(manifest)

    def resolve_under_lock(
        self,
        target: Path,
        owner: str,
        repo: str,
        commit_sha: str,
        *,
        host: str = "github.com",
    ) -> dict[str, Any] | None:
        """Serve the memo for a shelf whose target lock the caller holds.

        Valid only when the current counter equals the recorded counter or
        exceeds it by exactly one: ``recorded`` means the caller's take was
        a reentrant borrow of a hold that has been continuous since the
        recording (a foreign writer could not have acquired in between),
        and ``recorded + 1`` means the caller's own real acquisition is the
        only bump since.  Any other total means a further acquisition —
        this process in a later hold, or a foreign writer — intervened, so
        the caller must re-run the full cold gate under its lock.
        """
        target = target.expanduser().absolute()
        resolved = target.resolve(strict=False)
        target_key = os.path.normcase(str(resolved))
        with self._lock:
            self._require_open()
            if (
                self._degraded
                or self._window_depth == 0
                or self._window_thread != threading.get_ident()
                or not resolved.is_relative_to(self._root)
            ):
                self._stats["misses"] += 1
                return None
            entry = self._entries.get(target_key)
            if entry is None or not self._cache_identity_matches(
                entry.manifest, owner, repo, commit_sha, host
            ):
                self._stats["misses"] += 1
                return None
            epoch_now = self._read_epoch_or_none(target)
            recorded = materialize.parse_lock_epoch(entry.epoch)
            current = materialize.parse_lock_epoch(epoch_now or b"")
            if (
                epoch_now is None
                or recorded is None
                or current is None
                or current not in (recorded, recorded + 1)
            ):
                self._stats["revalidations"] += 1
                return None
            sweep = self._sweep_or_degrade(target)
            if (
                sweep is None
                or self._degraded
                or sweep[0] != entry.file_stats
                or sweep[1] != entry.manifest_stat
            ):
                self._stats["revalidations"] += 1
                return None
            # Refresh the recorded generation to this acquisition's counter
            # so each later locked open observes exactly its own +1 step.
            self._entries[target_key] = _WarmEntry(
                manifest=entry.manifest,
                file_stats=sweep[0],
                manifest_stat=sweep[1],
                epoch=epoch_now,
            )
            self._stats["hits"] += 1
            return copy.deepcopy(entry.manifest)

    def record_under_lock(
        self,
        target: Path,
        owner: str,
        repo: str,
        commit_sha: str,
        manifest: dict[str, Any],
        *,
        host: str = "github.com",
    ) -> None:
        """Pin a just-verified manifest for a lock the caller still holds.

        The caller performed a full cold verification under the target lock
        and has not yet released it, so the stat sweep and epoch read here
        cannot interleave with a cooperating writer.
        """
        if not self._cache_identity_matches(manifest, owner, repo, commit_sha, host):
            return
        target = target.expanduser().absolute()
        resolved = target.resolve(strict=False)
        target_key = os.path.normcase(str(resolved))
        with self._lock:
            self._require_open()
            if (
                self._degraded
                or self._window_depth == 0
                or self._window_thread != threading.get_ident()
                or not resolved.is_relative_to(self._root)
            ):
                return
            epoch = self._read_epoch_or_none(target)
            sweep = self._sweep_or_degrade(target)
            if epoch is None or sweep is None or self._degraded:
                return
            self._entries[target_key] = _WarmEntry(
                manifest=copy.deepcopy(manifest),
                file_stats=sweep[0],
                manifest_stat=sweep[1],
                epoch=epoch,
            )

    def stats(self) -> dict[str, int]:
        """Return deterministic copies of the session counters."""
        with self._lock:
            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "revalidations": self._stats["revalidations"],
                "cold_fallbacks": self._stats["cold_fallbacks"],
            }

    def invalidate(self, target: Path) -> None:
        """Forget one target's cache entry."""
        target_key = os.path.normcase(str(target.expanduser().resolve(strict=False)))
        with self._lock:
            self._require_open()
            self._entries.pop(target_key, None)

    def close(self) -> None:
        """Discard every task-local memo; no locks are held to release."""
        with self._lock:
            if self._closed:
                return
            self._entries.clear()
            self._window_depth = 0
            self._window_thread = None
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("warm session is closed")

    def _degrade(self) -> None:
        if not self._degraded:
            self._degraded = True
            logger.warning("warm session degraded; falling back to cold manifest reads")

    def _cold_read(
        self, target: Path, owner: str, repo: str, commit_sha: str, *, host: str
    ) -> dict[str, Any] | None:
        self._stats["cold_fallbacks"] += 1
        status, manifest = materialize._read_valid_manifest_with_status(
            target,
            owner,
            repo,
            commit_sha,
            host=host,
            allow_missing_tree_hash=False,
        )
        return copy.deepcopy(manifest) if status == "ok" and manifest is not None else None

    def _read_epoch_or_none(self, target: Path) -> bytes | None:
        identity = materialize._target_lock_identity(self._root, target, "")
        return materialize.read_lock_epoch(identity)

    def _epoch_unchanged(self, target: Path, entry: _WarmEntry) -> bool:
        current = self._read_epoch_or_none(target)
        return current is not None and current == entry.epoch

    def _sweep_or_degrade(self, target: Path) -> _Sweep:
        try:
            return _stat_sweep(target)
        except OSError:
            # A one-off stat race merely requires a full re-verify.  A second
            # failure cannot establish reliable warm evidence, so degrade.
            try:
                _stat_sweep(target)
            except OSError:
                self._degrade()
            return None

    @staticmethod
    def _cache_identity_matches(
        manifest: dict[str, Any], owner: str, repo: str, commit_sha: str, host: str
    ) -> bool:
        return (
            manifest.get("host") == host
            and manifest.get("owner") == owner
            and manifest.get("repo") == repo
            and manifest.get("commit_sha") == commit_sha
        )


@contextmanager
def warm_session(root: str | os.PathLike[str]) -> Iterator[WarmSession]:
    """Construct and close a :class:`WarmSession` around one task."""
    with WarmSession(root) as session:
        yield session
