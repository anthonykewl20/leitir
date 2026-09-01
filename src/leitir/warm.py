"""Task-bounded warm manifest verification (ADR-0035).

One session supports one corpus root and is intended for one thread at a time.
Within an explicit :meth:`WarmSession.call` window, it retains each target's
advisory lock and can reuse an already verified manifest only while the same
lock acquisition remains continuous.  File-stat evidence is an invalidation
signal, never an integrity substitute: ambiguity always falls back to ADR-0006
full verification.
"""

from __future__ import annotations

import copy
import logging
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from leitir import materialize
from leitir.materialize import MANIFEST_NAME, MaterializationError

logger = logging.getLogger(__name__)

_FileStats = tuple[tuple[str, int, int, int], ...]
_ManifestStat = tuple[int, int, int]
_Sweep = tuple[_FileStats, _ManifestStat] | None


@dataclass(frozen=True)
class _WarmEntry:
    """A private, verified manifest with post-verification stat evidence."""

    manifest: dict[str, Any]
    file_stats: _FileStats
    manifest_stat: _ManifestStat


def _stat_tuple(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_ino, metadata.st_mtime_ns, metadata.st_size


def _stat_sweep(target: Path) -> _Sweep:
    """Capture all regular-file stats, or ``None`` for ambiguous tree shape."""
    root_metadata = os.lstat(target)
    if not stat.S_ISDIR(root_metadata.st_mode):
        return None

    file_stats: list[tuple[str, int, int, int]] = []

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
        self._entry_epochs: dict[str, int] = {}
        self._sticky: set[str] = set()
        self._held: dict[str, AbstractContextManager[None]] = {}
        self._held_order: list[str] = []
        self._window_thread: int | None = None
        self._window_depth = 0
        self._closed = False
        self._degraded = False
        self._stats = {
            "hits": 0,
            "misses": 0,
            "revalidations": 0,
            "sticky_rejects": 0,
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
        """Open a reentrant per-tool-call lock-holding window."""
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
                            self._release_all()
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
        """Return a verified manifest, using a same-window memo only safely."""
        target = target.expanduser().absolute()
        target_key = os.path.normcase(str(target.resolve(strict=False)))
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
            if target_key in self._sticky:
                return None
            if not target.is_relative_to(self._root):
                return self._cold_read(target, owner, repo, commit_sha, host=host)

            try:
                lock_identity = self._hold_target_lock(target, commit_sha, host=host)
            except (MaterializationError, OSError, RuntimeError, ValueError):
                self._degrade()
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
                    and self._entry_epochs.get(target_key)
                    == materialize._lock_epoch(lock_identity)
                ):
                    self._stats["hits"] += 1
                    return copy.deepcopy(entry.manifest)

            was_cached = entry is not None
            self._stats["misses"] += 1
            if was_cached:
                self._stats["revalidations"] += 1
            status, manifest = materialize._read_valid_manifest_with_status(
                target,
                owner,
                repo,
                commit_sha,
                host=host,
                allow_missing_tree_hash=False,
            )
            if status == "invalid":
                self._entries.pop(target_key, None)
                self._entry_epochs.pop(target_key, None)
                self._sticky.add(target_key)
                self._stats["sticky_rejects"] += 1
                return None
            if status != "ok" or manifest is None:
                return None

            sweep = self._sweep_or_degrade(target)
            if sweep is not None and not self._degraded:
                self._entries[target_key] = _WarmEntry(
                    manifest=copy.deepcopy(manifest),
                    file_stats=sweep[0],
                    manifest_stat=sweep[1],
                )
                self._entry_epochs[target_key] = materialize._lock_epoch(lock_identity)
            return copy.deepcopy(manifest)

    def stats(self) -> dict[str, int]:
        """Return deterministic copies of the session counters."""
        with self._lock:
            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "revalidations": self._stats["revalidations"],
                "sticky_rejects": self._stats["sticky_rejects"],
                "cold_fallbacks": self._stats["cold_fallbacks"],
            }

    def invalidate(self, target: Path) -> None:
        """Forget one target's cache entry and sticky rejection."""
        target_key = os.path.normcase(str(target.expanduser().resolve(strict=False)))
        with self._lock:
            self._require_open()
            self._entries.pop(target_key, None)
            self._entry_epochs.pop(target_key, None)
            self._sticky.discard(target_key)

    def close(self) -> None:
        """Release held locks and discard every task-local cache value."""
        with self._lock:
            if self._closed:
                return
            self._release_all()
            self._entries.clear()
            self._entry_epochs.clear()
            self._sticky.clear()
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

    def _hold_target_lock(self, target: Path, commit_sha: str, *, host: str) -> str:
        lock_identity = materialize._target_lock_identity(
            self._root, target, commit_sha, host=host
        )
        if lock_identity in self._held:
            return lock_identity
        held = materialize._target_lock(self._root, target, commit_sha)
        held.__enter__()
        self._held[lock_identity] = held
        self._held_order.append(lock_identity)
        return lock_identity

    def _release_all(self) -> None:
        while self._held_order:
            lock_identity = self._held_order.pop()
            held = self._held.pop(lock_identity)
            held.__exit__(None, None, None)

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
