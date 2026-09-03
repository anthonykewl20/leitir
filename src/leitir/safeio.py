"""Small fail-closed readers and atomic writers for corpus-controlled files.

The atomic-write mechanics for every durable artifact in leitir live here
(issue #200): temp file in the target's directory by default, write,
``os.fsync(file)``, ``os.replace``, then ``fsync`` of the affected directory
entries, with an fd sentinel so every failure path closes the descriptor
exactly once and never closes a recycled descriptor owned by another thread.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import BinaryIO, TextIO


class SafeIOError(OSError):
    """Base class for a rejected safe file operation."""


class NoFollowUnavailableError(SafeIOError):
    """The platform cannot enforce the required final-component link check."""


def confined_path(root: Path, relative: str) -> Path:
    """Return a lexical corpus-relative path, rejecting absolute and escaping input."""

    candidate = PurePosixPath(relative)
    if not relative or candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != relative:
        raise ValueError("path must be normalized and relative")
    resolved_root = root.resolve(strict=True)
    target = (resolved_root / Path(*candidate.parts)).resolve(strict=False)
    try:
        target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("path escapes its corpus root") from exc
    return target


def read_regular_file(path: Path, *, maximum_bytes: int, no_follow: bool = True) -> bytes:
    """Read one bounded regular file, rejecting final-component substitution races."""

    if not isinstance(path, Path) or type(maximum_bytes) is not int or maximum_bytes < 0 or type(no_follow) is not bool:
        raise TypeError("path, maximum_bytes, and no_follow have invalid types")
    no_follow_flag = getattr(os, "O_NOFOLLOW", 0)
    if no_follow and (type(no_follow_flag) is not int or no_follow_flag == 0):
        raise NoFollowUnavailableError("platform does not support O_NOFOLLOW")
    # An unpinned input may opt out only when its bytes are independently
    # digest-anchored.  The lstat/fstat comparison still rejects a path swap
    # (including a final-component symlink) between inspection and open.
    expected = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(expected.st_mode):
        raise OSError("not a regular file")
    descriptor = os.open(path, os.O_RDONLY | (no_follow_flag if no_follow else 0))
    try:
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode):
            raise OSError("not a regular file")
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError("file changed while opening")
        data = bytearray()
        while len(data) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > maximum_bytes:
            raise ValueError("file exceeds bound")
        return bytes(data)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    """Flush a directory entry so a completed rename is durable (no-op on nt)."""
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _StagedFile:
    """A staged temporary file whose descriptor ownership is sentinel-tracked.

    ``fd`` holds the raw descriptor until ownership transfers to a file
    object (``open_binary``/``open_text`` set the sentinel to ``-1``); a
    failed ``os.fdopen`` hands ownership back so the failure path closes the
    descriptor exactly once and never touches a recycled one.  The staged
    path stays a plain ``str`` so no pathlib factory dispatch (which is
    ``os.name``-dependent) re-renders the tempfile name mid-write.
    """

    __slots__ = ("_fd", "path")

    def __init__(self, path: str, fd: int) -> None:
        self.path = path
        self._fd = fd

    @property
    def fd(self) -> int:
        return self._fd

    def _release(self) -> int:
        fd, self._fd = self._fd, -1
        return fd

    def _reclaim(self, fd: int) -> None:
        self._fd = fd

    def open_binary(self) -> BinaryIO:
        fd = self._release()
        try:
            return os.fdopen(fd, "wb")
        except BaseException:
            self._reclaim(fd)
            raise

    def open_text(self, *, encoding: str, newline: str | None) -> TextIO:
        fd = self._release()
        try:
            return os.fdopen(fd, "w", encoding=encoding, newline=newline)
        except BaseException:
            self._reclaim(fd)
            raise

    def discard(self) -> None:
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        try:
            os.unlink(self.path)
        except OSError:
            pass


@contextmanager
def _staged_file(
    path: Path,
    *,
    fsync_dir: bool,
    # Issue #282: a verified-tree writer must stage outside that tree so a
    # lock-free verifier cannot observe an unmapped transient entry. The
    # verifier's universe rules remain unchanged: hostile or crashed debris
    # inside the tree is still rejected fail-closed.
    staging_directory: Path | None = None,
    staging_prefix: str | None = None,
) -> Iterator[_StagedFile]:
    """Stage one atomic replacement of ``path`` in the selected directory.

    ``staging_directory`` MUST NOT be inside a tree verified by
    ``verify_materialized_integrity``.
    """
    stage_dir = path.parent if staging_directory is None else staging_directory
    prefix = f".{path.name}.tmp-" if staging_prefix is None else staging_prefix
    fd, name = tempfile.mkstemp(prefix=prefix, dir=stage_dir)
    staged = _StagedFile(name, fd)
    try:
        yield staged
        os.replace(staged.path, path)
        if fsync_dir:
            fsync_directory(stage_dir)
            if stage_dir != path.parent:
                # Moving across sibling directories mutates both directory
                # entry sets, so preserve durability for the destination too.
                fsync_directory(path.parent)
    except BaseException:
        staged.discard()
        raise


@contextmanager
def atomic_writer(
    path: Path,
    *,
    fsync_dir: bool = True,
    staging_directory: Path | None = None,
    staging_prefix: str | None = None,
) -> Iterator[BinaryIO]:
    """Yield a binary handle whose close publishes ``path`` atomically.

    The handle writes a temporary file in ``path``'s directory by default; a
    normal exit flushes, fsyncs the file, renames it onto ``path``, and fsyncs
    the affected directory entries. Any failure removes the temporary, closes
    the descriptor exactly once, and re-raises the original error.

    ``staging_directory`` MUST NOT be inside a tree verified by
    ``verify_materialized_integrity``.
    """
    with _staged_file(
        path,
        fsync_dir=fsync_dir,
        staging_directory=staging_directory,
        staging_prefix=staging_prefix,
    ) as staged:
        with staged.open_binary() as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())


@contextmanager
def atomic_text_writer(
    path: Path,
    *,
    encoding: str = "utf-8",
    newline: str | None = "\n",
    fsync_dir: bool = True,
    staging_directory: Path | None = None,
    staging_prefix: str | None = None,
) -> Iterator[TextIO]:
    """Text sibling of :func:`atomic_writer` with io-compatible newlines.

    ``staging_directory`` MUST NOT be inside a tree verified by
    ``verify_materialized_integrity``.
    """
    with _staged_file(
        path,
        fsync_dir=fsync_dir,
        staging_directory=staging_directory,
        staging_prefix=staging_prefix,
    ) as staged:
        with staged.open_text(encoding=encoding, newline=newline) as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())


def atomic_write_bytes(
    path: Path,
    data: bytes,
    *,
    fsync_dir: bool = True,
    staging_directory: Path | None = None,
    staging_prefix: str | None = None,
) -> None:
    """Atomically replace ``path`` with ``data`` (file + parent-dir fsync).

    ``staging_directory`` MUST NOT be inside a tree verified by
    ``verify_materialized_integrity``.
    """
    with atomic_writer(
        path,
        fsync_dir=fsync_dir,
        staging_directory=staging_directory,
        staging_prefix=staging_prefix,
    ) as handle:
        handle.write(data)


def atomic_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    newline: str | None = "\n",
    fsync_dir: bool = True,
    staging_directory: Path | None = None,
    staging_prefix: str | None = None,
) -> None:
    """Atomically replace ``path`` with ``text`` (file + parent-dir fsync).

    ``staging_directory`` MUST NOT be inside a tree verified by
    ``verify_materialized_integrity``.
    """
    with atomic_text_writer(
        path,
        encoding=encoding,
        newline=newline,
        fsync_dir=fsync_dir,
        staging_directory=staging_directory,
        staging_prefix=staging_prefix,
    ) as handle:
        handle.write(text)
