"""Small fail-closed readers for corpus-controlled regular files."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath


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
