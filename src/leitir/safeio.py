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


def read_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one bounded regular file exactly once, never following its final link."""

    if not isinstance(path, Path) or type(maximum_bytes) is not int or maximum_bytes < 0:
        raise TypeError("path and maximum_bytes have invalid types")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if type(no_follow) is not int or no_follow == 0:
        raise NoFollowUnavailableError("platform does not support O_NOFOLLOW")
    descriptor = os.open(path, os.O_RDONLY | no_follow)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("not a regular file")
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
