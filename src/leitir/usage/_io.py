"""Portable bounded file reads for the usage evidence package.

Every read in ``leitir.usage`` is independently digest-anchored: report
bytes are checked against ``report_digest``, ``requirements.txt`` bytes
against ``dependency_evidence.requirements_digest``, and each source span's
bytes against its declared ``code_digest``. ``src/leitir/safeio.py:44-58``
documents exactly this escape hatch verbatim: "An unpinned input may opt out
only when its bytes are independently digest-anchored. The lstat/fstat
comparison still rejects a path swap (including a final-component symlink)
between inspection and open."

Platforms without ``os.O_NOFOLLOW`` (Windows) cannot honor
``no_follow=True`` -- ``leitir.safeio.read_regular_file`` raises
``NoFollowUnavailableError`` immediately, before any I/O. ``read_portable_file``
below always attempts ``no_follow=True`` first and falls back to
``no_follow=False`` *only* when that specific platform-capability error is
raised. The lstat/fstat device+inode comparison inside ``read_regular_file``
still runs unconditionally in both branches and still rejects a path swap or
final-component symlink race between inspection and open, so no security
guarantee is weakened by the fallback.

On a platform that *does* support ``O_NOFOLLOW`` (Linux, macOS), behavior is
byte-for-byte identical to calling
``leitir.safeio.read_regular_file(path, maximum_bytes=..., no_follow=True)``
directly: the fallback branch is never reached, and a symlinked input is
still refused exactly as before.

Package-private: import only from within ``leitir.usage`` (and its tests).
"""

from __future__ import annotations

from pathlib import Path

from leitir.safeio import NoFollowUnavailableError, read_regular_file


def read_portable_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one bounded, digest-anchored file, tolerating a missing O_NOFOLLOW."""

    try:
        return read_regular_file(path, maximum_bytes=maximum_bytes, no_follow=True)
    except NoFollowUnavailableError:
        return read_regular_file(path, maximum_bytes=maximum_bytes, no_follow=False)
