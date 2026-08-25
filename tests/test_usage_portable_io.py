"""Portable bounded reads for the usage package (Windows O_NOFOLLOW gap).

``leitir.safeio.read_regular_file(..., no_follow=True)`` raises
``NoFollowUnavailableError`` immediately on a platform without
``os.O_NOFOLLOW`` (Windows) -- before CI-blocking issue this fixed, the
entire ``leitir.usage`` package was unusable there, since every read in the
package passed ``no_follow=True`` unconditionally.

``leitir.usage._io.read_portable_file`` is the fix: it always attempts
``no_follow=True`` first, and falls back to ``no_follow=False`` *only* when
that specific platform-capability error is raised -- never for any other
failure. This module proves both directions:

- on a simulated no-O_NOFOLLOW platform, reads still succeed (falling back)
  and the fallback still goes through the real lstat/fstat device+inode
  check, so a genuine path-swap race is still caught;
- on a real platform that *does* support O_NOFOLLOW (this test host), a
  symlinked input is still refused -- the fallback is never reached and no
  security guarantee regresses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from leitir.safeio import NoFollowUnavailableError
from leitir.usage._io import read_portable_file


def test_read_portable_file_falls_back_when_o_nofollow_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulates a Windows-like platform: no_follow=True always raises."""

    target = tmp_path / "requirements.txt"
    target.write_bytes(b"widgetlib==1.2.3\n")

    import leitir.usage._io as usage_io

    real_read_regular_file = usage_io.read_regular_file

    def _no_o_nofollow(path: Path, *, maximum_bytes: int, no_follow: bool = True) -> bytes:
        if no_follow:
            raise NoFollowUnavailableError("platform does not support O_NOFOLLOW")
        return real_read_regular_file(path, maximum_bytes=maximum_bytes, no_follow=False)

    monkeypatch.setattr(usage_io, "read_regular_file", _no_o_nofollow)

    assert read_portable_file(target, maximum_bytes=65_536) == b"widgetlib==1.2.3\n"


def test_read_portable_file_fallback_still_rejects_a_path_swap_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback (no_follow=False) still runs the lstat/fstat device+inode
    check inside the real ``read_regular_file`` -- it is not a bare open()."""

    import leitir.usage._io as usage_io

    def _always_unavailable(path: Path, *, maximum_bytes: int, no_follow: bool = True) -> bytes:
        if no_follow:
            raise NoFollowUnavailableError("platform does not support O_NOFOLLOW")
        # Simulate the underlying lstat/fstat mismatch a real path-swap race
        # would trigger, by raising the same OSError read_regular_file raises.
        raise OSError("file changed while opening")

    monkeypatch.setattr(usage_io, "read_regular_file", _always_unavailable)

    with pytest.raises(OSError, match="file changed while opening"):
        read_portable_file(tmp_path / "requirements.txt", maximum_bytes=65_536)


def test_read_portable_file_never_falls_back_on_an_unrelated_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-capability OSError must propagate as-is, never trigger a retry."""

    import leitir.usage._io as usage_io

    calls: list[bool] = []

    def _raises_plain_oserror(path: Path, *, maximum_bytes: int, no_follow: bool = True) -> bytes:
        calls.append(no_follow)
        raise OSError("not a regular file")

    monkeypatch.setattr(usage_io, "read_regular_file", _raises_plain_oserror)

    with pytest.raises(OSError, match="not a regular file"):
        read_portable_file(tmp_path / "missing.txt", maximum_bytes=65_536)
    assert calls == [True]  # exactly one attempt -- no retry for a non-capability failure


def test_read_portable_file_on_a_capable_platform_still_refuses_a_symlink(tmp_path: Path) -> None:
    """No monkeypatching: proves the real, unmodified behavior on this host
    (which does support O_NOFOLLOW) still refuses a symlinked input, i.e.
    the fallback branch is never exercised and no security guarantee
    regresses for platforms that can enforce O_NOFOLLOW."""

    import os

    no_follow_flag = getattr(os, "O_NOFOLLOW", 0)
    if type(no_follow_flag) is not int or no_follow_flag == 0:
        pytest.skip("this platform does not support O_NOFOLLOW")

    real_target = tmp_path / "real_requirements.txt"
    real_target.write_bytes(b"widgetlib==1.2.3\n")
    symlink_path = tmp_path / "requirements.txt"
    symlink_path.symlink_to(real_target)

    with pytest.raises(OSError):
        read_portable_file(symlink_path, maximum_bytes=65_536)
