from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from leitir.safeio import NoFollowUnavailableError, read_regular_file


def test_read_regular_file_fails_closed_when_no_follow_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "regular.txt"
    path.write_bytes(b"contents")
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    with pytest.raises(NoFollowUnavailableError):
        read_regular_file(path, maximum_bytes=64)


def test_read_regular_file_can_read_digest_anchored_input_without_no_follow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "regular.txt"
    path.write_bytes(b"contents")
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    assert read_regular_file(path, maximum_bytes=64, no_follow=False) == b"contents"


def test_read_regular_file_rejects_non_regular_and_oversized_inputs(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"contents")

    with pytest.raises(ValueError, match="exceeds bound"):
        read_regular_file(oversized, maximum_bytes=3)
    with pytest.raises(OSError, match="not a regular file"):
        read_regular_file(tmp_path, maximum_bytes=64, no_follow=False)


@pytest.mark.parametrize("no_follow", [None, 0, 1, "false"])
def test_read_regular_file_rejects_non_boolean_no_follow(tmp_path: Path, no_follow: object) -> None:
    with pytest.raises(TypeError):
        read_regular_file(tmp_path / "regular.txt", maximum_bytes=64, no_follow=no_follow)  # type: ignore[arg-type]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux O_NOFOLLOW behavior")
def test_read_regular_file_rejects_a_final_component_symlink_on_linux(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_bytes(b"contents")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(OSError):
        read_regular_file(link, maximum_bytes=64)
