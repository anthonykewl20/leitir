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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux O_NOFOLLOW behavior")
def test_read_regular_file_rejects_a_final_component_symlink_on_linux(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_bytes(b"contents")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(OSError):
        read_regular_file(link, maximum_bytes=64)
