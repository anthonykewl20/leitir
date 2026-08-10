"""Focused malformed-input coverage for registry artifact parity."""

from __future__ import annotations

import io
import stat
import warnings
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from leitir.materialize import MANIFEST_NAME, UnsafeArchiveError
from leitir.parity import (
    ArtifactInfo,
    ParityResult,
    RegistryArtifactFetcher,
    extract_artifact,
)


def _zip(entries: tuple[tuple[str, bytes, int | None], ...]) -> bytes:
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w") as archive:
            for name, content, mode in entries:
                member = zipfile.ZipInfo(name)
                if mode is not None:
                    member.create_system = 3
                    member.external_attr = mode << 16
                archive.writestr(member, content)
    return output.getvalue()


@pytest.mark.parametrize(
    ("archive", "message"),
    [
        (_zip(()), "archive is empty"),
        (_zip((("root\\file.txt", b"x", None),)), "invalid archive member path"),
        (_zip((("root/../escape.txt", b"x", None),)), "escapes its target"),
        (_zip(((f"root/{MANIFEST_NAME}", b"{}", None),)), "reserved manifest"),
        (
            _zip((("root/file.txt", b"a", None), ("root/file.txt", b"b", None))),
            "duplicate member paths",
        ),
        (
            _zip((("root/link", b"target", stat.S_IFLNK | 0o777),)),
            "link or special file",
        ),
        (
            _zip((("first/a.txt", b"a", None), ("second/b.txt", b"b", None))),
            "single top-level directory",
        ),
        (
            _zip((("root", b"not a directory", None),)),
            "top-level member is not a directory",
        ),
    ],
)
def test_extract_artifact_rejects_unsafe_zip_members(
    tmp_path: Path, archive: bytes, message: str
) -> None:
    with pytest.raises(UnsafeArchiveError, match=message):
        extract_artifact(archive, tmp_path / "output")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ArtifactInfo(
            "sdist", "http://example.test/source.zip", "sha256", "0", "0"
        ),
        lambda: ParityResult("maybe", 0, 0, 0),
        lambda: ParityResult("exact", -1, 0, 0),
    ],
)
def test_parity_value_objects_reject_invalid_contracts(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValueError):
        factory()


def test_artifact_fetch_override_enforces_compressed_size_limit() -> None:
    fetcher = RegistryArtifactFetcher(get_bytes=lambda _url: b"too large", max_bytes=3)
    artifact = ArtifactInfo(
        "sdist", "https://example.test/source.zip", "sha256", "0", "0"
    )

    with pytest.raises(ValueError, match="compressed size limit"):
        fetcher.fetch(artifact)
