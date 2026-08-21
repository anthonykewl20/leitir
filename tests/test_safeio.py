from __future__ import annotations

import os
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from leitir import safeio
from leitir.safeio import (
    NoFollowUnavailableError,
    atomic_text_writer,
    atomic_write_bytes,
    atomic_write_text,
    atomic_writer,
    read_regular_file,
)


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


@pytest.mark.parametrize(
    "no_follow",
    [
        pytest.param(None, marks=pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="strict no-follow read requires O_NOFOLLOW")),
        False,
    ],
)
def test_read_regular_file_rejects_non_regular_and_oversized_inputs(tmp_path: Path, no_follow: bool | None) -> None:
    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"contents")

    with pytest.raises(ValueError, match="exceeds bound"):
        if no_follow is None:
            read_regular_file(oversized, maximum_bytes=3)
        else:
            read_regular_file(oversized, maximum_bytes=3, no_follow=no_follow)
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


# --- Atomic-write consolidation (issue #200) ---------------------------------
# Coverage for the shared helper: SP-1 replace failure (single close, temp
# cleanup, re-raise), SP-2 fdopen failure (fd closed exactly once via the
# sentinel), SP-3 durable ordering (fsync(file) -> replace -> fsync(parent
# dir)), SP-4 concurrent writers (unique temps, atomic last-writer-wins).


def test_atomic_write_bytes_persists_exact_bytes_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "artifact.bin"
    payload = b"\x00leitir\x0a\xff" * 128
    atomic_write_bytes(target, payload)
    assert target.read_bytes() == payload
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_write_bytes_replaces_existing_content_atomically(tmp_path: Path) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"stale contents")
    atomic_write_bytes(target, b"fresh")
    assert target.read_bytes() == b"fresh"
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_write_bytes_stages_temp_in_target_directory_with_stable_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged: list[Path] = []
    real_replace = os.replace

    def spy_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        staged.append(Path(src))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)
    atomic_write_bytes(tmp_path / "artifact.bin", b"data")
    assert len(staged) == 1
    assert staged[0].parent == tmp_path
    assert staged[0].name.startswith(".artifact.bin.tmp-")


def test_replace_failure_closes_fd_exactly_once_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SP-1 / AC-1: an ``os.replace`` failure must never close a recycled fd."""
    created: list[int] = []
    closed: list[int] = []
    recycled: list[int] = []
    real_mkstemp = tempfile.mkstemp
    real_close = os.close

    def spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, name = real_mkstemp(*args, **kwargs)  # type: ignore[arg-types]
        created.append(fd)
        return fd, name

    def spy_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    def replace_failure(src: object, dst: object) -> None:
        # Recycle the just-closed temp fd: lowest-free allocation hands this
        # descriptor number back, so a buggy except path would close a live
        # fd. A canary FILE is used because os.open() on a directory is a
        # PermissionError on Windows.
        recycled.append(os.open(canary, os.O_RDONLY))
        raise OSError("injected replace failure")

    canary = tmp_path / "canary.dat"
    canary.write_bytes(b"canary")
    monkeypatch.setattr(tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(os, "close", spy_close)
    monkeypatch.setattr(os, "replace", replace_failure)

    target = tmp_path / "artifact.bin"
    with pytest.raises(OSError, match="injected replace failure"):
        atomic_write_bytes(target, b"data")

    # The fd was closed exactly once (by the fdopen context exit), and the
    # sentinel kept the except path from closing the recycled descriptor.
    try:
        assert closed == []
        assert len(created) == 1
        assert recycled and os.fstat(recycled[0]).st_mode  # canary still alive
    finally:
        try:
            os.close(recycled[0])
        except OSError:
            pass
    assert list(tmp_path.glob(".artifact.bin.tmp-*")) == []
    assert not target.exists()


def test_fdopen_failure_closes_fd_once_via_sentinel_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SP-2: if ``os.fdopen`` itself raises, the fd is closed exactly once."""
    created: list[int] = []
    closed: list[int] = []
    real_mkstemp = tempfile.mkstemp
    real_close = os.close

    def spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, name = real_mkstemp(*args, **kwargs)  # type: ignore[arg-types]
        created.append(fd)
        return fd, name

    def spy_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    def fdopen_failure(fd: int, *args: object, **kwargs: object) -> object:
        raise OSError("injected fdopen failure")

    monkeypatch.setattr(tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(os, "close", spy_close)
    monkeypatch.setattr(os, "fdopen", fdopen_failure)

    target = tmp_path / "artifact.bin"
    with pytest.raises(OSError, match="injected fdopen failure"):
        atomic_write_bytes(target, b"data")

    # fdopen never produced a file object, so the sentinel path closed the
    # raw fd exactly once and the temp file was removed.
    assert closed == created
    assert list(tmp_path.glob(".artifact.bin.tmp-*")) == []
    assert not target.exists()


def test_write_failure_inside_streaming_writer_cleans_temp(tmp_path: Path) -> None:
    target = tmp_path / "stream.bin"
    with pytest.raises(RuntimeError, match="body failed"):
        with atomic_writer(target) as handle:
            handle.write(b"partial")
            raise RuntimeError("body failed")
    assert list(tmp_path.glob(".stream.bin.tmp-*")) == []
    assert not target.exists()


def test_durable_ordering_file_fsync_replace_then_parent_dir_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SP-3: fsync(file) strictly before replace, fsync(parent dir) after."""
    events: list[tuple[str, object]] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def spy_fsync(fd: int) -> None:
        events.append(("fsync-file", fd))
        real_fsync(fd)

    def spy_replace(src: object, dst: object) -> None:
        events.append(("replace", Path(dst).name))  # type: ignore[arg-type]
        real_replace(src, dst)

    def spy_fsync_directory(path: Path) -> None:
        # Recorded but not delegated: the real directory fsync would add a
        # second os.fsync event and blur the strict-sequence assertion.
        events.append(("fsync-dir", path))

    monkeypatch.setattr(os, "fsync", spy_fsync)
    monkeypatch.setattr(os, "replace", spy_replace)
    monkeypatch.setattr(safeio, "fsync_directory", spy_fsync_directory)

    target = tmp_path / "artifact.bin"
    atomic_write_bytes(target, b"payload")

    kinds = [kind for kind, _ in events]
    assert kinds.index("fsync-file") < kinds.index("replace") < kinds.index("fsync-dir")
    assert kinds == ["fsync-file", "replace", "fsync-dir"]
    assert events[-1] == ("fsync-dir", tmp_path)


def test_fsync_dir_false_skips_parent_dir_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dir_fsyncs: list[Path] = []
    real_fsync_directory = safeio.fsync_directory

    def spy_fsync_directory(path: Path) -> None:
        dir_fsyncs.append(path)
        real_fsync_directory(path)

    monkeypatch.setattr(safeio, "fsync_directory", spy_fsync_directory)
    target = tmp_path / "artifact.bin"
    atomic_write_bytes(target, b"payload", fsync_dir=False)
    assert dir_fsyncs == []
    assert target.read_bytes() == b"payload"


def test_atomic_write_text_writes_utf8_with_configured_newline(tmp_path: Path) -> None:
    target = tmp_path / "artifact.md"
    atomic_write_text(target, "alpha\nbeta\n", encoding="utf-8", newline="\n")
    assert target.read_bytes() == b"alpha\nbeta\n"
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_text_writer_streams_json_like_the_legacy_sites(tmp_path: Path) -> None:
    import json

    target = tmp_path / "index.json"
    with atomic_text_writer(target, encoding="utf-8", newline="\n") as handle:
        json.dump({"b": 1, "a": [1, 2]}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    assert target.read_bytes() == (
        json.dumps({"b": 1, "a": [1, 2]}, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def test_written_artifact_digests_pinned_in_repo(tmp_path: Path) -> None:
    """Pin the sha256 of exact bytes persisted through the helper (C-4/AC-3).

    Review remediation (P2): the written-byte compatibility contract is
    anchored in-repo by constant digests, not only by reconstruction. A
    deterministic sources.json-style document streams through
    ``atomic_text_writer`` exactly like the real sources-index site, and a
    deterministic binary blob goes through ``atomic_write_bytes``; any drift
    in what the helper lands on disk (truncation, newline translation,
    encoding change, torn write) breaks the pinned digests.
    """
    import hashlib
    import json

    document = {
        "digest": "a" * 64,
        "sources": [{"kind": "git", "url": "https://example.invalid/repo.git"}],
    }
    sources = tmp_path / "sources.json"
    with atomic_text_writer(sources, encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")

    payload = bytes(range(256)) * 4 + b"\n"
    blob = tmp_path / "manifest.bin"
    atomic_write_bytes(blob, payload)

    assert sources.read_bytes() == (
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    assert (
        hashlib.sha256(sources.read_bytes()).hexdigest()
        == "d7e6eee55d2437591c2f011062060e2c58749cdffe157b77ede7531a114d5a93"
    )
    assert blob.read_bytes() == payload
    assert (
        hashlib.sha256(blob.read_bytes()).hexdigest()
        == "402be1ab04705ce1a13d29c878e698c0c0f611dfb94bc5782d319354c4bcfa2b"
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows denies concurrent replaces of one shared destination "
    "(MoveFileEx races); leitir serializes same-target writes with file "
    "locks (see materialize._target_lock), so the bare-writer race is "
    "exercised on POSIX only",
)
def test_concurrent_writers_are_atomic_last_writer_wins(tmp_path: Path) -> None:
    """SP-4: interleaved writers never tear the target; temps are unique."""
    target = tmp_path / "shared.bin"
    payloads = [(f"writer-{index}".encode("ascii")) * 64 for index in range(8)]
    iterations = 40
    barrier = threading.Barrier(len(payloads))
    failures: list[BaseException] = []

    def worker(payload: bytes) -> None:
        try:
            barrier.wait(timeout=30)
            for _ in range(iterations):
                atomic_write_bytes(target, payload)
                observed = target.read_bytes()
                if observed not in payloads:
                    failures.append(
                        AssertionError(f"torn content observed: {observed[:32]!r}")
                    )
        except BaseException as exc:  # noqa: BLE001 - propagated to the main thread
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(payload,)) for payload in payloads]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive(), "concurrent writer hung"
    assert failures == []
    assert target.read_bytes() in payloads
    assert list(tmp_path.glob(".shared.bin.tmp-*")) == []


def test_retry_after_failure_persists_identical_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G-4 helper journey: failure leaves no partial state; retry persists."""
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"previous")
    real_replace = os.replace
    attempts: list[str] = []

    def fail_first_replace(src: object, dst: object) -> None:
        attempts.append("replace")
        if len(attempts) == 1:
            raise OSError("transient replace failure")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_first_replace)

    with pytest.raises(OSError, match="transient replace failure"):
        atomic_write_bytes(target, b"final contents")
    assert target.read_bytes() == b"previous"  # old content fully intact
    assert list(tmp_path.glob(".artifact.bin.tmp-*")) == []

    atomic_write_bytes(target, b"final contents")
    assert attempts == ["replace", "replace"]
    assert target.read_bytes() == b"final contents"
    assert list(tmp_path.glob(".artifact.bin.tmp-*")) == []
