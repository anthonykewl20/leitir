"""Regression coverage for manifest staging outside verified shelf trees."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from leitir import safeio
from leitir.corpus import record_trust, write_sources
from leitir.materialize import (
    MANIFEST_MAX_BYTES,
    MANIFEST_NAME,
    VerificationError,
    _target_lock,
    read_valid_manifest,
    update_manifest,
    verify_materialized_integrity,
)
from leitir.safeio import read_regular_file
from leitir.treehash import TreeHashMismatchError, full_coverage_manifest_fields

SHA = "d" * 40
SPEC = f"acme/widget@{SHA}"


def _shelf(root: Path) -> tuple[Path, dict[str, object]]:
    """Create one fully mapped, locally materialized shelf."""
    relative = f"repos/github.com/acme/widget/{SHA}"
    target = root / relative
    source = target / "src" / "widget.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    manifest: dict[str, object] = {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-30T00:00:00Z",
        "has_tests": False,
        "host": "github.com",
        "owner": "acme",
        "parity": "unknown",
        "repo": "widget",
        "repo_url": "https://github.com/acme/widget",
        "source": "git-commit",
        "spec": SPEC,
        "verified": False,
        "verified_at": None,
    }
    manifest.update(full_coverage_manifest_fields(target))
    (target / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_sources(
        root,
        [
            {
                "commit_sha": SHA,
                "fetched_at": manifest["fetched_at"],
                "host": "github.com",
                "name": "widget",
                "owner": "acme",
                "path": relative,
                "repo": "widget",
            }
        ],
    )
    return target, manifest


def test_manifest_rewrite_staging_file_never_exists_inside_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, manifest = _shelf(tmp_path)
    manifest_path = target / MANIFEST_NAME
    entered = threading.Event()
    release = threading.Event()
    staged: list[Path] = []
    failures: list[BaseException] = []
    real_replace = os.replace

    def paused_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(dst) == manifest_path:
            staged.append(Path(src))
            entered.set()
            if not release.wait(10):
                raise TimeoutError("timed out waiting to publish manifest")
        real_replace(src, dst)

    monkeypatch.setattr(safeio.os, "replace", paused_replace)

    def writer() -> None:
        try:
            update_manifest(target, {"race_test": True})
        except BaseException as exc:  # noqa: BLE001 - propagated to main thread
            failures.append(exc)

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        assert entered.wait(10)
        # This is the exact former race window: the old manifest still anchors
        # the unchanged shelf while the new manifest is waiting to publish.
        verify_materialized_integrity(target, manifest)
        assert staged and staged[0].parent == target.parent
        assert not staged[0].is_relative_to(target)
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    assert failures == []
    assert read_valid_manifest(target, "acme", "widget", SHA) is not None


def test_concurrent_trust_writers_never_break_lock_free_readers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _manifest = _shelf(tmp_path)
    manifest_path = target / MANIFEST_NAME
    real_replace = os.replace
    writers = 8
    readers = 4
    writer_lock = threading.Lock()
    pause_events = [threading.Event() for _ in range(writers)]
    release_events = [threading.Event() for _ in range(writers)]
    reader_completed = [threading.Event() for _ in range(writers)]
    writer_ids: dict[int, int] = {}
    result_lock = threading.Lock()
    worker_failures: list[BaseException] = []
    universe_failures: list[str] = []
    unexpected_failures: list[str] = []
    tolerated_reader_errors: list[str] = []

    def is_universe_failure(exc: VerificationError) -> bool:
        current: BaseException | None = exc
        while current is not None:
            message = str(current)
            if isinstance(current, TreeHashMismatchError) and (
                "unexpected file on disk is absent from the digest map" in message
            ):
                return True
            if "unexpected file on disk is absent from the digest map" in message:
                return True
            current = current.__cause__
        return False

    def is_transient_io_failure(exc: VerificationError) -> bool:
        current: BaseException | None = exc
        while current is not None:
            if isinstance(current, OSError):
                return True
            current = current.__cause__
        return False

    def read_and_verify() -> None:
        verification_started = False
        try:
            raw = read_regular_file(
                manifest_path, maximum_bytes=MANIFEST_MAX_BYTES, no_follow=False
            )
            payload = json.loads(raw.decode("utf-8", "strict"))
            if not isinstance(payload, dict):
                raise AssertionError("manifest reader returned a non-object")
            verification_started = True
            verify_materialized_integrity(target, payload)
        except VerificationError as exc:
            with result_lock:
                if is_universe_failure(exc):
                    universe_failures.append(str(exc))
                elif is_transient_io_failure(exc):
                    tolerated_reader_errors.append(f"VerificationError: {exc}")
                else:
                    unexpected_failures.append(f"VerificationError: {exc}")
        except OSError as exc:
            # The pre-existing lstat/open/fstat replacement race is unrelated
            # to staging-tree universe verification and remains fail-closed.
            with result_lock:
                tolerated_reader_errors.append(f"{type(exc).__name__}: {exc}")
        except (UnicodeError, json.JSONDecodeError, AssertionError) as exc:
            with result_lock:
                unexpected_failures.append(f"{type(exc).__name__}: {exc}")
        finally:
            if verification_started:
                for index, paused in enumerate(pause_events):
                    if paused.is_set() and not release_events[index].is_set():
                        reader_completed[index].set()
                        break

    def paused_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        # This pause is load-bearing for failure classification, not just for widening the window:
        # it keeps the in-tree staging temp stable and present during every verified read, which is
        # what makes a pre-fix staging regression classify as a fatal universe failure instead of a
        # tolerated ENOENT; removing the hook could let a real in-tree regression pass silently.
        if Path(dst) == manifest_path:
            index = writer_ids[threading.get_ident()]
            pause_events[index].set()
            if not release_events[index].wait(10):
                raise TimeoutError("timed out waiting to publish manifest")
            real_replace(src, dst)
            return
        real_replace(src, dst)

    monkeypatch.setattr(safeio.os, "replace", paused_replace)

    def writer(index: int) -> None:
        writer_ids[threading.get_ident()] = index
        try:
            with writer_lock:
                record_trust(SPEC, tmp_path)
        except BaseException as exc:  # noqa: BLE001 - propagated to main thread
            with result_lock:
                worker_failures.append(exc)

    def reader() -> None:
        try:
            for index in range(writers):
                if not pause_events[index].wait(10):
                    raise TimeoutError("timed out waiting for manifest staging")
                while not release_events[index].is_set():
                    read_and_verify()
        except BaseException as exc:  # noqa: BLE001 - propagated to main thread
            with result_lock:
                worker_failures.append(exc)

    reader_threads = [threading.Thread(target=reader) for _ in range(readers)]
    writer_threads = [threading.Thread(target=writer, args=(index,)) for index in range(writers)]
    for thread in reader_threads + writer_threads:
        thread.start()
    for index in range(writers):
        assert pause_events[index].wait(10)
        assert reader_completed[index].wait(10)
        release_events[index].set()
    for thread in reader_threads + writer_threads:
        thread.join(30)
    assert not [thread for thread in reader_threads + writer_threads if thread.is_alive()]
    assert worker_failures == []
    assert universe_failures == [], (
        "staging-temp universe failures: "
        f"{universe_failures}; tolerated reader errors: {tolerated_reader_errors}"
    )
    assert unexpected_failures == []
    raw = read_regular_file(manifest_path, maximum_bytes=MANIFEST_MAX_BYTES, no_follow=False)
    final_manifest = json.loads(raw.decode("utf-8", "strict"))
    assert isinstance(final_manifest, dict)
    verify_materialized_integrity(target, final_manifest)
    assert read_valid_manifest(target, "acme", "widget", SHA) is not None


def test_unmapped_extra_file_still_fails_verification(tmp_path: Path) -> None:
    target, manifest = _shelf(tmp_path)
    (target / "evil.txt").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="unexpected"):
        verify_materialized_integrity(target, manifest)
    assert read_valid_manifest(target, "acme", "widget", SHA) is None


def test_manifest_rewrite_leaves_no_staging_debris_in_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _manifest = _shelf(tmp_path)
    manifest_path = target / MANIFEST_NAME
    staged: list[Path] = []
    real_replace = os.replace

    def failed_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(dst) == manifest_path:
            staged.append(Path(src))
            raise OSError("injected manifest publish failure")
        real_replace(src, dst)

    monkeypatch.setattr(safeio.os, "replace", failed_replace)
    with pytest.raises(OSError, match="injected manifest publish failure"):
        update_manifest(target, {"race_test": True})

    assert staged and staged[0].parent == target.parent
    assert list(target.glob(f".{MANIFEST_NAME}.tmp-*")) == []
    assert not staged[0].exists()

    # A process crash cannot execute safeio cleanup. Its per-commit sibling
    # name is deliberately covered by _sweep_target_debris on the next target
    # lock acquisition, rather than leaving an unbounded new debris class.
    crash_debris = target.parent / f".{SHA}.tmp-manifest-crash"
    crash_debris.write_text("interrupted", encoding="utf-8")
    with _target_lock(tmp_path, target, SHA):
        pass
    assert not crash_debris.exists()
