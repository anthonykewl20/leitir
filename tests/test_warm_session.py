"""Unit tests for the ADR-0035 warm-session integrity boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from leitir import materialize
from leitir.materialize import MANIFEST_NAME
from leitir.treehash import full_coverage_manifest_fields
from leitir.warm import WarmSession

SHA = "a" * 40


def _shelf(root: Path) -> Path:
    target = root / "repos/github.com/acme/demo" / SHA
    (target / "nested").mkdir(parents=True)
    (target / "module.py").write_bytes(b"def demo():\n    return 1\n")
    (target / "nested" / "data.txt").write_bytes(b"pinned data\n")
    manifest = {
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "spec": f"acme/demo@{SHA}",
        "repo_url": "https://github.com/acme/demo",
        "fetched_at": "2026-08-27T00:00:00Z",
        "verified": False,
        "verified_at": None,
        **full_coverage_manifest_fields(target),
    }
    (target / MANIFEST_NAME).write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return target


def _count_verifications(monkeypatch: pytest.MonkeyPatch) -> list[None]:
    calls: list[None] = []
    real_verify = materialize.verify_materialized_integrity

    def counting_verify(target: str | os.PathLike[str], manifest: object) -> None:
        calls.append(None)
        assert isinstance(manifest, dict)
        real_verify(target, manifest)

    monkeypatch.setattr(materialize, "verify_materialized_integrity", counting_verify)
    return calls


def _read(session: WarmSession, target: Path) -> dict[str, object] | None:
    return session.read_valid_manifest(target, "acme", "demo", SHA)


def test_second_read_hits_cache_without_reverification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session, session.call():
        assert _read(session, target) is not None
        assert _read(session, target) is not None
        assert session.stats()["hits"] == 1
        assert session.stats()["misses"] == 1
    assert len(calls) == 1


def test_tamper_after_cache_is_never_served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        with (target / "module.py").open("ab") as handle:
            handle.write(b"tampered")
        with session.call():
            assert _read(session, target) is None
            assert _read(session, target) is None
        assert session.stats()["sticky_rejects"] == 1
    assert len(calls) == 2


def test_sticky_failure_persists_even_after_bytes_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shelf(tmp_path)
    original = (target / "module.py").read_bytes()
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        (target / "module.py").write_bytes(b"tampered")
        with session.call():
            assert _read(session, target) is None
        (target / "module.py").write_bytes(original)
        with session.call():
            assert _read(session, target) is None
    assert len(calls) == 2


def test_manifest_replacement_between_calls_forces_reverify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    manifest_path = target / MANIFEST_NAME
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        replacement = target / "replacement.json"
        replacement.write_bytes(manifest_path.read_bytes())
        os.replace(replacement, manifest_path)
        with session.call():
            assert _read(session, target) is not None
        assert session.stats()["revalidations"] == 1
        assert session.stats()["hits"] == 0
    assert len(calls) == 2


def test_symlink_appearing_in_tree_forces_reverify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    try:
        with WarmSession(tmp_path) as session:
            with session.call():
                assert _read(session, target) is not None
            (target / "link").symlink_to("module.py")
            with session.call():
                assert _read(session, target) is None
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    assert len(calls) == 2


def test_degraded_session_falls_back_to_cold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import leitir.warm as warm

    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None

        def broken_sweep(_target: Path) -> object:
            raise OSError("stat sweep failed")

        monkeypatch.setattr(warm, "_stat_sweep", broken_sweep)
        with session.call():
            assert _read(session, target) is not None
        assert session.degraded
        assert session.stats()["cold_fallbacks"] > 0
    assert len(calls) == 2


def test_no_window_reads_are_cold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        assert _read(session, target) is not None
        assert _read(session, target) is not None
        assert session.stats()["hits"] == 0
        assert session.stats()["misses"] == 0
    assert len(calls) == 2


def test_serve_returns_deep_copies(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    with WarmSession(tmp_path) as session, session.call():
        first = _read(session, target)
        assert first is not None
        first["nested"] = {"mutated": True}
        second = _read(session, target)
        assert second is not None
        assert "nested" not in second


def test_read_valid_manifest_session_kwarg_routes_to_session(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    with WarmSession(tmp_path) as session, session.call():
        routed = materialize.read_valid_manifest(
            target, "acme", "demo", SHA, session=session
        )
        direct = _read(session, target)
    assert routed == direct


def test_epochs_bump_on_acquire_and_release(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    identity = materialize._target_lock_identity(tmp_path, target, SHA)
    before = materialize._LOCK_EPOCHS.get(identity, 0)
    with materialize._target_lock(tmp_path, target, SHA):
        acquired = materialize._LOCK_EPOCHS[identity]
        with materialize._target_lock(tmp_path, target, SHA):
            assert materialize._LOCK_EPOCHS[identity] == acquired
    assert acquired > before
    assert materialize._LOCK_EPOCHS[identity] > acquired


def test_close_discards_all_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    session = WarmSession(tmp_path)
    with session.call():
        assert _read(session, target) is not None
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        _read(session, target)
    with WarmSession(tmp_path) as fresh, fresh.call():
        assert _read(fresh, target) is not None
    assert len(calls) == 2
