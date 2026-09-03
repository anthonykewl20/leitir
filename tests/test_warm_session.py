"""Unit tests for the ADR-0035 warm-session integrity boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from leitir import materialize
from leitir.adapters import PythonAdapter
from leitir.api import call_json, warm_call
from leitir.corpus import (
    enumerate_shelved_sources,
    find_materialized_sources,
    record_trust,
    write_sources,
)
from leitir.engine import ScopedSearcher
from leitir.materialize import MANIFEST_NAME
from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
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
        "source": "git-commit",
        "parity": "exact",
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


def _entry(target: Path) -> dict[str, str]:
    return {
        "name": "demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "path": target.relative_to(target.parents[4]).as_posix(),
        "fetched_at": "2026-08-27T00:00:00Z",
    }


def _local_searcher(root: Path, session: WarmSession | None = None) -> ScopedSearcher:
    return ScopedSearcher(
        tree_source=object(),  # The local, fully verified shelf avoids the tree source.
        adapters=(PythonAdapter(),),
        corpus_root=root,
        session=session,
    )


def _local_search(searcher: ScopedSearcher):
    return searcher.search(
        SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.IDENTIFIER, "demo"),),
            scopes=(RepoScope("acme/demo", SHA),),
        )
    )


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
    # Per-touch cold parity: both failed touches re-verified (review F3).
    assert len(calls) == 3


def test_failure_is_per_touch_and_restored_shelf_reverifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failures are per touch (cold parity); a restored shelf re-verifies.

    Lock-free verification failures cannot be attributed to corruption vs a
    racing writer's swap-and-restore, so the session never blacklists a
    shelf: each touch pays the cold gate.  A shelf whose bytes are restored
    to a manifest-consistent state is served again on fresh full evidence.
    """
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
            assert _read(session, target) is not None
    assert len(calls) == 3


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


def test_lock_acquisition_advances_on_disk_epoch(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    identity = materialize._target_lock_identity(tmp_path, target, SHA)
    epoch_path = materialize._epoch_path(identity)
    assert materialize.read_lock_epoch(identity) == b""

    with materialize._target_lock(tmp_path, target, SHA):
        acquired = materialize.read_lock_epoch(identity)
        assert materialize.parse_lock_epoch(acquired) == 1
        with materialize._target_lock(tmp_path, target, SHA):
            # A reentrant borrow of a held lock is not a new acquisition.
            assert materialize.read_lock_epoch(identity) == acquired
    # Releasing does not advance the counter; only acquisitions do.
    assert materialize.read_lock_epoch(identity) == acquired
    with materialize._target_lock(tmp_path, target, SHA):
        assert materialize.parse_lock_epoch(
            materialize.read_lock_epoch(identity)
        ) == 2
    assert epoch_path.exists()


def test_cross_window_read_hits_without_reverification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0035 option (b): untouched shelves reuse verification across calls."""
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        with session.call():
            assert _read(session, target) is not None
        assert session.stats()["hits"] == 1
        assert session.stats()["misses"] == 1
    assert len(calls) == 1


def test_cooperating_writer_epoch_bump_invalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any lock acquisition by a cooperating writer invalidates the memo,
    even when the shelf's stat signature is left untouched."""
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        # A cooperative writer takes the target lock (and, per protocol,
        # advances the on-disk epoch) without otherwise changing bytes.
        with materialize._target_lock(tmp_path, target, SHA):
            pass
        with session.call():
            assert _read(session, target) is not None
        assert session.stats()["hits"] == 0
        assert session.stats()["revalidations"] == 1
    assert len(calls) == 2


def test_foreign_epoch_advance_invalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The memo trusts the epoch file itself, not this process's state.

    A separate writer process that had advanced the epoch file leaves the
    same on-disk evidence; rewriting the file as it would must invalidate
    the memo even though this process never observed the lock.
    """
    target = _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        identity = materialize._target_lock_identity(tmp_path, target, SHA)
        epoch_path = materialize._epoch_path(identity)
        epoch_path.parent.mkdir(parents=True, exist_ok=True)
        epoch_path.write_bytes(b"41\n")
        with session.call():
            assert _read(session, target) is not None
        assert session.stats()["hits"] == 0
        assert session.stats()["revalidations"] == 1
    assert len(calls) == 2


@pytest.mark.skipif(os.name != "posix", reason="ctime restoration is POSIX-visible")
def test_stat_restoring_tamper_detected_via_ctime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in-place editor that restores size and mtime still moves ctime."""
    target = _shelf(tmp_path)
    victim = target / "nested" / "data.txt"
    original = victim.read_bytes()
    metadata = victim.stat()
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        victim.write_bytes(b"TAMPERED da\n")
        assert len(b"TAMPERED da\n") == len(original)
        os.utime(
            victim, ns=(metadata.st_atime_ns, metadata.st_mtime_ns)
        )
        with session.call():
            assert _read(session, target) is None
    assert len(calls) == 2


def test_resolve_under_lock_rejects_extra_intervening_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The under-lock arithmetic must reject anything beyond recorded+1.

    Two acquisitions between the recording and the caller's own take — a
    foreign writer's bump plus a re-open, or any wider gate someone might
    substitute — must force the full cold gate rather than a memo serve.
    Deleting or widening the accepted set in resolve_under_lock has to fail
    here (review P2: the rejection branch had no pin).
    """
    target = _shelf(tmp_path)
    with WarmSession(tmp_path) as session, session.call():
        with materialize._target_lock(tmp_path, target, SHA):
            # First touch: cold verification recorded under this hold, with
            # the epoch this acquisition itself advanced.
            assert session.read_valid_manifest(
                target, "acme", "demo", SHA
            ) is not None
        # Two further acquisitions land between the recording and the
        # caller's own take: current is recorded+2, outside the accepted
        # {recorded, recorded+1} set, so the memo must be refused.
        with materialize._target_lock(tmp_path, target, SHA):
            pass
        with materialize._target_lock(tmp_path, target, SHA):
            pass
        assert (
            session.resolve_under_lock(target, "acme", "demo", SHA) is None
        )
    assert session.stats()["revalidations"] >= 1


def _alternate_shelf(parent: Path, module_bytes: bytes, fetched_at: str) -> Path:
    """Build a fully valid alternate shelf state in a staging directory."""
    import tempfile as _tempfile

    staged = Path(_tempfile.mkdtemp(prefix="s2-", dir=parent))
    (staged / "nested").mkdir()
    (staged / "module.py").write_bytes(module_bytes)
    (staged / "nested" / "data.txt").write_bytes(b"pinned data\n")
    manifest = {
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "spec": f"acme/demo@{SHA}",
        "repo_url": "https://github.com/acme/demo",
        "fetched_at": fetched_at,
        "verified": False,
        "verified_at": None,
        "source": "git-commit",
        "parity": "exact",
        **full_coverage_manifest_fields(staged),
    }
    (staged / MANIFEST_NAME).write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return staged


def test_writer_swap_between_verify_and_sweep_never_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A swap landing between the verify and the post-sweep must not pin M1.

    The epoch brackets acquisitions, not mutations: a writer that acquired
    the lock before the reader started (same epoch on both bracket reads)
    swaps the shelf at the end of its held interval. Only the sweep pair can
    witness that swap, so an entry must never be pinned from this attempt
    (review F1: this interleaving previously pinned the old manifest against
    the new tree's signature and served it as a hit).
    """
    target = _shelf(tmp_path)
    s2 = _alternate_shelf(
        tmp_path, b"def demo():\n    return 2\n", "2026-09-03T12:00:00Z"
    )
    calls = _count_verifications(monkeypatch)
    real_status = materialize._read_valid_manifest_with_status

    def swap_after_verify(*args: object, **kwargs: object):
        status, manifest = real_status(*args, **kwargs)  # type: ignore[arg-type,return-value]
        backup = tmp_path / "backup-old"
        os.replace(target, backup)
        os.replace(s2, target)
        return status, manifest

    with WarmSession(tmp_path) as session:
        with session.call():
            first = _read(session, target)
        assert first is not None
        assert first["fetched_at"] == "2026-08-27T00:00:00Z"

        # The writer's acquisition (and bump) precedes the reader's attempt.
        with materialize._target_lock(tmp_path, target, SHA):
            pass
        monkeypatch.setattr(
            materialize, "_read_valid_manifest_with_status", swap_after_verify
        )
        with session.call():
            second = _read(session, target)
        monkeypatch.undo()
        with session.call():
            third = _read(session, target)

    assert second is None or second["fetched_at"] == "2026-08-27T00:00:00Z"
    # The pinned-or-not verdict: the settled state must serve its own
    # manifest, never the stale M1 hit.
    assert third is not None
    assert third["fetched_at"] == "2026-09-03T12:00:00Z"
    assert len(calls) >= 2


def test_transient_writer_race_is_not_sticky(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A torn verification caused by an overlapping writer is not corruption.

    The swap lands between the reader's manifest read and its tree hashing,
    so verification fails on a mixed state. Because a lock-free failure is
    attribution-ambiguous, the session must not blacklist the shelf; the
    next touch verifies the settled state normally (review F3).
    """
    target = _shelf(tmp_path)
    s2 = _alternate_shelf(
        tmp_path, b"def demo():\n    return 3\n", "2026-09-03T13:00:00Z"
    )
    calls = _count_verifications(monkeypatch)
    real_verify = materialize.verify_materialized_integrity

    def swap_before_verify(t: object, m: object) -> None:
        backup = tmp_path / "backup-race"
        os.replace(target, backup)
        os.replace(s2, target)
        real_verify(t, m)

    with WarmSession(tmp_path) as session:
        with session.call():
            assert _read(session, target) is not None
        with materialize._target_lock(tmp_path, target, SHA):
            pass
        monkeypatch.setattr(
            materialize, "verify_materialized_integrity", swap_before_verify
        )
        with session.call():
            torn = _read(session, target)
        monkeypatch.undo()
        with session.call():
            settled = _read(session, target)

    assert torn is None
    assert settled is not None
    assert settled["fetched_at"] == "2026-09-03T13:00:00Z"
    assert len(calls) >= 2


def test_epoch_bump_failure_fails_the_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bump that cannot be durably written must abort the lock holder."""
    target = _shelf(tmp_path)

    def failing_write(*args: object, **kwargs: object) -> None:
        raise PermissionError("epoch replace blocked")

    monkeypatch.setattr(materialize, "atomic_write_bytes", failing_write)
    with pytest.raises(materialize.MaterializationError):
        with materialize._target_lock(tmp_path, target, SHA):
            pass  # pragma: no cover - acquisition must fail before the body


def test_epoch_bump_retries_transient_permission_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Windows-shaped transient reader handle delays but does not abort."""
    target = _shelf(tmp_path)
    real_write = materialize.atomic_write_bytes
    attempts = [0]

    def flaky_write(path: object, data: object, **kwargs: object) -> None:
        attempts[0] += 1
        if attempts[0] <= 2:
            raise PermissionError("reader handle open")
        real_write(path, data, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(materialize, "atomic_write_bytes", flaky_write)
    with materialize._target_lock(tmp_path, target, SHA):
        pass
    assert attempts[0] == 3


def test_gc_recovery_advances_the_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The staging-recovery path heralds its restore/removal with a bump."""
    from leitir.cli_corpus import _gc_abandoned_staging

    target = _shelf(tmp_path)
    identity = materialize._target_lock_identity(tmp_path, target, SHA)
    before = materialize.read_lock_epoch(identity)
    backup = target.parent / f".{SHA}.old-0"
    backup.mkdir()
    (backup / "stale.txt").write_bytes(b"stale\n")
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    removed = _gc_abandoned_staging(tmp_path)
    assert removed >= 1
    assert not backup.exists()
    assert materialize.read_lock_epoch(identity) != before


def test_symlinked_corpus_root_stays_warm_and_correct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root whose spelling differs from its resolved form must gate, not crash.

    The memo key, containment guard, and epoch identity all derive from the
    resolved form; a symlink-spelled target (as engine and corpus build
    them) must hit the memo instead of raising or falling into a false
    verification failure (review round 3, finding 1).
    """
    real = tmp_path / "real"
    real.mkdir()
    _shelf(real)
    link = tmp_path / "link"
    try:
        link.symlink_to(real)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    calls = _count_verifications(monkeypatch)
    lexical = link / "repos" / "github.com" / "acme" / "demo" / SHA
    with WarmSession(link) as session, session.call():
        assert session.read_valid_manifest(lexical, "acme", "demo", SHA) is not None
        assert session.read_valid_manifest(lexical, "acme", "demo", SHA) is not None
        assert session.stats()["hits"] == 1
    assert len(calls) == 1


def test_parse_lock_epoch_accepts_only_the_canonical_spelling() -> None:
    assert materialize.parse_lock_epoch(b"41") == 41
    assert materialize.parse_lock_epoch(b"41\n") == 41
    assert materialize.parse_lock_epoch(b" 41\n") is None
    assert materialize.parse_lock_epoch(b"41 \n") is None
    assert materialize.parse_lock_epoch(b"4_1\n") is None
    assert materialize.parse_lock_epoch(b"+41\n") is None
    assert materialize.parse_lock_epoch(b"") is None
    assert materialize.parse_lock_epoch(b"41\n\n") is None


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


def test_engine_second_local_open_hits_warm_memo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _shelf(tmp_path)
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session, session.call():
        searcher = _local_searcher(tmp_path, session)
        first = _local_search(searcher)
        second = _local_search(searcher)
        assert first.matches == second.matches
        assert first.coverage == second.coverage
        assert session.stats()["hits"] == 1
        assert session.stats()["misses"] == 1
    assert len(calls) == 1


def test_corpus_enumerate_and_find_hit_warm_memo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shelf(tmp_path)
    write_sources(tmp_path, [_entry(target)])
    calls = _count_verifications(monkeypatch)
    with WarmSession(tmp_path) as session, session.call():
        first_enumerated = enumerate_shelved_sources(tmp_path, session=session)
        second_enumerated = enumerate_shelved_sources(tmp_path, session=session)
        first_found = find_materialized_sources(f"acme/demo@{SHA}", tmp_path, session=session)
        second_found = find_materialized_sources(f"acme/demo@{SHA}", tmp_path, session=session)
        assert first_enumerated == second_enumerated
        assert first_found == second_found
        assert session.stats()["hits"] == 3
        assert session.stats()["misses"] == 1
    assert len(calls) == 1


def test_record_trust_bypasses_and_invalidates_warm_memo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _shelf(tmp_path)
    write_sources(tmp_path, [_entry(target)])
    calls = _count_verifications(monkeypatch)

    class TrustResult:
        def as_dict(self) -> dict[str, int]:
            return {"trust_score": 100}

    monkeypatch.setattr("leitir.trust.compute_trust", lambda _manifest, _target: TrustResult())
    with WarmSession(tmp_path) as session, session.call():
        assert find_materialized_sources(f"acme/demo@{SHA}", tmp_path, session=session)
        record_trust(f"acme/demo@{SHA}", tmp_path, session=session)
        assert find_materialized_sources(f"acme/demo@{SHA}", tmp_path, session=session)
        # The location lookup hit before writing, but the writer's read and
        # update gate, plus the post-write read, fully verify instead of
        # reusing its memo.
        assert session.stats()["hits"] == 1
        assert session.stats()["misses"] == 2
    assert len(calls) == 4


def test_cold_and_first_warm_threaded_reads_have_identical_results(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    write_sources(tmp_path, [_entry(target)])
    cold_enumerated = enumerate_shelved_sources(tmp_path)
    cold_found = find_materialized_sources(f"acme/demo@{SHA}", tmp_path)
    cold_search = _local_search(_local_searcher(tmp_path))

    with WarmSession(tmp_path) as session, session.call():
        warm_enumerated = enumerate_shelved_sources(tmp_path, session=session)
        warm_found = find_materialized_sources(f"acme/demo@{SHA}", tmp_path, session=session)
        warm_search = _local_search(_local_searcher(tmp_path, session))

    assert warm_enumerated == cold_enumerated
    assert warm_found == cold_found
    assert warm_search.matches == cold_search.matches
    assert warm_search.coverage == cold_search.coverage


def test_warm_call_threads_session_to_corpus_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One corpus-search call records warm verification without changing JSON."""
    import leitir.api as api_module

    target = _shelf(tmp_path)
    write_sources(tmp_path, [_entry(target)])
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    monkeypatch.setattr("leitir.index.query._utc_now", lambda: "2026-09-02T00:00:00Z")
    observed_output: list[tuple[str, str]] = []
    real_main = api_module.main

    def capture_main(*args: object, **kwargs: object) -> int:
        code = real_main(*args, **kwargs)
        out = kwargs.get("stdout")
        err = kwargs.get("stderr")
        assert hasattr(out, "getvalue") and hasattr(err, "getvalue")
        observed_output.append((out.getvalue(), err.getvalue()))
        return code

    monkeypatch.setattr(api_module, "main", capture_main)
    argv = [
        "search",
        "--corpus",
        "--must",
        "identifier:demo",
        "--root",
        str(tmp_path),
    ]

    cold = call_json(argv)
    with warm_call(tmp_path) as caller:
        warm = caller(argv)
        stats = caller.stats()

    # The in-process API parses these exact stdout bytes after the dispatch
    # returns, so capture them at that boundary rather than comparing only
    # decoded JSON. The warm path serves the same bytes and enters verification.
    assert len(observed_output) == 2
    assert observed_output[1] == observed_output[0]
    assert warm == cold
    assert stats["hits"] + stats["misses"] > 0
    assert stats["misses"] > 0
    assert stats["cold_fallbacks"] == 0


def test_warm_call_writer_uses_no_manifest_memo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The trust writer verifies cold after invalidating its lookup memo."""
    target = _shelf(tmp_path)
    write_sources(tmp_path, [_entry(target)])
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    argv = ["trust", f"acme/demo@{SHA}", "--root", str(tmp_path), "--json"]

    cold = call_json(argv)
    with warm_call(tmp_path) as caller:
        warm = caller(argv)
        stats = caller.stats()

    assert warm == cold
    assert stats["hits"] == 0
    assert stats["misses"] == 1
