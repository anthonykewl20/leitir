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
