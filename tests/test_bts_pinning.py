from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

import leitir.bts as bts_module
from leitir.bts import BTSReport, DonorSnapshot, compute_bts
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.treehash import FULL, compute_materialized_tree_hash
from tests.test_bts_walk import _budget, _fixture, _policy


def _rehash(snapshot: DonorSnapshot) -> DonorSnapshot:
    tree_hash, scope = compute_materialized_tree_hash(snapshot.source_root)
    assert scope == FULL
    return replace(snapshot, materialized_tree_hash=tree_hash)


def test_primary_digest_binds_unrelated_full_tree_but_equivalence_does_not() -> None:
    snapshot, seed, graph = _fixture()
    first = compute_bts(snapshot, seed, graph, _budget(), _policy())
    assert first.bts is not None

    (snapshot.source_root / "unrelated.txt").write_bytes(b"unreachable\n")
    changed = compute_bts(_rehash(snapshot), seed, graph, _budget(), _policy())
    assert changed.bts is not None
    assert changed.bts.bts_digest != first.bts.bts_digest
    assert changed.bts.member_equivalence_digest == first.bts.member_equivalence_digest


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("source", "git-branch", BTSRejectReason.REJECT_MOVING_REFERENCE),
        ("source", "git-tag", BTSRejectReason.REJECT_MOVING_REFERENCE),
        ("parity", "best-effort", BTSRejectReason.REJECT_PROVENANCE_MISMATCH),
        ("materialized_tree_hash_scope", "sampled", BTSRejectReason.REJECT_PROVENANCE_MISMATCH),
        ("materialized_tree_hash", "", BTSRejectReason.REJECT_PROVENANCE_MISMATCH),
    ],
)
def test_snapshot_boundary_rejects_non_authoritative_provenance(
    field: str, value: str, reason: BTSRejectReason
) -> None:
    snapshot, _seed, _graph = _fixture()
    with pytest.raises(BTSError) as caught:
        replace(snapshot, **{field: value})
    assert caught.value.reason is reason


def test_stale_graph_blob_is_rejected_even_for_new_valid_tree_hash() -> None:
    snapshot, seed, graph = _fixture()
    path = snapshot.source_root / "src/pkg/mod.py"
    path.write_bytes(path.read_bytes() + b"# tampered generation\n")

    with pytest.raises(BTSError) as caught:
        compute_bts(_rehash(snapshot), seed, graph, _budget(), _policy())
    assert caught.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert caught.value.evidence.detail_code == "bts_blob_sha_mismatch_v1"


def test_one_lock_scope_covers_verify_provider_and_source_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, seed, graph = _fixture()
    real_lock = bts_module._target_lock
    real_read = bts_module._read_regular_file
    active = False
    acquisitions = 0

    @contextmanager
    def tracked_lock(root: Path, target: Path, commit_sha: str) -> Iterator[None]:
        nonlocal active, acquisitions
        assert not active
        acquisitions += 1
        with real_lock(root, target, commit_sha):
            active = True
            try:
                yield
            finally:
                active = False

    def provider(_root: Path):
        assert active
        return graph

    def tracked_read(root: Path, relative: str) -> bytes:
        assert active
        return real_read(root, relative)

    monkeypatch.setattr(bts_module, "_target_lock", tracked_lock)
    monkeypatch.setattr(bts_module, "_read_regular_file", tracked_read)
    assert compute_bts(snapshot, seed, provider, _budget(), _policy()).bts is not None
    assert acquisitions == 1
    assert not active


def test_report_round_trip_rederives_digest_and_rejects_mutated_cache() -> None:
    snapshot, seed, graph = _fixture()
    result = compute_bts(snapshot, seed, graph, _budget(), _policy())
    artifact = result.report.to_bytes()
    assert BTSReport.from_json(artifact).to_bytes() == artifact

    mutated = artifact.replace(result.report.analysis_digest.encode(), b"sha256:" + b"0" * 64)
    with pytest.raises(BTSError) as caught:
        BTSReport.from_json(mutated)
    assert caught.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
