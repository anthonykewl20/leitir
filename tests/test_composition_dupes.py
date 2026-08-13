"""ADR-0015 duplicate-abstraction detection gates."""

from __future__ import annotations

import hashlib
import os
import random
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from leitir.bts import BTS, BTS_SCHEMA_VERSION, BTSDisposition, DonorSnapshot, MemberEvidence, _digest
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.duplicates import (
    CandidateDependencyEvidence,
    ClosureCompleteness,
    CompatibilityStatus,
    CompositionCandidateRef,
    ConflictKind,
    DuplicateAssessment,
    DuplicateCandidate,
    assess_duplicates,
)
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.treehash import FULL, TREE_HASH_ALGORITHM

COMMIT = "1" * 40


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _blob(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def _candidate(
    root: Path,
    key: str,
    data: bytes,
    *,
    start: int = 1,
    end: int = 1,
    qualified_name: str = "organ",
    dependencies: tuple[tuple[str, str, str, str | None], ...] = (),
) -> DuplicateCandidate:
    donor = root / key
    donor.mkdir()
    path = "organ.py"
    (donor / path).write_bytes(data)
    lines = data.splitlines(keepends=True)
    end_col = len(lines[end - 1])
    source = SourceRef(key, COMMIT, path, _blob(data), start, 0, end, end_col)
    node = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "organ", qualified_name, f"{path}:{start}:0")
    member_bytes = b"".join(lines[start - 1 : end])
    member = MemberEvidence(node, source, _sha(member_bytes), BTSDisposition.INCLUDE)
    bts_digest = _sha(f"bts:{key}".encode())
    blank = BTS(BTS_SCHEMA_VERSION, node, (member,), (), (), (), bts_digest, _sha(b"blank"))
    bts = replace(blank, member_equivalence_digest=_digest(blank, omit=frozenset({"bts_digest", "member_equivalence_digest"})))
    subject = CompositionCandidateRef((key,), bts_digest, _sha(f"manifest:{key}".encode()), _sha(f"graph:{key}".encode()))
    snapshot = DonorSnapshot(
        key, COMMIT, "git-commit", "exact", _sha(f"tree:{key}".encode()),
        TREE_HASH_ALGORITHM, FULL, root, donor,
    )
    deps = tuple(
        CandidateDependencyEvidence(
            subject, ecosystem, name, version, resolved,
            ClosureCompleteness.COMPLETE, f"{key}.lock", _sha(f"lock:{key}".encode()),
        )
        for ecosystem, name, version, resolved in dependencies
    )
    return DuplicateCandidate(subject, bts, snapshot, deps)


def _assert_composition_input_reject(caught: pytest.ExceptionInfo[BTSError]) -> None:
    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert caught.value.evidence.detail_code == "composition_input_missing_v1"


def _same_source_candidate(
    root: Path, key: str, data: bytes, start: int, end: int, authority: DuplicateCandidate,
) -> DuplicateCandidate:
    candidate = _candidate(root, key, data, start=start, end=end)
    source = replace(candidate.bts.members[0].source, slug=authority.snapshot.slug)
    member = replace(candidate.bts.members[0], source=source)
    blank = replace(candidate.bts, members=(member,))
    bts = replace(blank, member_equivalence_digest=_digest(
        blank, omit=frozenset({"bts_digest", "member_equivalence_digest"}),
    ))
    return replace(candidate, bts=bts, snapshot=authority.snapshot)


def test_byte_identical_verified_seeds_hard_reject_without_deletion(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"def same():\n    return 1\n")
    right = _candidate(tmp_path, "right", b"def same():\n    return 1\n")

    with pytest.raises(BTSError) as caught:
        assess_duplicates((left, right), member_span_overlap_bps=5000)

    assert caught.value.reason is BTSRejectReason.REJECT_DUPLICATE_RESULT
    assert caught.value.evidence.detail_code == "exact_seed_bytes_duplicate_v1"


def test_same_name_with_different_verified_bytes_is_not_flagged(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"def same(): return 1\n", qualified_name="same")
    right = _candidate(tmp_path, "right", b"def same(): return 2\n", qualified_name="same")

    assert assess_duplicates((left, right), member_span_overlap_bps=5000) == ()


def test_member_equivalence_digest_is_not_duplicate_authority(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"left\n")
    right = _candidate(tmp_path, "right", b"right\n")
    same_secondary_digest = _sha(b"non-authorizing-secondary-identity")
    left = replace(left, bts=replace(left.bts, member_equivalence_digest=same_secondary_digest))
    right = replace(right, bts=replace(right.bts, member_equivalence_digest=same_secondary_digest))

    assert assess_duplicates((left, right), member_span_overlap_bps=5000) == ()


def test_span_overlap_uses_inclusive_exact_threshold_arithmetic(tmp_path: Path) -> None:
    data = b"one\ntwo\nthree\nfour\nfive\nsix\n"
    left = _candidate(tmp_path, "same", data, start=1, end=4)
    # A second subject can bind the same immutable source identity and snapshot.
    right_base = _candidate(tmp_path, "other", data, start=3, end=6)
    right_source = replace(right_base.bts.members[0].source, slug="same")
    right_member = replace(right_base.bts.members[0], source=right_source)
    right_blank = replace(right_base.bts, members=(right_member,))
    right_bts = replace(right_blank, member_equivalence_digest=_digest(right_blank, omit=frozenset({"bts_digest", "member_equivalence_digest"})))
    right = replace(right_base, bts=right_bts, snapshot=left.snapshot)

    emitted = assess_duplicates((left, right), member_span_overlap_bps=3333)
    silent = assess_duplicates((left, right), member_span_overlap_bps=3334)

    assert len(emitted) == 1
    assert emitted[0].kind is ConflictKind.BTS_MEMBER_SPAN_OVERLAP
    overlap = emitted[0].member_overlaps[0]
    assert (overlap.intersection_lines, overlap.union_lines, overlap.member_span_overlap_bps) == (2, 6, 3333)
    assert silent == ()


def test_span_overlap_identity_boundary_prevents_cross_blob_advisory(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"one\ntwo\n", start=1, end=2)
    right = _candidate(tmp_path, "right", b"ONE\nTWO\n", start=1, end=2)
    assert assess_duplicates((left, right), member_span_overlap_bps=1) == ()


def test_missing_span_threshold_is_typed_fail_closed(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"left\n")
    right = _candidate(tmp_path, "right", b"right\n")
    with pytest.raises(BTSError) as caught:
        assess_duplicates((left, right))
    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert caught.value.evidence.detail_code == "composition_policy_missing_v1"

    with pytest.raises(BTSError) as zero:
        assess_duplicates((left, right), member_span_overlap_bps=0)
    assert zero.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert zero.value.evidence.detail_code == "composition_policy_missing_v1"


def test_missing_and_multiple_seed_members_are_typed_rejects(tmp_path: Path) -> None:
    missing = _candidate(tmp_path, "missing", b"one\ntwo\n")
    absent_seed = replace(missing.bts.seed, qualified_name="absent")
    missing = replace(missing, bts=replace(missing.bts, seed=absent_seed))
    with pytest.raises(BTSError) as no_seed:
        assess_duplicates((missing,), member_span_overlap_bps=5000)
    _assert_composition_input_reject(no_seed)

    multiple = _candidate(tmp_path, "multiple", b"one\ntwo\n")
    first = multiple.bts.members[0]
    second_source = replace(first.source, start_line=2, end_line=2, end_col=4)
    second = replace(first, source=second_source, source_bytes_sha256=_sha(b"two\n"))
    multiple = replace(multiple, bts=replace(multiple.bts, members=(first, second)))
    with pytest.raises(BTSError) as many_seeds:
        assess_duplicates((multiple,), member_span_overlap_bps=5000)
    _assert_composition_input_reject(many_seeds)


@pytest.mark.parametrize(
    ("left_span", "right_span", "threshold", "emitted"),
    [
        ((1, 1), (3, 3), 1, False),       # disjoint, with a line-sized gap
        ((1, 2), (3, 4), 1, False),       # adjacent inclusive spans do not touch
        ((1, 4), (2, 3), 5000, True),     # nested: 2 / 4 reaches 50%
        ((1, 4), (2, 3), 5001, False),
    ],
)
def test_span_overlap_boundaries(
    tmp_path: Path,
    left_span: tuple[int, int],
    right_span: tuple[int, int],
    threshold: int,
    emitted: bool,
) -> None:
    data = b"one\ntwo\nthree\nfour\n"
    left = _candidate(tmp_path, "shared", data, start=left_span[0], end=left_span[1])
    right = _same_source_candidate(
        tmp_path, "other", data, right_span[0], right_span[1], left,
    )
    result = assess_duplicates((left, right), member_span_overlap_bps=threshold)
    assert bool(result) is emitted
    if emitted:
        overlap = result[0].member_overlaps[0]
        assert (overlap.intersection_lines, overlap.union_lines) == (2, 4)


def test_dependency_triple_overlap_survives_mismatched_resolved_identity(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"left\n", dependencies=(("npm", "pkg", "1.2.3", "aaa"),))
    right = _candidate(tmp_path, "right", b"right\n", dependencies=(("npm", "pkg", "1.2.3", "bbb"),))

    result = assess_duplicates((left, right), member_span_overlap_bps=5000)

    assert len(result) == 1
    assert result[0].kind is ConflictKind.DEPENDENCY_DECLARATION_OVERLAP
    assert result[0].status is CompatibilityStatus.COMPATIBLE
    assert "declaration_equal" in result[0].evidence_refs[0].evidence_kind


def test_equal_resolved_identity_strengthens_dependency_evidence(tmp_path: Path) -> None:
    mismatched_left = _candidate(tmp_path, "mismatch-left", b"left\n", dependencies=(("npm", "pkg", "1", "aaa"),))
    mismatched_right = _candidate(tmp_path, "mismatch-right", b"right\n", dependencies=(("npm", "pkg", "1", "bbb"),))
    mismatched_kind = assess_duplicates(
        (mismatched_left, mismatched_right), member_span_overlap_bps=5000,
    )[0].evidence_refs[0].evidence_kind

    equal_left = _candidate(tmp_path, "equal-left", b"LEFT\n", dependencies=(("npm", "pkg", "1", "same"),))
    equal_right = _candidate(tmp_path, "equal-right", b"RIGHT\n", dependencies=(("npm", "pkg", "1", "same"),))
    equal_kind = assess_duplicates(
        (equal_left, equal_right), member_span_overlap_bps=5000,
    )[0].evidence_refs[0].evidence_kind

    assert equal_kind.endswith(":resolved_equal")
    assert equal_kind != mismatched_kind


def test_duplicate_exhaustive_keys_are_typed_rejects(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, "candidate", b"candidate\n")
    duplicate_key = _candidate(tmp_path, "other", b"other\n")
    duplicate_key = replace(
        duplicate_key,
        subject=replace(duplicate_key.subject, candidate_key=candidate.subject.candidate_key),
    )
    with pytest.raises(BTSError) as duplicate_candidates:
        assess_duplicates((candidate, duplicate_key), member_span_overlap_bps=5000)
    _assert_composition_input_reject(duplicate_candidates)

    left = _candidate(tmp_path, "left-overlap", b"left\n")
    right = _candidate(tmp_path, "right-overlap", b"right\n")
    dependency = CandidateDependencyEvidence(
        left.subject, "pypi", "shared", "1", None, ClosureCompleteness.COMPLETE,
        "left.lock", _sha(b"left-lock"),
    )
    left = replace(left, dependencies=(dependency, dependency))
    with pytest.raises(BTSError) as duplicate_overlaps:
        assess_duplicates((left, right), member_span_overlap_bps=5000)
    _assert_composition_input_reject(duplicate_overlaps)


def test_version_clash_is_consumed_and_reemitted_unchanged(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"left\n")
    right = _candidate(tmp_path, "right", b"right\n")
    blank = DuplicateAssessment(
        left.subject, right.subject, ConflictKind.VERSION_CLASH,
        CompatibilityStatus.INCOMPATIBLE, (), (), "",
    )
    clash = replace(blank, assessment_digest=_digest(blank, omit=frozenset({"assessment_digest"})))

    assert assess_duplicates(
        (right, left), member_span_overlap_bps=5000, version_clashes=(clash,)
    ) == (clash,)


def test_forged_consumed_version_clash_is_rejected(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"left\n")
    right = _candidate(tmp_path, "right", b"right\n")
    forged = DuplicateAssessment(
        left.subject, right.subject, ConflictKind.VERSION_CLASH,
        CompatibilityStatus.INCOMPATIBLE, (), (), _sha(b"forged"),
    )
    with pytest.raises(BTSError) as caught:
        assess_duplicates(
            (left, right), member_span_overlap_bps=5000, version_clashes=(forged,),
        )
    _assert_composition_input_reject(caught)


def test_ordering_and_digests_are_stable_across_shuffled_construction(tmp_path: Path) -> None:
    candidates = [
        _candidate(tmp_path, key, f"{key}\n".encode(), dependencies=(("pypi", "shared", "1", key),))
        for key in ("c", "a", "b")
    ]
    expected = assess_duplicates(tuple(candidates), member_span_overlap_bps=5000)
    random.Random(42).shuffle(candidates)
    actual = assess_duplicates(tuple(candidates), member_span_overlap_bps=5000)
    assert actual == expected
    assert [item.left.candidate_key for item in actual] == [("a",), ("a",), ("b",)]
    assert all(item.assessment_digest.startswith("sha256:") for item in actual)


def test_forged_source_bytes_digest_is_rejected_before_comparison(tmp_path: Path) -> None:
    left = _candidate(tmp_path, "left", b"left\n")
    right = _candidate(tmp_path, "right", b"right\n")
    forged_member = replace(right.bts.members[0], source_bytes_sha256=left.bts.members[0].source_bytes_sha256)
    forged_blank = replace(right.bts, members=(forged_member,))
    forged_bts = replace(forged_blank, member_equivalence_digest=_digest(forged_blank, omit=frozenset({"bts_digest", "member_equivalence_digest"})))

    with pytest.raises(BTSError) as caught:
        assess_duplicates((left, replace(right, bts=forged_bts)), member_span_overlap_bps=5000)

    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert caught.value.evidence.detail_code == "composition_input_missing_v1"


def test_snapshot_provenance_mismatch_uses_consumed_record_contract(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, "candidate", b"candidate\n")
    mismatched_snapshot = replace(candidate.snapshot, commit_sha="2" * 40)
    with pytest.raises(BTSError) as caught:
        assess_duplicates(
            (replace(candidate, snapshot=mismatched_snapshot),),
            member_span_overlap_bps=5000,
        )
    _assert_composition_input_reject(caught)
    assert isinstance(caught.value.__cause__, BTSError)
    assert caught.value.__cause__.evidence.detail_code == "bts_graph_snapshot_identity_v1"


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_assessment_digest_is_hash_seed_independent(seed: str) -> None:
    script = """
import tempfile
from pathlib import Path
from tests.test_composition_dupes import _candidate
from leitir.duplicates import assess_duplicates
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    left = _candidate(root, "left", b"left\\n", dependencies=(("pypi", "shared", "1", "same"),))
    right = _candidate(root, "right", b"right\\n", dependencies=(("pypi", "shared", "1", "same"),))
    import sys; sys.stdout.buffer.write(assess_duplicates((right, left), member_span_overlap_bps=5000)[0].assessment_digest.encode("ascii") + b"\\n")
"""
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.fspath(Path(__file__).parent.parent),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "sha256:b96f97e5bef59a1044defff960fdf15ad0f0059ba9cffdd098058e32b4cf135c"
