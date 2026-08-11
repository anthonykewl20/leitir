from __future__ import annotations

import os
import subprocess
import sys

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.candidates import EvidencePointer
from leitir.comparison import (
    BehavioralInterfaceAssessment,
    BehavioralInterfaceValue,
    ComparisonResult,
    DependencyCostAssessment,
    DependencyCostValue,
    DimensionStatus,
    InterfaceMatch,
    RoleKind,
    RoleStatus,
    compare_and_select,
    compare_assessments,
)
from leitir.suitability import build_survivor_set
from tests.test_capability import _spec
from tests.test_suitability import _DIGEST, _candidate, _passing_context, _profile


def _dimension(kind: str, value: str) -> EvidencePointer:
    return EvidencePointer(f"dimension:{kind}:known:{value}", "leitir.dimension_assessment", "v1", _DIGEST)


def _assessment(value: DependencyCostValue | None) -> DependencyCostAssessment:
    evidence = (_dimension("dependency_cost", "1,2,0"),) if value is not None else ()
    status = DimensionStatus.KNOWN if value is not None else DimensionStatus.UNKNOWN
    return DependencyCostAssessment(status, "fixture.dependency", "v1", evidence, value)


def test_four_way_comparator_orders_equal_and_preserves_unknown_incomparability() -> None:
    low = _assessment(DependencyCostValue(1, 2, 0))
    high = _assessment(DependencyCostValue(3, 2, 0))
    same = _assessment(DependencyCostValue(1, 2, 0))
    unknown = _assessment(None)

    assert compare_assessments(low, high) is ComparisonResult.BETTER
    assert compare_assessments(high, low) is ComparisonResult.WORSE
    assert compare_assessments(low, same) is ComparisonResult.EQUAL
    assert compare_assessments(high, unknown) is ComparisonResult.INCOMPARABLE
    assert compare_assessments(unknown, high) is ComparisonResult.INCOMPARABLE

    behavioral = BehavioralInterfaceAssessment(
        DimensionStatus.KNOWN,
        "fixture.behavioral",
        "v1",
        (_dimension("behavioral_interface_fit", "1,1,0,0,exact"),),
        BehavioralInterfaceValue(1, 1, 0, 0, InterfaceMatch.EXACT),
    )
    with pytest.raises(BTSError) as caught:
        compare_assessments(low, behavioral)
    assert caught.value.reason is BTSRejectReason.REJECT_SEMANTIC_DEGRADATION


def _role_markers(*, direct: int, integration: int, evidence: int) -> tuple[EvidencePointer, ...]:
    return (
        _dimension("behavioral_interface_fit", f"1,1,{direct},3,exact"),
        _dimension("runtime_portability_fit", "1,1,exact"),
        _dimension("dependency_cost", f"{integration},{integration},0"),
        _dimension("extraction_difficulty", f"{integration},{integration},0,0"),
        _dimension("structural_complexity", f"{integration},{integration},0"),
        _dimension("test_example_evidence", f"{evidence},{evidence},{evidence}"),
        _dimension("documentation_evidence", f"{evidence},{evidence},{evidence}"),
        _dimension("maintenance_status", f"active,{evidence}"),
        _dimension("security_risk", "0,0,0,complete"),
        _dimension("version_stability", f"stable,{evidence}"),
    )


def _report_bytes() -> bytes:
    spec = _spec()
    profile = _profile()
    candidates = (
        _candidate(column=0, context=_passing_context() + _role_markers(direct=3, integration=3, evidence=1)),
        _candidate(column=8, context=_passing_context() + _role_markers(direct=2, integration=1, evidence=2)),
        _candidate(column=16, context=_passing_context() + _role_markers(direct=1, integration=2, evidence=3)),
    )
    return compare_and_select(build_survivor_set(candidates, spec, profile), spec, profile).to_bytes()


def test_best3_roles_are_independent_and_report_has_no_compensating_aggregate() -> None:
    spec = _spec()
    profile = _profile()
    candidates = (
        _candidate(column=0, context=_passing_context() + _role_markers(direct=3, integration=3, evidence=1)),
        _candidate(column=8, context=_passing_context() + _role_markers(direct=2, integration=1, evidence=2)),
        _candidate(column=16, context=_passing_context() + _role_markers(direct=1, integration=2, evidence=3)),
    )
    report = compare_and_select(build_survivor_set(candidates, spec, profile), spec, profile)
    selected = {role.role: role.candidate_key for role in report.roles}
    assert selected[RoleKind.DIRECT_FIT] == candidates[0].key()
    assert selected[RoleKind.INTEGRATION_COST] == candidates[1].key()
    assert selected[RoleKind.EVIDENCE_STRENGTH] == candidates[2].key()
    assert all(role.status is RoleStatus.PROVED_WINNER for role in report.roles)
    serialized = report.to_bytes()
    assert b'"score"' not in serialized
    assert b'"overall_score"' not in serialized
    assert b'"total"' not in serialized
    assert b'"weighted"' not in serialized


def test_unknown_heavy_survivors_leave_every_role_explicitly_unranked() -> None:
    spec = _spec()
    profile = _profile()
    survivors = build_survivor_set((_candidate(column=0), _candidate(column=8)), spec, profile)
    report = compare_and_select(survivors, spec, profile)
    assert all(role.status is RoleStatus.UNRANKED_INCOMPARABLE for role in report.roles)
    assert all(role.candidate_key is None for role in report.roles)
    assert all(role.incomparable_pairs for role in report.roles)


def test_only_c3a_survivor_set_can_enter_comparison() -> None:
    spec = _spec()
    profile = _profile()
    with pytest.raises(BTSError) as caught:
        compare_and_select((_candidate(),), spec, profile)  # type: ignore[arg-type]
    assert caught.value.reason is BTSRejectReason.REJECT_SEMANTIC_DEGRADATION
    assert caught.value.evidence.detail_code == "comparison_unauthorized_ranking_v1"


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_best3_report_is_byte_identical_across_hash_seeds(seed: str) -> None:
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [sys.executable, "-c", "from tests.test_comparison import _report_bytes; import sys; sys.stdout.buffer.write(_report_bytes())"],
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        env=environment,
        check=True,
        capture_output=True,
    )
    assert completed.stdout == _report_bytes()
