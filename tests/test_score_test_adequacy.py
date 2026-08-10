"""ADR-002 S5 coverage and mutation adequacy adapter gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.score_engine import (
    CheckStatus,
    EvidenceArtifact,
    canonical_json_bytes,
    evaluate_test_adequacy_evidence,
    load_policy,
    policy_from_dict,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "code_health"


def _fixture(name: str) -> EvidenceArtifact:
    content = (FIXTURES / name).read_bytes()
    return EvidenceArtifact(
        id=f"adequacy.{name.removesuffix('.json')}",
        path=f"tests/fixtures_score/code_health/{name}",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _artifact(name: str, value: object) -> EvidenceArtifact:
    content = canonical_json_bytes(value)
    return EvidenceArtifact(
        id=f"adequacy.{name}",
        path=f"tests/fixtures_score/code_health/{name}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _evaluation(*, coverage=None, mutmut=None, versions=None, policy=None, scope=None):
    return evaluate_test_adequacy_evidence(
        policy=policy or load_policy(REPO_ROOT / "scorecard" / "policy-v1.json"),
        scope_artifact=scope or _fixture("scope.json"),
        tool_versions=versions or _fixture("tool-versions.json"),
        coverage_json=coverage or _fixture("coverage.json"),
        mutmut_json=mutmut or _fixture("mutmut.json"),
    )


def _check(evaluation, check_id: str):
    return next(item for item in evaluation.checks if item.id == check_id)


def test_exact_line_branch_and_mutation_threshold_equality_passes():
    raw_policy = json.loads(
        (REPO_ROOT / "scorecard" / "policy-v1.json").read_text(encoding="utf-8")
    )
    ratchet = json.loads((FIXTURES / "policy-ratchet.json").read_text(encoding="utf-8"))
    for item in raw_policy["checks"]:
        if item["id"] in ratchet["base"]:
            item["criterion"]["value"] = ratchet["base"][item["id"]]
    evaluation = _evaluation(policy=policy_from_dict(raw_policy))

    assert evaluation.coverage.to_dict()["lines"] == {"covered": 16, "total": 20}
    assert evaluation.coverage.to_dict()["branches"] == {"covered": 14, "total": 20}
    assert (_check(evaluation, "test.line_coverage").score_bps, _check(evaluation, "test.line_coverage").status) == (8000, CheckStatus.PASS)
    assert (_check(evaluation, "test.branch_coverage").score_bps, _check(evaluation, "test.branch_coverage").status) == (7000, CheckStatus.PASS)
    assert (_check(evaluation, "test.mutation_score").score_bps, _check(evaluation, "test.mutation_score").status) == (8000, CheckStatus.PASS)


def test_policy_ratchet_fixture_fails_without_changing_measurements():
    raw_policy = json.loads(
        (REPO_ROOT / "scorecard" / "policy-v1.json").read_text(encoding="utf-8")
    )
    ratchet = json.loads((FIXTURES / "policy-ratchet.json").read_text(encoding="utf-8"))
    for item in raw_policy["checks"]:
        if item["id"] in {"test.line_coverage", "test.branch_coverage", "test.mutation_score"}:
            item["criterion"]["value"] = ratchet["ratcheted"][item["id"]]
    evaluation = _evaluation(policy=policy_from_dict(raw_policy))

    assert _check(evaluation, "test.line_coverage").status is CheckStatus.FAIL
    assert _check(evaluation, "test.branch_coverage").status is CheckStatus.FAIL
    assert _check(evaluation, "test.mutation_score").status is CheckStatus.FAIL


def test_unmeasured_production_file_is_unknown_and_reported():
    raw = json.loads((FIXTURES / "coverage.json").read_text(encoding="utf-8"))
    del raw["files"]["src/example/service.py"]
    raw["totals"] = raw["files"]["src/example/core.py"]["summary"]
    evaluation = _evaluation(coverage=_artifact("coverage-unmeasured", raw))

    scope_check = _check(evaluation, "test.coverage_scope")
    assert scope_check.status is CheckStatus.UNKNOWN
    assert scope_check.reason_code == "COVERAGE_PRODUCTION_FILE_UNMEASURED"
    assert evaluation.coverage.unmeasured_files == ("src/example/service.py",)
    assert _check(evaluation, "test.line_coverage").status is CheckStatus.UNKNOWN


def test_zero_statements_and_zero_branches_are_unknown_never_perfect():
    evaluation = _evaluation(coverage=_fixture("coverage-zero.json"))

    for check_id, reason in (
        ("test.line_coverage", "ZERO_STATEMENTS_UNRESOLVED"),
        ("test.branch_coverage", "ZERO_BRANCHES_UNRESOLVED"),
    ):
        check = _check(evaluation, check_id)
        assert check.status is CheckStatus.UNKNOWN
        assert check.score_bps is None
        assert check.reason_code == reason
        assert (check.numerator, check.denominator) == (0, 0)


def test_zero_branches_alone_is_unknown_even_with_measured_statements():
    raw = json.loads((FIXTURES / "coverage.json").read_text(encoding="utf-8"))
    for value in raw["files"].values():
        value["summary"]["covered_branches"] = 0
        value["summary"]["num_branches"] = 0
    raw["totals"]["covered_branches"] = 0
    raw["totals"]["num_branches"] = 0
    evaluation = _evaluation(coverage=_artifact("coverage-no-branches", raw))

    assert _check(evaluation, "test.line_coverage").status is CheckStatus.PASS
    assert _check(evaluation, "test.branch_coverage").status is CheckStatus.UNKNOWN


def test_zero_completed_mutants_is_unknown_and_never_a_perfect_score():
    evaluation = _evaluation(mutmut=_fixture("mutmut-zero.json"))
    mutation = _check(evaluation, "test.mutation_score")

    assert mutation.status is CheckStatus.UNKNOWN
    assert mutation.score_bps is None
    assert mutation.reason_code == "ZERO_COMPLETED_MUTANTS_UNRESOLVED"
    assert (mutation.numerator, mutation.denominator) == (0, 0)


@pytest.mark.parametrize(
    ("exit_code", "outcome", "expected_status"),
    [
        (0, "survived", CheckStatus.PASS),
        (5, "no_test", CheckStatus.PASS),
        (36, "timeout", CheckStatus.UNKNOWN),
        (-11, "crash", CheckStatus.UNKNOWN),
        (3, "internal_error", CheckStatus.UNKNOWN),
        (None, "pending", CheckStatus.UNKNOWN),
    ],
)
def test_mutmut_outcomes_remain_distinguishable(exit_code, outcome, expected_status):
    raw = json.loads((FIXTURES / "mutmut-zero.json").read_text(encoding="utf-8"))
    raw["mutants"] = [{"id": f"mutant-{outcome}", "exit_code": exit_code, "exclusion": None}]
    evaluation = _evaluation(mutmut=_artifact(f"mutmut-{outcome}", raw))

    counts = dict(evaluation.mutation.counts)
    assert counts[outcome] == 1
    assert sum(counts.values()) == 1
    assert _check(evaluation, "test.mutation_score").status is expected_status


def test_internal_error_is_not_laundered_as_mutmut_killed():
    raw = json.loads((FIXTURES / "mutmut-zero.json").read_text(encoding="utf-8"))
    raw["mutants"] = [{"id": "pytest-internal-error", "exit_code": 3, "exclusion": None}]
    evaluation = _evaluation(mutmut=_artifact("mutmut-internal", raw))

    assert dict(evaluation.mutation.counts)["internal_error"] == 1
    assert dict(evaluation.mutation.counts)["killed"] == 0
    assert _check(evaluation, "test.mutation_score").score_bps is None


def test_clean_control_and_forced_failure_sentinel_are_required():
    raw = json.loads((FIXTURES / "mutmut.json").read_text(encoding="utf-8"))
    raw["sentinel"] = {"exit_code": 0, "expected_failure_observed": False}
    evaluation = _evaluation(mutmut=_artifact("mutmut-bad-sentinel", raw))

    assert _check(evaluation, "test.mutation_controls").status is CheckStatus.ERROR
    assert _check(evaluation, "test.mutation_score").status is CheckStatus.ERROR


def test_scoring_tool_version_mismatch_is_error_not_auto_upgrade():
    versions = json.loads((FIXTURES / "tool-versions.json").read_text(encoding="utf-8"))
    versions["tools"]["coverage"] = "7.15.1"
    evaluation = _evaluation(versions=_artifact("versions-mismatch", versions))

    assert all(item.status is CheckStatus.ERROR for item in evaluation.checks)
    assert {item.reason_code for item in evaluation.checks} == {"SCORING_TOOL_VERSION_MISMATCH"}


def test_coverage_and_mutmut_fixtures_are_committed_real_shapes():
    coverage = json.loads((FIXTURES / "coverage.json").read_text(encoding="utf-8"))
    mutmut = json.loads((FIXTURES / "mutmut.json").read_text(encoding="utf-8"))
    assert coverage["meta"]["version"] == "7.15.2"
    assert coverage["meta"]["format"] == 3
    assert mutmut["tool"] == {"name": "mutmut", "version": "3.7.0"}
    assert mutmut["clean_control"]["tests_collected"] > 0
