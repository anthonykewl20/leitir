"""ADR-002 S1 assessment-contract and gate-algebra tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.score_engine import (
    POLICY_SCHEMA_VERSION,
    ApplicabilityRule,
    BlockerKind,
    CheckMode,
    CheckPolicy,
    CheckResult,
    CheckStatus,
    Criterion,
    Decision,
    DimensionPolicy,
    ExitCode,
    Policy,
    Producer,
    Profile,
    Subject,
    decision_exit_code,
    display_band,
    evaluate,
    load_policy,
    policy_from_dict,
    proportional_score_bps,
    score_from_counts,
    weighted_score_bps,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DIMENSIONS = (
    "engine_correctness",
    "output_effectiveness",
    "code_health",
    "test_adequacy",
    "process_supply_chain",
    "performance_operability",
)
SUBJECT = Subject(
    repository="https://github.com/anthonykewl20/leitir",
    commit_sha="1" * 40,
    worktree="clean",
)
PRODUCER = Producer(
    name="leitir-score-engine",
    version="1",
    commit_sha="2" * 40,
)


def _check_policy(
    check_id: str,
    *,
    dimension: str = "engine_correctness",
    weight: int = 1,
    offline_mode: CheckMode = CheckMode.REQUIRED,
    release_mode: CheckMode | None = None,
    score_eligible: bool = True,
    applicable: bool = False,
) -> CheckPolicy:
    return CheckPolicy(
        id=check_id,
        dimension=dimension,
        weight=weight,
        score_eligible=score_eligible,
        criterion=Criterion(op="gte", value=0),
        offline_mode=offline_mode,
        release_mode=release_mode or offline_mode,
        applicability=(
            ApplicabilityRule("declared scope contains no eligible items")
            if applicable
            else None
        ),
    )


def _policy(
    *checks: CheckPolicy,
    dimension_weights: tuple[int, ...] = (1, 1, 1, 1, 1, 1),
) -> Policy:
    populated = {check.dimension for check in checks}
    placeholders = tuple(
        _check_policy(
            f"placeholder.{dimension}",
            dimension=dimension,
            offline_mode=CheckMode.ADVISORY,
            score_eligible=False,
        )
        for dimension in DIMENSIONS
        if dimension not in populated
    )
    return Policy(
        schema_version=POLICY_SCHEMA_VERSION,
        id="test-policy-v1",
        dimensions=tuple(
            DimensionPolicy(id=dimension, weight=weight)
            for dimension, weight in zip(
                DIMENSIONS, dimension_weights, strict=True
            )
        ),
        checks=checks + placeholders,
    )


def _result(
    check_id: str,
    status: CheckStatus,
    *,
    score_bps: int | None = None,
    reason_code: str | None = None,
    numerator: int | None = None,
    denominator: int | None = None,
    evidence: tuple[dict[str, str], ...] = (),
) -> CheckResult:
    if score_bps is None and status in {CheckStatus.PASS, CheckStatus.FAIL}:
        score_bps = 10000 if status is CheckStatus.PASS else 0
    return CheckResult(
        id=check_id,
        status=status,
        score_bps=score_bps,
        reason_code=reason_code or f"CHECK_{status.value.upper()}",
        numerator=numerator,
        denominator=denominator,
        evidence=evidence,
    )


def _evaluate(
    policy: Policy,
    *results: CheckResult,
    profile: Profile = Profile.OFFLINE,
):
    return evaluate(
        policy,
        tuple(results),
        profile=profile,
        subject=SUBJECT,
        producer=PRODUCER,
    )


def _dimension(assessment, dimension_id: str):
    return next(item for item in assessment.dimensions if item.id == dimension_id)


class TestIntegerScoring:
    def test_round_half_up_proportional_exact_half_boundaries(self):
        # 10000 / 32 = 312.5 and 30000 / 32 = 937.5.  Banker's round
        # would return 312 for the first boundary; ADR-002 requires half-up.
        assert proportional_score_bps(1, 32) == 313
        assert proportional_score_bps(3, 32) == 938

    def test_round_half_up_weighted_exact_half_boundaries(self):
        # The exact weighted values are 0.5 and 2.5 basis points.
        assert weighted_score_bps(((0, 1), (1, 1))) == 1
        assert weighted_score_bps(((2, 1), (3, 1))) == 3

    def test_zero_denominator_is_null_never_zero_or_perfect(self):
        assert proportional_score_bps(0, 0) is None
        assert score_from_counts(((0, 0), (0, 0))) is None
        with pytest.raises(ValueError, match="zero denominator"):
            _result(
                "engine.zero_denominator",
                CheckStatus.PASS,
                numerator=0,
                denominator=0,
            )

    def test_raw_counts_aggregate_before_ratio(self):
        # Averaging the child grades (10000 and 0) would be 5000.  The raw
        # sufficient statistics are 1 / 10, which must score 1000.
        assert score_from_counts(((1, 1), (0, 9))) == 1000

    def test_weighted_score_uses_positive_integer_weights(self):
        assert weighted_score_bps(((10000, 1), (2000, 3))) == 4000
        with pytest.raises(ValueError, match="positive integer"):
            weighted_score_bps(((10000, 0),))
        with pytest.raises(ValueError, match="integer"):
            weighted_score_bps(((10000, 1.0),))

    @pytest.mark.parametrize("value", [1.5, float("nan"), float("inf")])
    def test_canonical_result_rejects_float_and_non_finite_scores(self, value):
        with pytest.raises(ValueError, match="integer"):
            CheckResult(
                id="engine.numeric_contract",
                status=CheckStatus.PASS,
                score_bps=value,
                reason_code="CHECK_PASSED",
            )

    def test_canonical_result_rejects_non_text_evidence_values(self):
        with pytest.raises(ValueError, match="kind and value"):
            CheckResult(
                id="engine.evidence_contract",
                status=CheckStatus.UNKNOWN,
                score_bps=None,
                reason_code="EVIDENCE_UNKNOWN",
                evidence=({"kind": "counter", "value": 1.5},),
            )


class TestTypedStatuses:
    @pytest.mark.parametrize(
        ("status", "expected_decision", "expected_exact", "expected_bounds"),
        [
            (CheckStatus.PASS, Decision.PASS, 10000, (10000, 10000)),
            (CheckStatus.FAIL, Decision.FAIL, 0, (0, 0)),
            (CheckStatus.UNKNOWN, Decision.INDETERMINATE, None, (0, 10000)),
            (CheckStatus.ERROR, Decision.INDETERMINATE, None, (0, 10000)),
            (CheckStatus.NOT_APPLICABLE, Decision.PASS, None, (None, None)),
            (CheckStatus.SKIPPED, Decision.INDETERMINATE, None, (0, 10000)),
        ],
    )
    def test_all_six_statuses_have_exact_numeric_and_gate_treatment(
        self,
        status,
        expected_decision,
        expected_exact,
        expected_bounds,
    ):
        policy = _policy(
            _check_policy(
                "engine.status_contract",
                applicable=status is CheckStatus.NOT_APPLICABLE,
            )
        )
        evidence = (
            ({"kind": "applicability", "value": "empty-declared-scope"},)
            if status is CheckStatus.NOT_APPLICABLE
            else ()
        )
        assessment = _evaluate(
            policy,
            _result("engine.status_contract", status, evidence=evidence),
        )
        dimension = _dimension(assessment, "engine_correctness").aggregate
        assert assessment.aggregate.decision is expected_decision
        assert dimension.score_bps == expected_exact
        assert (dimension.lower_bound_bps, dimension.upper_bound_bps) == (
            expected_bounds
        )

    @pytest.mark.parametrize(
        "status",
        [
            CheckStatus.UNKNOWN,
            CheckStatus.ERROR,
            CheckStatus.NOT_APPLICABLE,
            CheckStatus.SKIPPED,
        ],
    )
    def test_unresolved_and_not_applicable_statuses_require_null_score(self, status):
        with pytest.raises(ValueError, match="requires score_bps=None"):
            CheckResult(
                id="engine.null_contract",
                status=status,
                score_bps=0,
                reason_code="INVALID_NUMERIC_STATUS",
            )

    def test_not_applicable_requires_policy_rule_and_evidence(self):
        result = _result("engine.na_contract", CheckStatus.NOT_APPLICABLE)
        with pytest.raises(ValueError, match="policy rule"):
            _evaluate(_policy(_check_policy("engine.na_contract")), result)
        with pytest.raises(ValueError, match="without evidence"):
            _evaluate(
                _policy(_check_policy("engine.na_contract", applicable=True)),
                result,
            )


class TestAggregation:
    def test_hand_calculated_exact_observed_and_bounds(self):
        policy = _policy(
            _check_policy("engine.known", weight=1),
            _check_policy("engine.unresolved", weight=3),
        )
        assessment = _evaluate(
            policy,
            _result("engine.known", CheckStatus.PASS, score_bps=8000),
            _result("engine.unresolved", CheckStatus.UNKNOWN),
        )
        dimension = _dimension(assessment, "engine_correctness").aggregate
        assert dimension.score_bps is None
        assert dimension.observed_score_bps == 8000
        assert dimension.lower_bound_bps == 2000
        assert dimension.upper_bound_bps == 9500
        assert dimension.included_weight == 1
        assert dimension.eligible_weight == 4

    def test_dimensions_are_scored_before_equal_weight_overall(self):
        policy = _policy(
            _check_policy("engine.low"),
            _check_policy("engine.high"),
            _check_policy(
                "output.high", dimension="output_effectiveness"
            ),
        )
        assessment = _evaluate(
            policy,
            _result("engine.low", CheckStatus.FAIL, score_bps=0),
            _result("engine.high", CheckStatus.PASS, score_bps=10000),
            _result("output.high", CheckStatus.PASS, score_bps=10000),
        )
        assert _dimension(assessment, "engine_correctness").aggregate.score_bps == 5000
        assert (
            _dimension(assessment, "output_effectiveness").aggregate.score_bps
            == 10000
        )
        # Per-check averaging would produce 6667.  Explicit equal dimension
        # influence produces (5000 + 10000) / 2 = 7500.
        assert assessment.aggregate.scores.score_bps == 7500

    def test_explicit_dimension_weights_are_versioned_and_applied(self):
        policy = _policy(
            _check_policy("engine.low"),
            _check_policy(
                "output.high", dimension="output_effectiveness"
            ),
            dimension_weights=(3, 1, 1, 1, 1, 1),
        )
        assessment = _evaluate(
            policy,
            _result("engine.low", CheckStatus.FAIL, score_bps=0),
            _result("output.high", CheckStatus.PASS, score_bps=10000),
        )
        assert assessment.aggregate.scores.score_bps == 2500


class TestGatePrecedence:
    def test_required_fail_plus_error_stays_fail_and_preserves_both_blockers(self):
        policy = _policy(
            _check_policy("engine.known_failure"),
            _check_policy("engine.collector_error"),
        )
        assessment = _evaluate(
            policy,
            _result(
                "engine.known_failure",
                CheckStatus.FAIL,
                score_bps=9999,
                reason_code="KNOWN_POLICY_FAILURE",
            ),
            _result(
                "engine.collector_error",
                CheckStatus.ERROR,
                reason_code="COLLECTOR_ERROR",
            ),
        )
        assert assessment.aggregate.decision is Decision.FAIL
        assert assessment.aggregate.complete is False
        assert [item.kind for item in assessment.aggregate.blockers] == [
            BlockerKind.KNOWN_FAILURE,
            BlockerKind.UNRESOLVED,
        ]
        assert [item.reason_code for item in assessment.aggregate.blockers] == [
            "KNOWN_POLICY_FAILURE",
            "COLLECTOR_ERROR",
        ]

    def test_advisory_failure_never_changes_required_gate(self):
        policy = _policy(
            _check_policy("engine.required"),
            _check_policy(
                "engine.advisory", offline_mode=CheckMode.ADVISORY
            ),
        )
        assessment = _evaluate(
            policy,
            _result("engine.required", CheckStatus.PASS),
            _result("engine.advisory", CheckStatus.FAIL),
        )
        assert assessment.aggregate.decision is Decision.PASS
        assert assessment.aggregate.complete is True
        assert assessment.aggregate.blockers == ()

    def test_required_and_advisory_skips_are_distinct(self):
        policy = _policy(
            _check_policy("engine.required_skip"),
            _check_policy(
                "engine.advisory_skip", offline_mode=CheckMode.ADVISORY
            ),
        )
        assessment = _evaluate(
            policy,
            _result("engine.required_skip", CheckStatus.SKIPPED),
            _result("engine.advisory_skip", CheckStatus.SKIPPED),
        )
        assert assessment.aggregate.decision is Decision.INDETERMINATE
        assert [item.check_id for item in assessment.aggregate.blockers] == [
            "engine.required_skip"
        ]

    def test_scalar_score_cannot_rescue_required_failure(self):
        policy = _policy(
            _check_policy("engine.required"),
            _check_policy(
                "engine.advisory", offline_mode=CheckMode.ADVISORY
            ),
        )
        assessment = _evaluate(
            policy,
            _result("engine.required", CheckStatus.FAIL, score_bps=9999),
            _result("engine.advisory", CheckStatus.PASS, score_bps=10000),
        )
        assert assessment.aggregate.scores.score_bps == 10000
        assert assessment.aggregate.decision is Decision.FAIL
        assert assessment.exit_code is ExitCode.KNOWN_FAILURE

    def test_profile_changes_policy_mode_not_submitted_result(self):
        policy = _policy(
            _check_policy(
                "process.live_provenance",
                dimension="process_supply_chain",
                offline_mode=CheckMode.ADVISORY,
                release_mode=CheckMode.REQUIRED,
            )
        )
        result = _result("process.live_provenance", CheckStatus.UNKNOWN)
        assert _evaluate(policy, result).aggregate.decision is Decision.PASS
        assert (
            _evaluate(policy, result, profile=Profile.RELEASE).aggregate.decision
            is Decision.INDETERMINATE
        )


class TestPolicyExpectedSet:
    def test_duplicate_submitted_check_ids_are_rejected(self):
        policy = _policy(_check_policy("engine.unique"))
        result = _result("engine.unique", CheckStatus.PASS)
        with pytest.raises(ValueError, match="submitted check IDs must be unique"):
            _evaluate(policy, result, result)

    def test_duplicate_policy_check_ids_are_rejected(self):
        check = _check_policy("engine.unique")
        with pytest.raises(ValueError, match="policy check IDs must be unique"):
            _policy(check, check)

    def test_policy_declared_but_unsubmitted_check_is_unresolved(self):
        policy = _policy(
            _check_policy("engine.submitted"),
            _check_policy("engine.declared_but_missing"),
        )
        assessment = _evaluate(
            policy,
            _result("engine.submitted", CheckStatus.PASS),
        )
        missing = next(
            item
            for item in assessment.checks
            if item.id == "engine.declared_but_missing"
        )
        assert missing.status is CheckStatus.UNKNOWN
        assert missing.reason_code == "POLICY_CHECK_MISSING"
        assert missing.missing is True
        assert assessment.aggregate.decision is Decision.INDETERMINATE
        assert assessment.aggregate.scores.score_bps is None
        assert assessment.aggregate.blockers[0].kind is BlockerKind.MISSING_RESULT

    def test_policy_unknown_submitted_check_is_rejected(self):
        policy = _policy(_check_policy("engine.expected"))
        with pytest.raises(ValueError, match="policy-unknown"):
            _evaluate(
                policy,
                _result("engine.unexpected", CheckStatus.PASS),
            )


class TestPolicyAndCanonicalContract:
    def test_shipped_policy_is_strict_equal_weight_and_waiver_free(self):
        policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
        assert [item.id for item in policy.dimensions] == list(DIMENSIONS)
        assert [item.weight for item in policy.dimensions] == [1] * 6
        assert policy.waivers == ()

    def test_policy_parser_rejects_unknown_fields(self):
        raw = json.loads(
            (REPO_ROOT / "scorecard" / "policy-v1.json").read_text(
                encoding="utf-8"
            )
        )
        raw["threshold_to_make_green"] = 0
        with pytest.raises(ValueError, match="unknown fields"):
            policy_from_dict(raw)

    def test_assessment_schema_is_json_and_strict_at_every_owned_object(self):
        schema = json.loads(
            (REPO_ROOT / "scorecard" / "assessment-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        assert schema["additionalProperties"] is False
        for definition in (
            "subject",
            "producer",
            "policyIdentity",
            "criterion",
            "check",
            "evidence",
            "dimension",
            "blocker",
            "gateAggregate",
        ):
            assert schema["$defs"][definition]["additionalProperties"] is False
        assert schema["$defs"]["score"]["type"] == "integer"

    def test_canonical_output_contains_policy_enriched_shape(self):
        policy = _policy(_check_policy("engine.canonical"))
        assessment = _evaluate(
            policy,
            _result("engine.canonical", CheckStatus.PASS, score_bps=8750),
        )
        decoded = json.loads(assessment.to_json())
        assert decoded["schema_version"] == "leitir-assessment-v1"
        assert decoded["policy"] == {
            "id": policy.id,
            "sha256": policy.digest(),
        }
        assert decoded["checks"][0]["dimension"] == "engine_correctness"
        assert decoded["checks"][0]["mode"] == "required"
        assert decoded["aggregate"]["decision"] == "pass"

    def test_display_bands_are_metadata_boundaries_only(self):
        assert {
            point: display_band(point)
            for point in (0, 3999, 4000, 5999, 6000, 7999, 8000, 10000)
        } == {
            0: "critical",
            3999: "critical",
            4000: "serious",
            5999: "serious",
            6000: "fair",
            7999: "fair",
            8000: "good",
            10000: "good",
        }


def test_process_exit_contract():
    assert decision_exit_code(Decision.PASS) is ExitCode.COMPLETE_PASS
    assert decision_exit_code(Decision.FAIL) is ExitCode.KNOWN_FAILURE
    assert decision_exit_code(Decision.INDETERMINATE) is ExitCode.INDETERMINATE
    assert int(ExitCode.INVALID_USAGE_OR_POLICY) == 2
