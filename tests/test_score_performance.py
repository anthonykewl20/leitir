"""ADR-002 S7 controlled-performance adapter gates."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from tools.score_engine import (
    CheckMode,
    CheckStatus,
    EvidenceArtifact,
    canonical_json_bytes,
    evaluate_live_network_latency,
    evaluate_performance_evidence,
    load_policy,
    mann_whitney_u_two_sided,
    _local_evidence_artifact,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "performance"


def _fixture(name: str) -> EvidenceArtifact:
    content = (FIXTURES / name).read_bytes()
    return EvidenceArtifact(
        id=f"performance.{name.removesuffix('.json').replace('-', '_')}",
        path=f"tests/fixtures_score/performance/{name}",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _artifact(name: str, value: object) -> EvidenceArtifact:
    content = canonical_json_bytes(value)
    return EvidenceArtifact(
        id=f"performance.{name}",
        path=f"tests/fixtures_score/performance/{name}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _raw(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _set_benchmark(
    raw: dict[str, object],
    *,
    median: int | None = None,
    samples: list[int] | None = None,
) -> None:
    columns = raw["result_columns"]
    row = raw["results"]["benchmarks.TimeSearch.time_scoped_query"]
    row[columns.index("result")] = [median]
    row[columns.index("samples")] = [samples]


def _evaluation(
    *,
    runner: EvidenceArtifact | None = None,
    baseline: EvidenceArtifact | None = None,
    candidate: EvidenceArtifact | None = None,
):
    return evaluate_performance_evidence(
        runner_output=runner or _fixture("runner.json"),
        baseline_asv=baseline if baseline is not None else _fixture("baseline-asv-v2.json"),
        candidate_asv=candidate or _fixture("candidate-asv-v2.json"),
    )


def test_asv_orchestration_time_is_noncanonical_but_samples_remain_bound(tmp_path):
    first = _raw("candidate-asv-v2.json")
    second = json.loads(json.dumps(first))
    second["date"] = 1999999999999
    second["durations"] = {"build": 99.5}
    columns = second["result_columns"]
    row = second["results"]["benchmarks.TimeSearch.time_scoped_query"]
    row[columns.index("started_at")] = 1999999999998
    row[columns.index("duration")] = 88.5
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    path = evidence_dir / "candidate-asv.json"
    path.write_bytes(canonical_json_bytes(first))
    first_artifact = _local_evidence_artifact(
        evidence_dir, "candidate-asv.json", "performance.candidate"
    )
    path.write_bytes(canonical_json_bytes(second))
    second_artifact = _local_evidence_artifact(
        evidence_dir, "candidate-asv.json", "performance.candidate"
    )
    row[columns.index("samples")][0][0] += 1
    path.write_bytes(canonical_json_bytes(second))
    changed_artifact = _local_evidence_artifact(
        evidence_dir, "candidate-asv.json", "performance.candidate"
    )

    assert first_artifact is not None
    assert second_artifact is not None
    assert changed_artifact is not None
    assert first_artifact.raw_sha256 != second_artifact.raw_sha256
    assert first_artifact.sha256 == second_artifact.sha256
    assert changed_artifact.sha256 != second_artifact.sha256
    assert first_artifact.normalization == "asv-json-volatile-v1"


def test_exact_1_10_magnitude_boundary_passes_with_decimal_arithmetic():
    evaluation = _evaluation()
    comparison = evaluation.comparisons[0]

    assert comparison.baseline_median == Decimal("100")
    assert comparison.candidate_median == Decimal("110")
    assert comparison.candidate_median == comparison.baseline_median * Decimal("1.10")
    assert comparison.mann_whitney is None
    assert evaluation.checks[0].status is CheckStatus.PASS
    assert evaluation.checks[0].reason_code == "PERFORMANCE_NO_HARD_REGRESSION"


def test_significant_material_regression_is_known_failure():
    candidate = _raw("candidate-asv-v2.json")
    _set_benchmark(candidate, median=120, samples=list(range(120, 128)))
    evaluation = _evaluation(candidate=_artifact("significant", candidate))
    comparison = evaluation.comparisons[0]

    assert comparison.mann_whitney is not None
    assert abs(
        comparison.mann_whitney.p_value - Decimal("0.0009391056991171905")
    ) < Decimal("1e-15")
    assert evaluation.checks[0].status is CheckStatus.FAIL
    assert evaluation.checks[0].reason_code == "PERFORMANCE_SIGNIFICANT_REGRESSION"


def test_material_underpowered_result_is_unknown_not_pass_or_fail():
    baseline = _raw("baseline-asv-v2.json")
    candidate = _raw("candidate-asv-v2.json")
    _set_benchmark(baseline, median=100, samples=[90, 92, 94, 97, 100])
    _set_benchmark(candidate, median=120, samples=[120, 121, 122, 123, 124])
    evaluation = _evaluation(
        baseline=_artifact("underpowered-baseline", baseline),
        candidate=_artifact("underpowered-candidate", candidate),
    )

    assert evaluation.comparisons[0].mann_whitney is None
    assert evaluation.checks[0].status is CheckStatus.UNKNOWN
    assert evaluation.checks[0].score_bps is None
    assert evaluation.checks[0].reason_code == "PERFORMANCE_INSUFFICIENT_SAMPLES"


def test_material_slowdown_with_overlapping_samples_is_unknown():
    baseline = _raw("baseline-asv-v2.json")
    candidate = _raw("candidate-asv-v2.json")
    _set_benchmark(baseline, median=100, samples=[90, 95, 100, 105, 110, 115])
    _set_benchmark(candidate, median=120, samples=[95, 105, 110, 120, 125, 135])
    evaluation = _evaluation(
        baseline=_artifact("overlap-baseline", baseline),
        candidate=_artifact("overlap-candidate", candidate),
    )
    statistic = evaluation.comparisons[0].mann_whitney

    assert statistic is not None
    assert statistic.u == Decimal("8.5")
    assert abs(statistic.p_value - Decimal("0.1474013021678951")) < Decimal("1e-15")
    assert evaluation.checks[0].status is CheckStatus.UNKNOWN
    assert evaluation.checks[0].reason_code == "PERFORMANCE_REGRESSION_INCONCLUSIVE"


def test_missing_baseline_is_unresolved():
    evaluation = evaluate_performance_evidence(
        runner_output=_fixture("runner.json"),
        baseline_asv=None,
        candidate_asv=_fixture("candidate-asv-v2.json"),
    )

    assert evaluation.checks[0].status is CheckStatus.ERROR
    assert evaluation.checks[0].reason_code == "PERFORMANCE_BASELINE_MISSING"


def test_runner_mismatch_is_unresolved():
    candidate = _raw("candidate-asv-v2.json")
    candidate["params"]["machine"] = "different-runner"
    evaluation = _evaluation(candidate=_artifact("runner-mismatch", candidate))

    assert evaluation.checks[0].status is CheckStatus.ERROR
    assert evaluation.checks[0].reason_code == "PERFORMANCE_RUNNER_MISMATCH"


def test_candidate_functional_failure_after_successful_baseline_is_known_failure():
    candidate = _raw("candidate-asv-v2.json")
    _set_benchmark(candidate, median=None, samples=None)
    evaluation = _evaluation(candidate=_artifact("candidate-failure", candidate))

    assert evaluation.checks[0].status is CheckStatus.FAIL
    assert evaluation.checks[0].reason_code == "PERFORMANCE_CANDIDATE_FUNCTIONAL_FAILURE"


def test_benchmark_version_mismatch_is_unresolved():
    candidate = _raw("candidate-asv-v2.json")
    columns = candidate["result_columns"]
    row = candidate["results"]["benchmarks.TimeSearch.time_scoped_query"]
    row[columns.index("version")] = "time-scoped-query-v2"
    evaluation = _evaluation(candidate=_artifact("benchmark-version-mismatch", candidate))

    assert evaluation.checks[0].status is CheckStatus.ERROR
    assert evaluation.checks[0].reason_code == "PERFORMANCE_BENCHMARK_VERSION_MISMATCH"


def test_noninterleaved_runner_and_environment_mismatch_are_unresolved():
    runner = _raw("runner.json")
    runner["interleave_order"] = ["baseline", "baseline", "candidate", "candidate"]
    noninterleaved = _evaluation(runner=_artifact("noninterleaved", runner))
    assert noninterleaved.checks[0].reason_code == "PERFORMANCE_NOT_INTERLEAVED"

    candidate = _raw("candidate-asv-v2.json")
    candidate["params"]["environment_fingerprint"] = "b" * 64
    mismatch = _evaluation(candidate=_artifact("environment-mismatch", candidate))
    assert mismatch.checks[0].reason_code == "PERFORMANCE_ENVIRONMENT_MISMATCH"


def test_harness_error_and_unpinned_asv_are_unresolved():
    harness = _raw("runner.json")
    harness["harness_error"] = "worker exited before results were complete"
    harness_error = _evaluation(runner=_artifact("harness-error", harness))
    assert harness_error.checks[0].reason_code == "PERFORMANCE_HARNESS_ERROR"

    version = _raw("runner.json")
    version["asv_version"] = "0.6.5"
    version_error = _evaluation(runner=_artifact("asv-version", version))
    assert version_error.checks[0].reason_code == "PERFORMANCE_ASV_VERSION_MISMATCH"


def test_mann_whitney_matches_hand_calculated_untied_and_tied_values():
    # Complete separation: U=0, variance=8*8*(16+1)/12=272/3, and the
    # continuity-corrected z=(32-0.5)/sqrt(272/3).
    separated = mann_whitney_u_two_sided(range(1, 9), range(20, 28))
    assert separated.u == Decimal("0")
    assert separated.variance == Fraction(272, 3)
    assert abs(separated.z - Decimal("3.308161698516173")) < Decimal("1e-15")
    assert abs(
        separated.p_value - Decimal("0.0009391056991171905")
    ) < Decimal("1e-15")

    # Pooled tie groups have sizes 2, 4, 4, 2, so sum(t^3-t)=132.
    # The corrected variance is 36; hand ranking gives U=8 and z=9.5/6.
    tied = mann_whitney_u_two_sided(
        [1, 1, 2, 2, 3, 3],
        [2, 2, 3, 3, 4, 4],
    )
    assert tied.u == Decimal("8")
    assert tied.variance == Fraction(36, 1)
    assert tied.z == Decimal("1.5833333333333333")
    assert abs(tied.p_value - Decimal("0.11334550921952588")) < Decimal("1e-15")


def test_live_network_latency_is_policy_advisory_and_has_no_threshold():
    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    policy_check = next(
        item for item in policy.checks if item.id == "performance.live_network_latency"
    )
    latency = _raw("live-network-latency.json")
    latency["measurements"][0]["samples_ms"] = [999999999]
    result = evaluate_live_network_latency(_artifact("extreme-live-latency", latency))

    assert policy_check.offline_mode is CheckMode.ADVISORY
    assert policy_check.release_mode is CheckMode.ADVISORY
    assert policy_check.score_eligible is False
    assert result.status is CheckStatus.PASS
    assert result.reason_code == "PERFORMANCE_LATENCY_OBSERVED_ADVISORY"


def test_fixtures_are_native_asv_v2_result_shapes():
    baseline = _raw("baseline-asv-v2.json")
    candidate = _raw("candidate-asv-v2.json")

    assert baseline["version"] == candidate["version"] == 2
    assert baseline["result_columns"] == candidate["result_columns"]
    assert "samples" in baseline["result_columns"]
    assert baseline["params"] == candidate["params"]
