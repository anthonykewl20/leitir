"""Deterministic E5a BTS evaluation harness and metric contract tests."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace

import pytest

from leitir.bts_bench import (
    LEITIR_BTS_EVAL_MANIFEST_V1,
    AdaptationProbeObs,
    BTSEvalBenchmark,
    BTSEvalManifest,
    BTSEvalRun,
    BTSEvalTask,
    BTSGold,
    BTSTaskObservation,
    BTSTimingEnvelope,
    CandidateIdentity,
    CandidateJudgment,
    MemberObs,
    MetricApplicability,
    SeedSpan,
    compute_run_with_timing,
    from_pipeline_result,
    grade_adaptation_integrity,
    grade_candidate_top1,
    grade_candidate_top3,
    grade_donor_import_free,
    grade_example_recall,
    grade_hallucinated_dependency_rate,
    grade_helper_recall,
    grade_integration_success,
    grade_license_accuracy,
    grade_missing_dependency_rate,
    grade_probe_success,
    grade_seed_symbol_exact,
    grade_seed_symbol_line_overlap,
    grade_test_recall,
    manifest_from_dict,
)
from leitir.bts_errors import BTSRejectReason
from leitir.exec_sandbox import ValidationAbortEnvelope
from leitir.probes import ProbeOutcome, ProbeOutcomeEvidence
from leitir.rerun import RerunReport
from tests.test_bts_e4b import TrustedCorpusPipeline, _prepared_request
from tests.test_bts_skeleton import FIXTURE

SHA = "a" * 40
BLOB = "b" * 40


def _identity(symbol: str, start: int = 10, end: int = 14) -> CandidateIdentity:
    return CandidateIdentity("owner/repo", SHA, "src/mod.py", BLOB, symbol, start, end)


def _na(*metrics: str, reason: str = "not_in_task") -> tuple[MetricApplicability, ...]:
    return tuple(MetricApplicability(metric, False, reason) for metric in metrics)


def _gold(**changes: object) -> BTSGold:
    seed = _identity("seed")
    values: dict[str, object] = {
        "candidate_qrels": (CandidateJudgment(seed, 2),),
        "seed_span": SeedSpan(seed),
        "required_helpers": ("helper-a", "helper-b", "helper-c"),
        "required_tests": ("tests/a.py", "tests/b.py"),
        "required_examples": ("examples/a.py", "examples/b.py"),
        "expected_adaptations": ("adapt-a", "adapt-b"),
        "expected_baseline_digest": "sha256:" + "c" * 64,
        "expected_counts": (3, 0, 1),
        "expected_outcome_vector": (("a", "pass"), ("b", "skip")),
        "expected_selected_test_ids": ("a", "b"),
        "expected_zero_failure_baseline": True,
        "expected_license": "MIT",
        "expected_probe_ids": ("probe-a", "probe-b"),
        "applicability": (),
    }
    values.update(changes)
    return BTSGold(**values)  # type: ignore[arg-type]


def _task(task_id: str = "task-one", **changes: object) -> BTSEvalTask:
    return BTSEvalTask(task_id, _gold(**changes))


def _observation(task: BTSEvalTask, **changes: object) -> BTSTaskObservation:
    seed = task.gold.seed_span.identity if task.gold.seed_span is not None else _identity("seed")
    values: dict[str, object] = {
        "task_id": task.task_id,
        "task_digest": task.digest(),
        "candidate_ranking": (seed,),
        "bts_members": (
            MemberObs("seed", seed, "include"),
            MemberObs("helper-a", _identity("helper-a", 20, 21), "include"),
            MemberObs("helper-b", _identity("helper-b", 30, 31), "include"),
        ),
        "relocated_tests": ("tests/a.py",),
        "relocated_examples": ("examples/a.py",),
        "rerun_status": "complete",
        "rerun_counts": (3, 0, 1),
        "rerun_outcome_vector": (("a", "pass"), ("b", "skip")),
        "baseline_digest": "sha256:" + "c" * 64,
        "donor_import_observed": False,
        "classified_license": "MIT",
        "adaptation_probes": (AdaptationProbeObs("adapt-a", True), AdaptationProbeObs("adapt-b", False)),
        "probe_ran_ids": ("probe-a",),
        "probe_passed": 1,
        "probe_total": 1,
    }
    values.update(changes)
    return BTSTaskObservation(**values)  # type: ignore[arg-type]


class SyntheticRunner:
    def __init__(self, changes: dict[str, dict[str, object]] | None = None) -> None:
        self.changes = changes or {}

    def run(self, task: BTSEvalTask) -> BTSTaskObservation:
        return _observation(task, **self.changes.get(task.task_id, {}))


def _metric(run: object, name: str) -> object:
    metrics = run.metrics  # type: ignore[attr-defined]
    return next(item for item in metrics if item.metric == name)


def test_hand_computed_metric_definitions() -> None:
    task = _task()
    wrong = _identity("wrong", 1, 2)
    overlap = replace(task.gold.seed_span.identity, start_line=12, end_line=16)  # type: ignore[union-attr]
    obs = _observation(
        task,
        candidate_ranking=(wrong, task.gold.seed_span.identity),  # type: ignore[union-attr]
        bts_members=(
            MemberObs("seed", overlap, "include"),
            MemberObs("helper-a", _identity("helper-a", 20, 21), "include"),
            MemberObs("helper-b", _identity("helper-b", 30, 31), "include"),
            MemberObs("invented", _identity("invented", 40, 41), "include"),
        ),
        donor_import_observed=True,
    )

    assert (grade_candidate_top1(task.gold, obs).numerator, grade_candidate_top1(task.gold, obs).denominator) == (0, 1)
    assert (grade_candidate_top3(task.gold, obs).numerator, grade_candidate_top3(task.gold, obs).score_bps) == (1, 10000)
    assert grade_seed_symbol_exact(task.gold, obs).numerator == 0
    line = grade_seed_symbol_line_overlap(task.gold, obs)
    assert (line.numerator, line.denominator, line.score_bps) == (3, 7, 4286)
    helper = grade_helper_recall(task.gold, obs)
    assert (helper.numerator, helper.denominator, helper.score_bps) == (2, 3, 6667)
    assert (grade_test_recall(task.gold, obs).numerator, grade_test_recall(task.gold, obs).denominator) == (1, 2)
    assert (grade_example_recall(task.gold, obs).numerator, grade_example_recall(task.gold, obs).denominator) == (1, 2)
    assert grade_license_accuracy(task.gold, obs).numerator == 1
    assert grade_license_accuracy(task.gold, replace(obs, classified_license="BSD")).numerator == 0
    assert grade_integration_success(task.gold, obs).numerator == 1
    assert grade_integration_success(task.gold, replace(obs, baseline_digest="bad")).numerator == 0
    assert grade_donor_import_free(task.gold, obs).numerator == 0
    missing = grade_missing_dependency_rate(task.gold, obs)
    assert (missing.numerator, missing.denominator) == (1, 3)
    hallucinated = grade_hallucinated_dependency_rate(task.gold, obs)
    assert (hallucinated.numerator, hallucinated.denominator) == (1, 4)
    adaptation = grade_adaptation_integrity(task.gold, obs)
    assert (adaptation.numerator, adaptation.denominator) == (1, 2)
    probes = grade_probe_success(task.gold, obs)
    assert (probes.numerator, probes.denominator, probes.excluded) == (1, 2, 0)


def test_candidate_top1_hit_and_empty_ranking_miss_is_not_excluded() -> None:
    task = _task()
    hit = grade_candidate_top1(task.gold, _observation(task))
    miss = grade_candidate_top1(task.gold, _observation(task, candidate_ranking=()))
    assert (hit.numerator, hit.denominator, hit.score_bps) == (1, 1, 10000)
    assert (miss.numerator, miss.denominator, miss.excluded, miss.score_bps) == (0, 1, 0, 0)


def test_micro_aggregation_sums_counts_and_ignores_not_applicable_denominator() -> None:
    first = _task("task-one")
    second = _task(
        "task-two",
        required_helpers=(),
        applicability=_na("helper_recall", "missing_dependency_rate", reason="no_helpers"),
    )
    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "micro-bench", (second, first))
    run = BTSEvalBenchmark().execute(manifest, SyntheticRunner({"task-one": {"bts_members": _observation(first).bts_members[:2]}}))

    helper = _metric(run.aggregate, "helper_recall")
    assert (helper.numerator, helper.denominator, helper.score_bps) == (1, 3, 3333)
    assert (helper.excluded, helper.exclusions[0].reason) == (1, "no_helpers")
    top = _metric(run.aggregate, "candidate_top1")
    assert (top.numerator, top.denominator) == (2, 2)


def test_runner_task_binding_mismatches_are_errors() -> None:
    task = _task()
    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "binding-bench", (task,))
    with pytest.raises(ValueError, match="task_id mismatch"):
        BTSEvalBenchmark().execute(manifest, SyntheticRunner({task.task_id: {"task_id": "other-task"}}))
    with pytest.raises(ValueError, match="task_digest mismatch"):
        BTSEvalBenchmark().execute(manifest, SyntheticRunner({task.task_id: {"task_digest": "0" * 64}}))


def test_missing_manifest_task_is_an_error_without_partial_aggregate() -> None:
    class OmittingRunner:
        def run(self, task: BTSEvalTask) -> BTSTaskObservation:
            if task.task_id == "task-two":
                raise ValueError("missing task")
            return _observation(task)

    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "missing-bench", (_task("task-one"), _task("task-two")))
    with pytest.raises(ValueError, match="missing task"):
        BTSEvalBenchmark().execute(manifest, OmittingRunner())


def test_dropping_pinned_task_changes_digest_and_aggregate_denominator() -> None:
    tasks = (_task("task-one"), _task("task-two"))
    full = BTSEvalBenchmark().execute(BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "tamper-bench", tasks), SyntheticRunner())
    dropped = BTSEvalBenchmark().execute(BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "tamper-bench", tasks[:1]), SyntheticRunner())
    assert full.digest() != dropped.digest()
    assert _metric(full.aggregate, "candidate_top1").denominator == 2
    assert _metric(dropped.aggregate, "candidate_top1").denominator == 1


def test_zero_denominator_is_none_for_not_applicable_metric() -> None:
    task = _task(required_helpers=(), applicability=_na("helper_recall", "missing_dependency_rate", reason="no_helpers"))
    record = grade_helper_recall(task.gold, _observation(task))
    assert (record.numerator, record.denominator, record.excluded, record.score_bps) == (0, 0, 1, None)


def test_manifest_validation_and_strict_round_trip() -> None:
    task = _task()
    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "round-trip", (task,))
    assert manifest_from_dict(manifest.to_dict()) == manifest
    with pytest.raises(ValueError, match="schema_version"):
        replace(manifest, schema_version="bad")
    with pytest.raises(ValueError, match="unique"):
        replace(manifest, tasks=(task, task))
    with pytest.raises(ValueError, match="kebab"):
        replace(task, task_id="BAD_ID")
    with pytest.raises(ValueError, match="duplicate identities"):
        replace(task.gold, candidate_qrels=(task.gold.candidate_qrels[0], task.gold.candidate_qrels[0]))
    with pytest.raises(ValueError, match="grade-2"):
        replace(task.gold, candidate_qrels=(CandidateJudgment(_identity("wrong"), 1),))


def test_applicability_is_fail_closed_and_preserves_reason() -> None:
    with pytest.raises(ValueError, match="helper_recall has absent gold"):
        _gold(required_helpers=())
    gold = _gold(required_helpers=(), applicability=_na("helper_recall", "missing_dependency_rate", reason="no_helper_gold"))
    task = BTSEvalTask("task-one", gold)
    record = grade_helper_recall(gold, _observation(task))
    assert record.exclusions[0].reason == "no_helper_gold"


def test_missing_dependency_rate_applicability_is_fail_closed() -> None:
    with pytest.raises(ValueError, match="missing_dependency_rate has absent gold"):
        _gold(required_helpers=(), applicability=_na("helper_recall"))


def test_adapter_projects_real_pipeline_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _prepared_request(FIXTURE)
    pipeline = TrustedCorpusPipeline()(request)
    assert isinstance(pipeline.rerun, RerunReport)
    artifact = pipeline.bts.bts
    assert artifact is not None
    seed_member = next(item for item in artifact.members if item.node == request.seed)
    seed_identity = CandidateIdentity(
        seed_member.source.slug,
        seed_member.source.commit_sha,
        seed_member.source.path,
        seed_member.source.blob_sha,
        seed_member.node.qualified_name,
        seed_member.source.start_line,
        seed_member.source.end_line,
    )
    gold = _gold(
        candidate_qrels=(CandidateJudgment(seed_identity, 2),),
        seed_span=SeedSpan(seed_identity),
        required_helpers=tuple(item.node.qualified_name for item in artifact.members if item.node != request.seed),
        required_tests=tuple(item.path for item in pipeline.relocation.files if item.role.value == "test_rewritten"),
        required_examples=(),
        expected_adaptations=(),
        expected_baseline_digest=pipeline.rerun.baseline_digest,
        expected_counts=(pipeline.rerun.counts.passed, pipeline.rerun.counts.failed, pipeline.rerun.counts.skipped),
        expected_outcome_vector=tuple((item.canonical_test_id, item.outcome.value) for item in pipeline.rerun.outcomes),
        expected_selected_test_ids=pipeline.rerun.selected_test_ids,
        expected_license=None,
        expected_probe_ids=(),
        applicability=_na("example_recall", "adaptation_integrity", "license_accuracy", "probe_success"),
    )
    task = BTSEvalTask("fixture-task", gold)
    observation = from_pipeline_result(task, (seed_identity,), pipeline)
    assert len(observation.bts_members) == len(artifact.members)
    assert observation.relocated_tests == gold.required_tests
    assert observation.rerun_counts == gold.expected_counts
    assert grade_integration_success(gold, observation).numerator == 1


def test_adapter_counts_matched_fail_probe_as_success() -> None:
    pipeline = TrustedCorpusPipeline()(_prepared_request(FIXTURE))
    matched_fail = ProbeOutcomeEvidence(
        "probe-fail",
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
        ProbeOutcome.FAIL,
        ProbeOutcome.FAIL,
        "sha256:" + "3" * 64,
        "sha256:" + "4" * 64,
    )
    outcomes = (matched_fail,)
    pipeline = replace(pipeline, probes=replace(pipeline.probes, outcomes=outcomes))
    expected_ids = tuple(item.probe_id for item in outcomes)
    task = _task(expected_probe_ids=expected_ids)

    observation = from_pipeline_result(task, (), pipeline)
    record = grade_probe_success(task.gold, observation)

    assert (record.numerator, record.denominator) == (len(expected_ids), len(expected_ids))


def test_adapter_projects_rerun_abort_as_reject() -> None:
    pipeline = TrustedCorpusPipeline()(_prepared_request(FIXTURE))
    abort = ValidationAbortEnvelope(
        "leitir-validation-abort-v1",
        "execution",
        "donor",
        BTSRejectReason.REJECT_HARD_GATE_FAILED,
        "child_crash",
        "0" * 64,
        0,
        0,
    )
    pipeline = replace(pipeline, rerun=abort)
    task = _task()

    observation = from_pipeline_result(task, (), pipeline)

    assert observation.rerun_status == "reject"
    assert observation.rerun_counts is None
    assert grade_integration_success(task.gold, observation).numerator == 0


def test_adapter_rejects_pipeline_without_bts_artifact() -> None:
    pipeline = TrustedCorpusPipeline()(_prepared_request(FIXTURE))
    pipeline = replace(pipeline, bts=replace(pipeline.bts, bts=None))

    with pytest.raises(ValueError, match="complete BTS artifact"):
        from_pipeline_result(_task(), (), pipeline)


def test_timing_envelope_is_advisory_and_digest_excludes_it() -> None:
    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "timing-bench", (_task(),))
    run = BTSEvalBenchmark().execute(manifest, SyntheticRunner())
    envelope = BTSTimingEnvelope.empty(run.digest())
    detached = replace(run, timing=None)
    attached = replace(detached, timing=envelope)
    assert detached.digest() == attached.digest()
    assert envelope.to_json() == BTSTimingEnvelope.empty(run.digest()).to_json()


def test_compute_run_with_timing_rejects_mismatched_envelope() -> None:
    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "timing-bench", (_task(),))

    with pytest.raises(ValueError, match="not bound"):
        compute_run_with_timing(manifest, SyntheticRunner(), timing_envelope=BTSTimingEnvelope.empty("0" * 64))


def test_eval_run_rejects_duplicate_task_ids() -> None:
    manifest = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "duplicate-bench", (_task(),))
    run = BTSEvalBenchmark().execute(manifest, SyntheticRunner())
    task_run = run.tasks[0]

    with pytest.raises(ValueError, match="unique task_ids"):
        BTSEvalRun(run.schema_version, run.benchmark_id, run.manifest_sha256, (task_run, task_run), run.aggregate)


def test_seed_symbol_line_overlap_no_match_uses_gold_span_denominator() -> None:
    task = _task()
    observation = _observation(
        task,
        bts_members=(MemberObs("helper-a", _identity("helper-a", 20, 21), "include"),),
    )

    record = grade_seed_symbol_line_overlap(task.gold, observation)

    assert record.numerator == 0
    assert record.denominator == 5


def test_run_is_pythonhashseed_independent() -> None:
    script = r'''
from leitir.bts_bench import *
i = CandidateIdentity("owner/repo", "a"*40, "src/a.py", "b"*40, "seed", 1, 2)
na = tuple(MetricApplicability(name, False, "not_in_task") for name in {"helper_recall", "missing_dependency_rate", "test_recall", "example_recall", "license_accuracy", "integration_success", "adaptation_integrity", "probe_success"})
g = BTSGold((CandidateJudgment(i, 2),), SeedSpan(i), (), (), (), (), None, None, None, None, False, None, (), na)
tasks = tuple(BTSEvalTask(name, g) for name in {"task-two", "task-one"})
m = BTSEvalManifest(LEITIR_BTS_EVAL_MANIFEST_V1, "seed-bench", tasks)
class R:
    def run(self, task):
        return BTSTaskObservation(task.task_id, task.digest(), (), (), (), (), "reject", None, None, None, False, None, (), (), 0, 0)
r = BTSEvalBenchmark().execute(m, R())
print(r.to_json())
print(r.digest())
print(BTSTimingEnvelope.empty(r.digest()).to_json())
'''
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src:.")
        outputs.append(subprocess.check_output((sys.executable, "-c", script), env=environment))
    assert outputs[0] == outputs[1] == outputs[2]
