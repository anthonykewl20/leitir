"""Deterministic BTS evaluation contracts, metrics, execution, and projection.

E5a defines the invocation-independent harness, explicit count-based metrics,
versioned manifest and qrels contract, canonical run artifact, advisory timing
envelope, and adapter from real BTS pipeline artifacts. Live corpus discovery,
candidate execution, and the six agent tasks remain E5b.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Protocol, cast

from leitir.bts import BTSDisposition
from leitir.bts_pipeline import BTSPipelineResult
from leitir.exec_sandbox import ValidationAbortEnvelope
from leitir.relocate import FileRole
from leitir.rerun import RerunReport
from leitir.safeio import read_regular_file

LEITIR_BTS_EVAL_MANIFEST_V1 = "leitir-bts-eval-manifest-v1"
LEITIR_BTS_EVAL_RUN_V1 = "leitir-bts-eval-run-v1"
LEITIR_BTS_TIMING_V1 = "leitir-bts-timing-v1"

_TASK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_CANDIDATE_METRICS = frozenset({"candidate_top1", "candidate_top3", "candidate_top10"})
_METRICS = (
    "adaptation_integrity",
    "candidate_top1",
    "candidate_top10",
    "candidate_top3",
    "donor_import_free",
    "example_recall",
    "hallucinated_dependency_rate",
    "helper_recall",
    "integration_success",
    "license_accuracy",
    "missing_dependency_rate",
    "probe_success",
    "seed_symbol_exact",
    "seed_symbol_line_overlap",
    "test_recall",
    "time_saved",
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _tuple(value: object, name: str, item_type: type[object] | None = None) -> None:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if item_type is not None and any(not isinstance(item, item_type) for item in value):
        raise TypeError(f"{name} contains an invalid value")


def _text(value: object, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")


def _strings(value: object, name: str, *, unique: bool = True, sorted_: bool = False) -> None:
    _tuple(value, name)
    assert isinstance(value, tuple)
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{name} must contain non-empty strings")
    if unique and len(set(value)) != len(value):
        raise ValueError(f"{name} must be unique")
    if sorted_ and value != tuple(sorted(value)):
        raise ValueError(f"{name} must be sorted")


@dataclass(frozen=True, slots=True, order=True)
class CandidateIdentity:
    """One immutable candidate symbol and its complete provenance identity."""

    slug: str
    commit_sha: str
    path: str
    blob_sha: str
    symbol: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        for name in ("slug", "path", "symbol"):
            _text(getattr(self, name), name)
        for name in ("commit_sha", "blob_sha"):
            value = getattr(self, name)
            if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
                raise ValueError(f"{name} must be a 40-64 char lowercase git hex string")
        if isinstance(self.start_line, bool) or not isinstance(self.start_line, int) or self.start_line < 1:
            raise ValueError("start_line must be a positive integer")
        if isinstance(self.end_line, bool) or not isinstance(self.end_line, int) or self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")

    @property
    def sort_key(self) -> tuple[str, str, str, str, str, int, int]:
        return (self.slug, self.commit_sha, self.path, self.blob_sha, self.symbol, self.start_line, self.end_line)

    def to_dict(self) -> dict[str, object]:
        return {
            "blob_sha": self.blob_sha,
            "commit_sha": self.commit_sha,
            "end_line": self.end_line,
            "path": self.path,
            "slug": self.slug,
            "start_line": self.start_line,
            "symbol": self.symbol,
        }

    @classmethod
    def from_dict(cls, raw: object) -> CandidateIdentity:
        value = _mapping(raw, "candidate identity")
        _exact(value, {"slug", "commit_sha", "path", "blob_sha", "symbol", "start_line", "end_line"}, "candidate identity")
        return cls(
            slug=_str(value["slug"], "slug"),
            commit_sha=_str(value["commit_sha"], "commit_sha"),
            path=_str(value["path"], "path"),
            blob_sha=_str(value["blob_sha"], "blob_sha"),
            symbol=_str(value["symbol"], "symbol"),
            start_line=_int(value["start_line"], "start_line"),
            end_line=_int(value["end_line"], "end_line"),
        )


@dataclass(frozen=True, slots=True)
class CandidateJudgment:
    identity: CandidateIdentity
    grade: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, CandidateIdentity):
            raise TypeError("identity must be a CandidateIdentity")
        if isinstance(self.grade, bool) or self.grade not in {0, 1, 2}:
            raise ValueError("grade must be 0, 1, or 2")

    def to_dict(self) -> dict[str, object]:
        return {"grade": self.grade, "identity": self.identity.to_dict()}


@dataclass(frozen=True, slots=True)
class SeedSpan:
    identity: CandidateIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.identity, CandidateIdentity):
            raise TypeError("identity must be a CandidateIdentity")

    def to_dict(self) -> dict[str, object]:
        return {"identity": self.identity.to_dict()}


@dataclass(frozen=True, slots=True)
class MetricApplicability:
    metric: str
    applicable: bool
    not_applicable_reason: str | None

    def __post_init__(self) -> None:
        if self.metric not in _METRICS:
            raise ValueError("applicability metric is unknown")
        if not isinstance(self.applicable, bool):
            raise TypeError("applicable must be bool")
        if self.applicable:
            if self.not_applicable_reason is not None:
                raise ValueError("applicable metrics cannot have a not-applicable reason")
        else:
            _text(self.not_applicable_reason, "not_applicable_reason")

    def to_dict(self) -> dict[str, object]:
        return {"applicable": self.applicable, "metric": self.metric, "not_applicable_reason": self.not_applicable_reason}


@dataclass(frozen=True, slots=True)
class BTSGold:
    """Pinned qrels and expected evidence for every applicable BTS metric."""

    candidate_qrels: tuple[CandidateJudgment, ...]
    seed_span: SeedSpan | None
    required_helpers: tuple[str, ...]
    required_tests: tuple[str, ...]
    required_examples: tuple[str, ...]
    expected_adaptations: tuple[str, ...]
    expected_baseline_digest: str | None
    expected_counts: tuple[int, int, int] | None
    expected_outcome_vector: tuple[tuple[str, str], ...] | None
    expected_selected_test_ids: tuple[str, ...] | None
    expected_zero_failure_baseline: bool
    expected_license: str | None
    expected_probe_ids: tuple[str, ...]
    applicability: tuple[MetricApplicability, ...]

    def __post_init__(self) -> None:
        _tuple(self.candidate_qrels, "candidate_qrels", CandidateJudgment)
        identities = tuple(item.identity for item in self.candidate_qrels)
        if len(set(identities)) != len(identities):
            raise ValueError("candidate_qrels contains duplicate identities")
        if self.seed_span is not None and not isinstance(self.seed_span, SeedSpan):
            raise TypeError("seed_span must be SeedSpan or None")
        for name in ("required_helpers", "required_tests", "required_examples", "expected_adaptations", "expected_probe_ids"):
            _strings(getattr(self, name), name)
        if self.expected_baseline_digest is not None and not isinstance(self.expected_baseline_digest, str):
            raise TypeError("expected_baseline_digest must be text or None")
        if self.expected_counts is not None:
            _counts(self.expected_counts, "expected_counts")
        if self.expected_outcome_vector is not None:
            _pairs(self.expected_outcome_vector, "expected_outcome_vector", sorted_=True)
        if self.expected_selected_test_ids is not None:
            _strings(self.expected_selected_test_ids, "expected_selected_test_ids")
        if not isinstance(self.expected_zero_failure_baseline, bool):
            raise TypeError("expected_zero_failure_baseline must be bool")
        if self.expected_license is not None:
            _text(self.expected_license, "expected_license")
        _tuple(self.applicability, "applicability", MetricApplicability)
        names = tuple(item.metric for item in self.applicability)
        if len(set(names)) != len(names):
            raise ValueError("applicability metric names must be unique")
        applicability = {item.metric: item for item in self.applicability}
        candidate_applies = any(_declared_applicable(applicability, name, bool(self.candidate_qrels)) for name in _CANDIDATE_METRICS)
        if candidate_applies and not any(item.grade == 2 for item in self.candidate_qrels):
            raise ValueError("applicable candidate metrics require at least one grade-2 qrel")
        requirements = {
            "seed_symbol_exact": self.seed_span is not None,
            "seed_symbol_line_overlap": self.seed_span is not None,
            "helper_recall": bool(self.required_helpers),
            "missing_dependency_rate": bool(self.required_helpers),
            "test_recall": bool(self.required_tests),
            "example_recall": bool(self.required_examples),
            "license_accuracy": self.expected_license is not None,
            "integration_success": self.expected_counts is not None,
            "adaptation_integrity": bool(self.expected_adaptations),
            "probe_success": bool(self.expected_probe_ids),
        }
        for metric, present in requirements.items():
            entry = applicability.get(metric)
            if not present and (entry is None or entry.applicable):
                raise ValueError(f"{metric} has absent gold and must be declared not-applicable")
            if present and entry is not None and not entry.applicable:
                raise ValueError(f"{metric} has gold but is declared not-applicable")
        for metric in _CANDIDATE_METRICS:
            entry = applicability.get(metric)
            if not self.candidate_qrels and (entry is None or entry.applicable):
                raise ValueError(f"{metric} has absent gold and must be declared not-applicable")

    def to_dict(self) -> dict[str, object]:
        return {
            "applicability": [item.to_dict() for item in sorted(self.applicability, key=lambda item: item.metric)],
            "candidate_qrels": [item.to_dict() for item in sorted(self.candidate_qrels, key=lambda item: item.identity.sort_key)],
            "expected_adaptations": sorted(self.expected_adaptations),
            "expected_baseline_digest": self.expected_baseline_digest,
            "expected_counts": None if self.expected_counts is None else list(self.expected_counts),
            "expected_license": self.expected_license,
            "expected_outcome_vector": None if self.expected_outcome_vector is None else [list(item) for item in self.expected_outcome_vector],
            "expected_probe_ids": sorted(self.expected_probe_ids),
            "expected_selected_test_ids": None if self.expected_selected_test_ids is None else sorted(self.expected_selected_test_ids),
            "expected_zero_failure_baseline": self.expected_zero_failure_baseline,
            "required_examples": sorted(self.required_examples),
            "required_helpers": sorted(self.required_helpers),
            "required_tests": sorted(self.required_tests),
            "seed_span": None if self.seed_span is None else self.seed_span.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class TaskObservationPlan:
    """Non-gold inputs that may influence a task observation.

    Gold remains exclusively a grading oracle.  This plan contains the pinned
    candidates, execution seeds, contract sidecars, and capability identifiers
    available to the runner before grading starts.
    """

    candidates: tuple[CandidateIdentity, ...]
    execution_candidates: tuple[CandidateIdentity, ...]
    seed: CandidateIdentity
    contract_tests: tuple[str, ...]
    required_behaviors: tuple[str, ...]

    def __post_init__(self) -> None:
        _tuple(self.candidates, "observation candidates", CandidateIdentity)
        _tuple(self.execution_candidates, "observation execution candidates", CandidateIdentity)
        _strings(self.contract_tests, "observation contract tests", sorted_=True)
        _strings(self.required_behaviors, "observation required behaviors", sorted_=True)
        if not self.candidates or not self.execution_candidates or not isinstance(self.seed, CandidateIdentity):
            raise ValueError("observation plan requires candidates and a seed")
        if len(set(self.candidates)) != len(self.candidates) or tuple(sorted(self.candidates, key=lambda item: item.sort_key)) != self.candidates:
            raise ValueError("observation candidates must be sorted and unique")
        if len(set(self.execution_candidates)) != len(self.execution_candidates) or tuple(sorted(self.execution_candidates, key=lambda item: item.sort_key)) != self.execution_candidates:
            raise ValueError("observation execution candidates must be sorted and unique")
        if self.seed not in self.candidates or self.seed not in self.execution_candidates:
            raise ValueError("observation seed must be an execution candidate")
        if not set(self.execution_candidates) <= set(self.candidates):
            raise ValueError("execution candidates must be in the candidate set")
        if not self.contract_tests or not self.required_behaviors:
            raise ValueError("observation plan requires contract tests and behaviors")

    def to_dict(self) -> dict[str, object]:
        return {
            "candidates": [item.to_dict() for item in self.candidates],
            "contract_tests": list(self.contract_tests),
            "execution_candidates": [item.to_dict() for item in self.execution_candidates],
            "required_behaviors": list(self.required_behaviors),
            "seed": self.seed.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class BTSEvalTask:
    task_id: str
    gold: BTSGold
    observation: TaskObservationPlan | None = field(default=None, compare=False)
    observation_serialized: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or _TASK_ID.fullmatch(self.task_id) is None:
            raise ValueError("task_id must be lowercase kebab-case")
        if not isinstance(self.gold, BTSGold):
            raise TypeError("gold must be BTSGold")
        if self.observation is not None and not isinstance(self.observation, TaskObservationPlan):
            raise TypeError("observation must be TaskObservationPlan or None")
        if not isinstance(self.observation_serialized, bool):
            raise TypeError("observation_serialized must be bool")

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"gold": self.gold.to_dict(), "task_id": self.task_id}
        if self.observation is not None and self.observation_serialized:
            result["observation"] = self.observation.to_dict()
        return result

    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class BTSEvalManifest:
    schema_version: str
    benchmark_id: str
    tasks: tuple[BTSEvalTask, ...]

    def __post_init__(self) -> None:
        if self.schema_version != LEITIR_BTS_EVAL_MANIFEST_V1:
            raise ValueError(f"schema_version must be {LEITIR_BTS_EVAL_MANIFEST_V1!r}")
        if not isinstance(self.benchmark_id, str) or _TASK_ID.fullmatch(self.benchmark_id) is None:
            raise ValueError("benchmark_id must be lowercase kebab-case")
        _tuple(self.tasks, "tasks", BTSEvalTask)
        ids = tuple(task.task_id for task in self.tasks)
        if len(set(ids)) != len(ids):
            raise ValueError("benchmark task IDs must be unique")

    def to_dict(self) -> dict[str, object]:
        return {"benchmark_id": self.benchmark_id, "schema_version": self.schema_version, "tasks": [task.to_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)]}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MemberObs:
    node: str
    identity: CandidateIdentity
    disposition: str

    def __post_init__(self) -> None:
        _text(self.node, "node")
        if not isinstance(self.identity, CandidateIdentity):
            raise TypeError("identity must be CandidateIdentity")
        if self.disposition not in {item.value for item in BTSDisposition}:
            raise ValueError("disposition must be a BTSDisposition value")

    def to_dict(self) -> dict[str, object]:
        return {"disposition": self.disposition, "identity": self.identity.to_dict(), "node": self.node}


@dataclass(frozen=True, slots=True)
class AdaptationProbeObs:
    node: str
    passed: bool

    def __post_init__(self) -> None:
        _text(self.node, "node")
        if not isinstance(self.passed, bool):
            raise TypeError("passed must be bool")

    def to_dict(self) -> dict[str, object]:
        return {"node": self.node, "passed": self.passed}


@dataclass(frozen=True, slots=True)
class BTSTaskObservation:
    task_id: str
    task_digest: str
    candidate_ranking: tuple[CandidateIdentity, ...]
    bts_members: tuple[MemberObs, ...]
    relocated_tests: tuple[str, ...]
    relocated_examples: tuple[str, ...]
    rerun_status: str
    rerun_counts: tuple[int, int, int] | None
    rerun_outcome_vector: tuple[tuple[str, str], ...] | None
    baseline_digest: str | None
    donor_import_observed: bool
    classified_license: str | None
    adaptation_probes: tuple[AdaptationProbeObs, ...]
    probe_ran_ids: tuple[str, ...]
    probe_passed: int
    probe_total: int
    ranking_unranked: bool = False
    composition_mode: str = "single-recipient-run"

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or _TASK_ID.fullmatch(self.task_id) is None:
            raise ValueError("task_id must be lowercase kebab-case")
        if not isinstance(self.task_digest, str) or _SHA256.fullmatch(self.task_digest) is None:
            raise ValueError("task_digest must be a 64-char sha256 hex string")
        _tuple(self.candidate_ranking, "candidate_ranking", CandidateIdentity)
        if len(set(self.candidate_ranking)) != len(self.candidate_ranking):
            raise ValueError("candidate_ranking contains duplicate identities")
        if not isinstance(self.ranking_unranked, bool):
            raise TypeError("ranking_unranked must be bool")
        if self.composition_mode not in {"single-recipient-run", "coexisting-recipient-three-runs"}:
            raise ValueError("composition_mode is unsupported")
        _tuple(self.bts_members, "bts_members", MemberObs)
        if len({item.node for item in self.bts_members}) != len(self.bts_members):
            raise ValueError("bts_members contains duplicate nodes")
        _strings(self.relocated_tests, "relocated_tests")
        _strings(self.relocated_examples, "relocated_examples")
        if self.rerun_status not in {"complete", "reject", "abort"}:
            raise ValueError("rerun_status must be complete, reject, or abort")
        if self.rerun_counts is not None:
            _counts(self.rerun_counts, "rerun_counts")
        if self.rerun_outcome_vector is not None:
            _pairs(self.rerun_outcome_vector, "rerun_outcome_vector", sorted_=True)
        if self.baseline_digest is not None and not isinstance(self.baseline_digest, str):
            raise TypeError("baseline_digest must be text or None")
        if not isinstance(self.donor_import_observed, bool):
            raise TypeError("donor_import_observed must be bool")
        if self.classified_license is not None:
            _text(self.classified_license, "classified_license")
        _tuple(self.adaptation_probes, "adaptation_probes", AdaptationProbeObs)
        if len({item.node for item in self.adaptation_probes}) != len(self.adaptation_probes):
            raise ValueError("adaptation_probes contains duplicate nodes")
        _strings(self.probe_ran_ids, "probe_ran_ids")
        for name in ("probe_passed", "probe_total"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.probe_passed > self.probe_total or self.probe_total != len(self.probe_ran_ids):
            raise ValueError("probe counts must match probe_ran_ids")

    def to_dict(self) -> dict[str, object]:
        return {
            "adaptation_probes": [item.to_dict() for item in sorted(self.adaptation_probes, key=lambda item: item.node)],
            "baseline_digest": self.baseline_digest,
            "bts_members": [item.to_dict() for item in sorted(self.bts_members, key=lambda item: item.node)],
            "candidate_ranking": [item.to_dict() for item in self.candidate_ranking],
            "ranking_unranked": self.ranking_unranked,
            "classified_license": self.classified_license,
            "composition_mode": self.composition_mode,
            "donor_import_observed": self.donor_import_observed,
            "probe_passed": self.probe_passed,
            "probe_ran_ids": sorted(self.probe_ran_ids),
            "probe_total": self.probe_total,
            "relocated_examples": sorted(self.relocated_examples),
            "relocated_tests": sorted(self.relocated_tests),
            "rerun_counts": None if self.rerun_counts is None else list(self.rerun_counts),
            "rerun_outcome_vector": None if self.rerun_outcome_vector is None else [list(item) for item in self.rerun_outcome_vector],
            "rerun_status": self.rerun_status,
            "task_digest": self.task_digest,
            "task_id": self.task_id,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())


class BTSRunner(Protocol):
    def run(self, task: BTSEvalTask) -> BTSTaskObservation: ...


@dataclass(frozen=True, slots=True, order=True)
class Exclusion:
    reason: str
    count: int

    def __post_init__(self) -> None:
        _text(self.reason, "reason")
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 1:
            raise ValueError("exclusion count must be a positive integer")

    def to_dict(self) -> dict[str, object]:
        return {"count": self.count, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class MetricRecord:
    metric: str
    numerator: int
    denominator: int
    excluded: int
    exclusions: tuple[Exclusion, ...]
    score_bps: int | None
    diagnostic: bool

    def __post_init__(self) -> None:
        if self.metric not in _METRICS:
            raise ValueError("unknown metric")
        for name in ("numerator", "denominator", "excluded"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.numerator > self.denominator:
            raise ValueError("numerator cannot exceed denominator")
        _tuple(self.exclusions, "exclusions", Exclusion)
        if self.exclusions != tuple(sorted(self.exclusions, key=lambda item: item.reason)):
            raise ValueError("exclusions must be sorted by reason")
        if len({item.reason for item in self.exclusions}) != len(self.exclusions):
            raise ValueError("exclusion reasons must be unique")
        if sum(item.count for item in self.exclusions) != self.excluded:
            raise ValueError("excluded must equal the exclusion counts")
        expected = _score(self.numerator, self.denominator)
        if self.score_bps != expected:
            raise ValueError("score_bps does not match numerator and denominator")
        if not isinstance(self.diagnostic, bool):
            raise TypeError("diagnostic must be bool")

    def to_dict(self) -> dict[str, object]:
        return {"denominator": self.denominator, "diagnostic": self.diagnostic, "excluded": self.excluded, "exclusions": [item.to_dict() for item in self.exclusions], "metric": self.metric, "numerator": self.numerator, "score_bps": self.score_bps}


@dataclass(frozen=True, slots=True)
class BTSEvalTaskRun:
    task_id: str
    task_digest: str
    metrics: tuple[MetricRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or _TASK_ID.fullmatch(self.task_id) is None:
            raise ValueError("task_id must be lowercase kebab-case")
        if not isinstance(self.task_digest, str) or _SHA256.fullmatch(self.task_digest) is None:
            raise ValueError("task_digest must be sha256 hex")
        _tuple(self.metrics, "metrics", MetricRecord)
        if self.metrics != tuple(sorted(self.metrics, key=lambda item: item.metric)):
            raise ValueError("metrics must be sorted by metric name")
        if len({item.metric for item in self.metrics}) != len(self.metrics):
            raise ValueError("metric names must be unique")

    def to_dict(self) -> dict[str, object]:
        return {"metrics": [item.to_dict() for item in self.metrics], "task_digest": self.task_digest, "task_id": self.task_id}


@dataclass(frozen=True, slots=True)
class BTSAggregate:
    metrics: tuple[MetricRecord, ...]

    def __post_init__(self) -> None:
        _tuple(self.metrics, "metrics", MetricRecord)
        if self.metrics != tuple(sorted(self.metrics, key=lambda item: item.metric)):
            raise ValueError("aggregate metrics must be sorted")

    def to_dict(self) -> dict[str, object]:
        return {"metrics": [item.to_dict() for item in self.metrics]}


@dataclass(frozen=True, slots=True)
class BTSTimingEnvelope:
    schema_version: str
    run_digest: str
    pipeline_samples_ns: tuple[int, ...]
    ordinary_search_samples_ns: tuple[int, ...]
    runner_fingerprint: str
    note: str

    def __post_init__(self) -> None:
        if self.schema_version != LEITIR_BTS_TIMING_V1:
            raise ValueError("unsupported timing schema")
        if not isinstance(self.run_digest, str) or _SHA256.fullmatch(self.run_digest) is None:
            raise ValueError("run_digest must be sha256 hex")
        for name in ("pipeline_samples_ns", "ordinary_search_samples_ns"):
            values = getattr(self, name)
            _tuple(values, name)
            if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in values):
                raise ValueError(f"{name} must contain non-negative integers")
        _text(self.runner_fingerprint, "runner_fingerprint")
        _text(self.note, "note")

    @classmethod
    def empty(cls, run_digest: str, fingerprint: str = "offline-synthetic", note: str = "no timing samples collected offline; live comparison deferred to E5b") -> BTSTimingEnvelope:
        return cls(LEITIR_BTS_TIMING_V1, run_digest, (), (), fingerprint, note)

    def to_dict(self) -> dict[str, object]:
        return {"note": self.note, "ordinary_search_samples_ns": list(self.ordinary_search_samples_ns), "pipeline_samples_ns": list(self.pipeline_samples_ns), "run_digest": self.run_digest, "runner_fingerprint": self.runner_fingerprint, "schema_version": self.schema_version}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class BTSEvalRun:
    schema_version: str
    benchmark_id: str
    manifest_sha256: str
    tasks: tuple[BTSEvalTaskRun, ...]
    aggregate: BTSAggregate
    timing: BTSTimingEnvelope | None = None

    def __post_init__(self) -> None:
        if self.schema_version != LEITIR_BTS_EVAL_RUN_V1:
            raise ValueError("unsupported BTS evaluation run schema")
        if not isinstance(self.benchmark_id, str) or _TASK_ID.fullmatch(self.benchmark_id) is None:
            raise ValueError("benchmark_id must be lowercase kebab-case")
        if not isinstance(self.manifest_sha256, str) or _SHA256.fullmatch(self.manifest_sha256) is None:
            raise ValueError("manifest_sha256 must be sha256 hex")
        _tuple(self.tasks, "tasks", BTSEvalTaskRun)
        if self.tasks != tuple(sorted(self.tasks, key=lambda item: item.task_id)):
            raise ValueError("run tasks must be sorted")
        ids = [item.task_id for item in self.tasks]
        if len(set(ids)) != len(ids):
            raise ValueError("run tasks must have unique task_ids")
        if not isinstance(self.aggregate, BTSAggregate):
            raise TypeError("aggregate must be BTSAggregate")
        if self.timing is not None and not isinstance(self.timing, BTSTimingEnvelope):
            raise TypeError("timing must be BTSTimingEnvelope or None")
        if self.timing is not None and self.timing.run_digest != self.digest():
            raise ValueError("timing envelope run_digest mismatch")

    def _graded_dict(self) -> dict[str, object]:
        return {"aggregate": self.aggregate.to_dict(), "benchmark_id": self.benchmark_id, "manifest_sha256": self.manifest_sha256, "schema_version": self.schema_version, "tasks": [item.to_dict() for item in self.tasks]}

    def to_dict(self) -> dict[str, object]:
        return {**self._graded_dict(), "timing": None if self.timing is None else self.timing.to_dict()}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return _digest(self._graded_dict())


def _score(numerator: int, denominator: int) -> int | None:
    if denominator == 0:
        return None
    return int((Decimal(10000) * Decimal(numerator) / Decimal(denominator)).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def _record(metric: str, numerator: int, denominator: int, *, diagnostic: bool = False) -> MetricRecord:
    return MetricRecord(metric, numerator, denominator, 0, (), _score(numerator, denominator), diagnostic)


def _excluded(metric: str, reason: str, *, diagnostic: bool = False) -> MetricRecord:
    return MetricRecord(metric, 0, 0, 1, (Exclusion(reason, 1),), None, diagnostic)


def _applicability(gold: BTSGold, metric: str, default: bool) -> tuple[bool, str | None]:
    entry = next((item for item in gold.applicability if item.metric == metric), None)
    if entry is None:
        return default, None
    return entry.applicable, entry.not_applicable_reason


def _require_applicable(gold: BTSGold, metric: str, present: bool, *, diagnostic: bool = False) -> MetricRecord | None:
    applicable, reason = _applicability(gold, metric, present)
    if not applicable:
        if reason is None:
            raise ValueError(f"{metric} is not applicable without a not_applicable_reason")
        return _excluded(metric, reason, diagnostic=diagnostic)
    if not present:
        raise ValueError(f"{metric} requires gold that is absent")
    return None


def _grade_candidate(gold: BTSGold, obs: BTSTaskObservation, metric: str, k: int) -> MetricRecord:
    excluded = _require_applicable(gold, metric, bool(gold.candidate_qrels))
    if excluded is not None:
        return excluded
    if obs.ranking_unranked:
        return _excluded(metric, "unranked_no_comparison_evidence")
    exact = {item.identity for item in gold.candidate_qrels if item.grade == 2}
    return _record(metric, int(any(item in exact for item in obs.candidate_ranking[:k])), 1)


def grade_candidate_top1(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _grade_candidate(gold, obs, "candidate_top1", 1)


def grade_candidate_top3(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _grade_candidate(gold, obs, "candidate_top3", 3)


def grade_candidate_top10(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _grade_candidate(gold, obs, "candidate_top10", 10)


def grade_seed_symbol_exact(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "seed_symbol_exact", gold.seed_span is not None)
    if excluded is not None:
        return excluded
    assert gold.seed_span is not None
    return _record("seed_symbol_exact", int(any(item.identity == gold.seed_span.identity for item in obs.bts_members)), 1)


def grade_seed_symbol_line_overlap(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "seed_symbol_line_overlap", gold.seed_span is not None, diagnostic=True)
    if excluded is not None:
        return excluded
    assert gold.seed_span is not None
    identity = gold.seed_span.identity
    matches = [
        item.identity
        for item in obs.bts_members
        if item.identity.slug == identity.slug
        and item.identity.commit_sha == identity.commit_sha
        and item.identity.path == identity.path
        and item.identity.blob_sha == identity.blob_sha
        and item.identity.symbol == identity.symbol
    ]
    if not matches:
        return _record("seed_symbol_line_overlap", 0, identity.end_line - identity.start_line + 1, diagnostic=True)
    observed = min(matches, key=lambda item: item.sort_key)
    overlap = max(0, min(identity.end_line, observed.end_line) - max(identity.start_line, observed.start_line) + 1)
    union = max(identity.end_line, observed.end_line) - min(identity.start_line, observed.start_line) + 1
    return _record("seed_symbol_line_overlap", overlap, union, diagnostic=True)


def _recall(gold: BTSGold, obs: BTSTaskObservation, metric: str, required: tuple[str, ...], observed: set[str]) -> MetricRecord:
    excluded = _require_applicable(gold, metric, bool(required))
    if excluded is not None:
        return excluded
    return _record(metric, len(set(required) & observed), len(required))


def grade_helper_recall(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _recall(gold, obs, "helper_recall", gold.required_helpers, {item.node for item in obs.bts_members})


def grade_test_recall(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _recall(gold, obs, "test_recall", gold.required_tests, set(obs.relocated_tests))


def grade_example_recall(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _recall(gold, obs, "example_recall", gold.required_examples, set(obs.relocated_examples))


def grade_license_accuracy(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "license_accuracy", gold.expected_license is not None)
    if excluded is not None:
        return excluded
    return _record("license_accuracy", int(obs.classified_license == gold.expected_license), 1)


def grade_integration_success(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "integration_success", gold.expected_counts is not None)
    if excluded is not None:
        return excluded
    selected = None if obs.rerun_outcome_vector is None else tuple(item[0] for item in obs.rerun_outcome_vector)
    success = (
        obs.rerun_status.lower() == "complete"
        and obs.baseline_digest == gold.expected_baseline_digest
        and obs.rerun_counts == gold.expected_counts
        and (gold.expected_outcome_vector is None or obs.rerun_outcome_vector == gold.expected_outcome_vector)
        and (gold.expected_selected_test_ids is None or selected == gold.expected_selected_test_ids)
        and (not gold.expected_zero_failure_baseline or (obs.rerun_counts is not None and obs.rerun_counts[1] == 0))
    )
    return _record("integration_success", int(success), 1)


def grade_donor_import_free(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _record("donor_import_free", int(not obs.donor_import_observed), 1)


def grade_missing_dependency_rate(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "missing_dependency_rate", bool(gold.required_helpers), diagnostic=True)
    if excluded is not None:
        return excluded
    observed = {item.node for item in obs.bts_members}
    return _record("missing_dependency_rate", len(set(gold.required_helpers) - observed), len(gold.required_helpers), diagnostic=True)


def grade_hallucinated_dependency_rate(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    applicable, reason = _applicability(gold, "hallucinated_dependency_rate", True)
    if not applicable:
        if reason is None:
            raise ValueError("hallucinated_dependency_rate is not applicable without a not_applicable_reason")
        return _excluded("hallucinated_dependency_rate", reason, diagnostic=True)
    seed_symbol = None if gold.seed_span is None else gold.seed_span.identity.symbol
    justified = set(gold.required_helpers)
    hallucinated = [item for item in obs.bts_members if item.node not in justified and item.identity.symbol != seed_symbol and not _external_member(item)]
    return _record("hallucinated_dependency_rate", len(hallucinated), len(obs.bts_members), diagnostic=True)


def grade_adaptation_integrity(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "adaptation_integrity", bool(gold.expected_adaptations))
    if excluded is not None:
        return excluded
    passing = {item.node for item in obs.adaptation_probes if item.passed}
    return _record("adaptation_integrity", len(set(gold.expected_adaptations) & passing), len(gold.expected_adaptations))


def grade_probe_success(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    excluded = _require_applicable(gold, "probe_success", bool(gold.expected_probe_ids))
    if excluded is not None:
        return excluded
    ran = len(set(gold.expected_probe_ids) & set(obs.probe_ran_ids))
    return _record("probe_success", min(ran, obs.probe_passed), len(gold.expected_probe_ids))


def grade_time_saved(gold: BTSGold, obs: BTSTaskObservation) -> MetricRecord:
    return _excluded("time_saved", "advisory_timing_in_envelope", diagnostic=True)


def grade_task(gold: BTSGold, obs: BTSTaskObservation) -> tuple[MetricRecord, ...]:
    graders = (
        grade_adaptation_integrity,
        grade_candidate_top1,
        grade_candidate_top10,
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
        grade_time_saved,
    )
    return tuple(sorted((grader(gold, obs) for grader in graders), key=lambda item: item.metric))


def aggregate_task_runs(tasks: tuple[BTSEvalTaskRun, ...]) -> BTSAggregate:
    records: list[MetricRecord] = []
    for metric in _METRICS:
        selected = [record for task in tasks for record in task.metrics if record.metric == metric]
        reasons: dict[str, int] = {}
        for record in selected:
            for exclusion in record.exclusions:
                reasons[exclusion.reason] = reasons.get(exclusion.reason, 0) + exclusion.count
        numerator = sum(item.numerator for item in selected)
        denominator = sum(item.denominator for item in selected)
        exclusions = tuple(Exclusion(reason, reasons[reason]) for reason in sorted(reasons))
        records.append(MetricRecord(metric, numerator, denominator, sum(item.excluded for item in selected), exclusions, _score(numerator, denominator), any(item.diagnostic for item in selected)))
    return BTSAggregate(tuple(sorted(records, key=lambda item: item.metric)))


class BTSEvalBenchmark:
    """Execute and micro-aggregate all pinned tasks without partial output."""

    def __init__(self) -> None:
        pass

    def execute(self, manifest: BTSEvalManifest, runner: BTSRunner) -> BTSEvalRun:
        if not isinstance(manifest, BTSEvalManifest):
            raise TypeError("manifest must be BTSEvalManifest")
        if not callable(getattr(runner, "run", None)):
            raise TypeError("runner must provide a callable run method")
        runs: list[BTSEvalTaskRun] = []
        observed_ids: list[str] = []
        for task in sorted(manifest.tasks, key=lambda item: item.task_id):
            observation = runner.run(task)
            if not isinstance(observation, BTSTaskObservation):
                raise TypeError("runner must return BTSTaskObservation")
            observed_ids.append(observation.task_id)
            if observation.task_id != task.task_id:
                raise ValueError(f"observation task_id mismatch for {task.task_id}")
            if observation.task_digest != task.digest():
                raise ValueError(f"observation task_digest mismatch for {task.task_id}")
            runs.append(BTSEvalTaskRun(task.task_id, task.digest(), grade_task(task.gold, observation)))
        if set(observed_ids) != {task.task_id for task in manifest.tasks} or len(observed_ids) != len(manifest.tasks):
            raise ValueError("observed task IDs must exactly equal manifest task IDs")
        task_runs = tuple(runs)
        base = BTSEvalRun(LEITIR_BTS_EVAL_RUN_V1, manifest.benchmark_id, manifest.digest(), task_runs, aggregate_task_runs(task_runs))
        return replace(base, timing=BTSTimingEnvelope.empty(base.digest()))


def compute_run_with_timing(manifest: BTSEvalManifest, runner: BTSRunner, *, timing_envelope: BTSTimingEnvelope | None = None) -> BTSEvalRun:
    run = BTSEvalBenchmark().execute(manifest, runner)
    envelope = timing_envelope or BTSTimingEnvelope.empty(run.digest())
    if envelope.run_digest != run.digest():
        raise ValueError("timing envelope is not bound to the graded run")
    return replace(run, timing=envelope)


def _normalize_staging_test_path(path: str) -> str:
    """Drop only the E1 rewritten-test transport prefix."""

    return path.removeprefix("staging-v1/tests/rewritten/")


def from_pipeline_result(
    task: BTSEvalTask,
    candidate_ranking: tuple[CandidateIdentity, ...],
    pipeline: BTSPipelineResult,
    *,
    task_digest: str | None = None,
    classified_license: str | None = None,
    relocated_examples: tuple[str, ...] = (),
    donor_import_observed: bool = False,
    adaptation_probes: tuple[AdaptationProbeObs, ...] = (),
    ranking_unranked: bool = False,
    normalize_staging_test_paths: bool = False,
) -> BTSTaskObservation:
    """Project authoritative pipeline artifacts onto the gradable E5a surface."""

    if not isinstance(task, BTSEvalTask) or not isinstance(pipeline, BTSPipelineResult):
        raise TypeError("task and pipeline must be their typed contracts")
    artifact = pipeline.bts.bts
    if artifact is None:
        raise ValueError("pipeline must contain a complete BTS artifact")
    members = tuple(
        MemberObs(
            node=member.node.qualified_name,
            identity=CandidateIdentity(
                slug=member.source.slug,
                commit_sha=member.source.commit_sha,
                path=member.source.path,
                blob_sha=member.source.blob_sha,
                symbol=member.node.qualified_name,
                start_line=member.source.start_line,
                end_line=member.source.end_line,
            ),
            disposition=member.disposition.value,
        )
        for member in artifact.members
    )
    # E1 staging paths are transport details. Relocation already preserves the
    # corpus-owned ``contract_tests/`` prefix, so remove only E1's prefix.
    tests = tuple(sorted(
        (_normalize_staging_test_path(item.path) if normalize_staging_test_paths else item.path)
        for item in pipeline.relocation.files
        if item.role is FileRole.TEST_REWRITTEN
    ))
    if isinstance(pipeline.rerun, RerunReport):
        rerun_status = pipeline.rerun.status.value
        rerun_counts = (pipeline.rerun.counts.passed, pipeline.rerun.counts.failed, pipeline.rerun.counts.skipped)
        outcome_vector = tuple(sorted((item.canonical_test_id, item.outcome.value) for item in pipeline.rerun.outcomes))
        baseline_digest = pipeline.rerun.baseline_digest
        donor_import_observed = pipeline.rerun.reason is not None and pipeline.rerun.reason.value == "reject_donor_import_observed"
    elif isinstance(pipeline.rerun, ValidationAbortEnvelope):
        rerun_status = "reject"
        rerun_counts = None
        outcome_vector = None
        baseline_digest = None
        donor_import_observed = False
    else:
        raise TypeError("pipeline rerun has an unsupported type")
    outcomes = tuple(sorted(pipeline.probes.outcomes, key=lambda item: item.probe_id))
    return BTSTaskObservation(
        task.task_id,
        task.digest() if task_digest is None else task_digest,
        candidate_ranking,
        members,
        tests,
        relocated_examples,
        rerun_status,
        rerun_counts,
        outcome_vector,
        baseline_digest,
        donor_import_observed,
        classified_license,
        adaptation_probes,
        tuple(item.probe_id for item in outcomes),
        sum(item.observed_outcome is item.expected_outcome for item in outcomes),
        len(outcomes),
        ranking_unranked,
    )


def coexisting_recipient_three_runs_observation(
    task: BTSEvalTask,
    candidate_ranking: tuple[CandidateIdentity, ...],
    runs: tuple[tuple[CandidateIdentity, BTSPipelineResult], ...],
    *,
    task_digest: str | None = None,
    classified_license: str | None = None,
    relocated_examples: tuple[str, ...] = (),
    adaptation_probes: tuple[AdaptationProbeObs, ...] = (),
    ranking_unranked: bool = False,
) -> BTSTaskObservation:
    """Project three explicit contained reruns without claiming one merged rerun.

    ``Relocation.publish`` intentionally accepts only an empty recipient, so its
    public contract cannot construct a merged relocation tree.  This adapter
    therefore preserves each validator-produced result and combines only their
    disjoint, manifest-authorized test IDs; it never fabricates a single-run
    baseline.
    """

    if len(runs) != 3 or len({identity for identity, _ in runs}) != 3:
        raise ValueError("coexisting recipient composition requires three distinct runs")
    projected = tuple(
        (identity, from_pipeline_result(task, candidate_ranking, pipeline, task_digest=task_digest, classified_license=classified_license, relocated_examples=relocated_examples, adaptation_probes=adaptation_probes, ranking_unranked=ranking_unranked, normalize_staging_test_paths=True))
        for identity, pipeline in sorted(runs, key=lambda item: item[0].sort_key)
    )
    members = tuple(sorted((member for _identity, observation in projected for member in observation.bts_members), key=lambda item: item.node))
    if len({item.node for item in members}) != len(members):
        raise ValueError("coexisting recipient composition has overlapping BTS members")
    outcomes = tuple(sorted(
        (test_id, outcome)
        for _identity, observation in projected
        for test_id, outcome in observation.rerun_outcome_vector or ()
    ))
    if len({test_id for test_id, _outcome in outcomes}) != len(outcomes):
        raise ValueError("coexisting recipient composition has overlapping outcome IDs")
    counts = None if any(observation.rerun_counts is None for _identity, observation in projected) else cast(
        tuple[int, int, int],
        tuple(sum((observation.rerun_counts or (0, 0, 0))[index] for _identity, observation in projected) for index in range(3)),
    )
    status = "complete" if all(observation.rerun_status == "complete" for _identity, observation in projected) else "reject"
    return BTSTaskObservation(
        task.task_id,
        task.digest() if task_digest is None else task_digest,
        candidate_ranking,
        members,
        tuple(sorted({test for _identity, observation in projected for test in observation.relocated_tests})),
        relocated_examples,
        status,
        counts,
        outcomes if counts is not None else None,
        None,
        any(observation.donor_import_observed for _identity, observation in projected),
        classified_license,
        adaptation_probes,
        tuple(sorted({probe for _identity, observation in projected for probe in observation.probe_ran_ids})),
        sum(observation.probe_passed for _identity, observation in projected),
        sum(observation.probe_total for _identity, observation in projected),
        ranking_unranked,
        "coexisting-recipient-three-runs",
    )


def manifest_from_dict(raw: object) -> BTSEvalManifest:
    """Strictly validate and construct a BTS evaluation manifest."""

    value = _mapping(raw, "BTS evaluation manifest")
    _exact(value, {"schema_version", "benchmark_id", "tasks"}, "BTS evaluation manifest")
    tasks_raw = _list(value["tasks"], "tasks")
    return BTSEvalManifest(_str(value["schema_version"], "schema_version"), _str(value["benchmark_id"], "benchmark_id"), tuple(_task_from_dict(item) for item in tasks_raw))


def load_manifest(path: str | Path) -> BTSEvalManifest:
    if not isinstance(path, (str, Path)):
        raise TypeError("path must be text or Path")
    try:
        # Benchmark task manifests are digest-bound by their callers after
        # parsing, so this portable input may omit O_NOFOLLOW.
        return manifest_from_dict(json.loads(read_regular_file(Path(path), maximum_bytes=1 << 20, no_follow=False).decode("utf-8", "strict")))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("BTS evaluation manifest cannot be read as bounded UTF-8 JSON") from exc


def _task_from_dict(raw: object) -> BTSEvalTask:
    value = _mapping(raw, "task")
    if set(value) not in ({"task_id", "gold"}, {"task_id", "gold", "observation"}):
        raise ValueError("task has unknown or missing fields")
    gold = _gold_from_dict(value["gold"])
    return BTSEvalTask(
        _str(value["task_id"], "task_id"),
        gold,
        _observation_from_dict(value["observation"]) if "observation" in value else _legacy_observation_plan(gold),
        "observation" in value,
    )


def _observation_from_dict(raw: object) -> TaskObservationPlan:
    value = _mapping(raw, "task observation")
    _exact(value, {"candidates", "execution_candidates", "seed", "contract_tests", "required_behaviors"}, "task observation")
    candidates = tuple(CandidateIdentity.from_dict(item) for item in _list(value["candidates"], "observation candidates"))
    execution = tuple(CandidateIdentity.from_dict(item) for item in _list(value["execution_candidates"], "observation execution candidates"))
    return TaskObservationPlan(
        candidates,
        execution,
        CandidateIdentity.from_dict(value["seed"]),
        _string_tuple(value["contract_tests"], "observation contract tests"),
        _string_tuple(value["required_behaviors"], "observation required behaviors"),
    )


def _legacy_observation_plan(gold: BTSGold) -> TaskObservationPlan:
    """Lift legacy v1 task setup once at manifest loading, never at observation."""

    if gold.seed_span is None:
        raise ValueError("legacy task has no observation seed")
    candidates = tuple(sorted((item.identity for item in gold.candidate_qrels), key=lambda item: item.sort_key))
    execution = candidates if len(candidates) == 3 and {item.slug for item in candidates} == {
        "mmcloughlin/luhn", "litl/backoff", "niksite/url-normalize",
    } else (gold.seed_span.identity,)
    return TaskObservationPlan(candidates, execution, gold.seed_span.identity, tuple(sorted(gold.required_tests)), ("python.callable.sync@v1",))


def _gold_from_dict(raw: object) -> BTSGold:
    value = _mapping(raw, "gold")
    fields = {"candidate_qrels", "seed_span", "required_helpers", "required_tests", "required_examples", "expected_adaptations", "expected_baseline_digest", "expected_counts", "expected_outcome_vector", "expected_selected_test_ids", "expected_zero_failure_baseline", "expected_license", "expected_probe_ids", "applicability"}
    _exact(value, fields, "gold")
    seed = value["seed_span"]
    seed_span = None
    if seed is not None:
        seed_raw = _mapping(seed, "seed_span")
        _exact(seed_raw, {"identity"}, "seed_span")
        seed_span = SeedSpan(CandidateIdentity.from_dict(seed_raw["identity"]))
    counts_raw = value["expected_counts"]
    counts = None if counts_raw is None else cast(tuple[int, int, int], tuple(_list(counts_raw, "expected_counts")))
    outcomes = _optional_pairs(value["expected_outcome_vector"], "expected_outcome_vector")
    selected = _optional_strings(value["expected_selected_test_ids"], "expected_selected_test_ids")
    qrels = tuple(CandidateJudgment(CandidateIdentity.from_dict(item["identity"]), _int(item["grade"], "grade")) for item in _objects(value["candidate_qrels"], "candidate_qrels", {"identity", "grade"}))
    applicability = tuple(MetricApplicability(_str(item["metric"], "metric"), _bool(item["applicable"], "applicable"), _optional_str(item["not_applicable_reason"], "not_applicable_reason")) for item in _objects(value["applicability"], "applicability", {"metric", "applicable", "not_applicable_reason"}))
    return BTSGold(qrels, seed_span, _string_tuple(value["required_helpers"], "required_helpers"), _string_tuple(value["required_tests"], "required_tests"), _string_tuple(value["required_examples"], "required_examples"), _string_tuple(value["expected_adaptations"], "expected_adaptations"), _optional_str(value["expected_baseline_digest"], "expected_baseline_digest"), counts, outcomes, selected, _bool(value["expected_zero_failure_baseline"], "expected_zero_failure_baseline"), _optional_str(value["expected_license"], "expected_license"), _string_tuple(value["expected_probe_ids"], "expected_probe_ids"), applicability)


def _declared_applicable(entries: dict[str, MetricApplicability], metric: str, default: bool) -> bool:
    return entries[metric].applicable if metric in entries else default


def _external_member(member: MemberObs) -> bool:
    text = member.node.lower()
    return "declared_external" in text or "stdlib" in text or member.disposition.lower() in {"external", "stdlib"}


def _counts(value: object, name: str) -> None:
    if not isinstance(value, tuple) or len(value) != 3 or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value):
        raise ValueError(f"{name} must be three non-negative integers")


def _pairs(value: object, name: str, *, sorted_: bool) -> None:
    _tuple(value, name)
    assert isinstance(value, tuple)
    if any(not isinstance(item, tuple) or len(item) != 2 or any(not isinstance(part, str) or not part for part in item) for item in value):
        raise ValueError(f"{name} must contain string pairs")
    if len({item[0] for item in value}) != len(value):
        raise ValueError(f"{name} IDs must be unique")
    if sorted_ and value != tuple(sorted(value)):
        raise ValueError(f"{name} must be sorted")


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _exact(value: dict[str, object], fields: set[str], name: str) -> None:
    if set(value) != fields:
        raise ValueError(f"{name} has missing or unknown fields")


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{name} must be a list")
    return value


def _objects(value: object, name: str, fields: set[str]) -> list[dict[str, object]]:
    result = []
    for item in _list(value, name):
        mapping = _mapping(item, name)
        _exact(mapping, fields, name)
        result.append(mapping)
    return result


def _str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    return value


def _optional_str(value: object, name: str) -> str | None:
    return None if value is None else _str(value, name)


def _int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be bool")
    return value


def _string_tuple(value: object, name: str) -> tuple[str, ...]:
    return tuple(_str(item, name) for item in _list(value, name))


def _optional_strings(value: object, name: str) -> tuple[str, ...] | None:
    return None if value is None else _string_tuple(value, name)


def _optional_pairs(value: object, name: str) -> tuple[tuple[str, str], ...] | None:
    if value is None:
        return None
    pairs = tuple(_list(item, name) for item in _list(value, name))
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError(f"{name} entries must contain exactly two values")
    return tuple((_str(pair[0], name), _str(pair[1], name)) for pair in pairs)


__all__ = [
    "LEITIR_BTS_EVAL_MANIFEST_V1",
    "LEITIR_BTS_EVAL_RUN_V1",
    "LEITIR_BTS_TIMING_V1",
    "AdaptationProbeObs",
    "BTSAggregate",
    "BTSEvalBenchmark",
    "BTSEvalManifest",
    "BTSEvalRun",
    "BTSEvalTask",
    "BTSEvalTaskRun",
    "BTSGold",
    "BTSRunner",
    "BTSTaskObservation",
    "BTSTimingEnvelope",
    "CandidateIdentity",
    "CandidateJudgment",
    "Exclusion",
    "MemberObs",
    "MetricApplicability",
    "MetricRecord",
    "SeedSpan",
    "TaskObservationPlan",
    "aggregate_task_runs",
    "compute_run_with_timing",
    "from_pipeline_result",
    "grade_adaptation_integrity",
    "grade_candidate_top1",
    "grade_candidate_top3",
    "grade_candidate_top10",
    "grade_donor_import_free",
    "grade_example_recall",
    "grade_hallucinated_dependency_rate",
    "grade_helper_recall",
    "grade_integration_success",
    "grade_license_accuracy",
    "grade_missing_dependency_rate",
    "grade_probe_success",
    "grade_seed_symbol_exact",
    "grade_seed_symbol_line_overlap",
    "grade_task",
    "grade_test_recall",
    "grade_time_saved",
    "load_manifest",
    "manifest_from_dict",
]
