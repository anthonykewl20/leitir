"""Versioned, evaluator-only smoke benchmark and PRD §6.2 reporting.

This module deliberately stays above the five-step workflow.  It selects task
bundles, supplies their Step 5 inputs through the orchestrator's evaluator
seam, and derives measurements from completed traces.  It does not construct
model requests, retrieve evidence, synthesize code, or run pytest itself.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
import re
from typing import TYPE_CHECKING, Protocol

from .contracts import (
    EvidenceTier,
    TargetLanguage,
    TerminalDisposition,
    WorkflowRequest,
)
from .orchestrator import WorkflowRunResult
from .trace import ExecutionTrace

if TYPE_CHECKING:
    from .cli import EvaluationRunOperation


BENCHMARK_VERSION = "smoke-v1"
_BUNDLE_ROOT = Path(__file__).with_name("benchmarks") / BENCHMARK_VERSION
_TASK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HIDDEN_ID = re.compile(r"^leitir:smoke-v1:[a-z0-9-]+:eval-v1$")
_OUTCOME_NAMES = (
    "first_pass_pass",
    "repaired_pass",
    "valid_failure",
    "spend_cap_termination",
    "infrastructure_invalid",
)


class BenchmarkValidationError(ValueError):
    """A bundled benchmark violates the fixed smoke-suite contract."""


@dataclass(frozen=True, slots=True)
class SmokeTask:
    """Validated metadata for one evaluator task bundle."""

    task_id: str
    prompt: str
    dependency: str
    dependency_version: str
    evidence_date: str
    declared_tiers: tuple[EvidenceTier, ...]
    dependencies: tuple[str, ...]
    valid: bool
    hidden_test_identity: str
    bundle_directory: Path

    @property
    def hidden_test_directory(self) -> Path:
        """Return the evaluator mount, never generation-visible task text."""

        return self.bundle_directory / "hidden"


@dataclass(frozen=True, slots=True)
class SmokeBenchmark:
    version: str
    tasks: tuple[SmokeTask, ...]

    @classmethod
    def load(cls, root: str | Path = _BUNDLE_ROOT) -> "SmokeBenchmark":
        root_path = Path(root)
        try:
            document = json.loads(
                (root_path / "manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise BenchmarkValidationError(
                "benchmark manifest is unreadable"
            ) from exc
        if not isinstance(document, Mapping):
            raise BenchmarkValidationError("benchmark manifest must be an object")
        if set(document) != {"version", "language", "runner", "tasks"}:
            raise BenchmarkValidationError("benchmark manifest has unknown fields")
        if document["version"] != BENCHMARK_VERSION:
            raise BenchmarkValidationError("unsupported benchmark version")
        if (
            document["language"] != "python"
            or document["runner"] != "docker-pytest"
        ):
            raise BenchmarkValidationError(
                "smoke tasks require Python and Docker pytest"
            )
        records = document["tasks"]
        if not isinstance(records, list) or not 3 <= len(records) <= 5:
            raise BenchmarkValidationError(
                "smoke benchmark must contain three to five tasks"
            )
        tasks = tuple(_load_task(root_path, item) for item in records)
        if len({item.task_id for item in tasks}) != len(tasks):
            raise BenchmarkValidationError("task identifiers must be unique")
        if len({item.evidence_date for item in tasks}) < 2:
            raise BenchmarkValidationError("smoke tasks require varied evidence dates")
        if len({item.declared_tiers for item in tasks}) < 2:
            raise BenchmarkValidationError(
                "smoke tasks require distinct retrieval behavior"
            )
        return cls(BENCHMARK_VERSION, tasks)

    @classmethod
    def default(cls) -> "SmokeBenchmark":
        return cls.load()


@dataclass(frozen=True, slots=True)
class Metric:
    """One percentage with the reporting context required by the rubric."""

    numerator: int
    denominator: int
    excluded_run_count: int
    benchmark_version: str = BENCHMARK_VERSION

    def __post_init__(self) -> None:
        for name in ("numerator", "denominator", "excluded_run_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.numerator > self.denominator:
            raise ValueError("metric numerator cannot exceed denominator")

    @property
    def percentage(self) -> float | None:
        return (
            None
            if self.denominator == 0
            else self.numerator * 100.0 / self.denominator
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "excluded_run_count": self.excluded_run_count,
            "benchmark_version": self.benchmark_version,
            "percentage": self.percentage,
        }


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    benchmark_version: str
    task_count: int
    outcomes: Mapping[str, int]
    ser: Metric
    dri: Metric
    dri_distribution: Mapping[str, int]
    fpcr: Metric
    sccr: Metric
    total_latency_ms: int | float
    provider_usage: Mapping[str, object]
    policy: Mapping[str, object]
    small_sample_notice: str

    def to_dict(self) -> dict[str, object]:
        return {
            "benchmark_version": self.benchmark_version,
            "task_count": self.task_count,
            "outcomes": dict(self.outcomes),
            "metrics": {
                "SER": self.ser.to_dict(),
                "DRI": {
                    **self.dri.to_dict(),
                    "distribution": dict(self.dri_distribution),
                },
                "FPCR": self.fpcr.to_dict(),
                "SCCR": self.sccr.to_dict(),
            },
            "total_latency_ms": self.total_latency_ms,
            "provider_usage": dict(self.provider_usage),
            "policy": dict(self.policy),
            "small_sample_notice": self.small_sample_notice,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )


class ReportWriter(Protocol):
    def __call__(self, report: EvaluationReport) -> object: ...


class SmokeEvaluationDriver:
    """Execute every valid smoke task through the supplied orchestrator run."""

    def __init__(
        self,
        benchmark: SmokeBenchmark | None = None,
        *,
        report_writer: ReportWriter | None = None,
    ) -> None:
        self.benchmark = benchmark or SmokeBenchmark.default()
        self._report_writer = report_writer

    def evaluate(self, run: "EvaluationRunOperation") -> EvaluationReport:
        if not callable(run):
            raise TypeError("evaluation run operation must be callable")
        results: list[WorkflowRunResult] = []
        for task in self.benchmark.tasks:
            if not task.valid:
                continue
            # Only this generation-visible string crosses Steps 1–4.
            request = WorkflowRequest(
                request_id=f"{self.benchmark.version}-{task.task_id}",
                task=task.prompt,
                target_language=TargetLanguage.PYTHON,
            )
            result = run(
                request,
                public_tests={},
                dependencies=task.dependencies,
                hidden_tests=task.hidden_test_directory,
            )
            if not isinstance(result, WorkflowRunResult):
                raise TypeError("evaluation run returned an invalid result")
            results.append(result)
        report = build_report(
            self.benchmark.version,
            results,
            total_task_count=len(self.benchmark.tasks),
        )
        if self._report_writer is not None:
            self._report_writer(report)
        return report


def build_report(
    benchmark_version: str,
    results: Sequence[WorkflowRunResult],
    *,
    total_task_count: int | None = None,
) -> EvaluationReport:
    """Build SER/DRI/FPCR/SCCR exclusively from completed run traces."""

    if benchmark_version != BENCHMARK_VERSION:
        raise ValueError("unsupported benchmark version")
    traces = tuple(_trace(item) for item in results)
    task_count = len(traces) if total_task_count is None else total_task_count
    if (
        isinstance(task_count, bool)
        or not isinstance(task_count, int)
        or task_count < 0
    ):
        raise ValueError("total task count must be a non-negative integer")
    if task_count < len(traces):
        raise ValueError("total task count cannot be smaller than run count")
    manifest_exclusions = task_count - len(traces)
    invalid = tuple(_infrastructure_invalid(trace) for trace in traces)
    outcomes = Counter(
        _outcome(trace, is_invalid)
        for trace, is_invalid in zip(traces, invalid, strict=True)
    )
    outcome_counts = {name: outcomes[name] for name in _OUTCOME_NAMES}

    ser_numerator = 0
    ser_denominator = 0
    ser_excluded = manifest_exclusions
    for trace, is_invalid in zip(traces, invalid, strict=True):
        accounting = _first_synthesis_accounting(trace)
        if is_invalid or accounting is None or accounting[1] == 0:
            ser_excluded += 1
            continue
        retained, total = accounting
        ser_numerator += retained
        ser_denominator += total

    resolutions: list[int] = []
    for trace, is_invalid in zip(traces, invalid, strict=True):
        tier = None if is_invalid else _resolved_tier(trace)
        if tier is not None:
            resolutions.append(tier)
    distribution = {
        "tier_1_alone": sum(item == 1 for item in resolutions),
        "tiers_1_2": sum(item == 2 for item in resolutions),
        "tiers_1_3": sum(item == 3 for item in resolutions),
    }
    dri_denominator = len(resolutions)
    dri_numerator = sum(item <= 2 for item in resolutions)

    valid_started = [
        trace
        for trace, is_invalid in zip(traces, invalid, strict=True)
        if not is_invalid
    ]
    first_passes = sum(_first_step5_passed(trace) for trace in valid_started)

    correction_population = [
        trace
        for trace in valid_started
        if _first_valid_step5_failed(trace)
    ]
    corrections = sum(
        trace.final_status is TerminalDisposition.ACCEPTED
        and trace.accepted_attempt is not None
        and 2 <= trace.accepted_attempt <= 4
        for trace in correction_population
    )

    usage = _provider_usage(traces)
    policy = _policy_summary(traces)
    return EvaluationReport(
        benchmark_version=benchmark_version,
        task_count=task_count,
        outcomes=outcome_counts,
        ser=Metric(
            ser_numerator,
            ser_denominator,
            ser_excluded,
            benchmark_version,
        ),
        dri=Metric(
            dri_numerator,
            dri_denominator,
            task_count - dri_denominator,
            benchmark_version,
        ),
        dri_distribution=distribution,
        fpcr=Metric(
            first_passes,
            len(valid_started),
            task_count - len(valid_started),
            benchmark_version,
        ),
        sccr=Metric(
            corrections,
            len(correction_population),
            task_count - len(correction_population),
            benchmark_version,
        ),
        total_latency_ms=sum(trace.total_latency_ms for trace in traces),
        provider_usage=usage,
        policy=policy,
        small_sample_notice=(
            "Smoke results are diagnostic only; this small suite does not "
            "establish full benchmark success."
        ),
    )


def _load_task(root: Path, record: object) -> SmokeTask:
    fields = {
        "id",
        "prompt",
        "dependency",
        "dependency_version",
        "evidence_date",
        "tiers",
        "sandbox",
        "valid",
        "hidden_test_identity",
    }
    if not isinstance(record, Mapping) or set(record) != fields:
        raise BenchmarkValidationError("task manifest entry has invalid fields")
    task_id = record["id"]
    if not isinstance(task_id, str) or _TASK_ID.fullmatch(task_id) is None:
        raise BenchmarkValidationError("task identifier is invalid")
    bundle = root / "tasks" / task_id
    prompt_name = record["prompt"]
    if prompt_name != "prompt.md":
        raise BenchmarkValidationError("generation prompt must be prompt.md")
    try:
        prompt = (bundle / prompt_name).read_text(encoding="utf-8").strip()
        dockerfile = (bundle / "Dockerfile").read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkValidationError(
            f"task {task_id} bundle is incomplete"
        ) from exc
    if not prompt or "eval_test.py" in prompt or "/hidden" in prompt:
        raise BenchmarkValidationError("generation prompt exposes evaluator identity")
    hidden_id = record["hidden_test_identity"]
    if not isinstance(hidden_id, str) or _HIDDEN_ID.fullmatch(hidden_id) is None:
        raise BenchmarkValidationError("hidden test identity is invalid")
    hidden_file = bundle / "hidden" / "eval_test.py"
    if not hidden_file.is_file():
        raise BenchmarkValidationError("task is missing evaluator-only eval_test.py")
    if "pytest" not in dockerfile or "python" not in dockerfile:
        raise BenchmarkValidationError("task Dockerfile must run Python pytest")
    forbidden = ("cargo test", "go test", "COPY hidden")
    if any(value in dockerfile for value in forbidden):
        raise BenchmarkValidationError("task Dockerfile violates smoke policy")
    dependency = record["dependency"]
    dependency_version = record["dependency_version"]
    if not all(
        isinstance(value, str) and value.strip()
        for value in (dependency, dependency_version)
    ):
        raise BenchmarkValidationError("dependency and version must be nonblank")
    try:
        date.fromisoformat(record["evidence_date"])
    except (TypeError, ValueError):
        raise BenchmarkValidationError("evidence date must be ISO-8601") from None
    tiers_value = record["tiers"]
    if (
        not isinstance(tiers_value, list)
        or not tiers_value
        or any(value not in (1, 2, 3) for value in tiers_value)
        or tiers_value != sorted(set(tiers_value))
    ):
        raise BenchmarkValidationError("task tiers must be ordered Tiers 1–3")
    sandbox = record["sandbox"]
    if (
        not isinstance(sandbox, Mapping)
        or set(sandbox) != {"runner", "dependencies"}
        or sandbox["runner"] != "pytest"
        or not isinstance(sandbox["dependencies"], list)
        or any(not isinstance(item, str) for item in sandbox["dependencies"])
    ):
        raise BenchmarkValidationError("task sandbox inputs are invalid")
    valid = record["valid"]
    if not isinstance(valid, bool):
        raise BenchmarkValidationError("task validity must be boolean")
    return SmokeTask(
        task_id=task_id,
        prompt=prompt,
        dependency=dependency,
        dependency_version=dependency_version,
        evidence_date=record["evidence_date"],
        declared_tiers=tuple(EvidenceTier(value) for value in tiers_value),
        dependencies=tuple(sandbox["dependencies"]),
        valid=valid,
        hidden_test_identity=hidden_id,
        bundle_directory=bundle,
    )


def _trace(result: WorkflowRunResult) -> ExecutionTrace:
    if not isinstance(result, WorkflowRunResult):
        raise TypeError("report inputs must be WorkflowRunResult values")
    trace = result.trace_reference
    if result.final_status is not trace.final_status:
        raise ValueError("run result and trace dispositions disagree")
    return trace


def _verification_spans(trace: ExecutionTrace):
    return tuple(span for span in trace.spans if span.sandbox is not None)


def _infrastructure_invalid(trace: ExecutionTrace) -> bool:
    if trace.final_status in {
        TerminalDisposition.INFRASTRUCTURE_ERROR,
        TerminalDisposition.CANCELLED,
    }:
        return True
    return any(
        span.sandbox is not None
        and span.sandbox.infrastructure_status == "invalid"
        for span in trace.spans
    )


def _outcome(trace: ExecutionTrace, invalid: bool) -> str:
    if invalid:
        return "infrastructure_invalid"
    if trace.final_status is TerminalDisposition.SPEND_CAP_EXCEEDED:
        return "spend_cap_termination"
    if (
        trace.final_status is TerminalDisposition.ACCEPTED
        and trace.accepted_attempt == 1
    ):
        return "first_pass_pass"
    if (
        trace.final_status is TerminalDisposition.ACCEPTED
        and trace.accepted_attempt is not None
        and trace.accepted_attempt > 1
    ):
        return "repaired_pass"
    return "valid_failure"


def _first_synthesis_accounting(
    trace: ExecutionTrace,
) -> tuple[int, int] | None:
    for span in trace.spans:
        if span.synthesis is not None and span.synthesis.is_first_prompt:
            return (
                span.synthesis.retained_evidence_tokens,
                span.synthesis.total_cleaned_evidence_tokens,
            )
    # Older/failure traces may only have the run-level evidence accounting.
    accounting = trace.evidence_accounting
    if accounting.total_cleaned_evidence_tokens:
        return (
            accounting.retained_evidence_tokens,
            accounting.total_cleaned_evidence_tokens,
        )
    return None


def _resolved_tier(trace: ExecutionTrace) -> int | None:
    if trace.final_status is not TerminalDisposition.ACCEPTED:
        return None
    accepted = trace.accepted_attempt
    synthesis = next(
        (
            span.synthesis
            for span in trace.spans
            if span.synthesis is not None
            and span.attempt_number == accepted
            and span.synthesis.candidate_artifact_id is not None
        ),
        None,
    )
    if synthesis is None:
        return None
    artifact_tiers = {
        item.artifact_id: item.tier
        for item in trace.artifacts
        if item.tier is not None
    }
    tiers = [
        artifact_tiers[item]
        for item in synthesis.cited_chunk_ids
        if item in artifact_tiers
    ]
    return max((int(item) for item in tiers), default=None)


def _first_step5_passed(trace: ExecutionTrace) -> bool:
    spans = _verification_spans(trace)
    return bool(
        spans
        and spans[0].sandbox is not None
        and spans[0].sandbox.infrastructure_status == "valid"
        and spans[0].sandbox.test_passed is True
    )


def _first_valid_step5_failed(trace: ExecutionTrace) -> bool:
    spans = _verification_spans(trace)
    return bool(
        spans
        and spans[0].sandbox is not None
        and spans[0].sandbox.infrastructure_status == "valid"
        and spans[0].sandbox.test_passed is False
    )


def _provider_usage(traces: Sequence[ExecutionTrace]) -> dict[str, object]:
    fields = {
        "cost_usd": "total_cost_usd",
        "prompt_tokens": "total_prompt_tokens",
        "completion_tokens": "total_completion_tokens",
        "reasoning_tokens": "total_reasoning_tokens",
    }
    output: dict[str, object] = {}
    for report_name, attribute in fields.items():
        values = [getattr(trace.aggregate, attribute) for trace in traces]
        known = [value for value in values if value is not None]
        output[report_name] = {
            "known_sum": sum(known) if known else None,
            "reported_run_count": len(known),
            "missing_run_count": len(values) - len(known),
        }
    output["missing_provider_fields"] = sorted(
        {
            field
            for trace in traces
            for field in trace.aggregate.missing_provider_fields
        }
    )
    return output


def _policy_summary(traces: Sequence[ExecutionTrace]) -> dict[str, object]:
    violations: list[str] = []
    review_calls = 0
    model_calls = 0
    for trace in traces:
        for span in trace.spans:
            if span.model is None:
                continue
            model_calls += 1
            model = span.model
            if span.step.value == 1:
                valid = (
                    not model.reasoning_effort_was_sent
                    and model.reasoning_effort_sent is None
                    and model.include_reasoning_sent is False
                )
            elif span.step.value == 4:
                valid = (
                    model.reasoning_effort_was_sent
                    and model.reasoning_effort_sent == "high"
                    and model.include_reasoning_sent is False
                )
            else:
                valid = False
                review_calls += 1
            if not valid:
                violations.append(
                    f"{trace.trace_id}:step-{span.step.value}:attempt-"
                    f"{span.attempt_number}"
                )
    return {
        "model_call_count": model_calls,
        "review_call_count": review_calls,
        "expected_review_call_count": 0,
        "reasoning_policy_violation_count": len(violations),
        "reasoning_policy_violations": violations,
    }


__all__ = [
    "BENCHMARK_VERSION",
    "BenchmarkValidationError",
    "EvaluationReport",
    "Metric",
    "SmokeBenchmark",
    "SmokeEvaluationDriver",
    "SmokeTask",
    "build_report",
]
