"""Secret-safe, replayable JSON execution traces.

This module records workflow facts; it deliberately performs no workflow,
provider, sandbox, or credential work.  Importing it has no external effects.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from difflib import unified_diff
from enum import Enum
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .contracts import (
    ArtifactId,
    ErrorCode,
    EvidenceTier,
    StepStatus,
    TerminalDisposition,
    WorkflowStep,
)
from .logging import redact


SCHEMA_VERSION = "1.0"


def _non_negative(name: str, value: int | float | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and non-negative")


def _positive(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 1:
        raise ValueError(f"{name} must be positive")


def _non_negative_int(name: str, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _timestamp(value: str) -> None:
    if not isinstance(value, str):
        raise TypeError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")


def utc_now() -> str:
    """Return an RFC 3339 UTC timestamp suitable for injection into a recorder."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ArtifactKind(str, Enum):
    PROMPT = "prompt"
    TOOL_OUTPUT = "tool_output"
    CLEANED_CHUNK = "cleaned_chunk"
    MODEL_RESPONSE = "model_response"
    CONFIGURATION = "configuration"
    GENERATED_CODE = "generated_code"
    ATTEMPT_DIFF = "attempt_diff"
    STDOUT = "stdout"
    STDERR = "stderr"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    """A small, secret-free pointer to content held by replaceable storage."""

    artifact_id: ArtifactId
    kind: ArtifactKind
    reference: str
    media_type: str = "application/octet-stream"
    size_bytes: int | None = None
    digest: str | None = None
    tier: EvidenceTier | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ArtifactKind):
            raise TypeError("kind must be an ArtifactKind")
        if not isinstance(self.reference, str) or not self.reference.strip():
            raise ValueError("reference must be a non-empty string")
        if not isinstance(self.media_type, str) or not self.media_type.strip():
            raise ValueError("media_type must be a non-empty string")
        if self.size_bytes is not None:
            _non_negative_int("size_bytes", self.size_bytes)
        if self.tier is not None and not isinstance(self.tier, EvidenceTier):
            raise TypeError("tier must be an EvidenceTier")
        safe = redact(dict(self.metadata))
        object.__setattr__(self, "metadata", MappingProxyType(safe))
        object.__setattr__(self, "reference", redact(self.reference))
        if self.digest is not None:
            object.__setattr__(self, "digest", redact(self.digest))


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    """OpenRouter usage, preserving raw data beside the exact normalization."""

    cost_usd: int | float | None
    prompt_tokens: int | None
    completion_tokens: int | None
    reasoning_tokens: int | None
    missing_fields: tuple[str, ...]
    raw_provider_fields: Mapping[str, object]

    FIELD_PATHS = (
        "usage.cost",
        "usage.prompt_tokens",
        "usage.completion_tokens",
        "usage.completion_tokens_details.reasoning_tokens",
    )

    def __post_init__(self) -> None:
        _non_negative("cost_usd", self.cost_usd)
        for name in ("prompt_tokens", "completion_tokens", "reasoning_tokens"):
            value = getattr(self, name)
            _non_negative_int(name, value)
        unknown = set(self.missing_fields) - set(self.FIELD_PATHS)
        if unknown:
            raise ValueError(f"unknown missing provider fields: {sorted(unknown)!r}")
        object.__setattr__(
            self,
            "raw_provider_fields",
            MappingProxyType(redact(dict(self.raw_provider_fields))),
        )

    @property
    def complete(self) -> bool:
        return not self.missing_fields

    @classmethod
    def from_openrouter(cls, response: Mapping[str, object]) -> ProviderUsage:
        """Map only the normative provider fields, without inference.

        ``response`` may be either the whole OpenRouter response or its ``usage``
        object.  The raw usage object is retained after recursive redaction.
        """

        candidate = response.get("usage")
        usage: Mapping[str, object]
        if isinstance(candidate, Mapping):
            usage = candidate
        else:
            usage = response

        missing: list[str] = []

        def scalar(key: str, path: str) -> object | None:
            if key not in usage or usage[key] is None:
                missing.append(path)
                return None
            return usage[key]

        cost = scalar("cost", "usage.cost")
        prompt = scalar("prompt_tokens", "usage.prompt_tokens")
        completion = scalar("completion_tokens", "usage.completion_tokens")
        details = usage.get("completion_tokens_details")
        if not isinstance(details, Mapping) or details.get("reasoning_tokens") is None:
            reasoning = None
            missing.append(
                "usage.completion_tokens_details.reasoning_tokens"
            )
        else:
            reasoning = details["reasoning_tokens"]

        return cls(
            cost_usd=cost,  # type: ignore[arg-type]
            prompt_tokens=prompt,  # type: ignore[arg-type]
            completion_tokens=completion,  # type: ignore[arg-type]
            reasoning_tokens=reasoning,  # type: ignore[arg-type]
            missing_fields=tuple(missing),
            raw_provider_fields=usage,
        )


@dataclass(frozen=True, slots=True)
class ModelData:
    model_used: str
    reasoning_effort_sent: str | None
    reasoning_effort_was_sent: bool
    include_reasoning_sent: bool
    usage: ProviderUsage
    prompt_artifact_id: ArtifactId | None = None
    response_artifact_id: ArtifactId | None = None
    parameters_artifact_id: ArtifactId | None = None

    def __post_init__(self) -> None:
        if not self.model_used:
            raise ValueError("model_used must not be empty")
        if self.reasoning_effort_was_sent != (
            self.reasoning_effort_sent is not None
        ):
            raise ValueError(
                "reasoning_effort_was_sent must distinguish omitted from sent"
            )
        if self.reasoning_effort_sent not in {None, "minimal", "low", "medium", "high"}:
            raise ValueError("invalid reasoning effort")
        if not isinstance(self.include_reasoning_sent, bool):
            raise TypeError("include_reasoning_sent must be a bool")


@dataclass(frozen=True, slots=True)
class ExpansionData:
    expanded_query_artifact_id: ArtifactId
    target_tiers: tuple[EvidenceTier, ...]
    parse_status: str

    def __post_init__(self) -> None:
        if not self.target_tiers:
            raise ValueError("query expansion requires at least one target tier")
        if not self.parse_status.strip():
            raise ValueError("parse_status must not be empty")


@dataclass(frozen=True, slots=True)
class DiscoveryData:
    urls_found: int
    usable_results: int
    deduplication_count: int
    result_tiers: tuple[EvidenceTier, ...] = ()
    source_domains: tuple[str, ...] = ()
    http_statuses: tuple[int, ...] = ()
    filtering_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("urls_found", "usable_results", "deduplication_count"):
            _non_negative_int(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class ExtractionData:
    raw_bytes: int
    cleaned_tokens: int
    comments_stripped: bool
    source_tier: EvidenceTier
    repository_stars: int | None = None
    extraction_failure: str | None = None

    def __post_init__(self) -> None:
        _non_negative_int("raw_bytes", self.raw_bytes)
        _non_negative_int("cleaned_tokens", self.cleaned_tokens)
        _non_negative_int("repository_stars", self.repository_stars)
        if not isinstance(self.source_tier, EvidenceTier):
            raise TypeError("source_tier must be an EvidenceTier")


@dataclass(frozen=True, slots=True)
class SecurityData:
    flags: tuple[str, ...] = ()
    instruction_like_content: bool = False


@dataclass(frozen=True, slots=True)
class SandboxData:
    exit_code: int | None
    test_passed: bool | None
    stdout_artifact_id: ArtifactId | None
    stderr_artifact_id: ArtifactId | None
    timed_out: bool
    error_category: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.timed_out, bool):
            raise TypeError("timed_out must be a bool")
        if self.timed_out and self.test_passed is True:
            raise ValueError("a timed-out sandbox cannot have passed")


@dataclass(frozen=True, slots=True)
class TraceSpan:
    step: WorkflowStep
    status: StepStatus
    latency_ms: int | float
    input_artifact_ids: tuple[ArtifactId, ...] = ()
    output_artifact_ids: tuple[ArtifactId, ...] = ()
    error_code: ErrorCode | None = None
    error_message: str | None = None
    retry_number: int = 0
    attempt_number: int = 1
    model: ModelData | None = None
    expansion: ExpansionData | None = None
    discovery: DiscoveryData | None = None
    extraction: ExtractionData | None = None
    security: SecurityData | None = None
    sandbox: SandboxData | None = None
    started_at: str | None = None
    ended_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.step, WorkflowStep):
            raise TypeError("step must be a WorkflowStep")
        if not isinstance(self.status, StepStatus):
            raise TypeError("status must be a StepStatus")
        _non_negative("latency_ms", self.latency_ms)
        _non_negative_int("retry_number", self.retry_number)
        _positive("attempt_number", self.attempt_number)
        if self.status is StepStatus.FAILED and self.error_code is None:
            raise ValueError("a failed span requires an error_code")
        for value in (self.started_at, self.ended_at):
            if value is not None:
                _timestamp(value)
        detail_steps = (
            (
                "model",
                self.model,
                {
                    WorkflowStep.QUERY_EXPANSION,
                    WorkflowStep.SYNTHESIS,
                    WorkflowStep.VERIFICATION,
                },
            ),
            ("expansion", self.expansion, {WorkflowStep.QUERY_EXPANSION}),
            ("discovery", self.discovery, {WorkflowStep.DISCOVERY}),
            ("extraction", self.extraction, {WorkflowStep.EXTRACTION}),
            ("security", self.security, {WorkflowStep.EXTRACTION}),
            ("sandbox", self.sandbox, {WorkflowStep.VERIFICATION}),
        )
        for name, detail, allowed_steps in detail_steps:
            if detail is not None and self.step not in allowed_steps:
                raise ValueError(f"{name} data does not apply to Step {self.step.value}")
        object.__setattr__(self, "error_message", redact(self.error_message))


@dataclass(frozen=True, slots=True)
class ReplayMetadata:
    """Artifact lineage sufficient to resume at extraction or synthesis."""

    prompt_artifact_ids: tuple[ArtifactId, ...]
    tool_output_artifact_ids: tuple[ArtifactId, ...]
    cleaned_chunk_artifact_ids: tuple[ArtifactId, ...]
    response_artifact_ids: tuple[ArtifactId, ...]
    configuration_artifact_id: ArtifactId
    replayable_from_steps: tuple[WorkflowStep, ...] = (
        WorkflowStep.EXTRACTION,
        WorkflowStep.SYNTHESIS,
    )

    def __post_init__(self) -> None:
        allowed = {WorkflowStep.EXTRACTION, WorkflowStep.SYNTHESIS}
        if not self.replayable_from_steps or not set(
            self.replayable_from_steps
        ).issubset(allowed):
            raise ValueError("replay is supported only from Step 3 or Step 4")


@dataclass(frozen=True, slots=True)
class EvidenceAccounting:
    total_cleaned_evidence_tokens: int
    total_cleaned_chunk_ids: tuple[ArtifactId, ...]
    retained_evidence_tokens: int
    retained_chunk_ids: tuple[ArtifactId, ...]

    def __post_init__(self) -> None:
        _non_negative_int(
            "total_cleaned_evidence_tokens", self.total_cleaned_evidence_tokens
        )
        _non_negative_int("retained_evidence_tokens", self.retained_evidence_tokens)
        if self.retained_evidence_tokens > self.total_cleaned_evidence_tokens:
            raise ValueError("retained evidence cannot exceed total cleaned evidence")
        if self.total_cleaned_evidence_tokens and not self.total_cleaned_chunk_ids:
            raise ValueError("total token accounting requires contributing chunk IDs")
        if self.retained_evidence_tokens and not self.retained_chunk_ids:
            raise ValueError("retained token accounting requires chunk IDs")
        if not set(self.retained_chunk_ids).issubset(self.total_cleaned_chunk_ids):
            raise ValueError("retained chunks must be among total cleaned chunks")


@dataclass(frozen=True, slots=True)
class AttemptDiff:
    from_attempt: int
    to_attempt: int
    from_code_artifact_id: ArtifactId
    to_code_artifact_id: ArtifactId
    diff_artifact_id: ArtifactId
    unified_diff: str

    def __post_init__(self) -> None:
        _positive("from_attempt", self.from_attempt)
        _positive("to_attempt", self.to_attempt)
        if self.to_attempt <= self.from_attempt:
            raise ValueError("attempt diff must move to a later attempt")
        object.__setattr__(self, "unified_diff", redact(self.unified_diff))

    @classmethod
    def between(
        cls,
        *,
        from_attempt: int,
        to_attempt: int,
        from_code_artifact_id: ArtifactId,
        to_code_artifact_id: ArtifactId,
        diff_artifact_id: ArtifactId,
        previous_code: str,
        current_code: str,
    ) -> AttemptDiff:
        diff = "".join(
            unified_diff(
                previous_code.splitlines(keepends=True),
                current_code.splitlines(keepends=True),
                fromfile=f"attempt-{from_attempt}",
                tofile=f"attempt-{to_attempt}",
            )
        )
        return cls(
            from_attempt=from_attempt,
            to_attempt=to_attempt,
            from_code_artifact_id=from_code_artifact_id,
            to_code_artifact_id=to_code_artifact_id,
            diff_artifact_id=diff_artifact_id,
            unified_diff=diff,
        )


@dataclass(frozen=True, slots=True)
class UsageAggregate:
    total_cost_usd: int | float | None
    total_prompt_tokens: int | None
    total_completion_tokens: int | None
    total_reasoning_tokens: int | None
    complete: bool
    missing_provider_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        _non_negative("total_cost_usd", self.total_cost_usd)
        for name in (
            "total_prompt_tokens",
            "total_completion_tokens",
            "total_reasoning_tokens",
        ):
            _non_negative_int(name, getattr(self, name))
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a bool")
        if self.complete and self.missing_provider_fields:
            raise ValueError("complete usage cannot have missing provider fields")


def _aggregate(spans: Sequence[TraceSpan]) -> UsageAggregate:
    usages = [span.model.usage for span in spans if span.model is not None]
    missing = tuple(
        sorted({path for usage in usages for path in usage.missing_fields})
    )

    def total(attr: str) -> int | float | None:
        values = [getattr(usage, attr) for usage in usages]
        if not values or any(value is None for value in values):
            return None
        return sum(values)

    return UsageAggregate(
        total_cost_usd=total("cost_usd"),
        total_prompt_tokens=total("prompt_tokens"),  # type: ignore[arg-type]
        total_completion_tokens=total("completion_tokens"),  # type: ignore[arg-type]
        total_reasoning_tokens=total("reasoning_tokens"),  # type: ignore[arg-type]
        complete=bool(usages) and not missing,
        missing_provider_fields=missing,
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, ArtifactId):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _json_value(getattr(value, item.name)) for item in fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    trace_id: str
    task_summary: str
    started_at: str
    ended_at: str
    total_latency_ms: int | float
    final_status: TerminalDisposition
    accepted_attempt: int | None
    spans: tuple[TraceSpan, ...]
    artifacts: tuple[ArtifactReference, ...]
    replay: ReplayMetadata
    attempt_diffs: tuple[AttemptDiff, ...]
    evidence_accounting: EvidenceAccounting
    aggregate: UsageAggregate
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.trace_id.strip() or not self.task_summary.strip():
            raise ValueError("trace_id and task_summary must not be empty")
        _timestamp(self.started_at)
        _timestamp(self.ended_at)
        _non_negative("total_latency_ms", self.total_latency_ms)
        if not isinstance(self.final_status, TerminalDisposition):
            raise TypeError("final_status must be a TerminalDisposition")
        if self.accepted_attempt is not None:
            _positive("accepted_attempt", self.accepted_attempt)
        if (
            self.final_status is TerminalDisposition.ACCEPTED
            and self.accepted_attempt is None
        ):
            raise ValueError("an accepted trace requires accepted_attempt")
        ids = [item.artifact_id for item in self.artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("artifact IDs must be unique")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported trace schema version: {self.schema_version!r}")
        if self.aggregate != _aggregate(self.spans):
            raise ValueError("usage aggregate does not match recorded model spans")
        known_ids = set(ids)
        referenced_ids = {
            self.replay.configuration_artifact_id,
            *self.replay.prompt_artifact_ids,
            *self.replay.tool_output_artifact_ids,
            *self.replay.cleaned_chunk_artifact_ids,
            *self.replay.response_artifact_ids,
            *self.evidence_accounting.total_cleaned_chunk_ids,
            *self.evidence_accounting.retained_chunk_ids,
        }
        for span in self.spans:
            referenced_ids.update(span.input_artifact_ids)
            referenced_ids.update(span.output_artifact_ids)
            if span.model is not None:
                referenced_ids.update(
                    item
                    for item in (
                        span.model.prompt_artifact_id,
                        span.model.response_artifact_id,
                        span.model.parameters_artifact_id,
                    )
                    if item is not None
                )
            if span.expansion is not None:
                referenced_ids.add(span.expansion.expanded_query_artifact_id)
            if span.sandbox is not None:
                referenced_ids.update(
                    item
                    for item in (
                        span.sandbox.stdout_artifact_id,
                        span.sandbox.stderr_artifact_id,
                    )
                    if item is not None
                )
        for attempt_diff in self.attempt_diffs:
            referenced_ids.update(
                (
                    attempt_diff.from_code_artifact_id,
                    attempt_diff.to_code_artifact_id,
                    attempt_diff.diff_artifact_id,
                )
            )
        if not referenced_ids.issubset(known_ids):
            missing = sorted(str(item) for item in referenced_ids - known_ids)
            raise ValueError(f"trace references unknown artifacts: {missing!r}")

    def to_dict(self) -> dict[str, object]:
        """Return the complete schema as a recursively redacted JSON value."""
        value = _json_value(self)
        # Root aggregate names follow PRD §5.1 while the aggregate object keeps
        # completeness and missing-field detail explicit.
        aggregate = value["aggregate"]
        assert isinstance(aggregate, dict)
        value.update(
            {
                "total_cost_usd": aggregate["total_cost_usd"],
                "total_prompt_tokens": aggregate["total_prompt_tokens"],
                "total_completion_tokens": aggregate["total_completion_tokens"],
                "total_reasoning_tokens": aggregate["total_reasoning_tokens"],
                "provider_usage_complete": aggregate["complete"],
                "missing_provider_fields": aggregate["missing_provider_fields"],
            }
        )
        evidence = value["evidence_accounting"]
        assert isinstance(evidence, dict)
        value["total_cleaned_evidence_tokens"] = evidence[
            "total_cleaned_evidence_tokens"
        ]
        value["retained_evidence_tokens"] = evidence["retained_evidence_tokens"]
        return redact(value)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )

    def write_json(self, path: str | Path) -> None:
        """Persist one trace document. Filesystem I/O occurs only when called."""
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_json(cls, document: str) -> ExecutionTrace:
        data = json.loads(document)
        return _trace_from_dict(data)

    @classmethod
    def read_json(cls, path: str | Path) -> ExecutionTrace:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


class TraceRecorder:
    """Narrow in-memory interface for ordered trace collection."""

    def __init__(self, trace_id: str, task_summary: str, *, started_at: str | None = None):
        if not trace_id.strip() or not task_summary.strip():
            raise ValueError("trace_id and task_summary must not be empty")
        self.trace_id = trace_id
        self.task_summary = redact(task_summary)
        self.started_at = started_at or utc_now()
        _timestamp(self.started_at)
        self._spans: list[TraceSpan] = []
        self._artifacts: dict[ArtifactId, ArtifactReference] = {}
        self._diffs: list[AttemptDiff] = []

    def add_artifact(self, artifact: ArtifactReference) -> None:
        if artifact.artifact_id in self._artifacts:
            raise ValueError(f"duplicate artifact ID: {artifact.artifact_id}")
        self._artifacts[artifact.artifact_id] = artifact

    def record_span(self, span: TraceSpan) -> None:
        self._spans.append(span)

    def record_attempt_diff(self, attempt_diff: AttemptDiff) -> None:
        if self._diffs and attempt_diff.from_attempt < self._diffs[-1].from_attempt:
            raise ValueError("attempt diffs must be recorded in attempt order")
        self._diffs.append(attempt_diff)

    def finish(
        self,
        *,
        ended_at: str,
        total_latency_ms: int | float,
        final_status: TerminalDisposition,
        accepted_attempt: int | None,
        replay: ReplayMetadata,
        evidence_accounting: EvidenceAccounting,
    ) -> ExecutionTrace:
        return ExecutionTrace(
            trace_id=self.trace_id,
            task_summary=self.task_summary,
            started_at=self.started_at,
            ended_at=ended_at,
            total_latency_ms=total_latency_ms,
            final_status=final_status,
            accepted_attempt=accepted_attempt,
            spans=tuple(self._spans),
            artifacts=tuple(self._artifacts.values()),
            replay=replay,
            attempt_diffs=tuple(self._diffs),
            evidence_accounting=evidence_accounting,
            aggregate=_aggregate(self._spans),
        )


def _artifact_id(value: str | None) -> ArtifactId | None:
    return None if value is None else ArtifactId(value)


def _ids(values: Sequence[str]) -> tuple[ArtifactId, ...]:
    return tuple(ArtifactId(value) for value in values)


def _usage(data: Mapping[str, Any]) -> ProviderUsage:
    return ProviderUsage(
        cost_usd=data["cost_usd"],
        prompt_tokens=data["prompt_tokens"],
        completion_tokens=data["completion_tokens"],
        reasoning_tokens=data["reasoning_tokens"],
        missing_fields=tuple(data["missing_fields"]),
        raw_provider_fields=data["raw_provider_fields"],
    )


def _span(data: Mapping[str, Any]) -> TraceSpan:
    model_data = data.get("model")
    expansion_data = data.get("expansion")
    discovery_data = data.get("discovery")
    extraction_data = data.get("extraction")
    security_data = data.get("security")
    sandbox_data = data.get("sandbox")
    return TraceSpan(
        step=WorkflowStep(data["step"]),
        status=StepStatus(data["status"]),
        latency_ms=data["latency_ms"],
        input_artifact_ids=_ids(data["input_artifact_ids"]),
        output_artifact_ids=_ids(data["output_artifact_ids"]),
        error_code=ErrorCode(data["error_code"]) if data["error_code"] else None,
        error_message=data["error_message"],
        retry_number=data["retry_number"],
        attempt_number=data["attempt_number"],
        model=ModelData(
            model_used=model_data["model_used"],
            reasoning_effort_sent=model_data["reasoning_effort_sent"],
            reasoning_effort_was_sent=model_data["reasoning_effort_was_sent"],
            include_reasoning_sent=model_data["include_reasoning_sent"],
            usage=_usage(model_data["usage"]),
            prompt_artifact_id=_artifact_id(model_data["prompt_artifact_id"]),
            response_artifact_id=_artifact_id(model_data["response_artifact_id"]),
            parameters_artifact_id=_artifact_id(
                model_data["parameters_artifact_id"]
            ),
        )
        if model_data
        else None,
        expansion=ExpansionData(
            expanded_query_artifact_id=ArtifactId(
                expansion_data["expanded_query_artifact_id"]
            ),
            target_tiers=tuple(
                EvidenceTier(value) for value in expansion_data["target_tiers"]
            ),
            parse_status=expansion_data["parse_status"],
        )
        if expansion_data
        else None,
        discovery=DiscoveryData(
            urls_found=discovery_data["urls_found"],
            usable_results=discovery_data["usable_results"],
            deduplication_count=discovery_data["deduplication_count"],
            result_tiers=tuple(EvidenceTier(v) for v in discovery_data["result_tiers"]),
            source_domains=tuple(discovery_data["source_domains"]),
            http_statuses=tuple(discovery_data["http_statuses"]),
            filtering_reasons=tuple(discovery_data["filtering_reasons"]),
        )
        if discovery_data
        else None,
        extraction=ExtractionData(
            raw_bytes=extraction_data["raw_bytes"],
            cleaned_tokens=extraction_data["cleaned_tokens"],
            comments_stripped=extraction_data["comments_stripped"],
            source_tier=EvidenceTier(extraction_data["source_tier"]),
            repository_stars=extraction_data["repository_stars"],
            extraction_failure=extraction_data["extraction_failure"],
        )
        if extraction_data
        else None,
        security=SecurityData(
            flags=tuple(security_data["flags"]),
            instruction_like_content=security_data["instruction_like_content"],
        )
        if security_data
        else None,
        sandbox=SandboxData(
            exit_code=sandbox_data["exit_code"],
            test_passed=sandbox_data["test_passed"],
            stdout_artifact_id=_artifact_id(sandbox_data["stdout_artifact_id"]),
            stderr_artifact_id=_artifact_id(sandbox_data["stderr_artifact_id"]),
            timed_out=sandbox_data["timed_out"],
            error_category=sandbox_data["error_category"],
        )
        if sandbox_data
        else None,
        started_at=data["started_at"],
        ended_at=data["ended_at"],
    )


def _trace_from_dict(data: Mapping[str, Any]) -> ExecutionTrace:
    replay = data["replay"]
    evidence = data["evidence_accounting"]
    aggregate = data["aggregate"]
    return ExecutionTrace(
        trace_id=data["trace_id"],
        task_summary=data["task_summary"],
        started_at=data["started_at"],
        ended_at=data["ended_at"],
        total_latency_ms=data["total_latency_ms"],
        final_status=TerminalDisposition(data["final_status"]),
        accepted_attempt=data["accepted_attempt"],
        spans=tuple(_span(item) for item in data["spans"]),
        artifacts=tuple(
            ArtifactReference(
                artifact_id=ArtifactId(item["artifact_id"]),
                kind=ArtifactKind(item["kind"]),
                reference=item["reference"],
                media_type=item["media_type"],
                size_bytes=item["size_bytes"],
                digest=item["digest"],
                tier=EvidenceTier(item["tier"]) if item["tier"] else None,
                metadata=item["metadata"],
            )
            for item in data["artifacts"]
        ),
        replay=ReplayMetadata(
            prompt_artifact_ids=_ids(replay["prompt_artifact_ids"]),
            tool_output_artifact_ids=_ids(replay["tool_output_artifact_ids"]),
            cleaned_chunk_artifact_ids=_ids(replay["cleaned_chunk_artifact_ids"]),
            response_artifact_ids=_ids(replay["response_artifact_ids"]),
            configuration_artifact_id=ArtifactId(
                replay["configuration_artifact_id"]
            ),
            replayable_from_steps=tuple(
                WorkflowStep(value) for value in replay["replayable_from_steps"]
            ),
        ),
        attempt_diffs=tuple(
            AttemptDiff(
                from_attempt=item["from_attempt"],
                to_attempt=item["to_attempt"],
                from_code_artifact_id=ArtifactId(item["from_code_artifact_id"]),
                to_code_artifact_id=ArtifactId(item["to_code_artifact_id"]),
                diff_artifact_id=ArtifactId(item["diff_artifact_id"]),
                unified_diff=item["unified_diff"],
            )
            for item in data["attempt_diffs"]
        ),
        evidence_accounting=EvidenceAccounting(
            total_cleaned_evidence_tokens=evidence[
                "total_cleaned_evidence_tokens"
            ],
            total_cleaned_chunk_ids=_ids(evidence["total_cleaned_chunk_ids"]),
            retained_evidence_tokens=evidence["retained_evidence_tokens"],
            retained_chunk_ids=_ids(evidence["retained_chunk_ids"]),
        ),
        aggregate=UsageAggregate(
            total_cost_usd=aggregate["total_cost_usd"],
            total_prompt_tokens=aggregate["total_prompt_tokens"],
            total_completion_tokens=aggregate["total_completion_tokens"],
            total_reasoning_tokens=aggregate["total_reasoning_tokens"],
            complete=aggregate["complete"],
            missing_provider_fields=tuple(aggregate["missing_provider_fields"]),
        ),
        schema_version=data["schema_version"],
    )
