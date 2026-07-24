"""Structured trace, provider normalization, replay, and SER accounting."""

from __future__ import annotations

import json
import logging

import pytest

from leitir.config import Config
from leitir.contracts import (
    ArtifactId,
    ErrorCode,
    EvidenceTier,
    StepStatus,
    TerminalDisposition,
    WorkflowStep,
)
from leitir.logging import install_redaction
from leitir.trace import (
    ArtifactKind,
    ArtifactReference,
    AttemptDiff,
    EvidenceAccounting,
    ExecutionTrace,
    ModelData,
    ProviderUsage,
    ReplayMetadata,
    SandboxData,
    TraceRecorder,
    TraceSpan,
)


SECRET = "sk-or-v1-synthetic-secret-never-serialize"
START = "2026-07-24T01:00:00Z"
END = "2026-07-24T01:00:01Z"


def aid(value: str) -> ArtifactId:
    return ArtifactId(value)


def reference(
    value: str, kind: ArtifactKind, *, metadata: dict[str, object] | None = None
) -> ArtifactReference:
    return ArtifactReference(
        artifact_id=aid(value),
        kind=kind,
        reference=f"artifact://sha256/{value}",
        metadata=metadata or {},
    )


def complete_usage() -> ProviderUsage:
    return ProviderUsage.from_openrouter(
        {
            "usage": {
                "cost": 0.00125,
                "prompt_tokens": 101,
                "completion_tokens": 52,
                "completion_tokens_details": {"reasoning_tokens": 31},
                "provider_extension": "preserved",
            }
        }
    )


def build_trace(
    *,
    status: TerminalDisposition = TerminalDisposition.ACCEPTED,
    usage: ProviderUsage | None = None,
) -> ExecutionTrace:
    recorder = TraceRecorder("trace-1", "generate a parser", started_at=START)
    artifacts = (
        reference("prompt", ArtifactKind.PROMPT),
        reference("tool", ArtifactKind.TOOL_OUTPUT),
        reference("chunk-1", ArtifactKind.CLEANED_CHUNK),
        reference("chunk-2", ArtifactKind.CLEANED_CHUNK),
        reference("response", ArtifactKind.MODEL_RESPONSE),
        ArtifactReference(
            artifact_id=aid("config"),
            kind=ArtifactKind.CONFIGURATION,
            reference="artifact://config",
            metadata={
                "configuration": Config().to_dict(),
                "Authorization": f"Bearer {SECRET}",
            },
        ),
        reference("code-1", ArtifactKind.GENERATED_CODE),
        reference("code-2", ArtifactKind.GENERATED_CODE),
        reference("diff-1-2", ArtifactKind.ATTEMPT_DIFF),
        reference("stdout", ArtifactKind.STDOUT),
        reference("stderr", ArtifactKind.STDERR),
    )
    for item in artifacts:
        recorder.add_artifact(item)

    recorder.record_span(
        TraceSpan(
            step=WorkflowStep.SYNTHESIS,
            status=StepStatus.SUCCEEDED,
            latency_ms=850,
            input_artifact_ids=(aid("chunk-1"),),
            output_artifact_ids=(aid("code-1"),),
            model=ModelData(
                model_used="tencent/hy3",
                reasoning_effort_sent="high",
                reasoning_effort_was_sent=True,
                include_reasoning_sent=False,
                usage=usage or complete_usage(),
                prompt_artifact_id=aid("prompt"),
                response_artifact_id=aid("response"),
                parameters_artifact_id=aid("config"),
            ),
        )
    )
    recorder.record_span(
        TraceSpan(
            step=WorkflowStep.VERIFICATION,
            status=StepStatus.FAILED,
            latency_ms=150,
            input_artifact_ids=(aid("code-1"),),
            output_artifact_ids=(aid("stdout"), aid("stderr")),
            error_code=ErrorCode.ERR_SYNTAX_COMPILATION_FAIL,
            error_message=f"authorization: Bearer {SECRET}",
            sandbox=SandboxData(
                exit_code=1,
                test_passed=False,
                stdout_artifact_id=aid("stdout"),
                stderr_artifact_id=aid("stderr"),
                timed_out=False,
                error_category="syntax",
            ),
        )
    )
    recorder.record_attempt_diff(
        AttemptDiff.between(
            from_attempt=1,
            to_attempt=2,
            from_code_artifact_id=aid("code-1"),
            to_code_artifact_id=aid("code-2"),
            diff_artifact_id=aid("diff-1-2"),
            previous_code="answer = 1\n",
            current_code="answer = 2\n",
        )
    )
    return recorder.finish(
        ended_at=END,
        total_latency_ms=1000,
        final_status=status,
        accepted_attempt=2 if status is TerminalDisposition.ACCEPTED else None,
        replay=ReplayMetadata(
            prompt_artifact_ids=(aid("prompt"),),
            tool_output_artifact_ids=(aid("tool"),),
            cleaned_chunk_artifact_ids=(aid("chunk-1"), aid("chunk-2")),
            response_artifact_ids=(aid("response"),),
            configuration_artifact_id=aid("config"),
        ),
        evidence_accounting=EvidenceAccounting(
            total_cleaned_evidence_tokens=300,
            total_cleaned_chunk_ids=(aid("chunk-1"), aid("chunk-2")),
            retained_evidence_tokens=120,
            retained_chunk_ids=(aid("chunk-1"),),
        ),
    )


def test_provider_usage_exact_mapping_and_raw_preservation():
    usage = complete_usage()
    assert usage.cost_usd == 0.00125
    assert usage.prompt_tokens == 101
    assert usage.completion_tokens == 52
    assert usage.reasoning_tokens == 31
    assert usage.complete
    assert usage.raw_provider_fields["provider_extension"] == "preserved"


def test_missing_usage_is_null_flagged_and_never_zero_inferred():
    usage = ProviderUsage.from_openrouter(
        {"usage": {"completion_tokens": 7, "completion_tokens_details": {}}}
    )
    assert usage.cost_usd is None
    assert usage.prompt_tokens is None
    assert usage.completion_tokens == 7
    assert usage.reasoning_tokens is None
    assert usage.missing_fields == (
        "usage.cost",
        "usage.prompt_tokens",
        "usage.completion_tokens_details.reasoning_tokens",
    )
    trace = build_trace(usage=usage)
    payload = trace.to_dict()
    assert payload["total_cost_usd"] is None
    assert payload["total_prompt_tokens"] is None
    assert payload["total_completion_tokens"] == 7
    assert payload["total_reasoning_tokens"] is None
    assert payload["provider_usage_complete"] is False


@pytest.mark.parametrize(
    "status",
    [
        TerminalDisposition.ACCEPTED,
        TerminalDisposition.FAILED,
        TerminalDisposition.INFRASTRUCTURE_ERROR,
    ],
)
def test_success_failure_and_timeout_style_runs_round_trip(status, tmp_path):
    trace = build_trace(status=status)
    document = trace.to_json()
    loaded = ExecutionTrace.from_json(document)
    assert loaded.to_json() == document
    path = tmp_path / "trace.json"
    trace.write_json(path)
    assert ExecutionTrace.read_json(path).to_json() == document
    assert json.loads(document)["spans"][0]["step"] == 4
    assert json.loads(document)["spans"][1]["step"] == 5


def test_replay_diffs_and_evidence_accounting_are_explicit():
    payload = build_trace().to_dict()
    assert payload["replay"]["replayable_from_steps"] == [3, 4]
    assert payload["replay"]["prompt_artifact_ids"] == ["prompt"]
    assert payload["replay"]["tool_output_artifact_ids"] == ["tool"]
    assert payload["replay"]["cleaned_chunk_artifact_ids"] == [
        "chunk-1",
        "chunk-2",
    ]
    assert payload["replay"]["response_artifact_ids"] == ["response"]
    assert payload["replay"]["configuration_artifact_id"] == "config"
    assert payload["attempt_diffs"][0]["from_attempt"] == 1
    assert "-answer = 1" in payload["attempt_diffs"][0]["unified_diff"]
    assert "+answer = 2" in payload["attempt_diffs"][0]["unified_diff"]
    assert payload["total_cleaned_evidence_tokens"] == 300
    assert payload["retained_evidence_tokens"] == 120
    assert payload["evidence_accounting"]["total_cleaned_chunk_ids"] == [
        "chunk-1",
        "chunk-2",
    ]
    assert payload["evidence_accounting"]["retained_chunk_ids"] == ["chunk-1"]


def test_trace_and_exception_logging_never_emit_credentials():
    document = build_trace().to_json()
    assert SECRET not in document
    assert "[REDACTED]" in document

    messages: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record):
            messages.append(self.format(record))

    logger = logging.getLogger("leitir.trace.security")
    logger.handlers = [Capture()]
    logger.filters = []
    logger.propagate = False
    install_redaction(logger)
    logger.info("headers=%s", {"Authorization": f"Bearer {SECRET}"})
    try:
        raise RuntimeError(f"api_key={SECRET}")
    except RuntimeError:
        logger.exception("trace persistence failed")
    rendered = "\n".join(messages)
    assert SECRET not in rendered
    assert "[REDACTED]" in rendered


def test_attempts_and_spans_retain_deterministic_recording_order():
    trace = build_trace()
    assert [span.step for span in trace.spans] == [
        WorkflowStep.SYNTHESIS,
        WorkflowStep.VERIFICATION,
    ]
    assert trace.to_json() == trace.to_json()


def test_timeout_retry_and_repeated_attempt_fields_are_typed():
    span = TraceSpan(
        step=WorkflowStep.VERIFICATION,
        status=StepStatus.FAILED,
        latency_ms=120_000,
        retry_number=2,
        attempt_number=3,
        error_code=ErrorCode.ERR_VERIFICATION_TIMEOUT,
        sandbox=SandboxData(
            exit_code=None,
            test_passed=False,
            stdout_artifact_id=None,
            stderr_artifact_id=None,
            timed_out=True,
        ),
    )
    assert span.retry_number == 2
    assert span.attempt_number == 3
    assert span.sandbox is not None and span.sandbox.timed_out


def test_invalid_evidence_accounting_is_rejected():
    with pytest.raises(ValueError, match="retained"):
        EvidenceAccounting(
            total_cleaned_evidence_tokens=10,
            total_cleaned_chunk_ids=(aid("a"),),
            retained_evidence_tokens=11,
            retained_chunk_ids=(aid("a"),),
        )
