"""Offline transition tests for the deterministic five-step orchestrator."""

from __future__ import annotations

from collections import deque

import pytest

from leitir import (
    ArtifactId,
    AttemptDisposition,
    CancellationToken,
    Config,
    DiscoveryData,
    DiscoveryResult,
    EvidenceAccounting,
    EvidenceCitation,
    EvidenceTier,
    ExecutionTrace,
    ExtractionResult,
    FailureClassification,
    FiveStepOrchestrator,
    InfrastructureStatus,
    ModelData,
    ProviderUsage,
    PythonCandidate,
    QueryExpansionPlan,
    QueryRecord,
    SandboxExecution,
    StepStatus,
    SynthesisData,
    SynthesisMode,
    TerminalDisposition,
    TestOutcome as VerificationTestOutcome,
    TraceRecorder,
    TraceSpan,
    VerificationAttempt,
    VerificationRoute,
    WorkflowRequest,
    WorkflowStep,
)
from leitir.synthesis import ChunkProvenance


REQUEST = WorkflowRequest("orchestrator-request", "Implement the fixture.")


def candidate(number: int) -> PythonCandidate:
    chunk_id = ArtifactId("fixture-chunk")
    provenance = ChunkProvenance(
        chunk_id=chunk_id,
        evidence_id=ArtifactId("fixture-evidence"),
        tier=EvidenceTier.TIER_1,
        source_uri="https://docs.example.test/api",
        ordinal=1,
        repository=None,
        file_path=None,
        revision="v1",
    )
    return PythonCandidate(
        artifact_id=ArtifactId(f"candidate-{number}"),
        code=f"answer = {number}\n",
        citation_ids=(chunk_id,),
        provenance=(EvidenceCitation(chunk_id, (provenance,)),),
        evidence_accounting=EvidenceAccounting(
            1, (chunk_id,), 1, (chunk_id,)
        ),
        attempt_number=number,
        mode=SynthesisMode.INITIAL if number == 1 else SynthesisMode.REPAIR,
    )


def execution(classification: FailureClassification) -> SandboxExecution:
    passed = classification is FailureClassification.PASS
    infrastructure = (
        InfrastructureStatus.INVALID
        if classification is FailureClassification.INFRASTRUCTURE
        else InfrastructureStatus.VALID
    )
    return SandboxExecution(
        exit_code=0 if passed else 1,
        stdout="passed" if passed else "failed",
        stderr="" if passed else classification.value,
        test_outcome=(
            VerificationTestOutcome.PASSED
            if passed
            else VerificationTestOutcome.FAILED
        ),
        timed_out=classification is FailureClassification.TIMEOUT,
        infrastructure_status=infrastructure,
        error_category=None if passed else classification.value,
        output_limit_exceeded=False,
        duration_ms=1,
    )


class Steps:
    def __init__(
        self,
        recorder: TraceRecorder,
        classifications: tuple[FailureClassification, ...],
        *,
        costs: tuple[float | None, ...] = (),
        fail_on: str | None = None,
    ) -> None:
        self.recorder = recorder
        self.classifications = deque(classifications)
        self.costs = deque(costs)
        self.fail_on = fail_on
        self.calls: list[str] = []

    def expand(self, request, *, attempt_number=1):
        self.calls.append("expand")
        self._maybe_fail("expand")
        self._model_span(WorkflowStep.QUERY_EXPANSION, attempt_number, high=False)
        return QueryExpansionPlan(
            request,
            (
                QueryRecord(
                    "provider api", "example.com", EvidenceTier.TIER_1, ("fixture",)
                ),
                QueryRecord(
                    "python api",
                    "docs.python.org",
                    EvidenceTier.TIER_2,
                    ("fixture",),
                ),
                QueryRecord(
                    "implementation", "github.com", EvidenceTier.TIER_3, ("fixture",)
                ),
            ),
        )

    def discover(self, plan, *, attempt_number=1):
        self.calls.append("discover")
        self._maybe_fail("discover")
        return DiscoveryResult((), DiscoveryData(0, 0, 0))

    def extract_all(self, candidates, *, attempt_number=1):
        self.calls.append("extract")
        self._maybe_fail("extract")
        return ExtractionResult(())

    def synthesize(self, request, evidence, *, attempt_number=1):
        self.calls.append("synthesize")
        if self.fail_on == "synthesis_accounted":
            retained_id = ArtifactId("retained-before-synthesis-failure")
            skipped_id = ArtifactId("skipped-before-synthesis-failure")
            self.recorder.record_span(
                TraceSpan(
                    step=WorkflowStep.SYNTHESIS,
                    status=StepStatus.FAILED,
                    latency_ms=1,
                    attempt_number=attempt_number,
                    synthesis=SynthesisData(
                        mode="initial",
                        parse_status="malformed",
                        candidate_artifact_id=None,
                        total_cleaned_evidence_tokens=7,
                        total_cleaned_chunk_ids=(retained_id, skipped_id),
                        retained_evidence_tokens=3,
                        retained_chunk_ids=(retained_id,),
                        is_first_prompt=True,
                    ),
                )
            )
            raise RuntimeError("synthesis failed after selecting evidence")
        self._maybe_fail("synthesize")
        self._model_span(WorkflowStep.SYNTHESIS, attempt_number, high=True)
        return candidate(attempt_number)

    def repair(self, request, evidence, context, *, attempt_number=2):
        self.calls.append("repair")
        self._maybe_fail("repair")
        assert context.prior_candidate.attempt_number == attempt_number - 1
        self._model_span(WorkflowStep.SYNTHESIS, attempt_number, high=True)
        return candidate(attempt_number)

    def verify_once(
        self,
        task,
        *,
        request,
        evidence,
        hidden_tests=None,
        evidence_state=None,
        last_allowed=False,
    ):
        self.calls.append("verify")
        self._maybe_fail("verify")
        classification = self.classifications.popleft()
        route = {
            FailureClassification.PASS: VerificationRoute.ACCEPT,
            FailureClassification.MISSING_EVIDENCE: VerificationRoute.STEP_1_REFRESH,
            FailureClassification.STALE_EVIDENCE: VerificationRoute.STEP_1_REFRESH,
            FailureClassification.INFRASTRUCTURE: VerificationRoute.TERMINAL,
            FailureClassification.TIMEOUT: VerificationRoute.TERMINAL,
        }.get(classification, VerificationRoute.STEP_4_REPAIR)
        disposition = {
            FailureClassification.PASS: AttemptDisposition.ACCEPTED,
            FailureClassification.MISSING_EVIDENCE: (
                AttemptDisposition.REFRESH_EVIDENCE
            ),
            FailureClassification.STALE_EVIDENCE: (
                AttemptDisposition.REFRESH_EVIDENCE
            ),
            FailureClassification.INFRASTRUCTURE: (
                AttemptDisposition.INFRASTRUCTURE_INVALID
            ),
            FailureClassification.TIMEOUT: AttemptDisposition.TIMEOUT,
        }.get(classification, AttemptDisposition.REPAIR_PENDING)
        return VerificationAttempt(
            number=task.candidate.attempt_number,
            candidate=task.candidate,
            execution=execution(classification),
            classification=classification,
            route=route,
            repair_used=route is VerificationRoute.STEP_4_REPAIR,
            disposition=disposition,
            candidate_artifact_id=ArtifactId(
                f"verified-{task.candidate.attempt_number}"
            ),
        )

    def _model_span(self, step, attempt, *, high):
        if not self.costs:
            return
        cost = self.costs.popleft()
        usage = ProviderUsage(
            cost_usd=cost,
            prompt_tokens=1,
            completion_tokens=1,
            reasoning_tokens=1 if high else 0,
            missing_fields=(
                ("usage.cost",) if cost is None else ()
            ),
            raw_provider_fields={},
        )
        self.recorder.record_span(
            TraceSpan(
                step=step,
                status=StepStatus.SUCCEEDED,
                latency_ms=1,
                attempt_number=attempt,
                model=ModelData(
                    "tencent/hy3",
                    "high" if high else None,
                    high,
                    False,
                    usage,
                ),
            )
        )

    def _maybe_fail(self, operation):
        if operation == self.fail_on:
            raise RuntimeError(f"{operation} infrastructure unavailable")


def orchestrator(
    classifications,
    *,
    costs=(),
    config=None,
    token=None,
    fail_on=None,
):
    recorder = TraceRecorder(
        "trace-orchestrator",
        REQUEST.task,
        started_at="2026-01-01T00:00:00Z",
    )
    steps = Steps(
        recorder,
        tuple(classifications),
        costs=tuple(costs),
        fail_on=fail_on,
    )
    workflow = FiveStepOrchestrator(
        steps,
        steps,
        steps,
        steps,
        steps,
        config=config,
        trace_recorder=recorder,
        trace_id_factory=lambda _request: "unused",
        monotonic=lambda: 1.0,
        now=lambda: "2026-01-01T00:00:01Z",
    )
    return workflow.run(REQUEST, cancellation=token), steps, recorder


def test_success_runs_five_steps_in_order_and_finalizes_one_trace():
    result, steps, recorder = orchestrator((FailureClassification.PASS,))
    assert result.final_status is TerminalDisposition.ACCEPTED
    assert result.accepted_attempt == 1
    assert steps.calls == [
        "expand",
        "discover",
        "extract",
        "synthesize",
        "verify",
    ]
    assert [span.step for span in result.trace.spans] == list(WorkflowStep)
    for previous, current in zip(
        result.trace.spans, result.trace.spans[1:]
    ):
        assert set(previous.output_artifact_ids) & set(
            current.input_artifact_ids
        )
    model_spans = [span for span in result.trace.spans if span.model is not None]
    assert model_spans[0].model.reasoning_effort_was_sent is False
    assert model_spans[1].model.reasoning_effort_sent == "high"
    assert all(
        span.step is not WorkflowStep.VERIFICATION for span in model_spans
    )
    assert recorder.finished
    with pytest.raises(RuntimeError, match="only once"):
        recorder.finish(
            ended_at="2026-01-01T00:00:02Z",
            total_latency_ms=1,
            final_status=TerminalDisposition.ACCEPTED,
            accepted_attempt=1,
            replay=result.trace.replay,
            evidence_accounting=result.trace.evidence_accounting,
        )


@pytest.mark.parametrize(
    "classification, expected",
    [
        (FailureClassification.TIMEOUT, TerminalDisposition.FAILED),
        (
            FailureClassification.INFRASTRUCTURE,
            TerminalDisposition.INFRASTRUCTURE_ERROR,
        ),
    ],
)
def test_terminal_verification_classes_do_not_run_more_steps(
    classification, expected
):
    result, steps, _ = orchestrator((classification,))
    assert result.final_status is expected
    assert steps.calls[-1] == "verify"
    assert steps.calls.count("verify") == 1


@pytest.mark.parametrize(
    "classification",
    [
        FailureClassification.MISSING_EVIDENCE,
        FailureClassification.STALE_EVIDENCE,
    ],
)
def test_missing_or_stale_evidence_repeats_steps_one_through_three(
    classification,
):
    result, steps, _ = orchestrator(
        (classification, FailureClassification.PASS)
    )
    assert result.final_status is TerminalDisposition.ACCEPTED
    assert steps.calls == [
        "expand",
        "discover",
        "extract",
        "synthesize",
        "verify",
        "expand",
        "discover",
        "extract",
        "repair",
        "verify",
    ]


def test_syntax_and_logic_repair_at_step_four_and_exhaust_after_three_loops():
    result, steps, _ = orchestrator(
        (
            FailureClassification.SYNTAX,
            FailureClassification.LOGIC,
            FailureClassification.SYNTAX,
            FailureClassification.LOGIC,
        )
    )
    assert result.final_status is TerminalDisposition.REPAIR_EXHAUSTED
    assert steps.calls.count("repair") == 3
    assert steps.calls.count("verify") == 4
    assert steps.calls.count("expand") == 1


def test_syntax_repair_can_succeed_on_the_next_attempt():
    result, steps, _ = orchestrator(
        (FailureClassification.SYNTAX, FailureClassification.PASS)
    )
    assert result.final_status is TerminalDisposition.ACCEPTED
    assert result.accepted_attempt == 2
    assert steps.calls[-3:] == ["verify", "repair", "verify"]


def test_spend_cap_breach_stops_before_another_step_and_records_trigger():
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,),
        costs=(0.051,),
    )
    assert result.final_status is TerminalDisposition.SPEND_CAP_EXCEEDED
    assert steps.calls == ["expand"]
    breach = result.trace.spend_cap_breach
    assert breach is not None
    assert breach.configured_cap_usd == 0.05
    assert breach.accumulated_provider_cost_usd == 0.051
    assert breach.triggering_step is WorkflowStep.QUERY_EXPANSION
    assert breach.provider_cost_complete
    restored = ExecutionTrace.from_json(result.trace.to_json())
    assert restored.spend_cap_breach == breach


def test_spend_accumulates_across_calls_and_stops_before_verification():
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,),
        costs=(0.03, 0.021),
    )
    assert result.final_status is TerminalDisposition.SPEND_CAP_EXCEEDED
    assert steps.calls == ["expand", "discover", "extract", "synthesize"]
    breach = result.trace.spend_cap_breach
    assert breach is not None
    assert breach.accumulated_provider_cost_usd == 0.051
    assert breach.triggering_step is WorkflowStep.SYNTHESIS


def test_spend_equal_to_cap_is_not_an_exceeded_cap():
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,),
        costs=(0.03, 0.02),
    )
    assert result.final_status is TerminalDisposition.ACCEPTED
    assert steps.calls[-1] == "verify"
    assert result.trace.aggregate.total_cost_usd == pytest.approx(0.05)
    assert result.trace.spend_cap_breach is None


def test_missing_cost_stays_incomplete_and_is_not_treated_as_zero():
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,),
        costs=(None, 0.001),
    )
    assert result.final_status is TerminalDisposition.ACCEPTED
    assert steps.calls[-1] == "verify"
    assert result.trace.aggregate.total_cost_usd is None
    assert not result.trace.aggregate.complete
    assert "usage.cost" in result.trace.aggregate.missing_provider_fields


def test_known_cost_can_breach_cap_while_cost_completeness_stays_false():
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,),
        costs=(None, 0.051),
    )
    assert result.final_status is TerminalDisposition.SPEND_CAP_EXCEEDED
    assert steps.calls[-1] == "synthesize"
    breach = result.trace.spend_cap_breach
    assert breach is not None
    assert breach.accumulated_provider_cost_usd == 0.051
    assert not breach.provider_cost_complete
    assert breach.missing_cost_span_indexes == (0,)


def test_cancellation_is_terminal_before_any_step_call():
    token = CancellationToken()
    token.cancel()
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,), token=token
    )
    assert result.final_status is TerminalDisposition.CANCELLED
    assert steps.calls == []
    assert len(result.trace.spans) == 1
    assert result.trace.spans[0].status is StepStatus.SKIPPED


@pytest.mark.parametrize(
    "operation",
    ["expand", "discover", "extract", "synthesize", "verify"],
)
def test_every_step_infrastructure_error_finalizes_and_stops(operation):
    result, steps, recorder = orchestrator(
        (FailureClassification.PASS,), fail_on=operation
    )
    assert result.final_status is TerminalDisposition.INFRASTRUCTURE_ERROR
    assert steps.calls[-1] == operation
    assert recorder.finished
    assert result.trace.spans[-1].status is StepStatus.FAILED


def test_synthesis_failure_preserves_selection_accounting_in_final_trace():
    result, steps, _ = orchestrator(
        (FailureClassification.PASS,),
        fail_on="synthesis_accounted",
    )

    assert result.final_status is TerminalDisposition.INFRASTRUCTURE_ERROR
    assert steps.calls[-1] == "synthesize"
    assert result.trace.evidence_accounting == EvidenceAccounting(
        total_cleaned_evidence_tokens=7,
        total_cleaned_chunk_ids=(
            ArtifactId("retained-before-synthesis-failure"),
            ArtifactId("skipped-before-synthesis-failure"),
        ),
        retained_evidence_tokens=3,
        retained_chunk_ids=(
            ArtifactId("retained-before-synthesis-failure"),
        ),
    )
