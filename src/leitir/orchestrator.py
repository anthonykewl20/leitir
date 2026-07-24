"""Deterministic coordination of Leitir's five existing workflow steps.

The orchestrator owns only state transitions, run-level spend, cancellation,
and final trace assembly.  Expansion, discovery, extraction, synthesis,
feedback construction, and sandbox classification remain in their step
modules.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
import hashlib
from pathlib import Path
import time
from typing import Protocol
import uuid

from .config import Config, OPENROUTER_MODEL
from .contracts import (
    ArtifactId,
    ErrorCode,
    QueryExpansionPlan,
    StepStatus,
    TerminalDisposition,
    WorkflowRequest,
    WorkflowStep,
)
from .discovery import (
    DiscoveryAuthError,
    DiscoveryEnginesBlockedError,
    DiscoveryResult,
    DiscoveryZeroResultsError,
)
from .expansion import ExpansionMalformedError
from .extraction import ExtractionResult
from .openrouter import (
    CredentialError,
    OpenRouterError,
    RequestValidationError,
    ResponseValidationError,
    TransportError,
)
from .synthesis import (
    PythonCandidate,
    RepairContext,
    SynthesisMalformedError,
    SynthesisMode,
    SynthesisPolicyError,
)
from .trace import (
    ArtifactKind,
    ArtifactReference,
    EvidenceAccounting,
    ExecutionTrace,
    ModelData,
    ProviderUsage,
    ReplayMetadata,
    SandboxData,
    SpendCapBreach,
    SynthesisData,
    TraceRecorder,
    TraceSpan,
    utc_now,
)
from .verification import (
    EvidenceState,
    FailureClassification,
    PythonVerificationTask,
    SandboxPolicyError,
    VerificationAttempt,
    build_repair_context,
    record_repair_diff,
)


class ExpansionStep(Protocol):
    def expand(
        self, request: WorkflowRequest, *, attempt_number: int = 1
    ) -> QueryExpansionPlan: ...


class DiscoveryStep(Protocol):
    def discover(
        self, plan: QueryExpansionPlan, *, attempt_number: int = 1
    ) -> DiscoveryResult: ...


class ExtractionStep(Protocol):
    def extract_all(
        self, candidates: DiscoveryResult, *, attempt_number: int = 1
    ) -> ExtractionResult: ...


class SynthesisStep(Protocol):
    def synthesize(
        self,
        request: WorkflowRequest,
        chunks: ExtractionResult,
        *,
        attempt_number: int = 1,
        repair_context: RepairContext | None = None,
    ) -> PythonCandidate: ...

    def repair(
        self,
        request: WorkflowRequest,
        chunks: ExtractionResult,
        context: RepairContext,
        *,
        attempt_number: int = 2,
    ) -> PythonCandidate: ...


class VerificationStep(Protocol):
    def verify_once(
        self,
        task: PythonVerificationTask,
        *,
        request: WorkflowRequest,
        evidence: ExtractionResult,
        hidden_tests: str | Path | None = None,
        evidence_state: EvidenceState = EvidenceState.CURRENT,
        last_allowed: bool = False,
    ) -> VerificationAttempt: ...


@dataclass(frozen=True, slots=True)
class WorkflowComponents:
    """One run's five injected step implementations."""

    expansion: ExpansionStep
    discovery: DiscoveryStep
    extraction: ExtractionStep
    synthesis: SynthesisStep
    verification: VerificationStep


class CancellationToken:
    """Small dependency-free cancellation token suitable for tests and CLIs."""

    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def is_cancelled(self) -> bool:
        return self._cancelled


class WorkflowStepFailure(RuntimeError):
    """An attributed, unrecoverable step failure from an injected double."""

    def __init__(
        self,
        step: WorkflowStep,
        message: str,
        *,
        error_code: ErrorCode | None = None,
    ) -> None:
        super().__init__(message)
        self.step = step
        self.error_code = error_code


@dataclass(frozen=True, slots=True)
class WorkflowRunResult:
    """The typed entry-operation result required by v1-09."""

    final_status: TerminalDisposition
    accepted_attempt: int | None
    trace_reference: ExecutionTrace
    accepted_candidate: PythonCandidate | None = None

    @property
    def status(self) -> TerminalDisposition:
        return self.final_status

    @property
    def trace(self) -> ExecutionTrace:
        return self.trace_reference

    @property
    def disposition(self) -> TerminalDisposition:
        return self.final_status


class _State(Enum):
    EXPANSION = WorkflowStep.QUERY_EXPANSION
    DISCOVERY = WorkflowStep.DISCOVERY
    EXTRACTION = WorkflowStep.EXTRACTION
    SYNTHESIS = WorkflowStep.SYNTHESIS
    REPAIR = "repair"
    VERIFICATION = WorkflowStep.VERIFICATION

    @property
    def step(self) -> WorkflowStep:
        if self is _State.REPAIR:
            return WorkflowStep.SYNTHESIS
        assert isinstance(self.value, WorkflowStep)
        return self.value

    @property
    def paid(self) -> bool:
        return self in {_State.EXPANSION, _State.SYNTHESIS, _State.REPAIR}


class _SpendLedger:
    def __init__(self, recorder: TraceRecorder, cap_usd: int | float) -> None:
        self._recorder = recorder
        self._cap = cap_usd
        self._decimal_cap = Decimal(str(cap_usd))
        self._observed = 0
        self.accumulated = Decimal("0")
        self.missing_cost_span_indexes: list[int] = []

    def observe(self) -> SpendCapBreach | None:
        if self._recorder.spend_cap_breach is not None:
            return self._recorder.spend_cap_breach
        spans = self._recorder.spans
        for index in range(self._observed, len(spans)):
            span = spans[index]
            if span.model is None:
                continue
            cost = span.model.usage.cost_usd
            if cost is None:
                self.missing_cost_span_indexes.append(index)
            else:
                self.accumulated += Decimal(str(cost))
            if self.accumulated > self._decimal_cap:
                breach = SpendCapBreach(
                    configured_cap_usd=self._cap,
                    accumulated_provider_cost_usd=float(self.accumulated),
                    triggering_span_index=index,
                    triggering_step=span.step,
                    triggering_attempt=span.attempt_number,
                    provider_cost_complete=not self.missing_cost_span_indexes,
                    missing_cost_span_indexes=tuple(
                        self.missing_cost_span_indexes
                    ),
                )
                self._recorder.record_spend_cap_breach(breach)
                self._observed = len(spans)
                return breach
        self._observed = len(spans)
        return None


class FiveStepOrchestrator:
    """Run Steps 1→5 with deterministic, bounded feedback routing."""

    def __init__(
        self,
        expansion: ExpansionStep | None = None,
        discovery: DiscoveryStep | None = None,
        extraction: ExtractionStep | None = None,
        synthesis: SynthesisStep | None = None,
        verification: VerificationStep | None = None,
        *,
        components_factory: Callable[[TraceRecorder], WorkflowComponents]
        | None = None,
        config: Config | None = None,
        trace_recorder: TraceRecorder | None = None,
        public_tests: Mapping[str, str] | None = None,
        dependencies: tuple[str, ...] = (),
        hidden_tests: str | Path | None = None,
        verification_task_factory: Callable[
            [PythonCandidate], PythonVerificationTask
        ]
        | None = None,
        evidence_state_resolver: Callable[
            [WorkflowRequest, ExtractionResult, PythonCandidate, int],
            EvidenceState,
        ]
        | None = None,
        trace_id_factory: Callable[[WorkflowRequest], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], str] = utc_now,
    ) -> None:
        if components_factory is not None and any(
            item is not None
            for item in (
                expansion,
                discovery,
                extraction,
                synthesis,
                verification,
            )
        ):
            raise ValueError(
                "provide either components_factory or fixed components, not both"
            )
        if components_factory is None and any(
            item is None
            for item in (
                expansion,
                discovery,
                extraction,
                synthesis,
                verification,
            )
        ):
            raise ValueError("all five fixed step components are required")
        self._fixed_components = (
            None
            if components_factory is not None
            else WorkflowComponents(
                expansion=expansion,  # type: ignore[arg-type]
                discovery=discovery,  # type: ignore[arg-type]
                extraction=extraction,  # type: ignore[arg-type]
                synthesis=synthesis,  # type: ignore[arg-type]
                verification=verification,  # type: ignore[arg-type]
            )
        )
        self._components_factory = components_factory
        self._config = config or Config.default()
        self._fixed_recorder = trace_recorder
        tests = dict(public_tests or {})
        if verification_task_factory is None:
            self._verification_task_factory = lambda candidate: (
                PythonVerificationTask(candidate, tests, dependencies)
            )
        else:
            self._verification_task_factory = verification_task_factory
        self._hidden_tests = hidden_tests
        self._evidence_state_resolver = (
            evidence_state_resolver
            or (
                lambda _request, _evidence, _candidate, _attempt: (
                    EvidenceState.CURRENT
                )
            )
        )
        self._trace_id_factory = trace_id_factory or (
            lambda request: f"{request.request_id}-{uuid.uuid4().hex}"
        )
        self._monotonic = monotonic
        self._now = now
        self._has_run = False

    def run(
        self,
        request: WorkflowRequest,
        *,
        cancellation: CancellationToken | Callable[[], bool] | object | None = None,
        public_tests: Mapping[str, str] | None = None,
        dependencies: tuple[str, ...] | None = None,
        hidden_tests: str | Path | None = None,
    ) -> WorkflowRunResult:
        """Execute one complete workflow and finalize exactly one trace.

        The optional verification inputs are an evaluator seam.  They are
        consumed only while constructing and executing Step 5; in particular,
        ``hidden_tests`` is never added to the workflow request, evidence, or
        synthesis/repair context.
        """

        if not isinstance(request, WorkflowRequest):
            raise TypeError("request must be a WorkflowRequest")
        max_repairs = min(self._config.max_repairs, 3)
        if self._fixed_recorder is not None and self._has_run:
            raise RuntimeError("a fixed trace recorder supports exactly one run")
        self._has_run = True
        recorder = self._fixed_recorder or TraceRecorder(
            self._trace_id_factory(request),
            request.task,
            started_at=self._now(),
        )
        if recorder.finished:
            raise RuntimeError("trace recorder is already finished")
        started = self._monotonic()
        config_id = self._record_configuration(recorder)
        try:
            components = (
                self._components_factory(recorder)
                if self._components_factory is not None
                else self._fixed_components
            )
            if not isinstance(components, WorkflowComponents):
                raise TypeError(
                    "components_factory must return WorkflowComponents"
                )
        except BaseException as exc:
            cancelled = isinstance(exc, KeyboardInterrupt)
            self._record_exception_if_needed(
                recorder,
                before=len(recorder.spans),
                step=WorkflowStep.QUERY_EXPANSION,
                attempt_number=1,
                input_ids=(),
                exc=exc,
                latency_ms=self._elapsed_ms(started),
                paid=False,
                error_code=self._error_code(exc),
            )
            accounting = EvidenceAccounting(0, (), 0, ())
            self._ensure_trace_artifacts(recorder, accounting)
            trace = recorder.finish(
                ended_at=self._now(),
                total_latency_ms=self._elapsed_ms(started),
                final_status=(
                    TerminalDisposition.CANCELLED
                    if cancelled
                    else TerminalDisposition.INFRASTRUCTURE_ERROR
                ),
                accepted_attempt=None,
                replay=self._replay_metadata(recorder, config_id),
                evidence_accounting=accounting,
            )
            return WorkflowRunResult(
                final_status=trace.final_status,
                accepted_attempt=None,
                trace_reference=trace,
            )
        ledger = _SpendLedger(recorder, self._config.spend_cap_usd)

        state = _State.EXPANSION
        attempt_number = 1
        feedback_loops = 0
        lineage: tuple[ArtifactId, ...] = ()
        plan: QueryExpansionPlan | None = None
        discovered: DiscoveryResult | None = None
        evidence: ExtractionResult | None = None
        candidate: PythonCandidate | None = None
        repair_context: RepairContext | None = None
        prior_diff = "Initial attempt; no earlier candidate diff."
        refresh_pending = False
        final_status: TerminalDisposition | None = None
        accepted_attempt: int | None = None
        accepted_candidate: PythonCandidate | None = None

        while final_status is None:
            step = state.step
            try:
                cancellation_requested = self._cancelled(cancellation)
            except BaseException as exc:
                self._record_exception_if_needed(
                    recorder,
                    before=len(recorder.spans),
                    step=step,
                    attempt_number=attempt_number,
                    input_ids=lineage,
                    exc=exc,
                    latency_ms=0,
                    paid=False,
                    error_code=self._error_code(exc),
                )
                final_status = (
                    TerminalDisposition.CANCELLED
                    if isinstance(exc, KeyboardInterrupt)
                    else TerminalDisposition.INFRASTRUCTURE_ERROR
                )
                break
            if cancellation_requested:
                self._record_fallback_span(
                    recorder,
                    step=step,
                    attempt_number=attempt_number,
                    input_ids=lineage,
                    status=StepStatus.SKIPPED,
                    error_code=None,
                    error_message="workflow cancellation requested",
                    paid=False,
                )
                final_status = TerminalDisposition.CANCELLED
                break

            # This pre-call guard is intentionally repeated even though a breach
            # is normally observed immediately after its triggering span.
            if state.paid and ledger.observe() is not None:
                final_status = TerminalDisposition.SPEND_CAP_EXCEEDED
                break

            before = len(recorder.spans)
            call_started = self._monotonic()
            try:
                if state is _State.EXPANSION:
                    plan = components.expansion.expand(
                        request, attempt_number=attempt_number
                    )
                    output = plan
                elif state is _State.DISCOVERY:
                    assert plan is not None
                    discovered = components.discovery.discover(
                        plan, attempt_number=attempt_number
                    )
                    output = discovered
                elif state is _State.EXTRACTION:
                    assert discovered is not None
                    evidence = components.extraction.extract_all(
                        discovered, attempt_number=attempt_number
                    )
                    output = evidence
                elif state is _State.SYNTHESIS:
                    assert evidence is not None
                    candidate = components.synthesis.synthesize(
                        request, evidence, attempt_number=attempt_number
                    )
                    self._validate_candidate(candidate, attempt_number, repair=False)
                    self._add_placeholder(
                        recorder, candidate.artifact_id, ArtifactKind.GENERATED_CODE
                    )
                    output = candidate
                elif state is _State.REPAIR:
                    assert evidence is not None and repair_context is not None
                    previous = repair_context.prior_candidate
                    candidate = components.synthesis.repair(
                        request,
                        evidence,
                        repair_context,
                        attempt_number=attempt_number,
                    )
                    self._validate_candidate(candidate, attempt_number, repair=True)
                    self._add_placeholder(
                        recorder, candidate.artifact_id, ArtifactKind.GENERATED_CODE
                    )
                    prior_diff = record_repair_diff(
                        previous,
                        candidate,
                        trace_recorder=recorder,
                        config=self._config,
                    )
                    output = candidate
                else:
                    assert evidence is not None and candidate is not None
                    if public_tests is None and dependencies is None:
                        verification_task = self._verification_task_factory(candidate)
                    else:
                        verification_task = PythonVerificationTask(
                            candidate,
                            public_tests or {},
                            dependencies or (),
                        )
                    evidence_state = self._evidence_state_resolver(
                        request, evidence, candidate, attempt_number
                    )
                    if not isinstance(evidence_state, EvidenceState):
                        raise TypeError(
                            "evidence_state_resolver must return EvidenceState"
                        )
                    verification_attempt = components.verification.verify_once(
                        verification_task,
                        request=request,
                        evidence=evidence,
                        hidden_tests=(
                            hidden_tests
                            if hidden_tests is not None
                            else self._hidden_tests
                        ),
                        evidence_state=evidence_state,
                        last_allowed=feedback_loops >= max_repairs,
                    )
                    self._validate_verification_attempt(
                        verification_attempt, candidate, attempt_number
                    )
                    output = verification_attempt
            except KeyboardInterrupt:
                self._record_exception_if_needed(
                    recorder,
                    before=before,
                    step=step,
                    attempt_number=attempt_number,
                    input_ids=lineage,
                    exc=KeyboardInterrupt(),
                    latency_ms=self._elapsed_ms(call_started),
                    paid=state.paid,
                    error_code=None,
                )
                ledger.observe()
                final_status = TerminalDisposition.CANCELLED
                break
            except BaseException as exc:
                self._record_exception_if_needed(
                    recorder,
                    before=before,
                    step=step,
                    attempt_number=attempt_number,
                    input_ids=lineage,
                    exc=exc,
                    latency_ms=self._elapsed_ms(call_started),
                    paid=state.paid,
                    error_code=self._error_code(exc),
                )
                if ledger.observe() is not None:
                    final_status = TerminalDisposition.SPEND_CAP_EXCEEDED
                else:
                    final_status = self._exception_disposition(exc)
                break

            if state is _State.VERIFICATION:
                assert isinstance(output, VerificationAttempt)
                self._record_verification_if_needed(
                    recorder,
                    before=before,
                    attempt=output,
                    input_ids=lineage,
                    latency_ms=self._elapsed_ms(call_started),
                )
            else:
                self._record_success_if_needed(
                    recorder,
                    before=before,
                    step=step,
                    attempt_number=attempt_number,
                    input_ids=lineage,
                    latency_ms=self._elapsed_ms(call_started),
                    paid=state.paid,
                    output=output,
                )
            new_spans = recorder.spans[before:]
            outputs = tuple(
                artifact_id
                for span in new_spans
                for artifact_id in span.output_artifact_ids
            )
            if outputs:
                lineage = tuple(dict.fromkeys(outputs))

            if ledger.observe() is not None:
                final_status = TerminalDisposition.SPEND_CAP_EXCEEDED
                break

            if state is _State.EXPANSION:
                state = _State.DISCOVERY
            elif state is _State.DISCOVERY:
                state = _State.EXTRACTION
            elif state is _State.EXTRACTION:
                state = _State.REPAIR if refresh_pending else _State.SYNTHESIS
                refresh_pending = False
            elif state in {_State.SYNTHESIS, _State.REPAIR}:
                state = _State.VERIFICATION
            else:
                attempt = output
                assert isinstance(attempt, VerificationAttempt)
                classification = attempt.classification
                if classification is FailureClassification.PASS:
                    final_status = TerminalDisposition.ACCEPTED
                    accepted_attempt = attempt.number
                    accepted_candidate = attempt.candidate
                    continue
                if classification is FailureClassification.INFRASTRUCTURE:
                    final_status = TerminalDisposition.INFRASTRUCTURE_ERROR
                    continue
                if classification is FailureClassification.TIMEOUT:
                    final_status = TerminalDisposition.FAILED
                    continue
                if feedback_loops >= max_repairs:
                    final_status = TerminalDisposition.REPAIR_EXHAUSTED
                    continue

                feedback_loops += 1
                repair_context = build_repair_context(
                    attempt,
                    prior_diff=prior_diff,
                    config=self._config,
                    hidden_tests_mounted=(
                        hidden_tests is not None or self._hidden_tests is not None
                    ),
                )
                attempt_number = feedback_loops + 1
                if classification in {
                    FailureClassification.MISSING_EVIDENCE,
                    FailureClassification.STALE_EVIDENCE,
                }:
                    plan = None
                    discovered = None
                    evidence = None
                    refresh_pending = True
                    state = _State.EXPANSION
                else:
                    state = _State.REPAIR

        assert final_status is not None
        accounting = self._evidence_accounting(candidate, evidence)
        self._ensure_trace_artifacts(recorder, accounting)
        replay = self._replay_metadata(recorder, config_id)
        trace = recorder.finish(
            ended_at=self._now(),
            total_latency_ms=self._elapsed_ms(started),
            final_status=final_status,
            accepted_attempt=accepted_attempt,
            replay=replay,
            evidence_accounting=accounting,
        )
        return WorkflowRunResult(
            final_status=final_status,
            accepted_attempt=accepted_attempt,
            trace_reference=trace,
            accepted_candidate=accepted_candidate,
        )

    execute = run
    orchestrate = run

    def _record_configuration(self, recorder: TraceRecorder) -> ArtifactId:
        digest = hashlib.sha256(self._config.serialize().encode("utf-8")).hexdigest()
        artifact_id = ArtifactId(f"configuration-{digest[:20]}")
        if artifact_id not in recorder.artifact_ids:
            recorder.add_artifact(
                ArtifactReference(
                    artifact_id,
                    ArtifactKind.CONFIGURATION,
                    f"memory://configuration/{artifact_id}",
                    media_type="application/json",
                    size_bytes=len(self._config.serialize().encode("utf-8")),
                    digest=digest,
                    metadata={"configuration": self._config.to_dict()},
                )
            )
        return artifact_id

    def _record_success_if_needed(
        self,
        recorder: TraceRecorder,
        *,
        before: int,
        step: WorkflowStep,
        attempt_number: int,
        input_ids: tuple[ArtifactId, ...],
        latency_ms: float,
        paid: bool,
        output: object,
    ) -> None:
        new_spans = recorder.spans[before:]
        if any(span.step is step for span in new_spans):
            return
        output_id = (
            output.artifact_id
            if isinstance(output, PythonCandidate)
            else ArtifactId(
                f"orchestrator-{recorder.trace_id}-step-{step.value}"
                f"-attempt-{attempt_number}-output"
            )
        )
        self._add_placeholder(recorder, output_id, self._output_kind(step))
        recorder.record_span(
            TraceSpan(
                step=step,
                status=StepStatus.SUCCEEDED,
                latency_ms=latency_ms,
                input_artifact_ids=input_ids,
                output_artifact_ids=(output_id,),
                attempt_number=attempt_number,
                model=(
                    self._missing_model_data(step)
                    if paid and not any(span.model is not None for span in new_spans)
                    else None
                ),
            )
        )

    def _record_exception_if_needed(
        self,
        recorder: TraceRecorder,
        *,
        before: int,
        step: WorkflowStep,
        attempt_number: int,
        input_ids: tuple[ArtifactId, ...],
        exc: BaseException,
        latency_ms: float,
        paid: bool,
        error_code: ErrorCode | None,
    ) -> None:
        if len(recorder.spans) != before:
            return
        normalized_code = error_code
        if normalized_code is None:
            normalized_code = {
                WorkflowStep.QUERY_EXPANSION: ErrorCode.ERR_EXPANSION_MALFORMED,
                WorkflowStep.DISCOVERY: ErrorCode.ERR_SEARCH_ZERO_RESULTS,
                WorkflowStep.EXTRACTION: ErrorCode.ERR_SCRAPE_BOILERPLATE_LEAK,
            }.get(step)
        recorder.record_span(
            TraceSpan(
                step=step,
                status=StepStatus.FAILED,
                latency_ms=latency_ms,
                input_artifact_ids=input_ids,
                error_code=normalized_code,
                error_message=f"{type(exc).__name__}: {exc}",
                attempt_number=attempt_number,
                model=self._missing_model_data(step) if paid else None,
                synthesis=(
                    SynthesisData(
                        mode="repair" if attempt_number > 1 else "initial",
                        parse_status="provider_failure",
                        candidate_artifact_id=None,
                        total_cleaned_evidence_tokens=0,
                        total_cleaned_chunk_ids=(),
                        retained_evidence_tokens=0,
                        retained_chunk_ids=(),
                        is_first_prompt=attempt_number == 1,
                    )
                    if step is WorkflowStep.SYNTHESIS
                    else None
                ),
                sandbox=(
                    SandboxData(
                        exit_code=None,
                        test_passed=None,
                        stdout_artifact_id=None,
                        stderr_artifact_id=None,
                        timed_out=False,
                        error_category=type(exc).__name__,
                        infrastructure_status="invalid",
                        classification="infrastructure",
                    )
                    if step is WorkflowStep.VERIFICATION
                    else None
                ),
            )
        )

    def _record_fallback_span(
        self,
        recorder: TraceRecorder,
        *,
        step: WorkflowStep,
        attempt_number: int,
        input_ids: tuple[ArtifactId, ...],
        status: StepStatus,
        error_code: ErrorCode | None,
        error_message: str,
        paid: bool,
    ) -> None:
        recorder.record_span(
            TraceSpan(
                step=step,
                status=status,
                latency_ms=0,
                input_artifact_ids=input_ids,
                error_code=error_code,
                error_message=error_message,
                attempt_number=attempt_number,
                model=self._missing_model_data(step) if paid else None,
            )
        )

    def _record_verification_if_needed(
        self,
        recorder: TraceRecorder,
        *,
        before: int,
        attempt: VerificationAttempt,
        input_ids: tuple[ArtifactId, ...],
        latency_ms: float,
    ) -> None:
        if len(recorder.spans) != before:
            return
        stdout_id = ArtifactId(f"{attempt.candidate_artifact_id}-stdout")
        stderr_id = ArtifactId(f"{attempt.candidate_artifact_id}-stderr")
        for artifact_id, kind, text in (
            (stdout_id, ArtifactKind.STDOUT, attempt.execution.stdout),
            (stderr_id, ArtifactKind.STDERR, attempt.execution.stderr),
        ):
            encoded = text.encode("utf-8")
            if artifact_id not in recorder.artifact_ids:
                recorder.add_artifact(
                    ArtifactReference(
                        artifact_id,
                        kind,
                        f"memory://step-5/{artifact_id}",
                        media_type="text/plain",
                        size_bytes=len(encoded),
                        digest=hashlib.sha256(encoded).hexdigest(),
                        metadata={"attempt_number": attempt.number},
                    )
                )
        category = attempt.execution.error_category
        if (
            attempt.classification is not FailureClassification.PASS
            and category is None
        ):
            category = attempt.classification.value
        recorder.record_span(
            TraceSpan(
                step=WorkflowStep.VERIFICATION,
                status=(
                    StepStatus.SUCCEEDED
                    if attempt.classification is FailureClassification.PASS
                    else StepStatus.FAILED
                ),
                latency_ms=latency_ms,
                input_artifact_ids=input_ids,
                output_artifact_ids=(stdout_id, stderr_id),
                error_code=attempt.error_code,
                error_message=category,
                attempt_number=attempt.number,
                sandbox=SandboxData(
                    exit_code=attempt.execution.exit_code,
                    test_passed=attempt.execution.test_passed,
                    stdout_artifact_id=stdout_id,
                    stderr_artifact_id=stderr_id,
                    timed_out=attempt.execution.timed_out,
                    error_category=category,
                    infrastructure_status=(
                        attempt.execution.infrastructure_status.value
                    ),
                    classification=attempt.classification.value,
                    repair_used=attempt.repair_used,
                    disposition=attempt.disposition.value,
                ),
            )
        )

    def _missing_model_data(self, step: WorkflowStep) -> ModelData:
        high = step is WorkflowStep.SYNTHESIS
        return ModelData(
            model_used=OPENROUTER_MODEL,
            reasoning_effort_sent="high" if high else None,
            reasoning_effort_was_sent=high,
            include_reasoning_sent=False,
            usage=ProviderUsage(
                cost_usd=None,
                prompt_tokens=None,
                completion_tokens=None,
                reasoning_tokens=None,
                missing_fields=ProviderUsage.FIELD_PATHS,
                raw_provider_fields={},
            ),
        )

    def _ensure_trace_artifacts(
        self, recorder: TraceRecorder, accounting: EvidenceAccounting
    ) -> None:
        references: set[ArtifactId] = {
            *accounting.total_cleaned_chunk_ids,
            *accounting.retained_chunk_ids,
        }
        for span in recorder.spans:
            references.update(span.input_artifact_ids)
            references.update(span.output_artifact_ids)
            if span.model is not None:
                references.update(
                    item
                    for item in (
                        span.model.prompt_artifact_id,
                        span.model.response_artifact_id,
                        span.model.parameters_artifact_id,
                    )
                    if item is not None
                )
            if span.expansion is not None:
                references.add(span.expansion.expanded_query_artifact_id)
            if span.synthesis is not None:
                references.update(span.synthesis.total_cleaned_chunk_ids)
                references.update(span.synthesis.retained_chunk_ids)
                references.update(span.synthesis.cited_chunk_ids)
                references.update(span.synthesis.deduplicated_chunk_ids)
                if span.synthesis.candidate_artifact_id is not None:
                    references.add(span.synthesis.candidate_artifact_id)
            if span.sandbox is not None:
                references.update(
                    item
                    for item in (
                        span.sandbox.stdout_artifact_id,
                        span.sandbox.stderr_artifact_id,
                    )
                    if item is not None
                )
        for artifact_id in references - recorder.artifact_ids:
            self._add_placeholder(recorder, artifact_id, ArtifactKind.OTHER)

    def _replay_metadata(
        self, recorder: TraceRecorder, configuration_id: ArtifactId
    ) -> ReplayMetadata:
        by_kind: dict[ArtifactKind, list[ArtifactId]] = {}
        for artifact in recorder.artifacts:
            by_kind.setdefault(artifact.kind, []).append(artifact.artifact_id)
        return ReplayMetadata(
            prompt_artifact_ids=tuple(by_kind.get(ArtifactKind.PROMPT, ())),
            tool_output_artifact_ids=tuple(
                by_kind.get(ArtifactKind.TOOL_OUTPUT, ())
            ),
            cleaned_chunk_artifact_ids=tuple(
                by_kind.get(ArtifactKind.CLEANED_CHUNK, ())
            ),
            response_artifact_ids=tuple(
                by_kind.get(ArtifactKind.MODEL_RESPONSE, ())
            ),
            configuration_artifact_id=configuration_id,
        )

    def _evidence_accounting(
        self,
        candidate: PythonCandidate | None,
        evidence: ExtractionResult | None,
    ) -> EvidenceAccounting:
        if candidate is not None:
            return candidate.evidence_accounting
        chunks = evidence.chunks if evidence is not None else ()
        return EvidenceAccounting(
            total_cleaned_evidence_tokens=sum(chunk.token_count for chunk in chunks),
            total_cleaned_chunk_ids=tuple(chunk.artifact_id for chunk in chunks),
            retained_evidence_tokens=0,
            retained_chunk_ids=(),
        )

    @staticmethod
    def _validate_candidate(
        candidate: PythonCandidate, attempt_number: int, *, repair: bool
    ) -> None:
        if not isinstance(candidate, PythonCandidate):
            raise TypeError("Step 4 must return PythonCandidate")
        if candidate.attempt_number != attempt_number:
            raise ValueError("Step 4 candidate attempt number is invalid")
        expected = SynthesisMode.REPAIR if repair else SynthesisMode.INITIAL
        if candidate.mode is not expected:
            raise ValueError("Step 4 candidate synthesis mode is invalid")

    @staticmethod
    def _validate_verification_attempt(
        attempt: VerificationAttempt,
        candidate: PythonCandidate,
        attempt_number: int,
    ) -> None:
        if not isinstance(attempt, VerificationAttempt):
            raise TypeError("Step 5 must return VerificationAttempt")
        if (
            attempt.number != candidate.attempt_number
            or attempt.candidate.artifact_id != candidate.artifact_id
        ):
            raise ValueError("Step 5 returned an attempt for another candidate")

    @staticmethod
    def _error_code(exc: BaseException) -> ErrorCode | None:
        if isinstance(exc, WorkflowStepFailure):
            return exc.error_code
        code = getattr(exc, "code", None)
        return code if isinstance(code, ErrorCode) else None

    @staticmethod
    def _exception_disposition(exc: BaseException) -> TerminalDisposition:
        attributed = (
            WorkflowStepFailure,
            ExpansionMalformedError,
            DiscoveryAuthError,
            DiscoveryEnginesBlockedError,
            DiscoveryZeroResultsError,
            SynthesisMalformedError,
            SynthesisPolicyError,
            SandboxPolicyError,
            ValueError,
            TypeError,
        )
        infrastructure = (
            CredentialError,
            OpenRouterError,
            RequestValidationError,
            ResponseValidationError,
            TransportError,
            OSError,
        )
        if isinstance(exc, attributed):
            return TerminalDisposition.FAILED
        if isinstance(exc, infrastructure):
            return TerminalDisposition.INFRASTRUCTURE_ERROR
        return TerminalDisposition.INFRASTRUCTURE_ERROR

    @staticmethod
    def _cancelled(
        cancellation: CancellationToken | Callable[[], bool] | object | None,
    ) -> bool:
        if cancellation is None:
            return False
        if callable(cancellation):
            return bool(cancellation())
        for name in ("is_cancelled", "is_set"):
            operation = getattr(cancellation, name, None)
            if callable(operation):
                return bool(operation())
        raise TypeError(
            "cancellation must be callable or expose is_cancelled()/is_set()"
        )

    @staticmethod
    def _output_kind(step: WorkflowStep) -> ArtifactKind:
        if step is WorkflowStep.SYNTHESIS:
            return ArtifactKind.GENERATED_CODE
        return ArtifactKind.TOOL_OUTPUT

    @staticmethod
    def _add_placeholder(
        recorder: TraceRecorder, artifact_id: ArtifactId, kind: ArtifactKind
    ) -> None:
        if artifact_id in recorder.artifact_ids:
            return
        recorder.add_artifact(
            ArtifactReference(
                artifact_id,
                kind,
                f"memory://orchestrator/{artifact_id}",
                metadata={"placeholder": True},
            )
        )

    def _elapsed_ms(self, started: float) -> float:
        return max(0, (self._monotonic() - started) * 1000)


Orchestrator = FiveStepOrchestrator
WorkflowOrchestrator = FiveStepOrchestrator


__all__ = [
    "CancellationToken",
    "FiveStepOrchestrator",
    "Orchestrator",
    "WorkflowComponents",
    "WorkflowOrchestrator",
    "WorkflowRunResult",
    "WorkflowStepFailure",
]
