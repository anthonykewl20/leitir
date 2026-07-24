"""Offline coverage for the v1-11 smoke evaluator and hidden boundary."""

from __future__ import annotations

import io
import json

from leitir.cli import ExitCode, main
from leitir.contracts import (
    ArtifactId,
    EvidenceTier,
    QueryExpansionPlan,
    QueryRecord,
    StepStatus,
    TerminalDisposition,
    WorkflowRequest,
    WorkflowStep,
)
from leitir.discovery import DiscoveryData, DiscoveryResult
from leitir.evaluation import (
    BENCHMARK_VERSION,
    SmokeBenchmark,
    SmokeEvaluationDriver,
    build_report,
)
from leitir.extraction import ExtractionResult
from leitir.orchestrator import FiveStepOrchestrator, WorkflowRunResult
from leitir.synthesis import (
    ChunkProvenance,
    EvidenceCitation,
    PythonCandidate,
    SynthesisMode,
)
from leitir.trace import (
    ArtifactKind,
    ArtifactReference,
    EvidenceAccounting,
    ModelData,
    ProviderUsage,
    ReplayMetadata,
    SandboxData,
    SpendCapBreach,
    SynthesisData,
    TraceRecorder,
    TraceSpan,
)
from leitir.verification import (
    AttemptDisposition,
    FailureClassification,
    InfrastructureStatus,
    SandboxExecution,
    TestOutcome as VerificationTestOutcome,
    VerificationAttempt,
    VerificationRoute,
)


def test_default_bundle_is_versioned_varied_python_docker_pytest():
    suite = SmokeBenchmark.default()

    assert suite.version == BENCHMARK_VERSION
    assert 3 <= len(suite.tasks) <= 5
    assert len({task.evidence_date for task in suite.tasks}) > 1
    assert len({task.declared_tiers for task in suite.tasks}) > 1
    for task in suite.tasks:
        assert task.valid
        assert task.dependency and task.dependency_version
        assert task.hidden_test_identity.startswith("leitir:smoke-v1:")
        assert task.hidden_test_directory.name == "hidden"
        assert (task.hidden_test_directory / "eval_test.py").is_file()
        dockerfile = (task.bundle_directory / "Dockerfile").read_text()
        assert "python" in dockerfile
        assert "pytest" in dockerfile
        assert "eval_test.py" not in task.prompt
        assert str(task.hidden_test_directory) not in task.prompt


def test_driver_supplies_hidden_mount_only_as_orchestrator_step5_input():
    suite = SmokeBenchmark.default()
    calls = []

    def run(request, **verification_inputs):
        task = suite.tasks[len(calls)]
        calls.append((request, verification_inputs))
        assert request.task == task.prompt
        # Generation-visible input contains neither source nor evaluator IDs.
        generation = json.dumps(
            {"request_id": request.request_id, "task": request.task}
        )
        hidden_source = (
            task.hidden_test_directory / "eval_test.py"
        ).read_text(encoding="utf-8")
        assert hidden_source not in generation
        assert task.hidden_test_identity not in generation
        assert "eval_test.py" not in generation
        assert verification_inputs == {
            "public_tests": {},
            "dependencies": task.dependencies,
            "hidden_tests": task.hidden_test_directory,
        }
        trace = _workflow_trace(
            f"driver-{task.task_id}",
            TerminalDisposition.ACCEPTED,
            accepted_attempt=1,
            verification=("pass",),
        )
        return WorkflowRunResult(
            TerminalDisposition.ACCEPTED, 1, trace
        )

    report = SmokeEvaluationDriver(suite).evaluate(run)

    assert len(calls) == len(suite.tasks)
    assert report.task_count == len(suite.tasks)
    assert report.outcomes["first_pass_pass"] == len(suite.tasks)


def test_cli_runs_fully_stubbed_suite_writes_one_trace_per_task_and_report():
    suite = SmokeBenchmark.default()

    class Orchestrator:
        def __init__(self):
            self.calls = []

        def run(self, request, *, cancellation=None, **verification_inputs):
            self.calls.append((request, cancellation, verification_inputs))
            trace = _workflow_trace(
                f"cli-{len(self.calls)}",
                TerminalDisposition.ACCEPTED,
                accepted_attempt=1,
                verification=("pass",),
            )
            return WorkflowRunResult(TerminalDisposition.ACCEPTED, 1, trace)

    orchestrator = Orchestrator()
    traces = []
    stdout = io.StringIO()
    code = main(
        ["eval"],
        orchestrator_factory=lambda _config: orchestrator,
        eval_driver_factory=lambda _config: SmokeEvaluationDriver(suite),
        trace_writer=lambda trace: traces.append(trace) or f"{trace.trace_id}.json",
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == ExitCode.SUCCESS
    assert len(orchestrator.calls) == len(suite.tasks)
    assert len(traces) == len(suite.tasks)
    lines = stdout.getvalue().splitlines()
    report = json.loads(lines[-2])
    assert report["benchmark_version"] == BENCHMARK_VERSION
    assert report["task_count"] == len(suite.tasks)
    assert lines[-1] == "status=accepted trace=driver-managed"


def test_integrated_orchestrator_never_leaks_hidden_input_to_repair_or_trace(
    tmp_path,
):
    hidden = tmp_path / "evaluator-secret-directory"
    hidden.mkdir()
    secret_source = "SECRET_HIDDEN_ASSERTION_9a83"
    (hidden / "eval_test.py").write_text(secret_source, encoding="utf-8")
    chunk = ArtifactId("secrecy-chunk")
    contexts = []
    verification_inputs = []

    def candidate(number):
        provenance = ChunkProvenance(
            chunk, ArtifactId("evidence"), EvidenceTier.TIER_1,
            "https://docs.example.test", 1, None, None, None,
        )
        return PythonCandidate(
            ArtifactId(f"secrecy-candidate-{number}"),
            f"answer = {number}\n",
            (chunk,),
            (EvidenceCitation(chunk, (provenance,)),),
            EvidenceAccounting(1, (chunk,), 1, (chunk,)),
            number,
            SynthesisMode.INITIAL if number == 1 else SynthesisMode.REPAIR,
        )

    class Steps:
        def expand(self, request, *, attempt_number=1):
            return QueryExpansionPlan(
                request,
                (
                    QueryRecord(
                        "contract",
                        "example.com",
                        EvidenceTier.TIER_1,
                        ("test",),
                    ),
                    QueryRecord(
                        "python", "docs.python.org", EvidenceTier.TIER_2, ("test",)
                    ),
                    QueryRecord(
                        "source", "github.com", EvidenceTier.TIER_3, ("test",)
                    ),
                ),
            )

        def discover(self, plan, *, attempt_number=1):
            return DiscoveryResult((), DiscoveryData(0, 0, 0))

        def extract_all(self, discovered, *, attempt_number=1):
            return ExtractionResult(())

        def synthesize(self, request, evidence, *, attempt_number=1):
            return candidate(attempt_number)

        def repair(self, request, evidence, context, *, attempt_number=2):
            contexts.append(context)
            return candidate(attempt_number)

        def verify_once(
            self, task, *, request, evidence, hidden_tests=None,
            evidence_state=None, last_allowed=False,
        ):
            verification_inputs.append(
                (task.public_tests, task.dependencies, hidden_tests)
            )
            passed = task.candidate.attempt_number == 2
            execution = SandboxExecution(
                exit_code=0 if passed else 1,
                stdout="passed" if passed else secret_source,
                stderr="" if passed else str(hidden / "eval_test.py"),
                test_outcome=(
                    VerificationTestOutcome.PASSED
                    if passed
                    else VerificationTestOutcome.FAILED
                ),
                timed_out=False,
                infrastructure_status=InfrastructureStatus.VALID,
                error_category=None if passed else "logic",
                output_limit_exceeded=False,
                duration_ms=1,
            )
            return VerificationAttempt(
                task.candidate.attempt_number,
                task.candidate,
                execution,
                (
                    FailureClassification.PASS
                    if passed
                    else FailureClassification.LOGIC
                ),
                (
                    VerificationRoute.ACCEPT
                    if passed
                    else VerificationRoute.STEP_4_REPAIR
                ),
                not passed,
                (
                    AttemptDisposition.ACCEPTED
                    if passed
                    else AttemptDisposition.REPAIR_PENDING
                ),
                ArtifactId(f"verified-{task.candidate.attempt_number}"),
            )

    steps = Steps()
    result = FiveStepOrchestrator(steps, steps, steps, steps, steps).run(
        WorkflowRequest("secrecy", "Implement only the public contract."),
        public_tests={"test_public.py": "def test_public(): assert True\n"},
        dependencies=(),
        hidden_tests=hidden,
    )

    assert result.final_status is TerminalDisposition.ACCEPTED, (
        result.trace_reference.to_json()
    )
    assert [item[2] for item in verification_inputs] == [hidden, hidden]
    assert all("test_public.py" in item[0] for item in verification_inputs)
    assert len(contexts) == 1
    assert secret_source not in contexts[0].diagnostics
    assert str(hidden) not in contexts[0].diagnostics
    serialized = result.trace_reference.to_json()
    assert secret_source not in serialized
    assert str(hidden) not in serialized
    assert "eval_test.py" not in serialized


def test_report_has_explicit_prd_metric_facts_and_outcome_classes():
    first = _workflow_trace(
        "first", TerminalDisposition.ACCEPTED,
        accepted_attempt=1, verification=("pass",), tier=EvidenceTier.TIER_1,
    )
    repaired = _workflow_trace(
        "repaired", TerminalDisposition.ACCEPTED,
        accepted_attempt=2, verification=("fail", "pass"),
        tier=EvidenceTier.TIER_3,
    )
    failed = _workflow_trace(
        "failed", TerminalDisposition.REPAIR_EXHAUSTED,
        verification=("fail", "fail"),
    )
    spend = _spend_trace()
    invalid = _workflow_trace(
        "invalid", TerminalDisposition.INFRASTRUCTURE_ERROR,
        verification=("invalid",),
    )

    report = build_report(
        BENCHMARK_VERSION,
        tuple(
            WorkflowRunResult(
                trace.final_status, trace.accepted_attempt, trace
            )
            for trace in (first, repaired, failed, spend, invalid)
        ),
    )
    document = report.to_dict()

    assert document["outcomes"] == {
        "first_pass_pass": 1,
        "repaired_pass": 1,
        "valid_failure": 1,
        "spend_cap_termination": 1,
        "infrastructure_invalid": 1,
    }
    assert report.ser.to_dict() == {
        "numerator": 90,
        "denominator": 300,
        "excluded_run_count": 2,
        "benchmark_version": BENCHMARK_VERSION,
        "percentage": 30.0,
    }
    assert (report.dri.numerator, report.dri.denominator) == (1, 2)
    assert report.dri.excluded_run_count == 3
    assert report.dri_distribution == {
        "tier_1_alone": 1,
        "tiers_1_2": 0,
        "tiers_1_3": 1,
    }
    assert (report.fpcr.numerator, report.fpcr.denominator) == (1, 4)
    assert report.fpcr.excluded_run_count == 1
    assert (report.sccr.numerator, report.sccr.denominator) == (1, 2)
    assert report.sccr.excluded_run_count == 3
    assert report.provider_usage["cost_usd"] == {
        "known_sum": 0.1,
        "reported_run_count": 1,
        "missing_run_count": 4,
    }
    assert report.policy["review_call_count"] == 0
    assert report.policy["reasoning_policy_violation_count"] == 0
    assert "does not establish full benchmark success" in report.small_sample_notice


def _workflow_trace(
    trace_id,
    status,
    *,
    accepted_attempt=None,
    verification=(),
    tier=EvidenceTier.TIER_2,
):
    recorder = TraceRecorder(
        trace_id, f"{trace_id} task", started_at="2026-01-01T00:00:00Z"
    )
    config = ArtifactId(f"{trace_id}-config")
    chunk = ArtifactId(f"{trace_id}-chunk")
    recorder.add_artifact(
        ArtifactReference(config, ArtifactKind.CONFIGURATION, "memory://config")
    )
    recorder.add_artifact(
        ArtifactReference(
            chunk, ArtifactKind.CLEANED_CHUNK, "memory://chunk", tier=tier
        )
    )
    attempt_count = max(len(verification), accepted_attempt or 1)
    for attempt in range(1, attempt_count + 1):
        candidate = ArtifactId(f"{trace_id}-candidate-{attempt}")
        recorder.add_artifact(
            ArtifactReference(
                candidate, ArtifactKind.GENERATED_CODE, "memory://candidate"
            )
        )
        recorder.record_span(
            TraceSpan(
                step=WorkflowStep.SYNTHESIS,
                status=StepStatus.SUCCEEDED,
                latency_ms=2,
                output_artifact_ids=(candidate,),
                attempt_number=attempt,
                synthesis=SynthesisData(
                    mode="initial" if attempt == 1 else "repair",
                    parse_status="parsed",
                    candidate_artifact_id=candidate,
                    total_cleaned_evidence_tokens=100,
                    total_cleaned_chunk_ids=(chunk,),
                    retained_evidence_tokens=30,
                    retained_chunk_ids=(chunk,),
                    cited_chunk_ids=(chunk,),
                    is_first_prompt=attempt == 1,
                ),
            )
        )
        if attempt <= len(verification):
            result = verification[attempt - 1]
            stdout = ArtifactId(f"{trace_id}-stdout-{attempt}")
            stderr = ArtifactId(f"{trace_id}-stderr-{attempt}")
            recorder.add_artifact(
                ArtifactReference(stdout, ArtifactKind.STDOUT, "memory://stdout")
            )
            recorder.add_artifact(
                ArtifactReference(stderr, ArtifactKind.STDERR, "memory://stderr")
            )
            invalid = result == "invalid"
            passed = result == "pass"
            recorder.record_span(
                TraceSpan(
                    step=WorkflowStep.VERIFICATION,
                    status=(
                        StepStatus.SUCCEEDED if passed else StepStatus.FAILED
                    ),
                    latency_ms=3,
                    input_artifact_ids=(candidate,),
                    output_artifact_ids=(stdout, stderr),
                    error_message=None if passed else result,
                    attempt_number=attempt,
                    sandbox=SandboxData(
                        exit_code=0 if passed else (None if invalid else 1),
                        test_passed=True if passed else (None if invalid else False),
                        stdout_artifact_id=stdout,
                        stderr_artifact_id=stderr,
                        timed_out=False,
                        error_category=None if passed else result,
                        infrastructure_status="invalid" if invalid else "valid",
                        classification=(
                            "pass" if passed else
                            ("infrastructure" if invalid else "logic")
                        ),
                    ),
                )
            )
    accounting = EvidenceAccounting(100, (chunk,), 30, (chunk,))
    return recorder.finish(
        ended_at="2026-01-01T00:00:01Z",
        total_latency_ms=10,
        final_status=status,
        accepted_attempt=accepted_attempt,
        replay=ReplayMetadata((), (), (chunk,), (), config),
        evidence_accounting=accounting,
    )


def _spend_trace():
    recorder = TraceRecorder(
        "spend", "spend task", started_at="2026-01-01T00:00:00Z"
    )
    config = ArtifactId("spend-config")
    recorder.add_artifact(
        ArtifactReference(config, ArtifactKind.CONFIGURATION, "memory://config")
    )
    recorder.record_span(
        TraceSpan(
            step=WorkflowStep.QUERY_EXPANSION,
            status=StepStatus.SUCCEEDED,
            latency_ms=1,
            model=ModelData(
                model_used="tencent/hy3",
                reasoning_effort_sent=None,
                reasoning_effort_was_sent=False,
                include_reasoning_sent=False,
                usage=ProviderUsage(0.1, 10, 5, 0, (), {}),
            ),
        )
    )
    recorder.record_spend_cap_breach(
        SpendCapBreach(
            configured_cap_usd=0.05,
            accumulated_provider_cost_usd=0.1,
            triggering_span_index=0,
            triggering_step=WorkflowStep.QUERY_EXPANSION,
            triggering_attempt=1,
            provider_cost_complete=True,
        )
    )
    return recorder.finish(
        ended_at="2026-01-01T00:00:01Z",
        total_latency_ms=1,
        final_status=TerminalDisposition.SPEND_CAP_EXCEEDED,
        accepted_attempt=None,
        replay=ReplayMetadata((), (), (), (), config),
        evidence_accounting=EvidenceAccounting(0, (), 0, ()),
    )
