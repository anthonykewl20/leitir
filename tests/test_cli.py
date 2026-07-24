"""Operator-boundary tests for the thin Leitir CLI."""

from __future__ import annotations

import io
import signal

import pytest

from leitir.cli import ExitCode, main, write_trace
from leitir.config import Config
from leitir.contracts import (
    ArtifactId,
    StepStatus,
    TerminalDisposition,
    WorkflowRequest,
    WorkflowStep,
)
from leitir.orchestrator import WorkflowRunResult
from leitir.trace import (
    ArtifactKind,
    ArtifactReference,
    EvidenceAccounting,
    ExecutionTrace,
    ReplayMetadata,
    SpendCapBreach,
    TraceRecorder,
    TraceSpan,
)


def completed_trace(status: TerminalDisposition) -> ExecutionTrace:
    recorder = TraceRecorder("cli-test-trace", "safe task")
    config_id = ArtifactId("config")
    recorder.add_artifact(
        ArtifactReference(
            config_id,
            ArtifactKind.CONFIGURATION,
            "memory://config",
            media_type="application/json",
            size_bytes=2,
        )
    )
    if status is TerminalDisposition.SPEND_CAP_EXCEEDED:
        recorder.record_span(
            TraceSpan(
                step=WorkflowStep.QUERY_EXPANSION,
                status=StepStatus.SUCCEEDED,
                latency_ms=1,
                attempt_number=1,
            )
        )
        recorder.record_spend_cap_breach(
            SpendCapBreach(
                configured_cap_usd=0.05,
                accumulated_provider_cost_usd=0.051,
                triggering_span_index=0,
                triggering_step=WorkflowStep.QUERY_EXPANSION,
                triggering_attempt=1,
                provider_cost_complete=True,
            )
        )
    return recorder.finish(
        ended_at="2026-07-24T00:00:01Z",
        total_latency_ms=1,
        final_status=status,
        accepted_attempt=1 if status is TerminalDisposition.ACCEPTED else None,
        replay=ReplayMetadata(
            prompt_artifact_ids=(),
            tool_output_artifact_ids=(),
            cleaned_chunk_artifact_ids=(),
            response_artifact_ids=(),
            configuration_artifact_id=config_id,
        ),
        evidence_accounting=EvidenceAccounting(0, (), 0, ()),
    )


class FakeOrchestrator:
    def __init__(self, status: TerminalDisposition) -> None:
        self.status = status
        self.calls: list[tuple[WorkflowRequest, object]] = []

    def run(self, request, *, cancellation=None):
        self.calls.append((request, cancellation))
        trace = completed_trace(self.status)
        return WorkflowRunResult(self.status, trace.accepted_attempt, trace)


def invoke(
    status: TerminalDisposition = TerminalDisposition.ACCEPTED,
    *,
    argv: list[str] | None = None,
    trace_writer=None,
):
    orchestrator = FakeOrchestrator(status)
    written = []
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        argv or ["run", "--task", "Build a parser"],
        orchestrator_factory=lambda _config: orchestrator,
        trace_writer=trace_writer
        or (lambda trace: written.append(trace) or "trace.json"),
        stdout=out,
        stderr=err,
    )
    return code, orchestrator, written, out.getvalue(), err.getvalue()


def test_help_lists_run_and_eval_without_loading_config(capsys):
    loaded = False

    def config_loader():
        nonlocal loaded
        loaded = True
        return Config.default()

    assert main(["--help"], config_loader=config_loader) == ExitCode.SUCCESS
    output = capsys.readouterr().out
    assert "run" in output
    assert "eval" in output
    assert not loaded


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["run"],
        ["run", "--task", "   "],
        ["run", "--task", "work", "--language", "go"],
        ["eval", "--task", "not-allowed"],
    ],
)
def test_malformed_usage_has_distinct_exit_code(argv, capsys):
    assert main(argv) == ExitCode.MALFORMED_USAGE
    assert "usage:" in capsys.readouterr().err


def test_run_loads_config_and_invokes_orchestrator_once():
    loaded = []
    orchestrator = FakeOrchestrator(TerminalDisposition.ACCEPTED)
    traces = []
    code = main(
        ["run", "--task", "Do the thing", "--language", "python"],
        config_loader=lambda: loaded.append(True) or Config.default(),
        orchestrator_factory=lambda config: orchestrator,
        trace_writer=lambda trace: traces.append(trace) or "/tmp/t.json",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == ExitCode.SUCCESS
    assert loaded == [True]
    assert len(orchestrator.calls) == 1
    assert orchestrator.calls[0][0].task == "Do the thing"
    assert orchestrator.calls[0][0].target_language.value == "python"
    assert len(traces) == 1


@pytest.mark.parametrize(
    ("status", "exit_code"),
    [
        (TerminalDisposition.ACCEPTED, ExitCode.SUCCESS),
        (TerminalDisposition.FAILED, ExitCode.TASK_FAILURE),
        (TerminalDisposition.REPAIR_EXHAUSTED, ExitCode.TASK_FAILURE),
        (
            TerminalDisposition.INFRASTRUCTURE_ERROR,
            ExitCode.INFRASTRUCTURE_FAILURE,
        ),
        (
            TerminalDisposition.SPEND_CAP_EXCEEDED,
            ExitCode.SPEND_CAP_TERMINATION,
        ),
        (TerminalDisposition.CANCELLED, ExitCode.CANCELLED),
    ],
)
def test_run_exit_mapping_and_one_trace_for_every_terminal_result(
    status, exit_code
):
    code, orchestrator, traces, out, err = invoke(status)
    assert code == exit_code
    assert len(orchestrator.calls) == 1
    assert len(traces) == 1
    assert ExecutionTrace.from_json(traces[0].to_json()).final_status is status
    assert out == f"status={status.value} trace=trace.json\n"
    assert err == ""


def test_configuration_failure_is_safe_and_does_not_start_a_run():
    secret = "sk-or-v1-cli-secret"
    out = io.StringIO()
    err = io.StringIO()

    def fail():
        raise ValueError(f"Authorization: Bearer {secret}")

    code = main(
        ["run", "--task", "safe"],
        config_loader=fail,
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    assert secret not in err.getvalue()
    assert "Bearer [REDACTED]" in err.getvalue()
    assert out.getvalue() == ""


def test_trace_persistence_failure_falls_back_to_redacted_stdout():
    secret = "sk-or-v1-cli-secret"
    out = io.StringIO()
    err = io.StringIO()
    orchestrator = FakeOrchestrator(TerminalDisposition.ACCEPTED)

    def fail(_trace):
        raise OSError(f"Authorization: Bearer {secret}")

    code = main(
        ["run", "--task", "safe"],
        orchestrator_factory=lambda _config: orchestrator,
        trace_writer=fail,
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    lines = out.getvalue().splitlines()
    assert ExecutionTrace.from_json(lines[0]).trace_id == "cli-test-trace"
    assert lines[1] == "status=infrastructure_error trace=stdout"
    assert secret not in out.getvalue() + err.getvalue()


def test_default_trace_writer_persists_one_valid_trace(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    trace = completed_trace(TerminalDisposition.FAILED)

    reference = write_trace(trace)

    trace_files = list(
        (tmp_path / ".local" / "state" / "leitir" / "traces").iterdir()
    )
    assert len(trace_files) == 1
    assert str(trace_files[0]) == reference
    assert ExecutionTrace.read_json(reference) == trace


def test_signal_requests_cancellation_and_finalizes_trace():
    traces = []

    class SignalOrchestrator(FakeOrchestrator):
        def run(self, request, *, cancellation=None):
            handler = signal.getsignal(signal.SIGINT)
            assert callable(handler)
            handler(signal.SIGINT, None)
            assert cancellation.is_cancelled()
            self.calls.append((request, cancellation))
            trace = completed_trace(TerminalDisposition.CANCELLED)
            return WorkflowRunResult(TerminalDisposition.CANCELLED, None, trace)

    orchestrator = SignalOrchestrator(TerminalDisposition.CANCELLED)
    code = main(
        ["run", "--task", "safe"],
        orchestrator_factory=lambda _config: orchestrator,
        trace_writer=lambda trace: traces.append(trace) or "cancelled.json",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == ExitCode.CANCELLED
    assert len(traces) == 1
    assert traces[0].final_status is TerminalDisposition.CANCELLED


def test_eval_delegates_run_operation_and_driver_executes_task():
    orchestrator = FakeOrchestrator(TerminalDisposition.ACCEPTED)
    traces = []
    drivers = []

    class Driver:
        def __init__(self):
            self.calls = 0

        def evaluate(self, run):
            self.calls += 1
            result = run(WorkflowRequest("eval-1", "smoke task"))
            assert result.final_status is TerminalDisposition.ACCEPTED

    driver = Driver()
    code = main(
        ["eval"],
        orchestrator_factory=lambda _config: orchestrator,
        eval_driver_factory=lambda _config: drivers.append(driver) or driver,
        trace_writer=lambda trace: traces.append(trace) or "eval.json",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == ExitCode.SUCCESS
    assert drivers == [driver]
    assert driver.calls == 1
    assert [call[0].task for call in orchestrator.calls] == ["smoke task"]
    assert len(traces) == 1


def test_eval_without_v1_11_driver_is_an_infrastructure_failure():
    code, _orchestrator, traces, out, err = invoke(
        argv=["eval"],
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    assert traces == []
    assert out == ""
    assert "evaluation driver is not installed" in err


def test_invalid_language_error_redacts_authorization_value(capsys):
    secret = "sk-or-v1-cli-secret"
    code = main(
        [
            "run",
            "--task",
            "safe",
            "--language",
            f"Authorization:Bearer {secret}",
        ]
    )
    assert code == ExitCode.MALFORMED_USAGE
    assert secret not in capsys.readouterr().err
