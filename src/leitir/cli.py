"""Thin command-line boundary for Leitir's existing application interfaces."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from enum import IntEnum
import hashlib
from pathlib import Path
import re
import signal
import sys
import threading
from typing import Protocol, TextIO
import uuid

from .config import Config
from .contracts import TargetLanguage, TerminalDisposition, WorkflowRequest
from .logging import redact
from .orchestrator import (
    CancellationToken,
    FiveStepOrchestrator,
    WorkflowComponents,
    WorkflowRunResult,
)
from .trace import ExecutionTrace, TraceRecorder


class ExitCode(IntEnum):
    """Stable process outcomes for automation."""

    SUCCESS = 0
    TASK_FAILURE = 1
    MALFORMED_USAGE = 2
    INFRASTRUCTURE_FAILURE = 3
    SPEND_CAP_TERMINATION = 4
    CANCELLED = 130


class EvaluationDriver(Protocol):
    """v1-11 extension point; the driver owns task selection and reporting."""

    def evaluate(
        self, run: Callable[[WorkflowRequest], WorkflowRunResult]
    ) -> object:
        """Execute evaluation tasks through the supplied orchestrator operation."""


class TraceWriter(Protocol):
    def __call__(self, trace: ExecutionTrace) -> str:
        """Persist one completed trace and return its reference."""


ConfigLoader = Callable[[], Config]
OrchestratorFactory = Callable[[Config], FiveStepOrchestrator]
EvaluationDriverFactory = Callable[[Config], EvaluationDriver]


class EvaluationDriverUnavailable(RuntimeError):
    """Raised until v1-11 supplies the concrete smoke evaluation driver."""


class _SafeArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message: str | None, file: TextIO | None = None) -> None:
        if message:
            (file or sys.stderr).write(str(redact(message)))


def _task(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("task must be nonblank")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="leitir",
        description="Leitir technical search and code synthesis",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="execute one task")
    run.add_argument(
        "--task", required=True, type=_task, help="task description"
    )
    run.add_argument(
        "--language",
        default=TargetLanguage.PYTHON.value,
        choices=(TargetLanguage.PYTHON.value,),
        help="target language (v1: python only)",
    )
    commands.add_parser("eval", help="run the configured evaluation driver")
    return parser


def build_orchestrator(config: Config) -> FiveStepOrchestrator:
    """Compose existing workflow components without duplicating their logic."""

    # Imports stay here so importing the CLI remains an effect-free operation.
    from .discovery import TargetedDiscovery, UrllibDiscoveryHttpTransport
    from .expansion import QueryExpander
    from .extraction import EvidenceExtractor, UrllibExtractionFetcher
    from .openrouter import OpenRouterHy3Client
    from .synthesis import EvidenceGroundedSynthesizer
    from .verification import DockerSandbox, Step5Controller

    def components(recorder: TraceRecorder) -> WorkflowComponents:
        client = OpenRouterHy3Client(config, trace_recorder=recorder)
        synthesis = EvidenceGroundedSynthesizer(
            client, config=config, trace_recorder=recorder
        )
        return WorkflowComponents(
            expansion=QueryExpander(
                client, config=config, trace_recorder=recorder
            ),
            discovery=TargetedDiscovery(
                UrllibDiscoveryHttpTransport(),
                config=config,
                trace_recorder=recorder,
            ),
            extraction=EvidenceExtractor(
                UrllibExtractionFetcher(),
                config=config,
                trace_recorder=recorder,
            ),
            synthesis=synthesis,
            verification=Step5Controller(
                DockerSandbox(config),
                synthesis,
                config,
                trace_recorder=recorder,
            ),
        )

    return FiveStepOrchestrator(components_factory=components, config=config)


def _missing_eval_driver(_config: Config) -> EvaluationDriver:
    raise EvaluationDriverUnavailable(
        "the evaluation driver is not installed; v1-11 supplies it"
    )


def write_trace(trace: ExecutionTrace) -> str:
    """Write exactly one trace document to Leitir's user-state directory."""

    root = Path.home() / ".local" / "state" / "leitir" / "traces"
    root.mkdir(parents=True, exist_ok=True)
    name = _trace_filename(trace.trace_id)
    destination = root / name
    temporary = root / f".{name}.{uuid.uuid4().hex}.tmp"
    try:
        temporary.write_text(trace.to_json(), encoding="utf-8")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return str(destination)


def _trace_filename(trace_id: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", trace_id).strip(".-")[:80]
    digest = hashlib.sha256(trace_id.encode("utf-8")).hexdigest()[:12]
    return f"{stem or 'trace'}-{digest}.json"


@contextmanager
def _cancellation_signals(token: CancellationToken):
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    installed: dict[signal.Signals, object] = {}

    def request_cancellation(_signum: int, _frame: object) -> None:
        token.cancel()

    for signum in (signal.SIGINT, signal.SIGTERM):
        installed[signum] = signal.getsignal(signum)
        signal.signal(signum, request_cancellation)
    try:
        yield
    finally:
        for signum, handler in installed.items():
            signal.signal(signum, handler)


def _exit_code(status: TerminalDisposition) -> ExitCode:
    if status is TerminalDisposition.ACCEPTED:
        return ExitCode.SUCCESS
    if status in {
        TerminalDisposition.FAILED,
        TerminalDisposition.REPAIR_EXHAUSTED,
    }:
        return ExitCode.TASK_FAILURE
    if status is TerminalDisposition.SPEND_CAP_EXCEEDED:
        return ExitCode.SPEND_CAP_TERMINATION
    if status is TerminalDisposition.CANCELLED:
        return ExitCode.CANCELLED
    return ExitCode.INFRASTRUCTURE_FAILURE


def _safe_print(message: object, *, file: TextIO) -> None:
    print(redact(str(message)), file=file)


def _write_result(
    result: WorkflowRunResult,
    *,
    trace_writer: TraceWriter,
    stdout: TextIO,
    stderr: TextIO,
) -> ExitCode:
    try:
        reference = trace_writer(result.trace_reference)
    except Exception as exc:
        # If persistence fails, stdout is the last-resort trace output. This
        # preserves the trace-on-every-started-run contract.
        _safe_print(result.trace_reference.to_json(), file=stdout)
        _safe_print(f"trace persistence failed: {exc}", file=stderr)
        reference = "stdout"
        status = TerminalDisposition.INFRASTRUCTURE_ERROR
    else:
        status = result.final_status
    _safe_print(
        f"status={status.value} trace={reference}",
        file=stdout,
    )
    return _exit_code(status)


def _run_operation(
    orchestrator: FiveStepOrchestrator,
    token: CancellationToken,
    trace_writer: TraceWriter,
    stdout: TextIO,
    stderr: TextIO,
) -> Callable[[WorkflowRequest], WorkflowRunResult]:
    def run(request: WorkflowRequest) -> WorkflowRunResult:
        result = orchestrator.run(request, cancellation=token)
        _write_result(
            result,
            trace_writer=trace_writer,
            stdout=stdout,
            stderr=stderr,
        )
        return result

    return run


def main(
    argv: Sequence[str] | None = None,
    *,
    config_loader: ConfigLoader = Config.default,
    orchestrator_factory: OrchestratorFactory = build_orchestrator,
    eval_driver_factory: EvaluationDriverFactory = _missing_eval_driver,
    trace_writer: TraceWriter = write_trace,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Parse one command and map existing application outcomes to exit codes."""

    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        config = config_loader()
        if not isinstance(config, Config):
            raise TypeError("configuration loader must return Config")
        orchestrator = orchestrator_factory(config)
    except Exception as exc:
        _safe_print(f"status=infrastructure_error error={exc}", file=err)
        return int(ExitCode.INFRASTRUCTURE_FAILURE)

    token = CancellationToken()
    with _cancellation_signals(token):
        if args.command == "run":
            request = WorkflowRequest(
                request_id=uuid.uuid4().hex,
                task=args.task,
                target_language=TargetLanguage(args.language),
            )
            try:
                result = orchestrator.run(request, cancellation=token)
            except KeyboardInterrupt:
                token.cancel()
                _safe_print(
                    "status=infrastructure_error error=run returned no trace",
                    file=err,
                )
                return int(ExitCode.INFRASTRUCTURE_FAILURE)
            except Exception as exc:
                _safe_print(
                    f"status=infrastructure_error error={exc}",
                    file=err,
                )
                return int(ExitCode.INFRASTRUCTURE_FAILURE)
            return int(
                _write_result(
                    result,
                    trace_writer=trace_writer,
                    stdout=out,
                    stderr=err,
                )
            )

        try:
            driver = eval_driver_factory(config)
            driver.evaluate(
                _run_operation(orchestrator, token, trace_writer, out, err)
            )
        except KeyboardInterrupt:
            token.cancel()
            _safe_print("status=cancelled trace=driver-managed", file=out)
            return int(ExitCode.CANCELLED)
        except Exception as exc:
            _safe_print(f"status=infrastructure_error error={exc}", file=err)
            return int(ExitCode.INFRASTRUCTURE_FAILURE)
        _safe_print("status=accepted trace=driver-managed", file=out)
        return int(ExitCode.SUCCESS)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EvaluationDriver",
    "EvaluationDriverUnavailable",
    "ExitCode",
    "TraceWriter",
    "build_orchestrator",
    "build_parser",
    "main",
    "write_trace",
]
