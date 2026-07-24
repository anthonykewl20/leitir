"""Step 5: least-privilege Docker verification and bounded repair control.

Candidate source is untrusted.  It is never imported or executed by the host:
the host only writes it into a task-scoped temporary directory which is mounted
read-only into an ephemeral, unprivileged, networkless container.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import time
from types import MappingProxyType
from typing import Any, Callable, Protocol
import uuid

from .config import Config
from .contracts import (
    ArtifactId,
    ErrorCode,
    StepStatus,
    TerminalDisposition,
    WorkflowRequest,
    WorkflowStep,
)
from .extraction import EvidenceChunk, ExtractionResult
from .logging import redact
from .protocols import ExecutionTraceRecorder, SandboxExecutor
from .synthesis import PythonCandidate, RepairContext
from .trace import (
    ArtifactKind,
    ArtifactReference,
    AttemptDiff,
    SandboxData,
    TraceSpan,
)


PYTEST_VERSION = "9.0.2"
BASE_IMAGE_TAG = f"leitir/python311-pytest:{PYTEST_VERSION}"
CONTAINER_USER = "65532:65532"
BASE_DOCKERFILE = f"""FROM python:3.11-slim
RUN python -m pip install --no-cache-dir pytest=={PYTEST_VERSION} \\
    && groupadd --gid 65532 leitir \\
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /tmp \\
       --shell /usr/sbin/nologin leitir
USER {CONTAINER_USER}
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "pytest"]
"""
PYTEST_ARGUMENTS = (
    "-q",
    "--tb=no",
    "--no-header",
    "-p",
    "no:cacheprovider",
    "-p",
    "leitir_pytest_plugin",
    "/workspace/tests",
)
_IMPORT_TEST = (
    "import candidate\n\n"
    "def test_leitir_candidate_imported():\n"
    "    assert candidate is not None\n"
)
_RESERVED_TEST = "test_000_leitir_candidate_import.py"
_PYTEST_PLUGIN = """\
_collection_category = None


def pytest_collectreport(report):
    global _collection_category
    if not report.failed:
        return
    diagnostic = (
        repr(report.longrepr) + getattr(report, "longreprtext", "")
    ).casefold()
    if any(name in diagnostic for name in (
        "syntaxerror", "indentationerror", "taberror"
    )):
        _collection_category = "syntax"
    elif _collection_category is None:
        _collection_category = "collection"


def pytest_terminal_summary(terminalreporter):
    if _collection_category is not None:
        terminalreporter.write_line(
            f"LEITIR_ERROR_CATEGORY={_collection_category}"
        )
"""
_DEPENDENCY = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)*\])?"
    r"(?:(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9.*+!_-]*"
    r"(?:,(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9.*+!_-]*)*)?$"
)
_PROTECTED_PROJECTS = frozenset({"pip", "pytest", "setuptools", "wheel"})
_SYNTAX_MARKERS = (
    "syntaxerror",
    "indentationerror",
    "taberror",
    "leitir_error_category=syntax",
)
_COLLECTION_FAILURE_MARKERS = (
    *_SYNTAX_MARKERS,
    "importerror",
    "modulenotfounderror",
    "leitir_error_category=collection",
)
_TRUNCATION = b"\n...[output truncated by Leitir]...\n"


class SandboxPolicyError(ValueError):
    """A task requested execution outside the fixed Python/pytest policy."""


class TestOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


class InfrastructureStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"


class EvidenceState(str, Enum):
    CURRENT = "current"
    MISSING = "missing"
    STALE = "stale"


class FailureClassification(str, Enum):
    PASS = "pass"
    SYNTAX = "syntax"
    LOGIC = "logic"
    MISSING_EVIDENCE = "missing_evidence"
    STALE_EVIDENCE = "stale_evidence"
    TIMEOUT = "timeout"
    INFRASTRUCTURE = "infrastructure"


class VerificationRoute(str, Enum):
    ACCEPT = "accept"
    STEP_4_REPAIR = "step_4_repair"
    STEP_1_REFRESH = "step_1_refresh"
    TERMINAL = "terminal"


class AttemptDisposition(str, Enum):
    ACCEPTED = "accepted"
    REPAIR_PENDING = "repair_pending"
    REFRESH_EVIDENCE = "refresh_evidence"
    TIMEOUT = "timeout"
    INFRASTRUCTURE_INVALID = "infrastructure_invalid"
    REPAIR_EXHAUSTED = "repair_exhausted"


@dataclass(frozen=True, slots=True)
class PythonVerificationTask:
    """Policy-controlled material for one Python candidate verification."""

    candidate: PythonCandidate
    public_tests: Mapping[str, str]
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, PythonCandidate):
            raise TypeError("candidate must be a PythonCandidate")
        if not isinstance(self.public_tests, Mapping):
            raise TypeError("public_tests must be a mapping")
        tests = dict(self.public_tests)
        for name, source in tests.items():
            _test_path(name)
            if name == _RESERVED_TEST:
                raise SandboxPolicyError(f"{name!r} is reserved by Leitir")
            if not isinstance(source, str):
                raise TypeError("public test source must be text")
        if isinstance(self.dependencies, (str, bytes)):
            raise TypeError("dependencies must be a tuple of declarations")
        normalized = tuple(_dependency(value) for value in self.dependencies)
        projects = tuple(_dependency_project(item) for item in normalized)
        if len(set(projects)) != len(projects):
            raise SandboxPolicyError("dependency projects must be unique")
        object.__setattr__(self, "public_tests", MappingProxyType(tests))
        object.__setattr__(self, "dependencies", normalized)


@dataclass(frozen=True, slots=True)
class SandboxExecution:
    """One bounded execution, including validity independent of test failure."""

    exit_code: int | None
    stdout: str
    stderr: str
    test_outcome: TestOutcome
    timed_out: bool
    infrastructure_status: InfrastructureStatus
    error_category: str | None
    output_limit_exceeded: bool
    duration_ms: int | float

    def __post_init__(self) -> None:
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool)
            or not isinstance(self.exit_code, int)
        ):
            raise TypeError("exit_code must be an integer or None")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be text")
        if not isinstance(self.test_outcome, TestOutcome):
            raise TypeError("test_outcome must be a TestOutcome")
        if not isinstance(self.infrastructure_status, InfrastructureStatus):
            raise TypeError("infrastructure_status must be an InfrastructureStatus")
        if not isinstance(self.timed_out, bool):
            raise TypeError("timed_out must be a bool")
        if not isinstance(self.output_limit_exceeded, bool):
            raise TypeError("output_limit_exceeded must be a bool")
        if self.timed_out and self.test_outcome is TestOutcome.PASSED:
            raise ValueError("a timed-out execution cannot pass")
        if (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, (int, float))
            or self.duration_ms < 0
        ):
            raise ValueError("duration_ms must be non-negative")
        if self.error_category is not None and not isinstance(
            self.error_category, str
        ):
            raise TypeError("error_category must be text or None")
        object.__setattr__(self, "stdout", redact(self.stdout))
        object.__setattr__(self, "stderr", redact(self.stderr))

    @property
    def valid_execution(self) -> bool:
        return self.infrastructure_status is InfrastructureStatus.VALID

    @property
    def test_passed(self) -> bool:
        return self.test_outcome is TestOutcome.PASSED


@dataclass(frozen=True, slots=True)
class VerificationAttempt:
    number: int
    candidate: PythonCandidate
    execution: SandboxExecution
    classification: FailureClassification
    route: VerificationRoute
    repair_used: bool
    disposition: AttemptDisposition
    candidate_artifact_id: ArtifactId
    error_code: ErrorCode | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.number, bool)
            or not isinstance(self.number, int)
            or not 1 <= self.number <= 4
        ):
            raise ValueError("verification attempt must be between one and four")
        if self.candidate.attempt_number != self.number:
            raise ValueError("candidate and verification attempt must match")
        if not isinstance(self.execution, SandboxExecution):
            raise TypeError("execution must be a SandboxExecution")
        if not isinstance(self.classification, FailureClassification):
            raise TypeError("classification must be a FailureClassification")
        if not isinstance(self.route, VerificationRoute):
            raise TypeError("route must be a VerificationRoute")
        if not isinstance(self.repair_used, bool):
            raise TypeError("repair_used must be a bool")
        if not isinstance(self.disposition, AttemptDisposition):
            raise TypeError("disposition must be an AttemptDisposition")
        if self.error_code is not None and not isinstance(
            self.error_code, ErrorCode
        ):
            raise TypeError("error_code must be an ErrorCode or None")

    @property
    def valid_execution(self) -> bool:
        return self.execution.valid_execution


@dataclass(frozen=True, slots=True)
class VerificationResult:
    attempts: tuple[VerificationAttempt, ...]
    disposition: TerminalDisposition
    route: VerificationRoute
    accepted_candidate: PythonCandidate | None = None
    repair_error_category: str | None = None

    def __post_init__(self) -> None:
        if not self.attempts:
            raise ValueError("verification requires at least one recorded attempt")
        if len(self.attempts) > 4:
            raise ValueError("verification cannot contain more than four attempts")
        if [item.number for item in self.attempts] != list(
            range(1, len(self.attempts) + 1)
        ):
            raise ValueError("verification attempts must be consecutive")
        if not isinstance(self.disposition, TerminalDisposition):
            raise TypeError("disposition must be a TerminalDisposition")
        if not isinstance(self.route, VerificationRoute):
            raise TypeError("route must be a VerificationRoute")
        if self.disposition is TerminalDisposition.ACCEPTED:
            if self.accepted_candidate is None:
                raise ValueError("accepted verification requires a candidate")
        elif self.accepted_candidate is not None:
            raise ValueError("only accepted verification has an accepted candidate")

    @property
    def valid_execution_count(self) -> int:
        return sum(item.valid_execution for item in self.attempts)


class RepairSynthesizer(Protocol):
    def repair(
        self,
        request: WorkflowRequest,
        chunks: ExtractionResult | Iterable[EvidenceChunk],
        context: RepairContext,
        *,
        attempt_number: int,
    ) -> PythonCandidate: ...


class DockerSandbox:
    """Create, run, and always destroy a hardened task-scoped container."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        docker_client: Any | None = None,
        run_label: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or Config.default()
        self._client = docker_client
        self._owns_client = docker_client is None
        label = run_label or uuid.uuid4().hex
        if (
            not isinstance(label, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label)
            or redact(label) != label
        ):
            raise SandboxPolicyError("run label must be short, safe text")
        self._run_label = label
        self._monotonic = monotonic

    def execute(
        self,
        task: PythonVerificationTask,
        *,
        hidden_tests: str | Path | None = None,
    ) -> SandboxExecution:
        if not isinstance(task, PythonVerificationTask):
            raise TypeError("task must be a PythonVerificationTask")
        hidden = _hidden_directory(hidden_tests)
        started = self._monotonic()
        client: Any | None = None
        ephemeral_image: str | None = None
        try:
            client = self._docker()
            self._ensure_base_image(client)
            if task.dependencies:
                ephemeral_image = self._dependency_image(client, task.dependencies)
            image = ephemeral_image or BASE_IMAGE_TAG
            with tempfile.TemporaryDirectory(prefix="leitir-step5-") as directory:
                workspace = Path(directory)
                _write_workspace(workspace, task)
                return self._run_container(
                    client,
                    image,
                    workspace,
                    hidden,
                    started,
                )
        except SandboxPolicyError:
            raise
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return self._infrastructure_failure(started, exc)
        finally:
            if ephemeral_image is not None and client is not None:
                try:
                    client.images.remove(ephemeral_image, force=True)
                except Exception:
                    pass
            if self._owns_client and client is not None:
                try:
                    client.close()
                except Exception:
                    pass
                self._client = None

    def _docker(self) -> Any:
        if self._client is None:
            import docker

            self._client = docker.from_env()
        return self._client

    def _ensure_base_image(self, client: Any) -> None:
        try:
            client.images.get(BASE_IMAGE_TAG)
            return
        except Exception as exc:
            if not _image_missing(exc):
                raise
        memory = self._config.sandbox_memory_mb * 1024 * 1024
        client.images.build(
            fileobj=io.BytesIO(BASE_DOCKERFILE.encode("utf-8")),
            tag=BASE_IMAGE_TAG,
            quiet=True,
            rm=True,
            forcerm=True,
            pull=True,
            network_mode="default",
            timeout=self._config.sandbox_timeout_seconds,
            shmsize=self._config.sandbox_tmpfs_mb * 1024 * 1024,
            use_config_proxy=False,
            container_limits={
                "memory": memory,
                "memswap": memory,
                "cpushares": 1024 * self._config.sandbox_cpu_count,
            },
        )

    def _dependency_image(
        self, client: Any, dependencies: tuple[str, ...]
    ) -> str:
        tag = f"leitir/task-{uuid.uuid4().hex}:ephemeral"
        dockerfile = (
            f"FROM {BASE_IMAGE_TAG}\n"
            "USER root\n"
            "COPY requirements.txt /tmp/leitir-requirements.txt\n"
            "RUN python -m pip install --no-cache-dir --only-binary=:all: "
            "--no-deps --requirement /tmp/leitir-requirements.txt "
            "&& rm -f /tmp/leitir-requirements.txt\n"
            f"USER {CONTAINER_USER}\n"
        )
        context = _build_context(
            {
                "Dockerfile": dockerfile.encode("utf-8"),
                "requirements.txt": (
                    "\n".join(dependencies) + "\n"
                ).encode("utf-8"),
            }
        )
        memory = self._config.sandbox_memory_mb * 1024 * 1024
        client.images.build(
            fileobj=context,
            custom_context=True,
            tag=tag,
            quiet=True,
            rm=True,
            forcerm=True,
            network_mode="default",
            timeout=self._config.sandbox_timeout_seconds,
            shmsize=self._config.sandbox_tmpfs_mb * 1024 * 1024,
            use_config_proxy=False,
            container_limits={
                "memory": memory,
                "memswap": memory,
                "cpushares": 1024 * self._config.sandbox_cpu_count,
            },
        )
        return tag

    def _run_container(
        self,
        client: Any,
        image: str,
        workspace: Path,
        hidden: Path | None,
        started: float,
    ) -> SandboxExecution:
        container: Any | None = None
        timed_out = False
        exit_code: int | None = None
        infrastructure_error: BaseException | None = None
        try:
            policy = self._runtime_policy(workspace, hidden)
            container = client.containers.create(image, **policy)
            container.start()
            try:
                wait_result = container.wait(
                    timeout=self._config.sandbox_timeout_seconds
                )
                if not isinstance(wait_result, Mapping):
                    raise RuntimeError("Docker wait returned an invalid result")
                status = wait_result.get("StatusCode")
                if isinstance(status, bool) or not isinstance(status, int):
                    raise RuntimeError("Docker wait omitted the exit status")
                exit_code = status
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                if _timeout(exc):
                    timed_out = True
                    try:
                        container.kill()
                    except Exception:
                        pass
                else:
                    infrastructure_error = exc
                    try:
                        container.kill()
                    except Exception:
                        pass

            stdout_bytes = b""
            stderr_bytes = b""
            try:
                stdout_bytes = _log_bytes(
                    container.logs(stdout=True, stderr=False)
                )
                stderr_bytes = _log_bytes(
                    container.logs(stdout=False, stderr=True)
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                infrastructure_error = infrastructure_error or exc
            stdout, stderr, truncated = _bounded_streams(
                stdout_bytes,
                stderr_bytes,
                self._config.sandbox_max_output_bytes,
            )
            elapsed = max(0, (self._monotonic() - started) * 1000)

            if infrastructure_error is not None or truncated:
                category = (
                    "output_limit"
                    if truncated
                    else f"docker_{type(infrastructure_error).__name__.lower()}"
                )
                return SandboxExecution(
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    test_outcome=TestOutcome.NOT_RUN,
                    timed_out=False,
                    infrastructure_status=InfrastructureStatus.INVALID,
                    error_category=category,
                    output_limit_exceeded=truncated,
                    duration_ms=elapsed,
                )
            if timed_out:
                return SandboxExecution(
                    exit_code=None,
                    stdout=stdout,
                    stderr=stderr,
                    test_outcome=TestOutcome.FAILED,
                    timed_out=True,
                    infrastructure_status=InfrastructureStatus.VALID,
                    error_category="timeout",
                    output_limit_exceeded=False,
                    duration_ms=elapsed,
                )

            combined = f"{stdout}\n{stderr}".casefold()
            passed = exit_code == 0
            category = None
            if not passed:
                category = (
                    "syntax"
                    if any(marker in combined for marker in _SYNTAX_MARKERS)
                    else "logic"
                )
            invalid_exit = (
                exit_code is None
                or exit_code in {3, 4, 5}
                or exit_code >= 128
                or (
                    exit_code == 2
                    and not any(
                        marker in combined
                        for marker in _COLLECTION_FAILURE_MARKERS
                    )
                )
            )
            if invalid_exit:
                return SandboxExecution(
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    test_outcome=TestOutcome.NOT_RUN,
                    timed_out=False,
                    infrastructure_status=InfrastructureStatus.INVALID,
                    error_category=f"pytest_exit_{exit_code}",
                    output_limit_exceeded=False,
                    duration_ms=elapsed,
                )
            return SandboxExecution(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                test_outcome=(
                    TestOutcome.PASSED if passed else TestOutcome.FAILED
                ),
                timed_out=False,
                infrastructure_status=InfrastructureStatus.VALID,
                error_category=category,
                output_limit_exceeded=False,
                duration_ms=elapsed,
            )
        finally:
            if container is not None:
                cleanup_error: Exception | None = None
                for _attempt in range(2):
                    try:
                        container.remove(force=True)
                        cleanup_error = None
                        break
                    except Exception as exc:
                        cleanup_error = exc
                if cleanup_error is not None:
                    raise RuntimeError(
                        "ephemeral sandbox container cleanup failed"
                    ) from cleanup_error

    def _runtime_policy(
        self, workspace: Path, hidden: Path | None
    ) -> dict[str, object]:
        volumes: dict[str, dict[str, str]] = {
            str(workspace.resolve()): {
                "bind": "/workspace",
                "mode": "ro",
            }
        }
        command = PYTEST_ARGUMENTS
        if hidden is not None:
            volumes[str(hidden)] = {"bind": "/hidden-tests", "mode": "ro"}
            command = (*command, "/hidden-tests")
        memory = f"{self._config.sandbox_memory_mb}m"
        output = self._config.sandbox_max_output_bytes
        return {
            "command": command,
            "detach": True,
            "stdin_open": False,
            "tty": False,
            "working_dir": "/workspace",
            "environment": {
                "HOME": "/tmp",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": "/workspace",
            },
            "volumes": volumes,
            "network_mode": "none",
            "network_disabled": True,
            "privileged": False,
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "user": CONTAINER_USER,
            "mem_limit": memory,
            "memswap_limit": memory,
            "nano_cpus": self._config.sandbox_cpu_count * 1_000_000_000,
            "pids_limit": self._config.sandbox_process_limit,
            "oom_kill_disable": False,
            "tmpfs": {
                "/tmp": (
                    "rw,noexec,nosuid,nodev,"
                    f"size={self._config.sandbox_tmpfs_mb}m,mode=1777"
                )
            },
            "shm_size": f"{self._config.sandbox_tmpfs_mb}m",
            "ipc_mode": "private",
            "init": True,
            "log_config": {
                "type": "local",
                "config": {
                    "max-size": f"{output}b",
                    "max-file": "1",
                    "compress": "false",
                },
            },
            "labels": {
                "org.leitir.component": "step5-sandbox",
                "org.leitir.run": self._run_label,
            },
        }

    def _infrastructure_failure(
        self, started: float, exc: BaseException
    ) -> SandboxExecution:
        elapsed = max(0, (self._monotonic() - started) * 1000)
        return SandboxExecution(
            exit_code=None,
            stdout="",
            stderr=f"Sandbox infrastructure failure ({type(exc).__name__})",
            test_outcome=TestOutcome.NOT_RUN,
            timed_out=False,
            infrastructure_status=InfrastructureStatus.INVALID,
            error_category=f"docker_{type(exc).__name__.lower()}",
            output_limit_exceeded=False,
            duration_ms=elapsed,
        )


class Step5Controller:
    """Verify once, then permit no more than three evidence-aware repairs."""

    def __init__(
        self,
        sandbox: SandboxExecutor,
        synthesizer: RepairSynthesizer,
        config: Config | None = None,
        *,
        trace_recorder: ExecutionTraceRecorder | None = None,
    ) -> None:
        self._sandbox = sandbox
        self._synthesizer = synthesizer
        self._config = config or Config.default()
        self._trace = trace_recorder

    def verify_once(
        self,
        task: PythonVerificationTask,
        *,
        request: WorkflowRequest,
        evidence: ExtractionResult | Iterable[EvidenceChunk],
        hidden_tests: str | Path | None = None,
        evidence_state: EvidenceState = EvidenceState.CURRENT,
        last_allowed: bool = False,
    ) -> VerificationAttempt:
        """Run and classify exactly one sandbox attempt.

        The five-step orchestrator owns feedback routing and calls this seam so
        no repair model call can occur behind its run-level spend guard.  The
        older :meth:`verify` operation remains the standalone bounded controller.
        """

        if not isinstance(task, PythonVerificationTask):
            raise TypeError("task must be a PythonVerificationTask")
        if not isinstance(request, WorkflowRequest):
            raise TypeError("request must be a WorkflowRequest")
        if not isinstance(evidence_state, EvidenceState):
            raise TypeError("evidence_state must be an EvidenceState")
        if not isinstance(last_allowed, bool):
            raise TypeError("last_allowed must be a bool")

        number = task.candidate.attempt_number
        snapshot = _candidate_snapshot_id(task.candidate, number)
        self._record_candidate(task.candidate, snapshot, set())
        try:
            execution = self._sandbox.execute(task, hidden_tests=hidden_tests)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            execution = SandboxExecution(
                exit_code=None,
                stdout="",
                stderr=f"Sandbox infrastructure failure ({type(exc).__name__})",
                test_outcome=TestOutcome.NOT_RUN,
                timed_out=False,
                infrastructure_status=InfrastructureStatus.INVALID,
                error_category=f"sandbox_{type(exc).__name__.lower()}",
                output_limit_exceeded=False,
                duration_ms=0,
            )
        classification = _classify(execution, evidence_state)
        route, disposition, repair_used, _ = _decision(
            classification, last_allowed
        )
        attempt = VerificationAttempt(
            number=number,
            candidate=task.candidate,
            execution=execution,
            classification=classification,
            route=route,
            repair_used=repair_used,
            disposition=disposition,
            candidate_artifact_id=snapshot,
            error_code=_error_code(classification),
        )
        self._record_attempt(attempt)
        return attempt

    def verify(
        self,
        task: PythonVerificationTask,
        *,
        request: WorkflowRequest,
        evidence: ExtractionResult | Iterable[EvidenceChunk],
        hidden_tests: str | Path | None = None,
        evidence_state: EvidenceState = EvidenceState.CURRENT,
    ) -> VerificationResult:
        if not isinstance(task, PythonVerificationTask):
            raise TypeError("task must be a PythonVerificationTask")
        if not isinstance(evidence_state, EvidenceState):
            raise TypeError("evidence_state must be an EvidenceState")
        chunks = (
            evidence.chunks
            if isinstance(evidence, ExtractionResult)
            else tuple(evidence)
        )
        attempts: list[VerificationAttempt] = []
        current_task = task
        prior_diff = "Initial attempt; no earlier candidate diff."
        recorded_candidates: set[ArtifactId] = set()

        # Config validation caps max_repairs at three, making attempt five and a
        # fourth repair structurally unreachable.
        for index in range(self._config.max_repairs + 1):
            number = index + 1
            candidate = current_task.candidate
            candidate_snapshot = _candidate_snapshot_id(candidate, number)
            self._record_candidate(candidate, candidate_snapshot, recorded_candidates)
            try:
                execution = self._sandbox.execute(
                    current_task, hidden_tests=hidden_tests
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                execution = SandboxExecution(
                    exit_code=None,
                    stdout="",
                    stderr=f"Sandbox infrastructure failure ({type(exc).__name__})",
                    test_outcome=TestOutcome.NOT_RUN,
                    timed_out=False,
                    infrastructure_status=InfrastructureStatus.INVALID,
                    error_category=f"sandbox_{type(exc).__name__.lower()}",
                    output_limit_exceeded=False,
                    duration_ms=0,
                )

            classification = _classify(execution, evidence_state)
            last_allowed = index == self._config.max_repairs
            route, disposition, repair_used, terminal = _decision(
                classification, last_allowed
            )
            error_code = _error_code(classification)
            attempt = VerificationAttempt(
                number=number,
                candidate=candidate,
                execution=execution,
                classification=classification,
                route=route,
                repair_used=repair_used,
                disposition=disposition,
                candidate_artifact_id=candidate_snapshot,
                error_code=error_code,
            )
            attempts.append(attempt)
            self._record_attempt(attempt)

            if terminal is not None:
                return VerificationResult(
                    tuple(attempts),
                    terminal,
                    route,
                    candidate if terminal is TerminalDisposition.ACCEPTED else None,
                )

            diagnostics = _repair_diagnostics(
                execution,
                self._config.repair_max_diagnostics_characters,
                hidden_tests_mounted=hidden_tests is not None,
            )
            context = RepairContext(
                prior_candidate=candidate,
                diagnostics=diagnostics,
                prior_diff=prior_diff,
            )
            try:
                repaired = self._synthesizer.repair(
                    request,
                    chunks,
                    context,
                    attempt_number=number + 1,
                )
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                return VerificationResult(
                    tuple(attempts),
                    TerminalDisposition.INFRASTRUCTURE_ERROR,
                    VerificationRoute.TERMINAL,
                    repair_error_category=type(exc).__name__,
                )
            if (
                repaired.attempt_number != number + 1
                or repaired.mode.value != "repair"
            ):
                raise ValueError("repair synthesizer returned an invalid attempt")

            repaired_snapshot = _candidate_snapshot_id(repaired, number + 1)
            self._record_candidate(
                repaired, repaired_snapshot, recorded_candidates
            )
            diff = AttemptDiff.between(
                from_attempt=number,
                to_attempt=number + 1,
                from_code_artifact_id=candidate_snapshot,
                to_code_artifact_id=repaired_snapshot,
                diff_artifact_id=_diff_id(candidate, repaired, number),
                previous_code=candidate.code,
                current_code=repaired.code,
            )
            self._record_diff(diff)
            prior_diff = _bounded_text(
                diff.unified_diff or "Repair made no textual change.",
                self._config.repair_max_diff_characters,
            )
            current_task = replace(current_task, candidate=repaired)

        raise AssertionError("bounded Step 5 loop did not terminate")

    def _record_candidate(
        self,
        candidate: PythonCandidate,
        snapshot_id: ArtifactId,
        recorded: set[ArtifactId],
    ) -> None:
        if self._trace is None or snapshot_id in recorded:
            return
        encoded = candidate.code.encode("utf-8")
        self._trace.add_artifact(
            ArtifactReference(
                snapshot_id,
                ArtifactKind.GENERATED_CODE,
                f"memory://step-5/{snapshot_id}",
                media_type="text/x-python",
                size_bytes=len(encoded),
                digest=hashlib.sha256(encoded).hexdigest(),
                metadata={
                    "attempt_number": candidate.attempt_number,
                    "source_candidate_artifact_id": candidate.artifact_id.value,
                    "verification_snapshot": True,
                },
            )
        )
        recorded.add(snapshot_id)

    def _record_attempt(self, attempt: VerificationAttempt) -> None:
        if self._trace is None:
            return
        prefix = str(attempt.candidate_artifact_id)
        stdout_id = ArtifactId(f"{prefix}-stdout")
        stderr_id = ArtifactId(f"{prefix}-stderr")
        for artifact_id, kind, text in (
            (stdout_id, ArtifactKind.STDOUT, attempt.execution.stdout),
            (stderr_id, ArtifactKind.STDERR, attempt.execution.stderr),
        ):
            encoded = text.encode("utf-8")
            self._trace.add_artifact(
                ArtifactReference(
                    artifact_id,
                    kind,
                    f"memory://step-5/{artifact_id}",
                    media_type="text/plain",
                    size_bytes=len(encoded),
                    digest=hashlib.sha256(encoded).hexdigest(),
                    metadata={
                        "attempt_number": attempt.number,
                        "bounded": True,
                    },
                )
            )
        self._trace.record_span(
            TraceSpan(
                step=WorkflowStep.VERIFICATION,
                status=(
                    StepStatus.SUCCEEDED
                    if attempt.classification is FailureClassification.PASS
                    else StepStatus.FAILED
                ),
                latency_ms=attempt.execution.duration_ms,
                input_artifact_ids=(attempt.candidate_artifact_id,),
                output_artifact_ids=(stdout_id, stderr_id),
                error_code=attempt.error_code,
                error_message=attempt.execution.error_category,
                retry_number=attempt.number - 1,
                attempt_number=attempt.number,
                sandbox=SandboxData(
                    exit_code=attempt.execution.exit_code,
                    test_passed=attempt.execution.test_passed,
                    stdout_artifact_id=stdout_id,
                    stderr_artifact_id=stderr_id,
                    timed_out=attempt.execution.timed_out,
                    error_category=attempt.execution.error_category,
                    infrastructure_status=(
                        attempt.execution.infrastructure_status.value
                    ),
                    classification=attempt.classification.value,
                    repair_used=attempt.repair_used,
                    disposition=attempt.disposition.value,
                ),
            )
        )

    def _record_diff(self, diff: AttemptDiff) -> None:
        if self._trace is None:
            return
        encoded = diff.unified_diff.encode("utf-8")
        self._trace.add_artifact(
            ArtifactReference(
                diff.diff_artifact_id,
                ArtifactKind.ATTEMPT_DIFF,
                f"memory://step-5/{diff.diff_artifact_id}",
                media_type="text/x-diff",
                size_bytes=len(encoded),
                digest=hashlib.sha256(encoded).hexdigest(),
                metadata={
                    "from_attempt": diff.from_attempt,
                    "to_attempt": diff.to_attempt,
                },
            )
        )
        self._trace.record_attempt_diff(diff)


def _classify(
    execution: SandboxExecution, evidence_state: EvidenceState
) -> FailureClassification:
    if execution.infrastructure_status is InfrastructureStatus.INVALID:
        return FailureClassification.INFRASTRUCTURE
    if execution.timed_out:
        return FailureClassification.TIMEOUT
    if execution.test_outcome is TestOutcome.PASSED:
        return FailureClassification.PASS
    if execution.error_category == "syntax":
        return FailureClassification.SYNTAX
    if evidence_state is EvidenceState.MISSING:
        return FailureClassification.MISSING_EVIDENCE
    if evidence_state is EvidenceState.STALE:
        return FailureClassification.STALE_EVIDENCE
    return FailureClassification.LOGIC


def _decision(
    classification: FailureClassification, last_allowed: bool
) -> tuple[
    VerificationRoute,
    AttemptDisposition,
    bool,
    TerminalDisposition | None,
]:
    if classification is FailureClassification.PASS:
        return (
            VerificationRoute.ACCEPT,
            AttemptDisposition.ACCEPTED,
            False,
            TerminalDisposition.ACCEPTED,
        )
    if classification is FailureClassification.INFRASTRUCTURE:
        return (
            VerificationRoute.TERMINAL,
            AttemptDisposition.INFRASTRUCTURE_INVALID,
            False,
            TerminalDisposition.INFRASTRUCTURE_ERROR,
        )
    if classification is FailureClassification.TIMEOUT:
        return (
            VerificationRoute.TERMINAL,
            AttemptDisposition.TIMEOUT,
            False,
            TerminalDisposition.FAILED,
        )
    if classification in {
        FailureClassification.MISSING_EVIDENCE,
        FailureClassification.STALE_EVIDENCE,
    }:
        return (
            VerificationRoute.STEP_1_REFRESH,
            AttemptDisposition.REFRESH_EVIDENCE,
            False,
            TerminalDisposition.FAILED,
        )
    if last_allowed:
        return (
            VerificationRoute.TERMINAL,
            AttemptDisposition.REPAIR_EXHAUSTED,
            False,
            TerminalDisposition.REPAIR_EXHAUSTED,
        )
    return (
        VerificationRoute.STEP_4_REPAIR,
        AttemptDisposition.REPAIR_PENDING,
        True,
        None,
    )


def _error_code(
    classification: FailureClassification,
) -> ErrorCode | None:
    if classification is FailureClassification.SYNTAX:
        return ErrorCode.ERR_SYNTAX_COMPILATION_FAIL
    if classification is FailureClassification.TIMEOUT:
        return ErrorCode.ERR_VERIFICATION_TIMEOUT
    return None


def _repair_diagnostics(
    execution: SandboxExecution,
    maximum: int,
    *,
    hidden_tests_mounted: bool,
) -> str:
    document = (
        f"pytest_exit_code={execution.exit_code!r}\n"
        f"test_outcome={execution.test_outcome.value}\n"
        f"error_category={execution.error_category or 'none'}"
    )
    if hidden_tests_mounted:
        document += (
            "\nhidden evaluation output omitted by Leitir; hidden test source "
            "and source-derived diagnostics are never sent to the model."
        )
    else:
        document += (
            "\n--- bounded stdout ---\n"
            f"{execution.stdout}\n"
            "--- bounded stderr ---\n"
            f"{execution.stderr}"
        )
    return _bounded_text(redact(document), maximum)


def build_repair_context(
    attempt: VerificationAttempt,
    *,
    prior_diff: str,
    config: Config | None = None,
    hidden_tests_mounted: bool = False,
) -> RepairContext:
    """Build the bounded, redacted Step 5 feedback consumed by Step 4."""

    if not isinstance(attempt, VerificationAttempt):
        raise TypeError("attempt must be a VerificationAttempt")
    if not isinstance(prior_diff, str) or not prior_diff.strip():
        raise ValueError("prior_diff must be non-empty text")
    settings = config or Config.default()
    return RepairContext(
        prior_candidate=attempt.candidate,
        diagnostics=_repair_diagnostics(
            attempt.execution,
            settings.repair_max_diagnostics_characters,
            hidden_tests_mounted=hidden_tests_mounted,
        ),
        prior_diff=_bounded_text(
            redact(prior_diff), settings.repair_max_diff_characters
        ),
        relevant_chunk_ids=attempt.candidate.citation_ids,
    )


def record_repair_diff(
    previous: PythonCandidate,
    current: PythonCandidate,
    *,
    trace_recorder: ExecutionTraceRecorder,
    config: Config | None = None,
) -> str:
    """Record one candidate transition and return bounded next-loop context."""

    if not isinstance(previous, PythonCandidate) or not isinstance(
        current, PythonCandidate
    ):
        raise TypeError("repair diff candidates must be PythonCandidate values")
    if current.attempt_number != previous.attempt_number + 1:
        raise ValueError("repair candidates must be consecutive")
    settings = config or Config.default()
    diff = AttemptDiff.between(
        from_attempt=previous.attempt_number,
        to_attempt=current.attempt_number,
        from_code_artifact_id=previous.artifact_id,
        to_code_artifact_id=current.artifact_id,
        diff_artifact_id=_diff_id(previous, current, previous.attempt_number),
        previous_code=previous.code,
        current_code=current.code,
    )
    encoded = diff.unified_diff.encode("utf-8")
    trace_recorder.add_artifact(
        ArtifactReference(
            diff.diff_artifact_id,
            ArtifactKind.ATTEMPT_DIFF,
            f"memory://step-5/{diff.diff_artifact_id}",
            media_type="text/x-diff",
            size_bytes=len(encoded),
            digest=hashlib.sha256(encoded).hexdigest(),
            metadata={
                "from_attempt": diff.from_attempt,
                "to_attempt": diff.to_attempt,
            },
        )
    )
    trace_recorder.record_attempt_diff(diff)
    return _bounded_text(
        diff.unified_diff or "Repair made no textual change.",
        settings.repair_max_diff_characters,
    )


def _bounded_text(value: str, maximum: int) -> str:
    if len(value) <= maximum:
        return value
    marker = "\n...[truncated by Leitir]..."
    if maximum <= len(marker):
        return marker[:maximum]
    head = (maximum - len(marker)) // 2
    tail = maximum - len(marker) - head
    return value[:head] + marker + value[-tail:]


def _candidate_snapshot_id(
    candidate: PythonCandidate, attempt: int
) -> ArtifactId:
    digest = hashlib.sha256(
        f"{candidate.artifact_id.value}\0{attempt}".encode("utf-8")
    ).hexdigest()[:20]
    return ArtifactId(f"step-5-attempt-{attempt}-candidate-{digest}")


def _diff_id(
    previous: PythonCandidate, current: PythonCandidate, attempt: int
) -> ArtifactId:
    digest = hashlib.sha256(
        (
            f"{previous.artifact_id.value}\0{current.artifact_id.value}\0"
            f"{attempt}"
        ).encode("utf-8")
    ).hexdigest()[:20]
    return ArtifactId(f"step-5-diff-{attempt}-{attempt + 1}-{digest}")


def _test_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SandboxPolicyError("test path must be non-empty text")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or len(path.parts) != 1
        or path.name != value
        or not value.startswith("test_")
        or not value.endswith(".py")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SandboxPolicyError("public tests must be flat test_*.py files")
    return value


def _dependency(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise SandboxPolicyError("dependency must be a normalized declaration")
    if not _DEPENDENCY.fullmatch(value):
        raise SandboxPolicyError(
            "dependencies must be package-index names/specifiers only"
        )
    normalized_project = _dependency_project(value)
    if normalized_project in _PROTECTED_PROJECTS:
        raise SandboxPolicyError("dependency cannot replace sandbox tooling")
    return value


def _dependency_project(value: str) -> str:
    project = re.split(r"[\[<>=!~]", value, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", project).casefold()


def _hidden_directory(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except OSError:
        raise SandboxPolicyError(
            "hidden tests mount could not be resolved"
        ) from None
    if not path.is_dir():
        raise SandboxPolicyError("hidden tests mount must be a directory")
    broad_mounts = {
        Path("/"),
        Path("/bin"),
        Path("/boot"),
        Path("/dev"),
        Path("/etc"),
        Path("/home"),
        Path("/proc"),
        Path("/root"),
        Path("/run"),
        Path("/sys"),
        Path("/usr"),
        Path("/var"),
        Path.home().resolve(),
    }
    if path in broad_mounts:
        raise SandboxPolicyError("hidden tests mount is too broad")
    if path == Path("/var/run/docker.sock"):
        raise SandboxPolicyError("Docker socket access is forbidden")
    return path


def _write_workspace(path: Path, task: PythonVerificationTask) -> None:
    tests = path / "tests"
    tests.mkdir(mode=0o755)
    _write_read_only(path / "candidate.py", task.candidate.code)
    _write_read_only(path / "leitir_pytest_plugin.py", _PYTEST_PLUGIN)
    _write_read_only(tests / _RESERVED_TEST, _IMPORT_TEST)
    for name, source in task.public_tests.items():
        _write_read_only(tests / name, source)
    path.chmod(0o755)


def _write_read_only(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o444)


def _build_context(files: Mapping[str, bytes]) -> io.BytesIO:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o444
            archive.addfile(info, io.BytesIO(content))
    buffer.seek(0)
    return buffer


def _bounded_streams(
    stdout: bytes, stderr: bytes, maximum: int
) -> tuple[str, str, bool]:
    total = len(stdout) + len(stderr)
    truncated = total > maximum
    if not truncated:
        selected_stdout, selected_stderr = stdout, stderr
    else:
        marker = _TRUNCATION[:maximum]
        content_budget = max(0, maximum - len(marker))
        stdout_budget = min(len(stdout), content_budget)
        selected_stdout = stdout[:stdout_budget]
        remaining = content_budget - stdout_budget
        selected_stderr = stderr[:remaining] + marker
    return (
        selected_stdout.decode("utf-8", errors="ignore"),
        selected_stderr.decode("utf-8", errors="ignore"),
        truncated,
    )


def _log_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    raise RuntimeError("Docker log API returned non-bytes output")


def _image_missing(exc: BaseException) -> bool:
    return type(exc).__name__ in {"ImageNotFound", "NotFound", "KeyError"}


def _timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    name = type(exc).__name__.casefold()
    module = type(exc).__module__.casefold()
    return "timeout" in name or (
        "requests" in module and "read timed out" in str(exc).casefold()
    )


__all__ = [
    "AttemptDisposition",
    "BASE_DOCKERFILE",
    "BASE_IMAGE_TAG",
    "DockerSandbox",
    "EvidenceState",
    "FailureClassification",
    "InfrastructureStatus",
    "PYTEST_ARGUMENTS",
    "PYTEST_VERSION",
    "PythonVerificationTask",
    "SandboxExecution",
    "SandboxPolicyError",
    "Step5Controller",
    "TestOutcome",
    "VerificationAttempt",
    "VerificationResult",
    "VerificationRoute",
    "build_repair_context",
    "record_repair_diff",
]
