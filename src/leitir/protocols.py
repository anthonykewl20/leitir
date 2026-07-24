"""Replaceable interfaces for all external effects.

Only structural interfaces live here.  Concrete HTTP, Docker, credential, and
trace implementations belong to later issues and are never created on import.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Mapping, Protocol, runtime_checkable

from .contracts import Artifact, StepResult, TerminalDisposition, WorkflowRequest
from .trace import (
    ArtifactReference,
    AttemptDiff,
    EvidenceAccounting,
    ExecutionTrace,
    ReplayMetadata,
    TraceSpan,
)

if TYPE_CHECKING:
    from .verification import PythonVerificationTask, SandboxExecution


@runtime_checkable
class ModelTransport(Protocol):
    def send(self, request: WorkflowRequest) -> Mapping[str, object]: ...


@runtime_checkable
class SearchProvider(Protocol):
    def search(self, query: str) -> Iterable[Artifact]: ...


@runtime_checkable
class ExtractionProvider(Protocol):
    def extract(self, artifact: Artifact) -> Artifact: ...


@runtime_checkable
class CredentialProvider(Protocol):
    def get_openrouter_key(self) -> str: ...


@runtime_checkable
class SandboxExecutor(Protocol):
    def execute(
        self,
        task: PythonVerificationTask,
        *,
        hidden_tests: str | Path | None = None,
    ) -> SandboxExecution: ...


@runtime_checkable
class TraceSink(Protocol):
    def emit(self, result: StepResult) -> None: ...


@runtime_checkable
class ExecutionTraceRecorder(Protocol):
    """Replaceable narrow interface implemented by the in-memory recorder."""

    def add_artifact(self, artifact: ArtifactReference) -> None: ...

    def record_span(self, span: TraceSpan) -> None: ...

    def record_attempt_diff(self, attempt_diff: AttemptDiff) -> None: ...

    def finish(
        self,
        *,
        ended_at: str,
        total_latency_ms: int | float,
        final_status: TerminalDisposition,
        accepted_attempt: int | None,
        replay: ReplayMetadata,
        evidence_accounting: EvidenceAccounting,
    ) -> ExecutionTrace: ...
