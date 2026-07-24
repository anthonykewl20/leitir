"""Replaceable interfaces for all external effects.

Only structural interfaces live here.  Concrete HTTP, Docker, credential, and
trace implementations belong to later issues and are never created on import.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Protocol, runtime_checkable

from .contracts import Artifact, StepResult, WorkflowRequest


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
    def execute(self, source: str) -> StepResult: ...


@runtime_checkable
class TraceSink(Protocol):
    def emit(self, result: StepResult) -> None: ...

