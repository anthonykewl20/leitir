"""Stable domain vocabulary shared by Leitir's five workflow steps."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Mapping


class TargetLanguage(str, Enum):
    """The sole language boundary supported by this v1 implementation."""

    PYTHON = "python"


class EvidenceTier(IntEnum):
    """Allowed v1 evidence doors; browser-based Tier 4 is intentionally absent."""

    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


class WorkflowStep(IntEnum):
    QUERY_EXPANSION = 1
    DISCOVERY = 2
    EXTRACTION = 3
    SYNTHESIS = 4
    VERIFICATION = 5


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class AttemptStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"


class TerminalDisposition(str, Enum):
    ACCEPTED = "accepted"
    FAILED = "failed"
    REPAIR_EXHAUSTED = "repair_exhausted"
    SPEND_CAP_EXCEEDED = "spend_cap_exceeded"
    INFRASTRUCTURE_ERROR = "infrastructure_error"


class ErrorCode(str, Enum):
    ERR_EXPANSION_MALFORMED = "ERR_EXPANSION_MALFORMED"
    ERR_SEARCH_ZERO_RESULTS = "ERR_SEARCH_ZERO_RESULTS"
    ERR_SCRAPE_BOILERPLATE_LEAK = "ERR_SCRAPE_BOILERPLATE_LEAK"
    ERR_SECURITY_PROMPT_INJECTION = "ERR_SECURITY_PROMPT_INJECTION"
    ERR_SYNTAX_COMPILATION_FAIL = "ERR_SYNTAX_COMPILATION_FAIL"
    ERR_VERIFICATION_TIMEOUT = "ERR_VERIFICATION_TIMEOUT"


@dataclass(frozen=True, slots=True, order=True)
class ArtifactId:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("artifact identifier must be a non-empty string")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class AttemptId:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("attempt identifier must be a non-empty string")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class WorkflowRequest:
    request_id: str
    task: str
    target_language: TargetLanguage = TargetLanguage.PYTHON

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ValueError("request_id must be a non-empty string")
        if not isinstance(self.task, str) or not self.task.strip():
            raise ValueError("task must be a non-empty string")
        if self.target_language is not TargetLanguage.PYTHON:
            raise ValueError("v1 supports Python requests only")


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: ArtifactId
    tier: EvidenceTier
    source_uri: str
    content_reference: str
    media_type: str = "text/plain"
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.tier, EvidenceTier):
            raise TypeError("tier must be an EvidenceTier")
        if not self.source_uri:
            raise ValueError("source_uri must not be empty")
        if not self.content_reference:
            raise ValueError("content_reference must not be empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class ErrorAttribution:
    code: ErrorCode
    owner: str
    step: WorkflowStep
    message: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.code, ErrorCode):
            raise TypeError("code must be an ErrorCode")
        if not isinstance(self.step, WorkflowStep):
            raise TypeError("step must be a WorkflowStep")
        if not self.owner.strip():
            raise ValueError("owner must not be empty")


@dataclass(frozen=True, slots=True)
class StepResult:
    step: WorkflowStep
    status: StepStatus
    input_artifact_ids: tuple[ArtifactId, ...] = ()
    output_artifact_ids: tuple[ArtifactId, ...] = ()
    attempt_number: int = 1
    error: ErrorAttribution | None = None

    def __post_init__(self) -> None:
        if self.attempt_number < 1:
            raise ValueError("attempt_number must be positive")
        if self.status is StepStatus.FAILED and self.error is None:
            raise ValueError("a failed step requires error attribution")
        if self.error is not None and self.error.step is not self.step:
            raise ValueError("error attribution must identify the result step")


@dataclass(frozen=True, slots=True)
class Attempt:
    attempt_id: AttemptId
    number: int
    status: AttemptStatus
    step_results: tuple[StepResult, ...] = ()
    disposition: TerminalDisposition | None = None

    def __post_init__(self) -> None:
        if self.number < 1 or self.number > 4:
            raise ValueError("attempt number must be between 1 and 4")
        if self.status in {AttemptStatus.PENDING, AttemptStatus.RUNNING}:
            if self.disposition is not None:
                raise ValueError("non-terminal attempts cannot have a disposition")

