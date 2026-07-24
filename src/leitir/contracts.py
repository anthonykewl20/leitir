"""Stable domain vocabulary shared by Leitir's five workflow steps."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
import re
from types import MappingProxyType
from typing import Mapping


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SITE_OPERATOR = re.compile(r"(?i)(?<![a-z0-9_])[+-]?site\s*:")
_SPACE = re.compile(r"\s+")
_TIER_2_SITES = frozenset({"docs.python.org", "pypi.org"})
_TIER_3_SITES = frozenset({"github.com", "api.github.com"})


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
    CANCELLED = "cancelled"


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
class QueryRecord:
    """One site-bound discovery query emitted by Step 1."""

    query_text: str
    site: str
    tier: EvidenceTier
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        query = _normalized_text("query_text", self.query_text)
        site = _domain(self.site)
        if not isinstance(self.tier, EvidenceTier):
            raise TypeError("tier must be an EvidenceTier")
        _tier_site(self.tier, site)
        if _SITE_OPERATOR.search(query):
            raise ValueError("query_text must not contain a site operator")
        if isinstance(self.provenance, (str, bytes)) or not self.provenance:
            raise ValueError("provenance must contain at least one contributor")
        contributors: list[str] = []
        seen: set[str] = set()
        for value in self.provenance:
            item = _normalized_text("provenance", value)
            key = item.casefold()
            if key not in seen:
                contributors.append(item)
                seen.add(key)
        object.__setattr__(self, "query_text", query)
        object.__setattr__(self, "site", site)
        object.__setattr__(self, "provenance", tuple(contributors))

    @property
    def discovery_query(self) -> str:
        """Render the restriction only at the Step 1/Step 2 seam."""
        return f"{self.query_text} site:{self.site}"


@dataclass(frozen=True, slots=True)
class QueryExpansionPlan:
    """A complete Step 1 result which is safe to pass to discovery."""

    request: WorkflowRequest
    queries: tuple[QueryRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, WorkflowRequest):
            raise TypeError("request must be a WorkflowRequest")
        if not self.queries:
            raise ValueError("an expansion plan must contain queries")
        if {record.tier for record in self.queries} != set(EvidenceTier):
            raise ValueError("an expansion plan requires Tiers 1, 2, and 3")

    def for_tier(self, tier: EvidenceTier) -> tuple[QueryRecord, ...]:
        return tuple(record for record in self.queries if record.tier is tier)


def _normalized_text(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = _SPACE.sub(" ", value).strip()
    if not normalized:
        raise ValueError(f"{name} must be non-empty text")
    return normalized


def _domain(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("site must be a string")
    site = value.strip().lower().rstrip(".")
    if (
        not site
        or "://" in site
        or any(character in site for character in "/:@?#* \t\r\n")
    ):
        raise ValueError("site must be a bare domain")
    labels = site.split(".")
    if (
        len(labels) < 2
        or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
        or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("site must be a valid domain")
    return site


def _tier_site(tier: EvidenceTier, site: str) -> None:
    if tier is EvidenceTier.TIER_2 and site not in _TIER_2_SITES:
        raise ValueError("site is not valid for Tier 2")
    if tier is EvidenceTier.TIER_3 and site not in _TIER_3_SITES:
        raise ValueError("site is not valid for Tier 3")
    if tier is EvidenceTier.TIER_1 and site in _TIER_2_SITES | _TIER_3_SITES:
        raise ValueError("site is not valid for Tier 1")


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
