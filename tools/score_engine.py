"""Deterministic evidence scoring engine for ADR-002 S1-S3.

This standalone module intentionally imports no Leitir package code.  It owns
the policy vocabulary, integer scoring arithmetic, non-compensating gate, and
canonical provenance envelope, and offline engine-correctness collectors.
Later slices own retrieval metrics and the remaining assessment dimensions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP, localcontext
from enum import Enum, IntEnum
import hashlib
from importlib import machinery
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Iterable, Iterator, Mapping
from xml.etree import ElementTree


ASSESSMENT_SCHEMA_VERSION = "leitir-assessment-v1"
POLICY_SCHEMA_VERSION = "leitir-score-policy-v1"
RUN_ENVELOPE_SCHEMA_VERSION = "leitir-score-run-envelope-v1"
DIMENSION_IDS = (
    "engine_correctness",
    "output_effectiveness",
    "code_health",
    "test_adequacy",
    "process_supply_chain",
    "performance_operability",
)

_CHECK_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_POLICY_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_ID = re.compile(r"^[a-z][a-z0-9_.-]*$")
_REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TASK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


ADR001_OFFLINE_GATE_TESTS = (
    "tests/test_search.py",
    "tests/test_search_e2e.py",
    "tests/test_engine.py",
    "tests/test_engine_e2e.py",
    "tests/test_adapters_multi.py",
    "tests/test_resolver.py",
    "tests/test_resolver_e2e.py",
    "tests/test_cli.py",
    "tests/test_cli_e2e.py",
    "tests/test_global.py",
    "tests/test_global_e2e.py",
    "tests/test_ranking.py",
    "tests/test_bench.py",
)
_PYTEST_JUNIT_PATH = ".leitir-score/evidence/adr001-offline-junit.xml"
ADR001_OFFLINE_GATE_ARGV = (
    "python",
    "-m",
    "pytest",
    *ADR001_OFFLINE_GATE_TESTS,
    "-p",
    "no:cacheprovider",
    f"--junitxml={_PYTEST_JUNIT_PATH}",
)
_MAX_JUNIT_BYTES = 16 * 1024 * 1024
_RETIRED_V1_MODULES = (
    "_jsonutil",
    "config",
    "contracts",
    "discovery",
    "evaluation",
    "expansion",
    "extraction",
    "openrouter",
    "orchestrator",
    "protocols",
    "synthesis",
    "trace",
    "verification",
)


class CheckStatus(str, Enum):
    """The complete result vocabulary defined by ADR-002 section 3."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"


class CheckMode(str, Enum):
    """Whether a check participates in the non-compensating gate."""

    REQUIRED = "required"
    ADVISORY = "advisory"


class Profile(str, Enum):
    """The two assessment profiles defined by ADR-002 section 12."""

    OFFLINE = "offline"
    RELEASE = "release"


class Decision(str, Enum):
    """A policy decision, independent of the diagnostic scalar score."""

    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class ExitCode(IntEnum):
    """Stable process exits from ADR-002 section 12."""

    COMPLETE_PASS = 0
    KNOWN_FAILURE = 1
    INVALID_USAGE_OR_POLICY = 2
    INDETERMINATE = 3


class BlockerKind(str, Enum):
    """Why a required check prevents an unqualified pass."""

    KNOWN_FAILURE = "known_failure"
    UNRESOLVED = "unresolved"
    MISSING_RESULT = "missing_result"


class StandardReason(str, Enum):
    """Engine-owned reason codes; adapters may supply domain reason codes."""

    POLICY_CHECK_MISSING = "POLICY_CHECK_MISSING"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_non_negative_int(value: object, name: str) -> None:
    if not _is_int(value) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _validate_positive_int(value: object, name: str) -> None:
    if not _is_int(value) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _validate_score(value: object, name: str = "score_bps") -> None:
    if not _is_int(value) or not 0 <= value <= 10000:
        raise ValueError(f"{name} must be an integer from 0 through 10000")


def _validate_canonical_path(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        raise ValueError(f"{name} must be a normalized relative POSIX path")


@dataclass(frozen=True, slots=True, eq=False)
class _FrozenTextMap(Mapping[str, str]):
    """A sorted, immutable, hashable mapping used inside frozen contracts."""

    entries: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, str]) -> _FrozenTextMap:
        return cls(tuple(sorted(value.items())))

    def __getitem__(self, key: str) -> str:
        for item_key, item_value in self.entries:
            if item_key == key:
                return item_value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and dict(self.entries) == dict(other.items())

    def __hash__(self) -> int:
        return hash(self.entries)


def _round_half_up_fraction(numerator: int, denominator: int) -> int:
    """Round a non-negative exact fraction to an integer, half away from zero."""
    _validate_non_negative_int(numerator, "numerator")
    _validate_positive_int(denominator, "denominator")
    precision = max(len(str(numerator)), len(str(denominator))) + 16
    with localcontext() as context:
        context.prec = precision
        value = Decimal(numerator) / Decimal(denominator)
        return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def proportional_score_bps(numerator: int, denominator: int) -> int | None:
    """Return ``round_half_up(10000 * n / d)`` or null for a zero denominator."""
    _validate_non_negative_int(numerator, "numerator")
    _validate_non_negative_int(denominator, "denominator")
    if numerator > denominator:
        raise ValueError("numerator cannot exceed denominator")
    if denominator == 0:
        return None
    return _round_half_up_fraction(10000 * numerator, denominator)


def score_from_counts(counts: Iterable[tuple[int, int]]) -> int | None:
    """Aggregate raw sufficient statistics before deriving one ratio."""
    total_numerator = 0
    total_denominator = 0
    seen = False
    for item in counts:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("counts must contain (numerator, denominator) tuples")
        numerator, denominator = item
        _validate_non_negative_int(numerator, "numerator")
        _validate_non_negative_int(denominator, "denominator")
        if numerator > denominator:
            raise ValueError("numerator cannot exceed denominator")
        total_numerator += numerator
        total_denominator += denominator
        seen = True
    if not seen:
        raise ValueError("counts must contain at least one pair")
    return proportional_score_bps(total_numerator, total_denominator)


def weighted_score_bps(values: Iterable[tuple[int, int]]) -> int:
    """Return the positive-integer-weighted basis-point score."""
    weighted_total = 0
    total_weight = 0
    seen = False
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("values must contain (score_bps, weight) tuples")
        score_bps, weight = item
        _validate_score(score_bps)
        _validate_positive_int(weight, "weight")
        weighted_total += score_bps * weight
        total_weight += weight
        seen = True
    if not seen:
        raise ValueError("values must contain at least one score")
    return _round_half_up_fraction(weighted_total, total_weight)


def display_band(score_bps: int) -> str:
    """Return display-only continuity metadata; this is never called by the gate."""
    _validate_score(score_bps)
    if score_bps < 4000:
        return "critical"
    if score_bps < 6000:
        return "serious"
    if score_bps < 8000:
        return "fair"
    return "good"


@dataclass(frozen=True, slots=True)
class Criterion:
    """A typed policy criterion copied into the canonical assessment."""

    op: str
    value: int

    def __post_init__(self) -> None:
        if self.op not in {"eq", "gte", "lte"}:
            raise ValueError("criterion op must be one of: eq, gte, lte")
        _validate_score(self.value, "criterion value")

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "value": self.value}


@dataclass(frozen=True, slots=True)
class ApplicabilityRule:
    """A versioned policy predicate that can authorize not-applicable."""

    rule: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not self.rule.strip():
            raise ValueError("applicability rule must be non-empty text")

    def to_dict(self) -> dict[str, str]:
        return {"rule": self.rule}


@dataclass(frozen=True, slots=True)
class DimensionPolicy:
    """Explicit versioned influence of one assessment dimension."""

    id: str
    weight: int

    def __post_init__(self) -> None:
        if self.id not in DIMENSION_IDS:
            raise ValueError(f"unknown dimension ID: {self.id!r}")
        _validate_positive_int(self.weight, "dimension weight")

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "weight": self.weight}


@dataclass(frozen=True, slots=True)
class CheckPolicy:
    """Policy-owned identity, weighting, profile mode, and applicability."""

    id: str
    dimension: str
    weight: int
    score_eligible: bool
    criterion: Criterion
    offline_mode: CheckMode
    release_mode: CheckMode
    applicability: ApplicabilityRule | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CHECK_ID.fullmatch(self.id):
            raise ValueError("check ID must be lowercase dotted snake-case")
        if self.dimension not in DIMENSION_IDS:
            raise ValueError(f"unknown check dimension: {self.dimension!r}")
        _validate_positive_int(self.weight, "check weight")
        if not isinstance(self.score_eligible, bool):
            raise TypeError("score_eligible must be a bool")
        if not isinstance(self.criterion, Criterion):
            raise TypeError("criterion must be a Criterion")
        if not isinstance(self.offline_mode, CheckMode):
            raise TypeError("offline_mode must be a CheckMode")
        if not isinstance(self.release_mode, CheckMode):
            raise TypeError("release_mode must be a CheckMode")
        if self.applicability is not None and not isinstance(
            self.applicability, ApplicabilityRule
        ):
            raise TypeError("applicability must be an ApplicabilityRule or None")

    def mode_for(self, profile: Profile) -> CheckMode:
        if not isinstance(profile, Profile):
            raise TypeError("profile must be a Profile")
        if profile is Profile.OFFLINE:
            return self.offline_mode
        return self.release_mode

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "dimension": self.dimension,
            "weight": self.weight,
            "score_eligible": self.score_eligible,
            "criterion": self.criterion.to_dict(),
            "modes": {
                "offline": self.offline_mode.value,
                "release": self.release_mode.value,
            },
            "applicability": (
                None if self.applicability is None else self.applicability.to_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class Policy:
    """The complete versioned set of expected checks and dimension weights."""

    schema_version: str
    id: str
    dimensions: tuple[DimensionPolicy, ...]
    checks: tuple[CheckPolicy, ...]
    waivers: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != POLICY_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {POLICY_SCHEMA_VERSION!r}")
        if not isinstance(self.id, str) or not _POLICY_ID.fullmatch(self.id):
            raise ValueError("policy ID must be lowercase kebab-case")
        if not isinstance(self.dimensions, tuple) or any(
            not isinstance(item, DimensionPolicy) for item in self.dimensions
        ):
            raise TypeError("dimensions must be a tuple of DimensionPolicy")
        dimension_ids = [item.id for item in self.dimensions]
        if tuple(dimension_ids) != DIMENSION_IDS:
            raise ValueError(
                "policy must declare all six dimensions in canonical order"
            )
        if not isinstance(self.checks, tuple) or any(
            not isinstance(item, CheckPolicy) for item in self.checks
        ):
            raise TypeError("checks must be a tuple of CheckPolicy")
        if not self.checks:
            raise ValueError("policy must declare at least one check")
        check_ids = [item.id for item in self.checks]
        if len(set(check_ids)) != len(check_ids):
            raise ValueError("policy check IDs must be unique")
        declared_dimensions = set(dimension_ids)
        if any(item.dimension not in declared_dimensions for item in self.checks):
            raise ValueError("every check dimension must be declared by the policy")
        if set(item.dimension for item in self.checks) != declared_dimensions:
            raise ValueError("every policy dimension must contain at least one check")
        if not isinstance(self.waivers, tuple):
            raise TypeError("waivers must be a tuple")
        if self.waivers:
            raise ValueError("policy v1 does not permit waivers")
        object.__setattr__(
            self,
            "checks",
            tuple(sorted(self.checks, key=lambda item: item.id)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "dimensions": [item.to_dict() for item in self.dimensions],
            "checks": [item.to_dict() for item in self.checks],
            "waivers": [],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CommandExecution:
    """Exact subprocess provenance attached to one raw evidence artifact."""

    argv: tuple[str, ...]
    process_exit: int
    collector_reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv:
            raise TypeError("argv must be a non-empty tuple")
        if any(not isinstance(item, str) or not item for item in self.argv):
            raise ValueError("argv entries must be non-empty text")
        if not _is_int(self.process_exit):
            raise TypeError("process_exit must be an integer")
        if not isinstance(
            self.collector_reason_code, str
        ) or not _REASON_CODE.fullmatch(self.collector_reason_code):
            raise ValueError("collector_reason_code must be uppercase snake-case")

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "process_exit": self.process_exit,
            "collector_reason_code": self.collector_reason_code,
        }


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A source location bound to its exact repository blob."""

    path: str
    blob_digest: str
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        _validate_canonical_path(self.path, "source path")
        if not isinstance(self.blob_digest, str) or not (
            _SHA1.fullmatch(self.blob_digest) or _SHA256.fullmatch(self.blob_digest)
        ):
            raise ValueError("blob_digest must be a 40- or 64-char lowercase hex digest")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("start_line and end_line must be provided together")
        if self.start_line is not None and self.end_line is not None:
            _validate_positive_int(self.start_line, "start_line")
            _validate_positive_int(self.end_line, "end_line")
            if self.start_line > self.end_line:
                raise ValueError("start_line cannot exceed end_line")

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.path,
            0 if self.start_line is None else self.start_line,
            0 if self.end_line is None else self.end_line,
            self.blob_digest,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "blob_digest": self.blob_digest,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    """Raw evidence bytes plus the canonical provenance retained for them.

    ``content`` is evaluation input and is deliberately excluded from canonical
    output.  Its pinned SHA-256 is verified at construction, so altered bytes
    never reach scoring as apparently valid evidence.
    """

    id: str
    path: str
    sha256: str
    content: bytes = field(repr=False, compare=False)
    command: CommandExecution | None = None
    sources: tuple[SourceSpan, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _EVIDENCE_ID.fullmatch(self.id):
            raise ValueError("evidence ID must be a lowercase stable identifier")
        _validate_canonical_path(self.path, "evidence path")
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ValueError("evidence sha256 must be a 64-char lowercase hex digest")
        if not isinstance(self.content, bytes):
            raise TypeError("evidence content must be bytes")
        if hashlib.sha256(self.content).hexdigest() != self.sha256:
            raise ValueError("evidence content does not match its declared sha256")
        if self.command is not None and not isinstance(
            self.command, CommandExecution
        ):
            raise TypeError("evidence command must be a CommandExecution or None")
        if not isinstance(self.sources, tuple) or any(
            not isinstance(item, SourceSpan) for item in self.sources
        ):
            raise TypeError("evidence sources must be a tuple of SourceSpan")
        source_keys = [item.sort_key() for item in self.sources]
        if len(set(source_keys)) != len(source_keys):
            raise ValueError("evidence source spans must be unique")
        object.__setattr__(
            self,
            "sources",
            tuple(sorted(self.sources, key=SourceSpan.sort_key)),
        )

    @classmethod
    def from_path(
        cls,
        *,
        id: str,
        path: str | Path,
        canonical_path: str,
        sha256: str,
        command: CommandExecution | None = None,
        sources: tuple[SourceSpan, ...] = (),
    ) -> EvidenceArtifact:
        if not isinstance(path, (str, Path)):
            raise TypeError("path must be text or Path")
        return cls(
            id=id,
            path=canonical_path,
            sha256=sha256,
            content=Path(path).read_bytes(),
            command=command,
            sources=sources,
        )

    def sort_key(self) -> tuple[str, str, str]:
        return (self.id, self.path, self.sha256)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "path": self.path,
            "sha256": self.sha256,
            "command": None if self.command is None else self.command.to_dict(),
            "sources": [item.to_dict() for item in self.sources],
        }


def _normalized_exclusions(
    exclusions: object,
) -> tuple[tuple[str, int], ...]:
    if not isinstance(exclusions, tuple):
        raise TypeError("exclusions must be a tuple of (reason, count) pairs")
    exclusion_names: list[str] = []
    for item in exclusions:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("exclusions must contain (reason, count) tuples")
        reason, count = item
        if not isinstance(reason, str) or not _REASON_CODE.fullmatch(reason):
            raise ValueError("exclusion reasons must be uppercase snake-case")
        _validate_non_negative_int(count, "exclusion count")
        exclusion_names.append(reason)
    if len(set(exclusion_names)) != len(exclusion_names):
        raise ValueError("exclusion reasons must be unique")
    return tuple(sorted(exclusions))


def _normalized_check_evidence(
    evidence: object,
) -> tuple[Mapping[str, str], ...]:
    if not isinstance(evidence, tuple):
        raise TypeError("evidence must be a tuple of mappings")
    normalized: list[_FrozenTextMap] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            raise TypeError("evidence must be a tuple of mappings")
        if set(item) != {"kind", "value"}:
            raise ValueError("evidence entries require exactly kind and value")
        if any(
            not isinstance(value, str) or not value.strip() for value in item.values()
        ):
            raise ValueError("evidence kind and value must be non-empty text")
        normalized.append(_FrozenTextMap.from_mapping(item))
    return tuple(sorted(normalized, key=lambda item: (item["kind"], item["value"])))


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One submitted measurement before policy metadata is applied."""

    id: str
    status: CheckStatus
    score_bps: int | None
    reason_code: str
    numerator: int | None = None
    denominator: int | None = None
    exclusions: tuple[tuple[str, int], ...] = ()
    evidence: tuple[Mapping[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CHECK_ID.fullmatch(self.id):
            raise ValueError("check ID must be lowercase dotted snake-case")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("reason_code must be uppercase snake-case")
        if self.status in {CheckStatus.PASS, CheckStatus.FAIL}:
            _validate_score(self.score_bps)
        elif self.score_bps is not None:
            raise ValueError(f"{self.status.value} requires score_bps=None")
        if (self.numerator is None) != (self.denominator is None):
            raise ValueError("numerator and denominator must be provided together")
        if self.numerator is not None and self.denominator is not None:
            _validate_non_negative_int(self.numerator, "numerator")
            _validate_non_negative_int(self.denominator, "denominator")
            if self.numerator > self.denominator:
                raise ValueError("numerator cannot exceed denominator")
            if self.denominator == 0 and self.status in {
                CheckStatus.PASS,
                CheckStatus.FAIL,
            }:
                raise ValueError("a zero denominator cannot produce pass or fail")
        object.__setattr__(
            self, "exclusions", _normalized_exclusions(self.exclusions)
        )
        object.__setattr__(
            self, "evidence", _normalized_check_evidence(self.evidence)
        )


@dataclass(frozen=True, slots=True)
class AssessedCheck:
    """A result enriched only from the governing policy."""

    id: str
    dimension: str
    mode: CheckMode
    status: CheckStatus
    score_bps: int | None
    weight: int
    score_eligible: bool
    criterion: Criterion
    reason_code: str
    numerator: int | None
    denominator: int | None
    exclusions: tuple[tuple[str, int], ...]
    evidence: tuple[Mapping[str, str], ...]
    missing: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CHECK_ID.fullmatch(self.id):
            raise ValueError("check ID must be lowercase dotted snake-case")
        if self.dimension not in DIMENSION_IDS:
            raise ValueError(f"unknown check dimension: {self.dimension!r}")
        if not isinstance(self.mode, CheckMode):
            raise TypeError("mode must be a CheckMode")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")
        if self.status in {CheckStatus.PASS, CheckStatus.FAIL}:
            _validate_score(self.score_bps)
        elif self.score_bps is not None:
            raise ValueError(f"{self.status.value} requires score_bps=None")
        _validate_positive_int(self.weight, "check weight")
        if not isinstance(self.score_eligible, bool):
            raise TypeError("score_eligible must be a bool")
        if not isinstance(self.criterion, Criterion):
            raise TypeError("criterion must be a Criterion")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("reason_code must be uppercase snake-case")
        object.__setattr__(
            self, "exclusions", _normalized_exclusions(self.exclusions)
        )
        object.__setattr__(
            self, "evidence", _normalized_check_evidence(self.evidence)
        )
        if not isinstance(self.missing, bool):
            raise TypeError("missing must be a bool")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "dimension": self.dimension,
            "mode": self.mode.value,
            "status": self.status.value,
            "score_bps": self.score_bps,
            "weight": self.weight,
            "score_eligible": self.score_eligible,
            "criterion": self.criterion.to_dict(),
            "reason_code": self.reason_code,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "exclusions": dict(self.exclusions),
            "evidence": [dict(item) for item in self.evidence],
            "missing": self.missing,
        }


@dataclass(frozen=True, slots=True)
class ScoreAggregate:
    """Exact, observed, and pessimistic/optimistic bounded diagnostics."""

    score_bps: int | None
    observed_score_bps: int | None
    lower_bound_bps: int | None
    upper_bound_bps: int | None
    included_weight: int
    eligible_weight: int

    def __post_init__(self) -> None:
        for name in (
            "score_bps",
            "observed_score_bps",
            "lower_bound_bps",
            "upper_bound_bps",
        ):
            value = getattr(self, name)
            if value is not None:
                _validate_score(value, name)
        _validate_non_negative_int(self.included_weight, "included_weight")
        _validate_non_negative_int(self.eligible_weight, "eligible_weight")
        if self.included_weight > self.eligible_weight:
            raise ValueError("included_weight cannot exceed eligible_weight")
        if self.eligible_weight == 0 and any(
            value is not None
            for value in (
                self.score_bps,
                self.observed_score_bps,
                self.lower_bound_bps,
                self.upper_bound_bps,
            )
        ):
            raise ValueError("an ineligible aggregate cannot contain scores")
        if self.score_bps is not None and self.included_weight != self.eligible_weight:
            raise ValueError("an exact score requires all eligible weight")
        if self.included_weight == 0 and self.observed_score_bps is not None:
            raise ValueError("an observed score requires included weight")
        if (
            self.lower_bound_bps is not None
            and self.upper_bound_bps is not None
            and self.lower_bound_bps > self.upper_bound_bps
        ):
            raise ValueError("lower_bound_bps cannot exceed upper_bound_bps")

    def to_dict(self) -> dict[str, object]:
        return {
            "score_bps": self.score_bps,
            "observed_score_bps": self.observed_score_bps,
            "lower_bound_bps": self.lower_bound_bps,
            "upper_bound_bps": self.upper_bound_bps,
            "included_weight": self.included_weight,
            "eligible_weight": self.eligible_weight,
        }


@dataclass(frozen=True, slots=True)
class DimensionAssessment:
    """One dimension scored before its explicit overall policy weight."""

    id: str
    weight: int
    aggregate: ScoreAggregate

    def __post_init__(self) -> None:
        if self.id not in DIMENSION_IDS:
            raise ValueError(f"unknown dimension ID: {self.id!r}")
        _validate_positive_int(self.weight, "dimension weight")
        if not isinstance(self.aggregate, ScoreAggregate):
            raise TypeError("aggregate must be a ScoreAggregate")

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "weight": self.weight, **self.aggregate.to_dict()}


@dataclass(frozen=True, slots=True)
class Blocker:
    """A required failure or unresolved result retained in canonical output."""

    check_id: str
    kind: BlockerKind
    status: CheckStatus
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.check_id, str) or not _CHECK_ID.fullmatch(
            self.check_id
        ):
            raise ValueError("blocker check_id must be lowercase dotted snake-case")
        if not isinstance(self.kind, BlockerKind):
            raise TypeError("kind must be a BlockerKind")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("blocker reason_code must be uppercase snake-case")

    def sort_key(self) -> tuple[int, str, str]:
        precedence = {
            BlockerKind.KNOWN_FAILURE: 0,
            BlockerKind.MISSING_RESULT: 1,
            BlockerKind.UNRESOLVED: 1,
        }
        return (precedence[self.kind], self.check_id, self.reason_code)

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class GateAggregate:
    """The gate vector plus the independently-computed overall diagnostic."""

    decision: Decision
    complete: bool
    scores: ScoreAggregate
    blockers: tuple[Blocker, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            raise TypeError("decision must be a Decision")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a bool")
        if not isinstance(self.scores, ScoreAggregate):
            raise TypeError("scores must be a ScoreAggregate")
        if not isinstance(self.blockers, tuple) or any(
            not isinstance(item, Blocker) for item in self.blockers
        ):
            raise TypeError("blockers must be a tuple of Blocker")
        object.__setattr__(
            self,
            "blockers",
            tuple(sorted(self.blockers, key=Blocker.sort_key)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "complete": self.complete,
            **self.scores.to_dict(),
            "blockers": [item.to_dict() for item in self.blockers],
        }


@dataclass(frozen=True, slots=True)
class Subject:
    """Repository commit identity, including development-tree provenance."""

    repository: str
    commit_sha: str
    worktree: str
    patch_sha256: str | None = None
    untracked_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise ValueError("repository must be non-empty text")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("commit_sha must be a 40-char git SHA")
        if self.worktree not in {"clean", "dirty"}:
            raise ValueError("worktree must be clean or dirty")
        if self.worktree == "clean":
            if self.patch_sha256 is not None or self.untracked_sha256 is not None:
                raise ValueError("a clean subject cannot contain dirty-tree digests")
        else:
            if not isinstance(self.patch_sha256, str) or not _SHA256.fullmatch(
                self.patch_sha256
            ):
                raise ValueError("a dirty subject requires patch_sha256")
            if not isinstance(self.untracked_sha256, str) or not _SHA256.fullmatch(
                self.untracked_sha256
            ):
                raise ValueError("a dirty subject requires untracked_sha256")

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "worktree": self.worktree,
        }
        if self.worktree == "dirty":
            result["patch_sha256"] = self.patch_sha256
            result["untracked_sha256"] = self.untracked_sha256
        return result


@dataclass(frozen=True, slots=True)
class Producer:
    """Minimal producer identity required by the canonical v1 shape."""

    name: str
    version: str
    commit_sha: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("producer name must be non-empty text")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("producer version must be non-empty text")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("producer commit_sha must be a 40-char git SHA")

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "commit_sha": self.commit_sha,
        }


@dataclass(frozen=True, slots=True)
class Assessment:
    """Canonical assessment artifact whose exact bytes define its identity."""

    schema_version: str
    profile: Profile
    subject: Subject
    producer: Producer
    policy_id: str
    policy_sha256: str
    checks: tuple[AssessedCheck, ...]
    dimensions: tuple[DimensionAssessment, ...]
    aggregate: GateAggregate
    evidence: tuple[EvidenceArtifact, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {ASSESSMENT_SCHEMA_VERSION!r}")
        if not isinstance(self.profile, Profile):
            raise TypeError("profile must be a Profile")
        if not isinstance(self.subject, Subject):
            raise TypeError("subject must be a Subject")
        if not isinstance(self.producer, Producer):
            raise TypeError("producer must be a Producer")
        if not isinstance(self.policy_sha256, str) or not _SHA256.fullmatch(
            self.policy_sha256
        ):
            raise ValueError("policy_sha256 must be a 64-char sha256 hex string")
        if not isinstance(self.policy_id, str) or not _POLICY_ID.fullmatch(
            self.policy_id
        ):
            raise ValueError("policy_id must be lowercase kebab-case")
        if not isinstance(self.checks, tuple) or any(
            not isinstance(item, AssessedCheck) for item in self.checks
        ):
            raise TypeError("checks must be a tuple of AssessedCheck")
        check_ids = [item.id for item in self.checks]
        if len(set(check_ids)) != len(check_ids):
            raise ValueError("assessment check IDs must be unique")
        if not isinstance(self.dimensions, tuple) or any(
            not isinstance(item, DimensionAssessment) for item in self.dimensions
        ):
            raise TypeError("dimensions must be a tuple of DimensionAssessment")
        if tuple(item.id for item in self.dimensions) != DIMENSION_IDS:
            raise ValueError(
                "assessment must contain all dimensions in canonical order"
            )
        if not isinstance(self.aggregate, GateAggregate):
            raise TypeError("aggregate must be a GateAggregate")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, EvidenceArtifact) for item in self.evidence
        ):
            raise TypeError("evidence must be a tuple of EvidenceArtifact")
        evidence_ids = [item.id for item in self.evidence]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("assessment evidence IDs must be unique")
        object.__setattr__(
            self,
            "checks",
            tuple(sorted(self.checks, key=lambda item: item.id)),
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(self.evidence, key=EvidenceArtifact.sort_key)),
        )

    @property
    def exit_code(self) -> ExitCode:
        return decision_exit_code(self.aggregate.decision)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile.value,
            "subject": self.subject.to_dict(),
            "producer": self.producer.to_dict(),
            "policy": {"id": self.policy_id, "sha256": self.policy_sha256},
            "checks": [item.to_dict() for item in self.checks],
            "evidence": [item.to_dict() for item in self.evidence],
            "dimensions": [item.to_dict() for item in self.dimensions],
            "aggregate": self.aggregate.to_dict(),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class RunEnvelope:
    """Volatile execution metadata bound to, but outside, an assessment."""

    subject_sha256: str
    started_at_utc: str
    finished_at_utc: str
    duration_ns: int
    host: Mapping[str, str]
    log_paths: tuple[str, ...]
    schema_version: str = RUN_ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RUN_ENVELOPE_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {RUN_ENVELOPE_SCHEMA_VERSION!r}"
            )
        if not isinstance(self.subject_sha256, str) or not _SHA256.fullmatch(
            self.subject_sha256
        ):
            raise ValueError("subject_sha256 must be a 64-char sha256 hex string")
        for name in ("started_at_utc", "finished_at_utc"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty text")
        _validate_non_negative_int(self.duration_ns, "duration_ns")
        if not isinstance(self.host, Mapping) or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or not value
            for key, value in self.host.items()
        ):
            raise TypeError("host must map non-empty text keys to text values")
        object.__setattr__(self, "host", _FrozenTextMap.from_mapping(self.host))
        if not isinstance(self.log_paths, tuple) or any(
            not isinstance(item, str) or not item for item in self.log_paths
        ):
            raise TypeError("log_paths must be a tuple of non-empty text paths")
        object.__setattr__(self, "log_paths", tuple(sorted(self.log_paths)))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "subject": {"sha256": self.subject_sha256},
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "duration_ns": self.duration_ns,
            "host": dict(self.host),
            "log_paths": list(self.log_paths),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())


def _canonical_json(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize the canonical compact UTF-8 representation used for identity."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_patch_sha256(patch: bytes) -> str:
    """Hash the exact bytes emitted by the engine's fixed canonical diff argv."""
    if not isinstance(patch, bytes):
        raise TypeError("patch must be bytes")
    return hashlib.sha256(patch).hexdigest()


def untracked_inputs_sha256(inputs: Mapping[str, bytes]) -> str:
    """Hash a sorted canonical manifest of untracked paths and content digests."""
    if not isinstance(inputs, Mapping):
        raise TypeError("inputs must map canonical paths to bytes")
    manifest: list[dict[str, object]] = []
    for path, content in inputs.items():
        _validate_canonical_path(path, "untracked path")
        if not isinstance(content, bytes):
            raise TypeError("untracked input content must be bytes")
        manifest.append(
            {
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    manifest.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


_CANONICAL_GIT_WORKTREE_CONFIG = (
    "-c",
    "core.quotePath=false",
    "-c",
    f"core.excludesFile={os.devnull}",
    "-c",
    "core.filemode=true",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.safecrlf=false",
    "-c",
    "core.eol=lf",
    "-c",
    f"core.attributesFile={os.devnull}",
    "-c",
    "filter.lfs.clean=",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.process=",
    "-c",
    "filter.lfs.required=false",
)


class _GitCommand(Enum):
    """Engine-owned Git argv; policy and callers can select no command text."""

    REPOSITORY = ("git", "remote", "get-url", "origin")
    COMMIT = ("git", "rev-parse", "--verify", "HEAD")
    STATUS = (
        "git",
        *_CANONICAL_GIT_WORKTREE_CONFIG,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    PATCH = (
        "git",
        *_CANONICAL_GIT_WORKTREE_CONFIG,
        "-c",
        "color.ui=false",
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--diff-algorithm=myers",
        "--no-indent-heuristic",
        "--ignore-submodules=none",
        "--submodule=short",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "HEAD",
        "--",
    )
    UNTRACKED = (
        "git",
        "-c",
        "core.quotePath=false",
        "-c",
        f"core.excludesFile={os.devnull}",
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )


def _sanitized_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_fixed_git(root: Path, command: _GitCommand) -> bytes:
    import subprocess

    completed = subprocess.run(
        command.value,
        cwd=str(root),
        shell=False,
        check=False,
        capture_output=True,
        env=_sanitized_git_environment(),
    )
    if completed.returncode != 0:
        raise ValueError(
            f"fixed git command {command.name.lower()} failed with exit "
            f"{completed.returncode}"
        )
    if not isinstance(completed.stdout, bytes):
        raise TypeError("fixed git command stdout must be bytes")
    return completed.stdout


def _single_utf8_line(value: bytes, name: str) -> str:
    try:
        decoded = value.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must be UTF-8") from exc
    if not decoded or "\n" in decoded or "\r" in decoded:
        raise ValueError(f"{name} must contain exactly one non-empty line")
    return decoded


def _read_untracked_inputs(root: Path, encoded_paths: bytes) -> dict[str, bytes]:
    inputs: dict[str, bytes] = {}
    for encoded_path in encoded_paths.split(b"\0"):
        if not encoded_path:
            continue
        try:
            path = encoded_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("untracked paths must be UTF-8") from exc
        _validate_canonical_path(path, "untracked path")
        local_path = root / Path(*PurePosixPath(path).parts)
        if local_path.is_symlink():
            content = os.fsencode(os.readlink(local_path))
        else:
            if not local_path.is_file():
                raise ValueError(f"untracked input is not a regular file: {path}")
            content = local_path.read_bytes()
        inputs[path] = content
    return inputs


def subject_from_repository(
    root: str | Path,
    *,
    repository: str | None = None,
) -> Subject:
    """Read subject identity with fixed Git argv and no import-time execution."""
    if not isinstance(root, (str, Path)):
        raise TypeError("root must be text or Path")
    repository_root = Path(root).resolve()
    if not repository_root.is_dir():
        raise ValueError("root must be an existing directory")
    if repository is not None and (
        not isinstance(repository, str) or not repository.strip()
    ):
        raise ValueError("repository must be non-empty text or None")
    if repository is None:
        try:
            repository_url = _single_utf8_line(
                _run_fixed_git(repository_root, _GitCommand.REPOSITORY),
                "repository URL",
            )
        except ValueError as exc:
            raise ValueError(
                "origin repository URL is unavailable; pass the repository= keyword"
            ) from exc
    else:
        repository_url = repository
    commit_sha = _single_utf8_line(
        _run_fixed_git(repository_root, _GitCommand.COMMIT),
        "commit SHA",
    )
    status = _run_fixed_git(repository_root, _GitCommand.STATUS)
    if not status:
        return Subject(
            repository=repository_url,
            commit_sha=commit_sha,
            worktree="clean",
        )
    patch = _run_fixed_git(repository_root, _GitCommand.PATCH)
    untracked_paths = _run_fixed_git(repository_root, _GitCommand.UNTRACKED)
    untracked_inputs = _read_untracked_inputs(repository_root, untracked_paths)
    return Subject(
        repository=repository_url,
        commit_sha=commit_sha,
        worktree="dirty",
        patch_sha256=canonical_patch_sha256(patch),
        untracked_sha256=untracked_inputs_sha256(untracked_inputs),
    )


def _sanitized_collector_environment(root: Path) -> dict[str, str]:
    """Return the fixed, credential-free environment for offline collectors."""
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(root / "src"),
        "PYTHONUTF8": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TZ": "UTC",
    }


def _pytest_collector_artifact(
    *, content: bytes, process_exit: int, reason_code: str
) -> EvidenceArtifact:
    return EvidenceArtifact(
        id="engine.pytest-junit",
        path=_PYTEST_JUNIT_PATH,
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
        command=CommandExecution(
            argv=ADR001_OFFLINE_GATE_ARGV,
            process_exit=process_exit,
            collector_reason_code=reason_code,
        ),
    )


def _discard_pytest_junit(path: Path) -> None:
    """Best-effort cleanup; callers still return empty error evidence on failure."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # A path that cannot be removed is never read by the current run.  A
        # later run must remove it successfully before starting pytest, or it
        # also returns COLLECTOR_FILESYSTEM_ERROR without reading stale bytes.
        pass


def collect_adr001_pytest_junit(root: str | Path) -> EvidenceArtifact:
    """Execute ADR-001's cumulative offline gate and collect its JUnit XML.

    The test paths are copied verbatim from ADR-001.  Only deterministic
    collector options are appended.  Neither policy nor callers can supply
    command text or an output path.
    """
    import subprocess

    if not isinstance(root, (str, Path)):
        raise TypeError("root must be text or Path")
    repository_root = Path(root).resolve()
    if not repository_root.is_dir():
        raise ValueError("root must be an existing directory")
    output_path = repository_root / Path(*PurePosixPath(_PYTEST_JUNIT_PATH).parts)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.unlink(missing_ok=True)
    except OSError:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"",
            process_exit=-1,
            reason_code="COLLECTOR_FILESYSTEM_ERROR",
        )
    try:
        completed = subprocess.run(
            ADR001_OFFLINE_GATE_ARGV,
            cwd=str(repository_root),
            shell=False,
            check=False,
            capture_output=True,
            env=_sanitized_collector_environment(repository_root),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"", process_exit=-1, reason_code="COLLECTOR_TIMEOUT"
        )
    except OSError:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"",
            process_exit=-1,
            reason_code="COLLECTOR_EXECUTION_ERROR",
        )
    try:
        if not output_path.is_file():
            return _pytest_collector_artifact(
                content=b"",
                process_exit=completed.returncode,
                reason_code="COLLECTOR_ARTIFACT_MISSING",
            )
        content = output_path.read_bytes()
    except OSError:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"",
            process_exit=completed.returncode,
            reason_code="COLLECTOR_FILESYSTEM_ERROR",
        )
    return _pytest_collector_artifact(
        content=content,
        process_exit=completed.returncode,
        reason_code="COLLECTOR_COMPLETE",
    )


def _artifact_references(
    artifacts: Iterable[EvidenceArtifact],
) -> tuple[Mapping[str, str], ...]:
    return tuple(
        {"kind": "artifact", "value": artifact.id} for artifact in artifacts
    )


def _error_result(
    check_id: str,
    reason_code: str,
    artifacts: tuple[EvidenceArtifact, ...],
) -> CheckResult:
    return CheckResult(
        id=check_id,
        status=CheckStatus.ERROR,
        score_bps=None,
        reason_code=reason_code,
        evidence=_artifact_references(artifacts),
    )


def _binary_result(
    check_id: str,
    passed: bool,
    *,
    pass_reason: str,
    fail_reason: str,
    artifacts: tuple[EvidenceArtifact, ...] = (),
    numerator: int = 1,
    denominator: int = 1,
) -> CheckResult:
    return CheckResult(
        id=check_id,
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        score_bps=10000 if passed else 0,
        reason_code=pass_reason if passed else fail_reason,
        numerator=numerator if passed else 0,
        denominator=denominator,
        evidence=_artifact_references(artifacts),
    )


def _xml_local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _junit_count(element: ElementTree.Element, name: str) -> int:
    raw = element.get(name)
    if raw is None or not raw.isascii() or not raw.isdecimal():
        raise ValueError(f"JUnit testsuite {name} must be a non-negative integer")
    return int(raw)


def _pytest_junit_counts(content: bytes) -> tuple[int, int, int, int]:
    if len(content) > _MAX_JUNIT_BYTES:
        raise ValueError("JUnit artifact exceeds the fixed size limit")
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("JUnit artifact must not contain DTD or entity declarations")
    try:
        root = ElementTree.fromstring(content)
    except (ElementTree.ParseError, ValueError) as exc:
        raise ValueError("JUnit artifact is malformed XML") from exc
    root_name = _xml_local_name(root.tag)
    if root_name == "testsuite":
        suites = (root,)
    elif root_name == "testsuites":
        suites = tuple(
            item for item in root if _xml_local_name(item.tag) == "testsuite"
        )
    else:
        raise ValueError("JUnit root must be testsuite or testsuites")
    if not suites:
        raise ValueError("JUnit artifact contains no testsuite")

    declared = tuple(
        sum(_junit_count(suite, name) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    )
    tests, failures, errors, skipped = declared
    if failures + errors + skipped > tests:
        raise ValueError("JUnit outcome counts exceed collected tests")

    cases = tuple(
        item
        for suite in suites
        for item in suite.iter()
        if _xml_local_name(item.tag) == "testcase"
    )
    case_failures = 0
    case_errors = 0
    case_skipped = 0
    for case in cases:
        outcomes = [_xml_local_name(item.tag) for item in case]
        case_failures += outcomes.count("failure")
        case_errors += outcomes.count("error")
        case_skipped += outcomes.count("skipped")
        if sum(name in {"failure", "error", "skipped"} for name in outcomes) > 1:
            raise ValueError("JUnit testcase contains multiple terminal outcomes")
    if (len(cases), case_failures, case_errors, case_skipped) != declared:
        raise ValueError("JUnit declared counts do not match testcase outcomes")
    return declared


def evaluate_pytest_junit(artifact: EvidenceArtifact) -> CheckResult:
    """Require a fixed-command, nonempty, green ADR-001 pytest run."""
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    artifacts = (artifact,)
    if (
        artifact.command is None
        or artifact.command.argv != ADR001_OFFLINE_GATE_ARGV
    ):
        return _error_result(
            "engine.offline_contracts", "PYTEST_COMMAND_PROVENANCE_INVALID", artifacts
        )
    if artifact.command.collector_reason_code != "COLLECTOR_COMPLETE":
        return _error_result(
            "engine.offline_contracts",
            artifact.command.collector_reason_code,
            artifacts,
        )
    try:
        tests, failures, errors, skipped = _pytest_junit_counts(artifact.content)
    except ValueError:
        return _error_result(
            "engine.offline_contracts", "PYTEST_JUNIT_MALFORMED", artifacts
        )
    if tests == 0:
        return _binary_result(
            "engine.offline_contracts",
            False,
            pass_reason="PYTEST_GREEN_NONZERO",
            fail_reason="PYTEST_ZERO_TESTS_COLLECTED",
            artifacts=artifacts,
        )
    passed = tests - failures - errors - skipped
    skip_exclusions = (("PYTEST_SKIPPED", skipped),) if skipped else ()
    process_exit = artifact.command.process_exit
    if failures or errors or process_exit == 1:
        return CheckResult(
            id="engine.offline_contracts",
            status=CheckStatus.FAIL,
            score_bps=proportional_score_bps(passed, tests),
            reason_code=(
                "PYTEST_TEST_FAILURES"
                if failures or errors
                else "PYTEST_NON_GREEN_EXIT"
            ),
            numerator=passed,
            denominator=tests,
            exclusions=skip_exclusions,
            evidence=_artifact_references(artifacts),
        )
    if process_exit != 0:
        return _error_result(
            "engine.offline_contracts", "PYTEST_EXECUTION_ERROR", artifacts
        )
    if skipped == tests:
        return CheckResult(
            id="engine.offline_contracts",
            status=CheckStatus.SKIPPED,
            score_bps=None,
            reason_code="PYTEST_ALL_TESTS_SKIPPED",
            numerator=0,
            denominator=tests,
            exclusions=skip_exclusions,
            evidence=_artifact_references(artifacts),
        )
    if skipped:
        return CheckResult(
            id="engine.offline_contracts",
            status=CheckStatus.FAIL,
            score_bps=proportional_score_bps(passed, tests),
            reason_code="PYTEST_TESTS_SKIPPED",
            numerator=passed,
            denominator=tests,
            exclusions=skip_exclusions,
            evidence=_artifact_references(artifacts),
        )
    return CheckResult(
        id="engine.offline_contracts",
        status=CheckStatus.PASS,
        score_bps=10000,
        reason_code="PYTEST_GREEN_NONZERO",
        numerator=passed,
        denominator=tests,
        exclusions=skip_exclusions,
        evidence=_artifact_references(artifacts),
    )


def _load_json_object(artifact: EvidenceArtifact, name: str) -> Mapping[str, object]:
    def reject_constant(value: str) -> object:
        raise ValueError(f"{name} contains non-finite number {value}")

    try:
        decoded = json.loads(artifact.content, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{name} is not strict JSON") from exc
    if not isinstance(decoded, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    return decoded


def _object_keys(raw: object, keys: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{name} must be an object")
    if set(raw) != keys:
        raise ValueError(f"{name} has an invalid field set")
    return raw


def _list_value(raw: object, name: str, *, nonempty: bool = False) -> list[object]:
    if not isinstance(raw, list) or (nonempty and not raw):
        qualifier = "a nonempty" if nonempty else "a"
        raise ValueError(f"{name} must be {qualifier} list")
    return raw


def _non_negative_json_int(value: object, name: str) -> int:
    if not _is_int(value) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _finite_json_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a JSON number")
    decimal = Decimal(str(value))
    if not decimal.is_finite():
        raise ValueError(f"{name} must be finite")
    return decimal


def _benchmark_tasks(artifact: EvidenceArtifact) -> list[object]:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark run"),
        {"schema_version", "benchmark", "tasks"},
        "benchmark run",
    )
    if raw["schema_version"] != "leitir-benchmark-run-v1":
        raise ValueError("benchmark run schema version is unsupported")
    return _list_value(raw["tasks"], "benchmark tasks", nonempty=True)


def evaluate_deterministic_replay(
    artifacts: tuple[EvidenceArtifact, ...],
) -> CheckResult:
    """Compare baseline, repeated, and input-permuted canonical run bytes."""
    if not isinstance(artifacts, tuple) or any(
        not isinstance(item, EvidenceArtifact) for item in artifacts
    ):
        raise TypeError("artifacts must be a tuple of EvidenceArtifact")
    if len(artifacts) != 3:
        return _error_result(
            "engine.deterministic_replay", "REPLAY_EVIDENCE_INCOMPLETE", artifacts
        )
    return _binary_result(
        "engine.deterministic_replay",
        artifacts[0].content == artifacts[1].content == artifacts[2].content,
        pass_reason="REPLAY_AND_PERMUTATION_IDENTICAL",
        fail_reason="NONDETERMINISTIC_OUTPUT",
        artifacts=artifacts,
    )


def _source_identity_from_result(result: object) -> tuple[str, str, str, str, int, int]:
    result_raw = _object_keys(
        result,
        {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"},
        "ranked result",
    )
    source = _object_keys(
        result_raw["source"],
        {"slug", "commit_sha", "path", "blob_sha", "start_line", "end_line", "permalink"},
        "result source",
    )
    start_line = _non_negative_json_int(source["start_line"], "start_line")
    end_line = _non_negative_json_int(source["end_line"], "end_line")
    if start_line < 1 or end_line < start_line:
        raise ValueError("result source line span is invalid")
    values = (
        source["slug"],
        source["commit_sha"],
        source["path"],
        source["blob_sha"],
    )
    if any(not isinstance(value, str) for value in values):
        raise ValueError("result source identity fields must be text")
    return (*values, start_line, end_line)


def _total_order_is_valid(artifact: EvidenceArtifact) -> bool:
    tasks = _benchmark_tasks(artifact)
    task_ids: list[str] = []
    for task in tasks:
        task_raw = _object_keys(
            task,
            {"task_id", "language", "spec_digest", "coverage", "results"},
            "benchmark task",
        )
        task_id = task_raw["task_id"]
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise ValueError("task_id must be lowercase kebab-case")
        task_ids.append(task_id)
        results = _list_value(task_raw["results"], "ranked results")
        decorated: list[tuple[tuple[object, ...], int, int]] = []
        identities: list[tuple[str, str, str, str, int, int]] = []
        for result in results:
            result_raw = _object_keys(
                result,
                {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"},
                "ranked result",
            )
            _finite_json_decimal(result_raw["score"], "score")
            normalized = _finite_json_decimal(
                result_raw["normalized_score"], "normalized_score"
            )
            if not Decimal(0) <= normalized <= Decimal(1):
                raise ValueError("normalized_score must be within zero and one")
            identity = _source_identity_from_result(result)
            rank = _non_negative_json_int(result_raw["rank"], "rank")
            rank_score = _non_negative_json_int(result_raw["rank_score"], "rank_score")
            identities.append(identity)
            decorated.append(((-normalized, *identity), rank, rank_score))
        if len(set(identities)) != len(identities):
            return False
        expected_keys = sorted(item[0] for item in decorated)
        if [item[0] for item in decorated] != expected_keys:
            return False
        count = len(decorated)
        if [item[1] for item in decorated] != list(range(1, count + 1)):
            return False
        if [item[2] for item in decorated] != list(range(count, 0, -1)):
            return False
    return task_ids == sorted(task_ids) and len(set(task_ids)) == len(task_ids)


def evaluate_total_ordering(artifact: EvidenceArtifact) -> CheckResult:
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        passed = _total_order_is_valid(artifact)
    except ValueError:
        return _error_result("engine.total_ordering", "RANKED_RUN_MALFORMED", (artifact,))
    return _binary_result(
        "engine.total_ordering",
        passed,
        pass_reason="ADR001_TOTAL_ORDER_VALID",
        fail_reason="ADR001_TOTAL_ORDER_INVALID",
        artifacts=(artifact,),
    )


def _result_provenance_is_valid(artifact: EvidenceArtifact) -> bool:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark run"),
        {"schema_version", "benchmark", "tasks"},
        "benchmark run",
    )
    if raw["schema_version"] != "leitir-benchmark-run-v1":
        raise ValueError("benchmark run schema version is unsupported")
    benchmark = _object_keys(
        raw["benchmark"], {"id", "manifest_sha256"}, "benchmark identity"
    )
    if not isinstance(benchmark["id"], str) or not benchmark["id"]:
        raise ValueError("benchmark ID must be non-empty text")
    if not isinstance(benchmark["manifest_sha256"], str) or not _SHA256.fullmatch(
        benchmark["manifest_sha256"]
    ):
        raise ValueError("benchmark manifest digest is invalid")
    tasks = _list_value(raw["tasks"], "benchmark tasks", nonempty=True)
    for task in tasks:
        task_raw = _object_keys(
            task,
            {"task_id", "language", "spec_digest", "coverage", "results"},
            "benchmark task",
        )
        if not isinstance(task_raw["task_id"], str) or not _TASK_ID.fullmatch(
            task_raw["task_id"]
        ):
            raise ValueError("task_id must be lowercase kebab-case")
        if task_raw["language"] not in {"python", "rust", "go"}:
            raise ValueError("task language is invalid")
        if not isinstance(task_raw["spec_digest"], str) or not _SHA256.fullmatch(
            task_raw["spec_digest"]
        ):
            raise ValueError("task spec digest is invalid")
        for result in _list_value(task_raw["results"], "ranked results"):
            identity = _source_identity_from_result(result)
            slug, commit_sha, path, blob_sha, start_line, end_line = identity
            if not _REPO_SLUG.fullmatch(slug):
                raise ValueError("result repository slug is invalid")
            if not _SHA1.fullmatch(commit_sha) or not _SHA1.fullmatch(blob_sha):
                raise ValueError("result commit or blob provenance is invalid")
            _validate_canonical_path(path, "result source path")
            result_raw = _object_keys(
                result,
                {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"},
                "ranked result",
            )
            source = result_raw["source"]
            expected_permalink = (
                f"https://github.com/{slug}/blob/{commit_sha}/{path}"
                f"#L{start_line}-L{end_line}"
            )
            if source["permalink"] != expected_permalink:
                return False
            matched_kinds = result_raw["matched_kinds"]
            if not isinstance(matched_kinds, list) or not matched_kinds or any(
                not isinstance(item, str) or not item for item in matched_kinds
            ):
                raise ValueError("matched_kinds must be a nonempty text list")
    return True


def evaluate_result_provenance(artifact: EvidenceArtifact) -> CheckResult:
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        passed = _result_provenance_is_valid(artifact)
    except ValueError:
        return _error_result(
            "engine.result_provenance", "RESULT_PROVENANCE_MALFORMED", (artifact,)
        )
    return _binary_result(
        "engine.result_provenance",
        passed,
        pass_reason="RESULT_PROVENANCE_VALID",
        fail_reason="RESULT_PROVENANCE_MISMATCH",
        artifacts=(artifact,),
    )


def _coverage(raw: object) -> tuple[str, int, int, int, bool]:
    coverage = _object_keys(
        raw,
        {"status", "files_eligible", "files_indexed", "files_excluded", "incomplete_results"},
        "coverage",
    )
    status = coverage["status"]
    if not isinstance(status, str):
        raise ValueError("coverage status must be text")
    eligible = _non_negative_json_int(coverage["files_eligible"], "files_eligible")
    indexed = _non_negative_json_int(coverage["files_indexed"], "files_indexed")
    excluded = _non_negative_json_int(coverage["files_excluded"], "files_excluded")
    incomplete = coverage["incomplete_results"]
    if not isinstance(incomplete, bool) or indexed > eligible:
        raise ValueError("coverage counters or incomplete flag are invalid")
    return status, eligible, indexed, excluded, incomplete


def _scoped_coverage_is_valid(artifact: EvidenceArtifact) -> bool:
    for task in _benchmark_tasks(artifact):
        task_raw = _object_keys(
            task,
            {"task_id", "language", "spec_digest", "coverage", "results"},
            "benchmark task",
        )
        status, eligible, indexed, _excluded, incomplete = _coverage(
            task_raw["coverage"]
        )
        if (
            status != "complete_for_declared_universe"
            or indexed != eligible
            or incomplete
        ):
            return False
    return True


def evaluate_scoped_coverage(artifact: EvidenceArtifact) -> CheckResult:
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        passed = _scoped_coverage_is_valid(artifact)
    except ValueError:
        return _error_result(
            "engine.scoped_coverage", "SCOPED_COVERAGE_MALFORMED", (artifact,)
        )
    return _binary_result(
        "engine.scoped_coverage",
        passed,
        pass_reason="DECLARED_UNIVERSE_COMPLETE",
        fail_reason="DECLARED_UNIVERSE_PARTIAL",
        artifacts=(artifact,),
    )


def evaluate_global_no_exhaustiveness(artifact: EvidenceArtifact) -> CheckResult:
    """Require dedicated global evidence to retain INDETERMINATE_GLOBAL."""
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        raw = _object_keys(
            _load_json_object(artifact, "global search report"),
            {"spec_digest", "coverage", "matches"},
            "global search report",
        )
        if not isinstance(raw["spec_digest"], str) or not _SHA256.fullmatch(
            raw["spec_digest"]
        ):
            raise ValueError("global search spec digest is invalid")
        _list_value(raw["matches"], "global matches")
        status, _eligible, _indexed, _excluded, _incomplete = _coverage(
            raw["coverage"]
        )
    except ValueError:
        return _error_result(
            "engine.global_no_exhaustiveness",
            "GLOBAL_COVERAGE_MALFORMED",
            (artifact,),
        )
    if status == "complete_for_declared_universe":
        reason = "GLOBAL_EXHAUSTIVENESS_OVERCLAIM"
    else:
        reason = "GLOBAL_COVERAGE_NOT_INDETERMINATE"
    return _binary_result(
        "engine.global_no_exhaustiveness",
        status == "indeterminate_global",
        pass_reason="INDETERMINATE_GLOBAL_PRESERVED",
        fail_reason=reason,
        artifacts=(artifact,),
    )


def evaluate_retired_surfaces_absent(root: str | Path) -> CheckResult:
    """Fail if any retired v1 top-level module remains importable from src."""
    if not isinstance(root, (str, Path)):
        raise TypeError("root must be text or Path")
    module_root = Path(root).resolve() / "src" / "leitir"
    try:
        children = tuple(module_root.iterdir())
    except OSError:
        return _error_result(
            "engine.retired_surfaces_absent", "RETIRED_SURFACE_SCOPE_UNREADABLE", ()
        )
    import_suffixes = tuple(machinery.all_suffixes()) + (".pyi",)
    repository_root = Path(root).resolve()
    present = sorted(
        child.relative_to(repository_root).as_posix()
        for child in children
        for module in _RETIRED_V1_MODULES
        if (child.is_dir() and child.name == module)
        or (child.is_file() and child.name in {f"{module}{suffix}" for suffix in import_suffixes})
    )
    evidence = (
        {"kind": "scope", "value": "src/leitir top-level import surfaces"},
        {
            "kind": "retired_modules",
            "value": ",".join(_RETIRED_V1_MODULES),
        },
    )
    return CheckResult(
        id="engine.retired_surfaces_absent",
        status=CheckStatus.PASS if not present else CheckStatus.FAIL,
        score_bps=10000 if not present else 0,
        reason_code=(
            "RETIRED_SURFACES_ABSENT" if not present else "RETIRED_SURFACES_PRESENT"
        ),
        numerator=1 if not present else 0,
        denominator=1,
        evidence=evidence
        + tuple({"kind": "present_surface", "value": item} for item in present),
    )


def evaluate_engine_correctness_evidence(
    *,
    pytest_junit: EvidenceArtifact,
    replay_artifacts: tuple[EvidenceArtifact, ...],
    global_report: EvidenceArtifact,
    repository_root: str | Path,
) -> tuple[CheckResult, ...]:
    """Evaluate the complete ADR-002 S3 engine-correctness check vector."""
    primary_run = replay_artifacts[0] if replay_artifacts else None
    if primary_run is None:
        artifact_checks = (
            _error_result("engine.total_ordering", "RANKED_RUN_MISSING", ()),
            _error_result("engine.result_provenance", "RANKED_RUN_MISSING", ()),
            _error_result("engine.scoped_coverage", "RANKED_RUN_MISSING", ()),
        )
    else:
        artifact_checks = (
            evaluate_total_ordering(primary_run),
            evaluate_result_provenance(primary_run),
            evaluate_scoped_coverage(primary_run),
        )
    return tuple(
        sorted(
            (
                evaluate_pytest_junit(pytest_junit),
                evaluate_deterministic_replay(replay_artifacts),
                *artifact_checks,
                evaluate_global_no_exhaustiveness(global_report),
                evaluate_retired_surfaces_absent(repository_root),
            ),
            key=lambda item: item.id,
        )
    )


def _score_checks(checks: tuple[AssessedCheck, ...]) -> ScoreAggregate:
    eligible = tuple(
        item
        for item in checks
        if item.score_eligible and item.status is not CheckStatus.NOT_APPLICABLE
    )
    known = tuple(
        item
        for item in eligible
        if item.status in {CheckStatus.PASS, CheckStatus.FAIL}
    )
    eligible_weight = sum(item.weight for item in eligible)
    included_weight = sum(item.weight for item in known)
    if eligible_weight == 0:
        return ScoreAggregate(None, None, None, None, 0, 0)
    observed = (
        weighted_score_bps(
            (int(item.score_bps), item.weight) for item in known
        )
        if known
        else None
    )
    exact = observed if included_weight == eligible_weight else None
    known_total = sum(int(item.score_bps) * item.weight for item in known)
    unresolved_weight = eligible_weight - included_weight
    lower = _round_half_up_fraction(known_total, eligible_weight)
    upper = _round_half_up_fraction(
        known_total + 10000 * unresolved_weight,
        eligible_weight,
    )
    return ScoreAggregate(
        score_bps=exact,
        observed_score_bps=observed,
        lower_bound_bps=lower,
        upper_bound_bps=upper,
        included_weight=included_weight,
        eligible_weight=eligible_weight,
    )


def _score_dimensions(
    dimensions: tuple[DimensionAssessment, ...],
) -> ScoreAggregate:
    eligible = tuple(item for item in dimensions if item.aggregate.eligible_weight > 0)
    observed = tuple(
        item for item in eligible if item.aggregate.observed_score_bps is not None
    )
    eligible_weight = sum(item.weight for item in eligible)
    included_weight = sum(item.weight for item in observed)
    if eligible_weight == 0:
        return ScoreAggregate(None, None, None, None, 0, 0)
    observed_score = (
        weighted_score_bps(
            (int(item.aggregate.observed_score_bps), item.weight)
            for item in observed
        )
        if observed
        else None
    )
    exact = (
        weighted_score_bps(
            (int(item.aggregate.score_bps), item.weight) for item in eligible
        )
        if all(item.aggregate.score_bps is not None for item in eligible)
        else None
    )
    lower = weighted_score_bps(
        (int(item.aggregate.lower_bound_bps), item.weight)
        for item in eligible
    )
    upper = weighted_score_bps(
        (int(item.aggregate.upper_bound_bps), item.weight)
        for item in eligible
    )
    return ScoreAggregate(
        score_bps=exact,
        observed_score_bps=observed_score,
        lower_bound_bps=lower,
        upper_bound_bps=upper,
        included_weight=included_weight,
        eligible_weight=eligible_weight,
    )


def _gate(checks: tuple[AssessedCheck, ...], scores: ScoreAggregate) -> GateAggregate:
    required = tuple(item for item in checks if item.mode is CheckMode.REQUIRED)

    # This ordering is the ADR-002 section 4 precedence: all known failures are
    # selected first; unresolved required checks are considered only after the
    # decision is fixed as fail-or-indeterminate.  Both vectors remain output.
    failures = tuple(
        Blocker(
            check_id=item.id,
            kind=BlockerKind.KNOWN_FAILURE,
            status=item.status,
            reason_code=item.reason_code,
        )
        for item in required
        if item.status is CheckStatus.FAIL
    )
    unresolved = tuple(
        Blocker(
            check_id=item.id,
            kind=(
                BlockerKind.MISSING_RESULT if item.missing else BlockerKind.UNRESOLVED
            ),
            status=item.status,
            reason_code=item.reason_code,
        )
        for item in required
        if item.status
        in {CheckStatus.UNKNOWN, CheckStatus.ERROR, CheckStatus.SKIPPED}
    )
    if failures:
        decision = Decision.FAIL
    elif unresolved:
        decision = Decision.INDETERMINATE
    else:
        decision = Decision.PASS
    return GateAggregate(
        decision=decision,
        complete=not unresolved,
        scores=scores,
        blockers=failures + unresolved,
    )


def evaluate(
    policy: Policy,
    results: tuple[CheckResult, ...],
    *,
    profile: Profile,
    subject: Subject,
    producer: Producer,
    evidence: tuple[EvidenceArtifact, ...] = (),
) -> Assessment:
    """Apply policy metadata, score dimensions, and evaluate the hard gate."""
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy")
    if not isinstance(results, tuple) or any(
        not isinstance(item, CheckResult) for item in results
    ):
        raise TypeError("results must be a tuple of CheckResult")
    if not isinstance(profile, Profile):
        raise TypeError("profile must be a Profile")
    if not isinstance(subject, Subject):
        raise TypeError("subject must be a Subject")
    if not isinstance(producer, Producer):
        raise TypeError("producer must be a Producer")
    if not isinstance(evidence, tuple) or any(
        not isinstance(item, EvidenceArtifact) for item in evidence
    ):
        raise TypeError("evidence must be a tuple of EvidenceArtifact")
    evidence_ids = [item.id for item in evidence]
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("submitted evidence IDs must be unique")
    if profile is Profile.RELEASE and subject.worktree == "dirty":
        raise ValueError("release profile requires a clean subject worktree")
    result_ids = [item.id for item in results]
    if len(set(result_ids)) != len(result_ids):
        raise ValueError("submitted check IDs must be unique")
    expected_ids = {item.id for item in policy.checks}
    unexpected = sorted(set(result_ids) - expected_ids)
    if unexpected:
        raise ValueError(
            "results contain policy-unknown check IDs: " + ", ".join(unexpected)
        )
    referenced_artifacts = {
        entry["value"]
        for result in results
        for entry in result.evidence
        if entry["kind"] == "artifact"
    }
    missing_artifacts = sorted(referenced_artifacts - set(evidence_ids))
    if missing_artifacts:
        raise ValueError(
            "results reference missing evidence artifacts: "
            + ", ".join(missing_artifacts)
        )
    submitted = {item.id: item for item in results}
    assessed: list[AssessedCheck] = []
    for check_policy in policy.checks:
        result = submitted.get(check_policy.id)
        missing = result is None
        if result is None:
            result = CheckResult(
                id=check_policy.id,
                status=CheckStatus.UNKNOWN,
                score_bps=None,
                reason_code=StandardReason.POLICY_CHECK_MISSING.value,
            )
        if result.status is CheckStatus.NOT_APPLICABLE:
            if check_policy.applicability is None:
                raise ValueError(
                    f"{result.id} cannot be not_applicable without a policy rule"
                )
            if not result.evidence:
                raise ValueError(
                    f"{result.id} cannot be not_applicable without evidence"
                )
        assessed.append(
            AssessedCheck(
                id=result.id,
                dimension=check_policy.dimension,
                mode=check_policy.mode_for(profile),
                status=result.status,
                score_bps=result.score_bps,
                weight=check_policy.weight,
                score_eligible=check_policy.score_eligible,
                criterion=check_policy.criterion,
                reason_code=result.reason_code,
                numerator=result.numerator,
                denominator=result.denominator,
                exclusions=result.exclusions,
                evidence=result.evidence,
                missing=missing,
            )
        )
    assessed_checks = tuple(assessed)
    dimensions = tuple(
        DimensionAssessment(
            id=dimension.id,
            weight=dimension.weight,
            aggregate=_score_checks(
                tuple(
                    item for item in assessed_checks if item.dimension == dimension.id
                )
            ),
        )
        for dimension in policy.dimensions
    )
    scores = _score_dimensions(dimensions)
    return Assessment(
        schema_version=ASSESSMENT_SCHEMA_VERSION,
        profile=profile,
        subject=subject,
        producer=producer,
        policy_id=policy.id,
        policy_sha256=policy.digest(),
        checks=assessed_checks,
        dimensions=dimensions,
        aggregate=_gate(assessed_checks, scores),
        evidence=evidence,
    )


def decision_exit_code(decision: Decision) -> ExitCode:
    """Map a completed evaluation decision to its stable process exit."""
    if not isinstance(decision, Decision):
        raise TypeError("decision must be a Decision")
    if decision is Decision.PASS:
        return ExitCode.COMPLETE_PASS
    if decision is Decision.FAIL:
        return ExitCode.KNOWN_FAILURE
    return ExitCode.INDETERMINATE


def _require_exact_keys(raw: Mapping[str, object], keys: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing:
        raise ValueError(f"{name} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{name} contains unknown fields: {', '.join(extra)}")


def policy_from_dict(raw: object) -> Policy:
    """Strictly validate and construct a policy from decoded JSON."""
    if not isinstance(raw, Mapping):
        raise TypeError("policy must be an object")
    _require_exact_keys(
        raw,
        {"schema_version", "id", "dimensions", "checks", "waivers"},
        "policy",
    )
    dimensions_raw = raw["dimensions"]
    checks_raw = raw["checks"]
    waivers_raw = raw["waivers"]
    if not isinstance(dimensions_raw, list):
        raise TypeError("policy dimensions must be a list")
    if not isinstance(checks_raw, list):
        raise TypeError("policy checks must be a list")
    if not isinstance(waivers_raw, list):
        raise TypeError("policy waivers must be a list")
    dimensions: list[DimensionPolicy] = []
    for item in dimensions_raw:
        if not isinstance(item, Mapping):
            raise TypeError("dimension entries must be objects")
        _require_exact_keys(item, {"id", "weight"}, "dimension")
        dimensions.append(DimensionPolicy(id=item["id"], weight=item["weight"]))
    checks: list[CheckPolicy] = []
    for item in checks_raw:
        if not isinstance(item, Mapping):
            raise TypeError("check entries must be objects")
        _require_exact_keys(
            item,
            {
                "id",
                "dimension",
                "weight",
                "score_eligible",
                "criterion",
                "modes",
                "applicability",
            },
            "check",
        )
        criterion_raw = item["criterion"]
        modes_raw = item["modes"]
        applicability_raw = item["applicability"]
        if not isinstance(criterion_raw, Mapping):
            raise TypeError("check criterion must be an object")
        if not isinstance(modes_raw, Mapping):
            raise TypeError("check modes must be an object")
        _require_exact_keys(criterion_raw, {"op", "value"}, "criterion")
        _require_exact_keys(modes_raw, {"offline", "release"}, "modes")
        applicability = None
        if applicability_raw is not None:
            if not isinstance(applicability_raw, Mapping):
                raise TypeError("check applicability must be an object or null")
            _require_exact_keys(applicability_raw, {"rule"}, "applicability")
            applicability = ApplicabilityRule(rule=applicability_raw["rule"])
        try:
            offline_mode = CheckMode(modes_raw["offline"])
            release_mode = CheckMode(modes_raw["release"])
        except ValueError as exc:
            raise ValueError("policy check modes must be required or advisory") from exc
        checks.append(
            CheckPolicy(
                id=item["id"],
                dimension=item["dimension"],
                weight=item["weight"],
                score_eligible=item["score_eligible"],
                criterion=Criterion(
                    op=criterion_raw["op"], value=criterion_raw["value"]
                ),
                offline_mode=offline_mode,
                release_mode=release_mode,
                applicability=applicability,
            )
        )
    return Policy(
        schema_version=raw["schema_version"],
        id=raw["id"],
        dimensions=tuple(dimensions),
        checks=tuple(checks),
        waivers=tuple(waivers_raw),
    )


def load_policy(path: str | Path) -> Policy:
    """Load a local policy without importing or invoking any adapter."""
    if not isinstance(path, (str, Path)):
        raise TypeError("path must be text or Path")
    return policy_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = [
    "ADR001_OFFLINE_GATE_ARGV",
    "ADR001_OFFLINE_GATE_TESTS",
    "ASSESSMENT_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "RUN_ENVELOPE_SCHEMA_VERSION",
    "ApplicabilityRule",
    "Assessment",
    "AssessedCheck",
    "Blocker",
    "BlockerKind",
    "CheckMode",
    "CheckPolicy",
    "CheckResult",
    "CheckStatus",
    "CommandExecution",
    "Criterion",
    "Decision",
    "DimensionAssessment",
    "DimensionPolicy",
    "ExitCode",
    "EvidenceArtifact",
    "GateAggregate",
    "Policy",
    "Producer",
    "Profile",
    "RunEnvelope",
    "ScoreAggregate",
    "SourceSpan",
    "Subject",
    "canonical_json_bytes",
    "canonical_patch_sha256",
    "collect_adr001_pytest_junit",
    "decision_exit_code",
    "display_band",
    "evaluate",
    "evaluate_deterministic_replay",
    "evaluate_engine_correctness_evidence",
    "evaluate_global_no_exhaustiveness",
    "evaluate_pytest_junit",
    "evaluate_result_provenance",
    "evaluate_retired_surfaces_absent",
    "evaluate_scoped_coverage",
    "evaluate_total_ordering",
    "load_policy",
    "policy_from_dict",
    "proportional_score_bps",
    "score_from_counts",
    "subject_from_repository",
    "untracked_inputs_sha256",
    "weighted_score_bps",
]
