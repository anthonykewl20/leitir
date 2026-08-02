"""Deterministic assessment contracts and gate algebra for ADR-002 S1.

This standalone module intentionally imports no Leitir package code.  It owns
the policy vocabulary, integer scoring arithmetic, and non-compensating gate;
collectors and evidence adapters belong to later ADR-002 slices.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP, localcontext
from enum import Enum, IntEnum
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable, Mapping


ASSESSMENT_SCHEMA_VERSION = "leitir-assessment-v1"
POLICY_SCHEMA_VERSION = "leitir-score-policy-v1"
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

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "dimensions": [item.to_dict() for item in self.dimensions],
            "checks": [
                item.to_dict()
                for item in sorted(self.checks, key=lambda check: check.id)
            ],
            "waivers": [],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


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
        if not isinstance(self.exclusions, tuple):
            raise TypeError("exclusions must be a tuple of (reason, count) pairs")
        exclusion_names: list[str] = []
        for item in self.exclusions:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("exclusions must contain (reason, count) tuples")
            reason, count = item
            if not isinstance(reason, str) or not _REASON_CODE.fullmatch(reason):
                raise ValueError("exclusion reasons must be uppercase snake-case")
            _validate_non_negative_int(count, "exclusion count")
            exclusion_names.append(reason)
        if len(set(exclusion_names)) != len(exclusion_names):
            raise ValueError("exclusion reasons must be unique")
        if not isinstance(self.evidence, tuple):
            raise TypeError("evidence must be a tuple of mappings")
        for item in self.evidence:
            if not isinstance(item, Mapping):
                raise TypeError("evidence must be a tuple of mappings")
            if set(item) != {"kind", "value"}:
                raise ValueError("evidence entries require exactly kind and value")
            if any(
                not isinstance(value, str) or not value.strip()
                for value in item.values()
            ):
                raise ValueError("evidence kind and value must be non-empty text")


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
            "exclusions": dict(sorted(self.exclusions)),
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
        if not isinstance(self.kind, BlockerKind):
            raise TypeError("kind must be a BlockerKind")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")

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

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "complete": self.complete,
            **self.scores.to_dict(),
            "blockers": [item.to_dict() for item in self.blockers],
        }


@dataclass(frozen=True, slots=True)
class Subject:
    """Minimal subject identity required by the canonical v1 shape."""

    repository: str
    commit_sha: str
    worktree: str

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise ValueError("repository must be non-empty text")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("commit_sha must be a 40-char git SHA")
        if self.worktree not in {"clean", "dirty"}:
            raise ValueError("worktree must be clean or dirty")

    def to_dict(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "worktree": self.worktree,
        }


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
    """Canonical S1 assessment artifact."""

    schema_version: str
    profile: Profile
    subject: Subject
    producer: Producer
    policy_id: str
    policy_sha256: str
    checks: tuple[AssessedCheck, ...]
    dimensions: tuple[DimensionAssessment, ...]
    aggregate: GateAggregate

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
            "dimensions": [item.to_dict() for item in self.dimensions],
            "aggregate": self.aggregate.to_dict(),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
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
    result_ids = [item.id for item in results]
    if len(set(result_ids)) != len(result_ids):
        raise ValueError("submitted check IDs must be unique")
    expected_ids = {item.id for item in policy.checks}
    unexpected = sorted(set(result_ids) - expected_ids)
    if unexpected:
        raise ValueError(
            "results contain policy-unknown check IDs: " + ", ".join(unexpected)
        )
    submitted = {item.id: item for item in results}
    assessed: list[AssessedCheck] = []
    for check_policy in sorted(policy.checks, key=lambda item: item.id):
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
    "ASSESSMENT_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "ApplicabilityRule",
    "Assessment",
    "AssessedCheck",
    "Blocker",
    "BlockerKind",
    "CheckMode",
    "CheckPolicy",
    "CheckResult",
    "CheckStatus",
    "Criterion",
    "Decision",
    "DimensionAssessment",
    "DimensionPolicy",
    "ExitCode",
    "GateAggregate",
    "Policy",
    "Producer",
    "Profile",
    "ScoreAggregate",
    "Subject",
    "decision_exit_code",
    "display_band",
    "evaluate",
    "load_policy",
    "policy_from_dict",
    "proportional_score_bps",
    "score_from_counts",
    "weighted_score_bps",
]
