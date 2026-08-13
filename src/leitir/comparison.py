"""Independent, incomparable-aware candidate comparison (ADR-0010 C3b).

There is deliberately no scalar suitability value in this module.  Candidates
are assessed in eleven closed dimensions and selected only for one of three
lexicographic presentation roles.  Missing evidence makes a dimension unknown;
it is never converted to a poor value.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from enum import StrEnum
from fractions import Fraction
from itertools import combinations
from typing import Any, NoReturn, TypeAlias, TypeVar, cast

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.candidates import CandidateKey, CandidateProposal, EvidencePointer
from leitir.capability import CapabilitySpec
from leitir.project_profile import RecipientProfile
from leitir.suitability import GateOutcome, SurvivorSet

BEST3_REPORT_SCHEMA = "leitir-best3-report-v1"
COMPARISON_ALGORITHM_VERSION = "independent-dimensions-v1"
_DIMENSION_COLLECTOR = "leitir.dimension_assessment"
_DIMENSION_COLLECTOR_VERSION = "v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_COUNT = 10**9


class DimensionKind(StrEnum):
    BEHAVIORAL_INTERFACE_FIT = "behavioral_interface_fit"
    DEPENDENCY_COST = "dependency_cost"
    EXTRACTION_DIFFICULTY = "extraction_difficulty"
    TEST_EXAMPLE_EVIDENCE = "test_example_evidence"
    DOCUMENTATION_EVIDENCE = "documentation_evidence"
    MAINTENANCE_STATUS = "maintenance_status"
    SECURITY_RISK = "security_risk"
    LICENSE_FIT = "license_fit"
    STRUCTURAL_COMPLEXITY = "structural_complexity"
    RUNTIME_PORTABILITY_FIT = "runtime_portability_fit"
    VERSION_STABILITY = "version_stability"


class DimensionStatus(StrEnum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class ComparisonResult(StrEnum):
    BETTER = "better"
    WORSE = "worse"
    EQUAL = "equal"
    INCOMPARABLE = "incomparable"


class InterfaceMatch(StrEnum):
    INCOMPATIBLE = "incompatible"
    ADAPTABLE = "adaptable"
    EXACT = "exact"


class ReleaseState(StrEnum):
    UNSUPPORTED = "unsupported"
    MAINTENANCE = "maintenance"
    ACTIVE = "active"


class CoverageState(StrEnum):
    PARTIAL = "partial"
    COMPLETE = "complete"


class LicenseMatch(StrEnum):
    INCOMPATIBLE = "incompatible"
    CONDITIONAL = "conditional"
    COMPATIBLE = "compatible"


class RuntimeMatch(StrEnum):
    ADAPTABLE = "adaptable"
    COMPATIBLE = "compatible"
    EXACT = "exact"


class ApiStability(StrEnum):
    EXPERIMENTAL = "experimental"
    STABLE = "stable"
    GUARANTEED = "guaranteed"


class RoleKind(StrEnum):
    DIRECT_FIT = "direct_fit"
    INTEGRATION_COST = "integration_cost"
    EVIDENCE_STRENGTH = "evidence_strength"


class RoleStatus(StrEnum):
    PROVED_WINNER = "proved_winner"
    EQUAL_IDENTITY_TIEBREAK = "equal_identity_tiebreak"
    UNRANKED_INCOMPARABLE = "unranked_incomparable"
    UNRANKED_NO_CANDIDATES = "unranked_no_candidates"


@dataclass(frozen=True, slots=True)
class BehavioralInterfaceValue:
    required_proved: int
    required_total: int
    preferred_proved: int
    preferred_total: int
    interface_match: InterfaceMatch

    def __post_init__(self) -> None:
        _ratio(self.required_proved, self.required_total, "required behavior")
        _ratio(self.preferred_proved, self.preferred_total, "preferred behavior", allow_zero_total=True)
        _enum(self.interface_match, InterfaceMatch, "interface_match")


@dataclass(frozen=True, slots=True)
class DependencyCostValue:
    new_direct: int
    new_transitive: int
    unresolved: int

    def __post_init__(self) -> None:
        _counts(self.new_direct, self.new_transitive, self.unresolved)
        if self.unresolved != 0:
            _invalid("known dependency cost must have zero unresolved dependencies")


@dataclass(frozen=True, slots=True)
class ExtractionDifficultyValue:
    bts_members: int
    source_lines: int
    adapters: int
    external_interfaces: int

    def __post_init__(self) -> None:
        _counts(self.bts_members, self.source_lines, self.adapters, self.external_interfaces)


@dataclass(frozen=True, slots=True)
class TestExampleEvidenceValue:
    contract_tests: int
    applicable_probes: int
    nondeprecated_examples: int

    def __post_init__(self) -> None:
        _counts(self.contract_tests, self.applicable_probes, self.nondeprecated_examples)


@dataclass(frozen=True, slots=True)
class DocumentationEvidenceValue:
    api_docs: int
    usage_examples: int
    versioned_contracts: int

    def __post_init__(self) -> None:
        _counts(self.api_docs, self.usage_examples, self.versioned_contracts)


@dataclass(frozen=True, slots=True)
class MaintenanceStatusValue:
    release_state: ReleaseState
    supported_release_count: int

    def __post_init__(self) -> None:
        _enum(self.release_state, ReleaseState, "release_state")
        _counts(self.supported_release_count)


@dataclass(frozen=True, slots=True)
class SecurityRiskValue:
    known_critical: int
    known_high: int
    known_moderate: int
    advisory_coverage: CoverageState

    def __post_init__(self) -> None:
        _counts(self.known_critical, self.known_high, self.known_moderate)
        _enum(self.advisory_coverage, CoverageState, "advisory_coverage")


@dataclass(frozen=True, slots=True)
class LicenseFitValue:
    match: LicenseMatch
    obligations_count: int

    def __post_init__(self) -> None:
        _enum(self.match, LicenseMatch, "match")
        _counts(self.obligations_count)


@dataclass(frozen=True, slots=True)
class StructuralComplexityValue:
    max_cyclomatic: int
    total_branches: int
    dynamic_blockers: int

    def __post_init__(self) -> None:
        _counts(self.max_cyclomatic, self.total_branches, self.dynamic_blockers)
        if self.dynamic_blockers != 0:
            _invalid("known structural complexity must have zero dynamic blockers")


@dataclass(frozen=True, slots=True)
class RuntimePortabilityValue:
    required_platforms_proved: int
    required_platforms_total: int
    runtime_match: RuntimeMatch

    def __post_init__(self) -> None:
        _ratio(self.required_platforms_proved, self.required_platforms_total, "required platform")
        _enum(self.runtime_match, RuntimeMatch, "runtime_match")


@dataclass(frozen=True, slots=True)
class VersionStabilityValue:
    api_stability: ApiStability
    compatible_versions_proved: int

    def __post_init__(self) -> None:
        _enum(self.api_stability, ApiStability, "api_stability")
        _counts(self.compatible_versions_proved)


def _assessment_fields(status: object, rule_id: object, rule_version: object, evidence: object, value: object, expected: type[object]) -> None:
    if not isinstance(status, DimensionStatus):
        _invalid("dimension status is invalid")
    _text(rule_id, "dimension rule_id")
    _text(rule_version, "dimension rule_version")
    if not isinstance(evidence, tuple) or not all(isinstance(item, EvidencePointer) for item in evidence):
        _invalid("dimension evidence must be a tuple of evidence pointers")
    if tuple(sorted(evidence)) != evidence or len(evidence) != len(set(evidence)):
        _invalid("dimension evidence must be canonical and unique")
    if status is DimensionStatus.KNOWN:
        if not isinstance(value, expected) or not evidence:
            _invalid("a known dimension requires its exact typed value and evidence")
    elif value is not None:
        _invalid("unknown and not-applicable dimensions cannot carry a value")
    if status is DimensionStatus.NOT_APPLICABLE and not evidence:
        _invalid("not-applicable requires applicability proof")


@dataclass(frozen=True, slots=True)
class BehavioralInterfaceAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: BehavioralInterfaceValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, BehavioralInterfaceValue)


@dataclass(frozen=True, slots=True)
class DependencyCostAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: DependencyCostValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, DependencyCostValue)


@dataclass(frozen=True, slots=True)
class ExtractionDifficultyAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: ExtractionDifficultyValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, ExtractionDifficultyValue)


@dataclass(frozen=True, slots=True)
class TestExampleEvidenceAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: TestExampleEvidenceValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, TestExampleEvidenceValue)


@dataclass(frozen=True, slots=True)
class DocumentationEvidenceAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: DocumentationEvidenceValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, DocumentationEvidenceValue)


@dataclass(frozen=True, slots=True)
class MaintenanceStatusAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: MaintenanceStatusValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, MaintenanceStatusValue)


@dataclass(frozen=True, slots=True)
class SecurityRiskAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: SecurityRiskValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, SecurityRiskValue)


@dataclass(frozen=True, slots=True)
class LicenseFitAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: LicenseFitValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, LicenseFitValue)


@dataclass(frozen=True, slots=True)
class StructuralComplexityAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: StructuralComplexityValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, StructuralComplexityValue)


@dataclass(frozen=True, slots=True)
class RuntimePortabilityAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: RuntimePortabilityValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, RuntimePortabilityValue)


@dataclass(frozen=True, slots=True)
class VersionStabilityAssessment:
    status: DimensionStatus
    rule_id: str
    rule_version: str
    evidence: tuple[EvidencePointer, ...]
    value: VersionStabilityValue | None

    def __post_init__(self) -> None:
        _assessment_fields(self.status, self.rule_id, self.rule_version, self.evidence, self.value, VersionStabilityValue)


DimensionAssessment: TypeAlias = (
    BehavioralInterfaceAssessment
    | DependencyCostAssessment
    | ExtractionDifficultyAssessment
    | TestExampleEvidenceAssessment
    | DocumentationEvidenceAssessment
    | MaintenanceStatusAssessment
    | SecurityRiskAssessment
    | LicenseFitAssessment
    | StructuralComplexityAssessment
    | RuntimePortabilityAssessment
    | VersionStabilityAssessment
)

_ASSESSMENT_TYPES: dict[DimensionKind, type[object]] = {
    DimensionKind.BEHAVIORAL_INTERFACE_FIT: BehavioralInterfaceAssessment,
    DimensionKind.DEPENDENCY_COST: DependencyCostAssessment,
    DimensionKind.EXTRACTION_DIFFICULTY: ExtractionDifficultyAssessment,
    DimensionKind.TEST_EXAMPLE_EVIDENCE: TestExampleEvidenceAssessment,
    DimensionKind.DOCUMENTATION_EVIDENCE: DocumentationEvidenceAssessment,
    DimensionKind.MAINTENANCE_STATUS: MaintenanceStatusAssessment,
    DimensionKind.SECURITY_RISK: SecurityRiskAssessment,
    DimensionKind.LICENSE_FIT: LicenseFitAssessment,
    DimensionKind.STRUCTURAL_COMPLEXITY: StructuralComplexityAssessment,
    DimensionKind.RUNTIME_PORTABILITY_FIT: RuntimePortabilityAssessment,
    DimensionKind.VERSION_STABILITY: VersionStabilityAssessment,
}

_ROLE_DIMENSIONS: dict[RoleKind, tuple[DimensionKind, ...]] = {
    RoleKind.DIRECT_FIT: (DimensionKind.BEHAVIORAL_INTERFACE_FIT, DimensionKind.RUNTIME_PORTABILITY_FIT),
    RoleKind.INTEGRATION_COST: (DimensionKind.DEPENDENCY_COST, DimensionKind.EXTRACTION_DIFFICULTY, DimensionKind.STRUCTURAL_COMPLEXITY),
    RoleKind.EVIDENCE_STRENGTH: (
        DimensionKind.TEST_EXAMPLE_EVIDENCE,
        DimensionKind.DOCUMENTATION_EVIDENCE,
        DimensionKind.MAINTENANCE_STATUS,
        DimensionKind.SECURITY_RISK,
        DimensionKind.VERSION_STABILITY,
    ),
}


def _canonical_bytes(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def _content_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


COMPARISON_POLICY_DIGEST = _content_digest(
    {"algorithm": COMPARISON_ALGORITHM_VERSION, "roles": {role.value: [item.value for item in dimensions] for role, dimensions in _ROLE_DIMENSIONS.items()}}
)


def _reject(reason: BTSRejectReason, message: str, detail: str) -> NoReturn:
    raise BTSError(reason, message, detail_code=detail)


def _invalid(message: str) -> NoReturn:
    _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, message, "dimension_assessment_invalid_v1")


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        _invalid(f"{name} must be bounded non-empty text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _invalid(f"{name} must be strict UTF-8")
    return value


def _counts(*values: object) -> None:
    if any(isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_COUNT for value in values):
        _invalid("dimension counts must be bounded non-negative integers")


def _ratio(proved: object, total: object, name: str, *, allow_zero_total: bool = False) -> None:
    _counts(proved, total)
    assert isinstance(proved, int) and isinstance(total, int)
    if proved > total or (total == 0 and not allow_zero_total):
        _invalid(f"{name} ratio is invalid")


def _enum(value: object, enum_type: type[StrEnum], name: str) -> None:
    if not isinstance(value, enum_type):
        _invalid(f"{name} must be {enum_type.__name__}")


_T = TypeVar("_T")


def _ordered(left: _T, right: _T) -> ComparisonResult:
    if left == right:
        return ComparisonResult.EQUAL
    return ComparisonResult.BETTER if left > right else ComparisonResult.WORSE  # type: ignore[operator]


def _ordinal(value: StrEnum, enum_type: type[StrEnum]) -> int:
    return list(enum_type).index(value)


def compare_assessments(left: DimensionAssessment, right: DimensionAssessment) -> ComparisonResult:
    """Compare two values of exactly the same dimension, or reject cross-dimension use."""

    if type(left) is not type(right) or type(left) not in _ASSESSMENT_TYPES.values():
        _reject(BTSRejectReason.REJECT_SEMANTIC_DEGRADATION, "cross-dimension comparison is forbidden", "dimension_cross_compare_v1")
    if left.status is DimensionStatus.UNKNOWN or right.status is DimensionStatus.UNKNOWN:
        return ComparisonResult.INCOMPARABLE
    if left.status is DimensionStatus.NOT_APPLICABLE or right.status is DimensionStatus.NOT_APPLICABLE:
        return ComparisonResult.EQUAL if left.status is right.status else ComparisonResult.INCOMPARABLE
    if left.value is None or right.value is None:  # construction guards this; retain a fail-closed boundary
        _invalid("known dimension is missing its value")
    lv, rv = left.value, right.value
    if isinstance(lv, BehavioralInterfaceValue) and isinstance(rv, BehavioralInterfaceValue):
        return _ordered(
            (Fraction(lv.required_proved, lv.required_total), Fraction(lv.preferred_proved, lv.preferred_total or 1), _ordinal(lv.interface_match, InterfaceMatch)),
            (Fraction(rv.required_proved, rv.required_total), Fraction(rv.preferred_proved, rv.preferred_total or 1), _ordinal(rv.interface_match, InterfaceMatch)),
        )
    if isinstance(lv, DependencyCostValue) and isinstance(rv, DependencyCostValue):
        return _ordered((-lv.new_direct, -lv.new_transitive, -lv.unresolved), (-rv.new_direct, -rv.new_transitive, -rv.unresolved))
    if isinstance(lv, ExtractionDifficultyValue) and isinstance(rv, ExtractionDifficultyValue):
        return _ordered((-lv.bts_members, -lv.source_lines, -lv.adapters, -lv.external_interfaces), (-rv.bts_members, -rv.source_lines, -rv.adapters, -rv.external_interfaces))
    if isinstance(lv, TestExampleEvidenceValue) and isinstance(rv, TestExampleEvidenceValue):
        return _ordered((lv.contract_tests, lv.applicable_probes, lv.nondeprecated_examples), (rv.contract_tests, rv.applicable_probes, rv.nondeprecated_examples))
    if isinstance(lv, DocumentationEvidenceValue) and isinstance(rv, DocumentationEvidenceValue):
        return _ordered((lv.api_docs, lv.usage_examples, lv.versioned_contracts), (rv.api_docs, rv.usage_examples, rv.versioned_contracts))
    if isinstance(lv, MaintenanceStatusValue) and isinstance(rv, MaintenanceStatusValue):
        return _ordered((_ordinal(lv.release_state, ReleaseState), lv.supported_release_count), (_ordinal(rv.release_state, ReleaseState), rv.supported_release_count))
    if isinstance(lv, SecurityRiskValue) and isinstance(rv, SecurityRiskValue):
        return _ordered((-lv.known_critical, -lv.known_high, -lv.known_moderate, _ordinal(lv.advisory_coverage, CoverageState)), (-rv.known_critical, -rv.known_high, -rv.known_moderate, _ordinal(rv.advisory_coverage, CoverageState)))
    if isinstance(lv, LicenseFitValue) and isinstance(rv, LicenseFitValue):
        return _ordered((_ordinal(lv.match, LicenseMatch), -lv.obligations_count), (_ordinal(rv.match, LicenseMatch), -rv.obligations_count))
    if isinstance(lv, StructuralComplexityValue) and isinstance(rv, StructuralComplexityValue):
        return _ordered((-lv.max_cyclomatic, -lv.total_branches, -lv.dynamic_blockers), (-rv.max_cyclomatic, -rv.total_branches, -rv.dynamic_blockers))
    if isinstance(lv, RuntimePortabilityValue) and isinstance(rv, RuntimePortabilityValue):
        return _ordered((Fraction(lv.required_platforms_proved, lv.required_platforms_total), _ordinal(lv.runtime_match, RuntimeMatch)), (Fraction(rv.required_platforms_proved, rv.required_platforms_total), _ordinal(rv.runtime_match, RuntimeMatch)))
    if isinstance(lv, VersionStabilityValue) and isinstance(rv, VersionStabilityValue):
        return _ordered((_ordinal(lv.api_stability, ApiStability), lv.compatible_versions_proved), (_ordinal(rv.api_stability, ApiStability), rv.compatible_versions_proved))
    _invalid("assessment and value concrete types do not match")


@dataclass(frozen=True, slots=True)
class CandidateDimensionVector:
    candidate_key: CandidateKey
    gate_outcome: GateOutcome
    dimensions: tuple[DimensionAssessment, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.candidate_key, tuple)
            or not isinstance(self.gate_outcome, GateOutcome)
            or not self.gate_outcome.survives
            or self.gate_outcome.candidate_key != self.candidate_key
            or len(self.dimensions) != len(DimensionKind)
        ):
            _invalid("candidate dimension vector is incomplete")
        actual = tuple(_kind(item) for item in self.dimensions)
        if actual != tuple(DimensionKind):
            _invalid("candidate dimension vector is not in closed canonical order")


@dataclass(frozen=True, slots=True)
class IncomparablePair:
    left: CandidateKey
    right: CandidateKey
    dimension: DimensionKind


@dataclass(frozen=True, slots=True)
class RoleSelection:
    role: RoleKind
    status: RoleStatus
    candidate_key: CandidateKey | None
    dimensions: tuple[DimensionKind, ...]
    incomparable_pairs: tuple[IncomparablePair, ...]
    tradeoff: str


@dataclass(frozen=True, slots=True)
class Best3Report:
    schema_version: str
    algorithm_version: str
    comparison_policy_digest: str
    survivor_set_digest: str
    spec_digest: str
    profile_digest: str
    candidates: tuple[CandidateDimensionVector, ...]
    roles: tuple[RoleSelection, ...]
    report_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != BEST3_REPORT_SCHEMA or self.algorithm_version != COMPARISON_ALGORITHM_VERSION:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "unsupported comparison report envelope", "capability_report_artifact_v1")
        if self.comparison_policy_digest != COMPARISON_POLICY_DIGEST:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "comparison policy mismatch", "capability_report_artifact_v1")
        if tuple(item.candidate_key for item in self.candidates) != tuple(sorted(item.candidate_key for item in self.candidates)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "comparison candidates are not canonical", "capability_report_artifact_v1")
        if tuple(item.role for item in self.roles) != tuple(RoleKind):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "comparison roles are incomplete", "capability_report_artifact_v1")
        for value in (self.comparison_policy_digest, self.survivor_set_digest, self.spec_digest, self.profile_digest, self.report_digest):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "comparison report contains malformed digest", "capability_report_artifact_v1")
        if self.report_digest != _content_digest(_report_payload(self, omit_digest=True)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "comparison report digest mismatch", "capability_report_artifact_v1")

    def to_bytes(self) -> bytes:
        return _canonical_bytes(_report_payload(self))


def _kind(assessment: DimensionAssessment) -> DimensionKind:
    for kind, assessment_type in _ASSESSMENT_TYPES.items():
        if type(assessment) is assessment_type:
            return kind
    _invalid("assessment is outside the closed dimension union")


def _int_parts(parts: list[str], count: int) -> tuple[int, ...]:
    if len(parts) != count or any(re.fullmatch(r"0|[1-9][0-9]*", part) is None for part in parts):
        _invalid("dimension marker has malformed integer fields")
    values = tuple(int(part) for part in parts)
    _counts(*values)
    return values


def _known_value(kind: DimensionKind, parts: list[str]) -> object:
    try:
        if kind is DimensionKind.BEHAVIORAL_INTERFACE_FIT:
            values = _int_parts(parts[:4], 4)
            if len(parts) != 5:
                _invalid("behavioral/interface marker field count is invalid")
            return BehavioralInterfaceValue(values[0], values[1], values[2], values[3], InterfaceMatch(parts[4]))
        if kind is DimensionKind.DEPENDENCY_COST:
            return DependencyCostValue(*_int_parts(parts, 3))
        if kind is DimensionKind.EXTRACTION_DIFFICULTY:
            return ExtractionDifficultyValue(*_int_parts(parts, 4))
        if kind is DimensionKind.TEST_EXAMPLE_EVIDENCE:
            return TestExampleEvidenceValue(*_int_parts(parts, 3))
        if kind is DimensionKind.DOCUMENTATION_EVIDENCE:
            return DocumentationEvidenceValue(*_int_parts(parts, 3))
        if kind is DimensionKind.MAINTENANCE_STATUS:
            if len(parts) != 2:
                _invalid("maintenance marker field count is invalid")
            return MaintenanceStatusValue(ReleaseState(parts[0]), _int_parts(parts[1:], 1)[0])
        if kind is DimensionKind.SECURITY_RISK:
            values = _int_parts(parts[:3], 3)
            if len(parts) != 4:
                _invalid("security marker field count is invalid")
            return SecurityRiskValue(values[0], values[1], values[2], CoverageState(parts[3]))
        if kind is DimensionKind.LICENSE_FIT:
            if len(parts) != 2:
                _invalid("license marker field count is invalid")
            return LicenseFitValue(LicenseMatch(parts[0]), _int_parts(parts[1:], 1)[0])
        if kind is DimensionKind.STRUCTURAL_COMPLEXITY:
            return StructuralComplexityValue(*_int_parts(parts, 3))
        if kind is DimensionKind.RUNTIME_PORTABILITY_FIT:
            values = _int_parts(parts[:2], 2)
            if len(parts) != 3:
                _invalid("runtime/portability marker field count is invalid")
            return RuntimePortabilityValue(values[0], values[1], RuntimeMatch(parts[2]))
        if kind is DimensionKind.VERSION_STABILITY:
            if len(parts) != 2:
                _invalid("version marker field count is invalid")
            return VersionStabilityValue(ApiStability(parts[0]), _int_parts(parts[1:], 1)[0])
    except ValueError:
        _invalid("dimension marker contains an unknown closed enum value")
    _invalid("unsupported dimension marker")


def _assessment(kind: DimensionKind, candidate: CandidateProposal) -> DimensionAssessment:
    prefix = f"dimension:{kind.value}:"
    evidence = tuple(sorted(item for item in candidate.extraction_evidence + candidate.context_evidence if item.evidence_kind.startswith(prefix)))
    if len(evidence) > 1:
        _invalid(f"duplicate assessment markers for {kind.value}")
    status = DimensionStatus.UNKNOWN
    value: object | None = None
    if evidence:
        marker = evidence[0]
        if marker.collector_id != _DIMENSION_COLLECTOR or marker.collector_version != _DIMENSION_COLLECTOR_VERSION:
            _invalid(f"untrusted assessment marker for {kind.value}")
        encoded = marker.evidence_kind.removeprefix(prefix)
        if encoded == "unknown":
            status = DimensionStatus.UNKNOWN
        elif encoded == "not_applicable":
            status = DimensionStatus.NOT_APPLICABLE
        elif encoded.startswith("known:"):
            status = DimensionStatus.KNOWN
            value = _known_value(kind, encoded.removeprefix("known:").split(","))
        else:
            _invalid(f"malformed assessment marker for {kind.value}")
    common = (status, f"leitir.dimension.{kind.value}", "v1", evidence)
    if kind is DimensionKind.BEHAVIORAL_INTERFACE_FIT:
        return BehavioralInterfaceAssessment(*common, cast(BehavioralInterfaceValue | None, value))
    if kind is DimensionKind.DEPENDENCY_COST:
        return DependencyCostAssessment(*common, cast(DependencyCostValue | None, value))
    if kind is DimensionKind.EXTRACTION_DIFFICULTY:
        return ExtractionDifficultyAssessment(*common, cast(ExtractionDifficultyValue | None, value))
    if kind is DimensionKind.TEST_EXAMPLE_EVIDENCE:
        return TestExampleEvidenceAssessment(*common, cast(TestExampleEvidenceValue | None, value))
    if kind is DimensionKind.DOCUMENTATION_EVIDENCE:
        return DocumentationEvidenceAssessment(*common, cast(DocumentationEvidenceValue | None, value))
    if kind is DimensionKind.MAINTENANCE_STATUS:
        return MaintenanceStatusAssessment(*common, cast(MaintenanceStatusValue | None, value))
    if kind is DimensionKind.SECURITY_RISK:
        return SecurityRiskAssessment(*common, cast(SecurityRiskValue | None, value))
    if kind is DimensionKind.LICENSE_FIT:
        return LicenseFitAssessment(*common, cast(LicenseFitValue | None, value))
    if kind is DimensionKind.STRUCTURAL_COMPLEXITY:
        return StructuralComplexityAssessment(*common, cast(StructuralComplexityValue | None, value))
    if kind is DimensionKind.RUNTIME_PORTABILITY_FIT:
        return RuntimePortabilityAssessment(*common, cast(RuntimePortabilityValue | None, value))
    if kind is DimensionKind.VERSION_STABILITY:
        return VersionStabilityAssessment(*common, cast(VersionStabilityValue | None, value))
    _invalid("unsupported dimension assessment")


def _role_compare(left: CandidateDimensionVector, right: CandidateDimensionVector, dimensions: tuple[DimensionKind, ...]) -> tuple[ComparisonResult, DimensionKind | None]:
    left_by_kind = {_kind(item): item for item in left.dimensions}
    right_by_kind = {_kind(item): item for item in right.dimensions}
    for dimension in dimensions:
        result = compare_assessments(left_by_kind[dimension], right_by_kind[dimension])
        if result is not ComparisonResult.EQUAL:
            return result, dimension
    return ComparisonResult.EQUAL, None


def _select_role(role: RoleKind, candidates: tuple[CandidateDimensionVector, ...]) -> RoleSelection:
    dimensions = _ROLE_DIMENSIONS[role]
    if not candidates:
        return RoleSelection(role, RoleStatus.UNRANKED_NO_CANDIDATES, None, dimensions, (), f"{role.value}: no eligible survivors")
    pair_results: dict[tuple[CandidateKey, CandidateKey], ComparisonResult] = {}
    incomparable: list[IncomparablePair] = []
    for left, right in combinations(candidates, 2):
        result, dimension = _role_compare(left, right, dimensions)
        pair_results[(left.candidate_key, right.candidate_key)] = result
        if result is ComparisonResult.INCOMPARABLE:
            assert dimension is not None
            incomparable.append(IncomparablePair(left.candidate_key, right.candidate_key, dimension))
    if incomparable:
        return RoleSelection(
            role, RoleStatus.UNRANKED_INCOMPARABLE, None, dimensions, tuple(incomparable),
            f"{role.value}: unranked because required comparisons are incomparable",
        )
    winners: list[CandidateDimensionVector] = []
    for candidate in candidates:
        no_worse = True
        for other in candidates:
            if candidate is other:
                continue
            keys = (candidate.candidate_key, other.candidate_key)
            if keys in pair_results:
                result = pair_results[keys]
            else:
                reverse = pair_results[(other.candidate_key, candidate.candidate_key)]
                result = ComparisonResult.BETTER if reverse is ComparisonResult.WORSE else ComparisonResult.WORSE if reverse is ComparisonResult.BETTER else reverse
            if result is ComparisonResult.WORSE:
                no_worse = False
                break
        if no_worse:
            winners.append(candidate)
    if not winners:  # pragma: no cover - a comparable finite lexicographic order has a maximum
        _reject(BTSRejectReason.REJECT_SEMANTIC_DEGRADATION, "comparison could not prove a role maximum", "comparison_unauthorized_ranking_v1")
    selected = min(winners, key=lambda item: item.candidate_key)
    tied = len(winners) > 1 or len(candidates) == 1
    status = RoleStatus.EQUAL_IDENTITY_TIEBREAK if tied else RoleStatus.PROVED_WINNER
    explanation = "equal values; canonical identity is presentation-only" if tied else "proved comparable-better than every contender"
    return RoleSelection(role, status, selected.candidate_key, dimensions, (), f"{role.value}: {explanation}")


def compare_and_select(survivors: SurvivorSet, spec: CapabilitySpec, profile: RecipientProfile) -> Best3Report:
    """Return zero to three independently proved role selections from C3a survivors."""

    if not isinstance(survivors, SurvivorSet):
        _reject(BTSRejectReason.REJECT_SEMANTIC_DEGRADATION, "comparison accepts only a C3a SurvivorSet", "comparison_unauthorized_ranking_v1")
    if not isinstance(spec, CapabilitySpec) or not isinstance(profile, RecipientProfile):
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "comparison spec/profile types are invalid", "dimension_assessment_invalid_v1")
    if survivors.spec_digest != spec.spec_digest or survivors.profile_digest != profile.profile_digest:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "comparison inputs do not match the survivor set", "capability_report_artifact_v1")
    vectors = tuple(
        CandidateDimensionVector(candidate.key(), outcome, tuple(_assessment(kind, candidate) for kind in DimensionKind))
        for candidate, outcome in zip(survivors.candidates, survivors.outcomes, strict=True)
    )
    roles = tuple(_select_role(role, vectors) for role in RoleKind)
    base = {
        "algorithm_version": COMPARISON_ALGORITHM_VERSION,
        "candidates": [_vector_payload(item) for item in vectors],
        "comparison_policy_digest": COMPARISON_POLICY_DIGEST,
        "profile_digest": profile.profile_digest,
        "roles": [_role_payload(item) for item in roles],
        "schema_version": BEST3_REPORT_SCHEMA,
        "spec_digest": spec.spec_digest,
        "survivor_set_digest": survivors.survivor_set_digest,
    }
    return Best3Report(
        BEST3_REPORT_SCHEMA, COMPARISON_ALGORITHM_VERSION, COMPARISON_POLICY_DIGEST,
        survivors.survivor_set_digest, spec.spec_digest, profile.profile_digest, vectors, roles, _content_digest(base),
    )


def _value_payload(value: object) -> dict[str, object]:
    dataclass_value = cast(Any, value)
    return {field.name: (getattr(value, field.name).value if isinstance(getattr(value, field.name), StrEnum) else getattr(value, field.name)) for field in fields(dataclass_value)}


def _assessment_payload(item: DimensionAssessment) -> dict[str, object]:
    return {
        "dimension": _kind(item).value,
        "evidence": [{field.name: getattr(pointer, field.name) for field in fields(pointer)} for pointer in item.evidence],
        "rule_id": item.rule_id,
        "rule_version": item.rule_version,
        "status": item.status.value,
        "value": _value_payload(item.value) if item.value is not None else None,
    }


def _vector_payload(item: CandidateDimensionVector) -> dict[str, object]:
    gate_payload = json.loads(item.gate_outcome.to_bytes())
    return {
        "candidate_key": list(item.candidate_key),
        "dimensions": [_assessment_payload(assessment) for assessment in item.dimensions],
        "gate_outcome": gate_payload,
    }


def _role_payload(item: RoleSelection) -> dict[str, object]:
    return {
        "candidate_key": list(item.candidate_key) if item.candidate_key is not None else None,
        "dimensions": [dimension.value for dimension in item.dimensions],
        "incomparable_pairs": [
            {"dimension": pair.dimension.value, "left": list(pair.left), "right": list(pair.right)} for pair in item.incomparable_pairs
        ],
        "role": item.role.value,
        "status": item.status.value,
        "tradeoff": item.tradeoff,
    }


def _report_payload(report: Best3Report, *, omit_digest: bool = False) -> dict[str, object]:
    payload: dict[str, object] = {
        "algorithm_version": report.algorithm_version,
        "candidates": [_vector_payload(item) for item in report.candidates],
        "comparison_policy_digest": report.comparison_policy_digest,
        "profile_digest": report.profile_digest,
        "roles": [_role_payload(item) for item in report.roles],
        "schema_version": report.schema_version,
        "spec_digest": report.spec_digest,
        "survivor_set_digest": report.survivor_set_digest,
    }
    if not omit_digest:
        payload["report_digest"] = report.report_digest
    return payload


__all__ = [
    "BEST3_REPORT_SCHEMA", "COMPARISON_ALGORITHM_VERSION", "COMPARISON_POLICY_DIGEST", "ApiStability",
    "BehavioralInterfaceAssessment", "BehavioralInterfaceValue", "Best3Report", "CandidateDimensionVector",
    "ComparisonResult", "CoverageState", "DependencyCostAssessment", "DependencyCostValue", "DimensionAssessment",
    "DimensionKind", "DimensionStatus", "DocumentationEvidenceAssessment", "DocumentationEvidenceValue",
    "ExtractionDifficultyAssessment", "ExtractionDifficultyValue", "IncomparablePair", "InterfaceMatch",
    "LicenseFitAssessment", "LicenseFitValue", "LicenseMatch", "MaintenanceStatusAssessment", "MaintenanceStatusValue",
    "ReleaseState", "RoleKind", "RoleSelection", "RoleStatus", "RuntimeMatch", "RuntimePortabilityAssessment",
    "RuntimePortabilityValue", "SecurityRiskAssessment", "SecurityRiskValue", "StructuralComplexityAssessment",
    "StructuralComplexityValue", "TestExampleEvidenceAssessment", "TestExampleEvidenceValue", "VersionStabilityAssessment",
    "VersionStabilityValue", "compare_and_select", "compare_assessments",
]
