"""Deterministic, non-compensating suitability hard gates (ADR-0010 C3a).

The module deliberately does not rank candidates.  It retains ADR-0002's six
assessment statuses and admits to C3b only candidates for which every applicable
required gate passed.  Retrieval terms and scores are never inspected here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, fields
from enum import StrEnum
from itertools import pairwise
from typing import NoReturn

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.candidates import CandidateKey, CandidateProposal, EvidencePointer
from leitir.capability import CapabilitySpec, ConstraintMode
from leitir.project_profile import RecipientProfile

SUITABILITY_POLICY_SCHEMA = "leitir-suitability-policy-v1"
GATE_OUTCOME_SCHEMA = "leitir-gate-outcome-v1"
SURVIVOR_SET_SCHEMA = "leitir-survivor-set-v1"
_AUTHORITY = "leitir-maintainers"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_GATES = 128


class GateStatus(StrEnum):
    """The complete ADR-0002 status vocabulary; values are never collapsed."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"


class GateVerdictStatus(StrEnum):
    PASS = "pass"
    REJECT = "reject"
    INDETERMINATE = "indeterminate"


class GateKind(StrEnum):
    IMMUTABLE_PROVENANCE = "immutable_provenance"
    CANDIDATE_CONTRACT = "candidate_contract"
    LANGUAGE = "language"
    RUNTIME = "runtime"
    REQUIRED_BEHAVIOR = "required_behavior"
    PROHIBITED_BEHAVIOR = "prohibited_behavior"
    INTERFACE_EFFECT = "interface_effect"
    PERFORMANCE = "performance"
    LICENSE = "license"
    DEPENDENCY = "dependency"
    PLATFORM = "platform"
    MINIMUM_EVIDENCE = "minimum_evidence"


def _canonical_bytes(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def _content_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _reject(reason: BTSRejectReason, message: str, detail: str) -> NoReturn:
    raise BTSError(reason, message, detail_code=detail)


def _bounded_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"{name} must be bounded non-empty text", "suitability_status_conversion_v1")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"{name} must be strict UTF-8", "suitability_status_conversion_v1")
    return value


@dataclass(frozen=True, slots=True, order=True)
class AssessmentStatusEvidence:
    """Original assessment status retained verbatim beside its normalized value."""

    source: str
    original_status: str
    status: GateStatus

    def __post_init__(self) -> None:
        _bounded_text(self.source, "status source")
        if self.original_status != self.status.value:
            _reject(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                "assessment status conversion is not one-to-one",
                "suitability_status_conversion_v1",
            )


@dataclass(frozen=True, slots=True, order=True)
class SuitabilityGate:
    """One versioned gate template from the maintainer-pinned policy."""

    kind: GateKind
    rule_id: str
    rule_version: str
    default_mode: ConstraintMode
    not_applicable_when_empty: bool

    def __post_init__(self) -> None:
        if not isinstance(self.kind, GateKind) or not isinstance(self.default_mode, ConstraintMode):
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "invalid suitability gate enum", "suitability_status_conversion_v1")
        _bounded_text(self.rule_id, "gate rule_id")
        _bounded_text(self.rule_version, "gate rule_version")


@dataclass(frozen=True, slots=True)
class SuitabilityPolicy:
    schema_version: str
    authority: str
    policy_id: str
    policy_version: str
    gates: tuple[SuitabilityGate, ...]
    content_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != SUITABILITY_POLICY_SCHEMA or self.authority != _AUTHORITY:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "unsupported suitability policy authority", "capability_registry_digest_v1")
        _bounded_text(self.policy_id, "policy_id")
        _bounded_text(self.policy_version, "policy_version")
        if not isinstance(self.gates, tuple) or not self.gates or len(self.gates) > _MAX_GATES or not all(isinstance(gate, SuitabilityGate) for gate in self.gates):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid suitability policy gate set", "capability_registry_digest_v1")
        ordered = tuple(sorted(self.gates, key=lambda gate: gate.kind.value))
        if any(left.kind is right.kind for left, right in pairwise(ordered)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "duplicate suitability gate kind", "capability_registry_digest_v1")
        object.__setattr__(self, "gates", ordered)
        if not isinstance(self.content_digest, str) or _DIGEST.fullmatch(self.content_digest) is None or self.content_digest != _content_digest(self._payload(False)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "suitability policy digest mismatch", "capability_registry_digest_v1")

    @classmethod
    def create(cls, *, policy_id: str, policy_version: str, gates: tuple[SuitabilityGate, ...]) -> SuitabilityPolicy:
        ordered = tuple(sorted(gates, key=lambda gate: gate.kind.value))
        payload = {
            "authority": _AUTHORITY,
            "gates": [_gate_policy_payload(gate) for gate in ordered],
            "policy_id": policy_id,
            "policy_version": policy_version,
            "schema_version": SUITABILITY_POLICY_SCHEMA,
        }
        return cls(SUITABILITY_POLICY_SCHEMA, _AUTHORITY, policy_id, policy_version, ordered, _content_digest(payload))

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "authority": self.authority,
            "gates": [_gate_policy_payload(gate) for gate in self.gates],
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "schema_version": self.schema_version,
        }
        if include_digest:
            payload["content_digest"] = self.content_digest
        return payload


def _gate_policy_payload(gate: SuitabilityGate) -> dict[str, object]:
    return {
        "default_mode": gate.default_mode.value,
        "kind": gate.kind.value,
        "not_applicable_when_empty": gate.not_applicable_when_empty,
        "rule_id": gate.rule_id,
        "rule_version": gate.rule_version,
    }


def _pinned_policy() -> SuitabilityPolicy:
    required = ConstraintMode.REQUIRED
    gates = tuple(
        SuitabilityGate(kind, f"suitability.{kind.value}", "v1", required, kind in {
            GateKind.PROHIBITED_BEHAVIOR, GateKind.INTERFACE_EFFECT, GateKind.PERFORMANCE, GateKind.DEPENDENCY,
        })
        for kind in GateKind
    )
    return SuitabilityPolicy.create(policy_id="leitir-suitability", policy_version="v1", gates=gates)


PINNED_SUITABILITY_POLICY = _pinned_policy()


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    gate_kind: GateKind
    policy_rule_id: str
    policy_rule_version: str
    mode: ConstraintMode
    status: GateStatus
    status_evidence: AssessmentStatusEvidence
    applicable_fields: tuple[str, ...]
    evidence: tuple[EvidencePointer, ...]
    reason: BTSRejectReason | None
    detail_code: str | None

    def __post_init__(self) -> None:
        _bounded_text(self.gate_id, "gate_id")
        if not isinstance(self.gate_kind, GateKind) or not isinstance(self.mode, ConstraintMode) or not isinstance(self.status, GateStatus):
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "invalid gate result enum", "suitability_status_conversion_v1")
        if self.status_evidence.status is not self.status:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "gate status evidence mismatch", "suitability_status_conversion_v1")
        fields_ordered = tuple(sorted(_bounded_text(item, "applicable field") for item in self.applicable_fields))
        evidence_ordered = tuple(sorted(self.evidence))
        if len(fields_ordered) != len(set(fields_ordered)) or len(evidence_ordered) != len(set(evidence_ordered)):
            _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "duplicate suitability evidence", "candidate_identity_duplicate_v1")
        object.__setattr__(self, "applicable_fields", fields_ordered)
        object.__setattr__(self, "evidence", evidence_ordered)
        unresolved = self.status in {GateStatus.FAIL, GateStatus.UNKNOWN, GateStatus.ERROR, GateStatus.SKIPPED}
        if unresolved != (self.reason is not None and self.detail_code is not None):
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "gate rejection metadata does not match status", "suitability_status_conversion_v1")


@dataclass(frozen=True, slots=True)
class GateOutcome:
    schema_version: str
    candidate_key: CandidateKey
    spec_digest: str
    profile_digest: str
    policy_digest: str
    verdict: GateVerdictStatus
    complete: bool
    results: tuple[GateResult, ...]
    outcome_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != GATE_OUTCOME_SCHEMA or not self.results:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid gate outcome envelope", "candidate_source_provenance_v1")
        if tuple(result.gate_id for result in self.results) != tuple(sorted(result.gate_id for result in self.results)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "gate outcomes are not canonically ordered", "candidate_source_provenance_v1")
        required = tuple(result for result in self.results if result.mode is ConstraintMode.REQUIRED)
        failure = any(result.status is GateStatus.FAIL for result in required)
        unresolved = any(result.status in {GateStatus.UNKNOWN, GateStatus.ERROR, GateStatus.SKIPPED} for result in required)
        expected = GateVerdictStatus.REJECT if failure else GateVerdictStatus.INDETERMINATE if unresolved else GateVerdictStatus.PASS
        if self.verdict is not expected or self.complete is unresolved:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "gate outcome verdict does not match its result vector", "candidate_source_provenance_v1")
        for value in (self.spec_digest, self.profile_digest, self.policy_digest, self.outcome_digest):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "gate outcome contains a malformed digest", "candidate_source_provenance_v1")
        if self.outcome_digest != _content_digest(_outcome_payload(self, omit_digest=True)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "gate outcome digest mismatch", "candidate_source_provenance_v1")

    @property
    def survives(self) -> bool:
        return self.verdict is GateVerdictStatus.PASS

    def to_bytes(self) -> bytes:
        return _canonical_bytes(_outcome_payload(self))


@dataclass(frozen=True, slots=True)
class SurvivorSet:
    """The sole C3a output eligible for C3b consumption."""

    schema_version: str
    spec_digest: str
    profile_digest: str
    policy_digest: str
    candidates: tuple[CandidateProposal, ...]
    outcomes: tuple[GateOutcome, ...]
    survivor_set_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != SURVIVOR_SET_SCHEMA:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid survivor set schema", "candidate_source_provenance_v1")
        if any(not outcome.survives for outcome in self.outcomes) or len(self.candidates) != len(self.outcomes):
            _reject(BTSRejectReason.REJECT_SEMANTIC_DEGRADATION, "survivor set contains an ineligible candidate", "comparison_unauthorized_ranking_v1")
        if tuple(candidate.key() for candidate in self.candidates) != tuple(outcome.candidate_key for outcome in self.outcomes):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "survivor candidate/outcome mismatch", "candidate_source_provenance_v1")
        if tuple(candidate.key() for candidate in self.candidates) != tuple(sorted(candidate.key() for candidate in self.candidates)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "survivor set is not canonically ordered", "candidate_source_provenance_v1")
        if any(outcome.spec_digest != self.spec_digest or outcome.profile_digest != self.profile_digest or outcome.policy_digest != self.policy_digest for outcome in self.outcomes):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "survivor set input binding mismatch", "candidate_source_provenance_v1")
        for value in (self.spec_digest, self.profile_digest, self.policy_digest, self.survivor_set_digest):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "survivor set contains a malformed digest", "candidate_source_provenance_v1")
        if self.survivor_set_digest != _content_digest(_survivor_payload(self, omit_digest=True)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "survivor set digest mismatch", "candidate_source_provenance_v1")

    def to_bytes(self) -> bytes:
        return _canonical_bytes(_survivor_payload(self))


def _validate_inputs(candidate: CandidateProposal, spec: CapabilitySpec, profile: RecipientProfile, policy: SuitabilityPolicy) -> None:
    if not isinstance(candidate, CandidateProposal) or not isinstance(spec, CapabilitySpec) or not isinstance(profile, RecipientProfile):
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "suitability inputs have invalid types", "suitability_required_gate_unresolved_v1")
    if not isinstance(policy, SuitabilityPolicy) or policy.content_digest != PINNED_SUITABILITY_POLICY.content_digest or policy._payload() != PINNED_SUITABILITY_POLICY._payload():
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "suitability policy is not the maintainer-pinned policy", "capability_registry_digest_v1")
    profile_payload = asdict(profile)
    profile_digest = profile_payload.pop("profile_digest", None)
    if not isinstance(profile_digest, str) or not _DIGEST.fullmatch(profile_digest) or profile_digest != _content_digest(profile_payload):
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "recipient profile digest mismatch", "recipient_manifest_bytes_mismatch_v1")
    spec.validate_registry(spec.behavior_registry)


def _expanded_gates(spec: CapabilitySpec, policy: SuitabilityPolicy) -> tuple[tuple[SuitabilityGate, str, ConstraintMode, tuple[str, ...]], ...]:
    templates = {gate.kind: gate for gate in policy.gates}
    expanded: list[tuple[SuitabilityGate, str, ConstraintMode, tuple[str, ...]]] = []

    def add(kind: GateKind, suffix: str = "", mode: ConstraintMode | None = None, applicable: tuple[str, ...] = ()) -> None:
        template = templates[kind]
        gate_id = kind.value + (f".{suffix}" if suffix else "")
        expanded.append((template, gate_id, mode or template.default_mode, applicable))

    add(GateKind.IMMUTABLE_PROVENANCE, applicable=("candidate.source_ref",))
    add(GateKind.CANDIDATE_CONTRACT, applicable=("candidate.proposal_digest", "spec.spec_digest"))
    add(GateKind.LANGUAGE, spec.target_language, applicable=("spec.target_language",))
    add(GateKind.RUNTIME, spec.target_runtime, applicable=("spec.target_runtime", "recipient.runtime_constraints"))
    for behavior_requirement in spec.required_behaviors:
        add(GateKind.REQUIRED_BEHAVIOR, f"{behavior_requirement.behavior_id}@{behavior_requirement.contract_version}", applicable=("spec.required_behaviors", "spec.behavior_registry"))
    if spec.prohibited_behaviors:
        for prohibited_requirement in spec.prohibited_behaviors:
            add(GateKind.PROHIBITED_BEHAVIOR, f"{prohibited_requirement.behavior_id}@{prohibited_requirement.contract_version}", applicable=("spec.prohibited_behaviors", "spec.behavior_registry"))
    else:
        add(GateKind.PROHIBITED_BEHAVIOR, "none", applicable=("spec.prohibited_behaviors",))
    if spec.interfaces:
        for interface_requirement in spec.interfaces:
            add(GateKind.INTERFACE_EFFECT, interface_requirement.interface_id, interface_requirement.mode, ("spec.interfaces",))
    else:
        add(GateKind.INTERFACE_EFFECT, "none", applicable=("spec.interfaces",))
    if spec.performance_constraints:
        for constraint in spec.performance_constraints:
            add(GateKind.PERFORMANCE, constraint.metric_id, constraint.mode, ("spec.performance_constraints",))
    else:
        add(GateKind.PERFORMANCE, "none", applicable=("spec.performance_constraints",))
    add(GateKind.LICENSE, applicable=("spec.license_policy",))
    add(GateKind.DEPENDENCY, "policy" if spec.prohibited_dependencies else "none", applicable=("spec.prohibited_dependencies", "recipient.dependencies"))
    for platform in spec.required_platforms:
        add(GateKind.PLATFORM, platform, applicable=("spec.required_platforms",))
    add(GateKind.MINIMUM_EVIDENCE, applicable=("candidate.extraction_evidence",))
    return tuple(sorted(expanded, key=lambda item: item[1]))


def _status_marker(gate_id: str, evidence: tuple[EvidencePointer, ...]) -> tuple[GateStatus, tuple[EvidencePointer, ...]] | None:
    prefix = f"gate-status/{gate_id}/"
    markers = tuple(item for item in evidence if item.evidence_kind.startswith(prefix))
    if not markers:
        return None
    if len(markers) != 1:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"conflicting statuses for {gate_id}", "suitability_status_conversion_v1")
    marker = markers[0]
    raw = marker.evidence_kind.removeprefix(prefix)
    try:
        status = GateStatus(raw)
    except ValueError:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"unknown status for {gate_id}", "suitability_status_conversion_v1")
    if marker.collector_id != "leitir.suitability_assessment" or marker.collector_version != "v1" or status in {GateStatus.PASS, GateStatus.NOT_APPLICABLE}:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"unauthorized status assertion for {gate_id}", "suitability_status_conversion_v1")
    return status, markers


def _evaluate_one(
    template: SuitabilityGate,
    gate_id: str,
    mode: ConstraintMode,
    applicable: tuple[str, ...],
    candidate: CandidateProposal,
    spec: CapabilitySpec,
) -> GateResult:
    all_evidence = tuple(sorted(candidate.extraction_evidence + candidate.context_evidence))
    marker = _status_marker(gate_id, all_evidence)
    evidence: tuple[EvidencePointer, ...] = ()
    if marker is not None:
        status, evidence = marker
    elif gate_id.endswith(".none") and template.not_applicable_when_empty:
        status = GateStatus.NOT_APPLICABLE
    elif template.kind is GateKind.IMMUTABLE_PROVENANCE:
        status = GateStatus.PASS
        evidence = candidate.extraction_evidence
    elif template.kind is GateKind.CANDIDATE_CONTRACT:
        status = GateStatus.PASS if candidate.proposal_digest == _content_digest(candidate._payload(False)) else GateStatus.FAIL
        evidence = candidate.extraction_evidence
    elif template.kind is GateKind.LANGUAGE:
        evidence = tuple(item for item in all_evidence if item.evidence_kind == f"language:{spec.target_language}")
        status = GateStatus.PASS if evidence else GateStatus.UNKNOWN
    elif template.kind is GateKind.RUNTIME:
        evidence = tuple(item for item in all_evidence if item.evidence_kind == f"runtime:{spec.target_runtime}")
        status = GateStatus.PASS if evidence else GateStatus.UNKNOWN
    elif template.kind in {GateKind.REQUIRED_BEHAVIOR, GateKind.PROHIBITED_BEHAVIOR}:
        behavior_version = gate_id.split(".", 1)[1]
        behavior_id, contract_version = behavior_version.rsplit("@", 1)
        contract = spec.behavior_registry.resolve(behavior_id, contract_version)
        proof_kind = f"behavior-proof:{behavior_id}@{contract_version}:{contract.content_digest}"
        absence_kind = f"behavior-absence:{behavior_id}@{contract_version}:{contract.content_digest}"
        proofs = tuple(item for item in all_evidence if item.evidence_kind == proof_kind and item.collector_id == contract.collector_id and item.collector_version == contract.collector_version)
        absences = tuple(item for item in all_evidence if item.evidence_kind == absence_kind and item.collector_id == contract.collector_id and item.collector_version == contract.collector_version)
        evidence = tuple(sorted(proofs + absences))
        if proofs and absences:
            status = GateStatus.ERROR
        elif template.kind is GateKind.REQUIRED_BEHAVIOR:
            status = GateStatus.PASS if proofs else GateStatus.UNKNOWN
        else:
            status = GateStatus.FAIL if proofs else GateStatus.PASS if absences else GateStatus.UNKNOWN
    elif template.kind is GateKind.INTERFACE_EFFECT:
        evidence = tuple(item for item in all_evidence if item.evidence_kind == f"interface-proof:{gate_id.split('.', 1)[1]}")
        status = GateStatus.PASS if evidence else GateStatus.UNKNOWN
    elif template.kind is GateKind.PERFORMANCE:
        evidence = tuple(item for item in all_evidence if item.evidence_kind == f"performance-proof:{gate_id.split('.', 1)[1]}:pass")
        status = GateStatus.PASS if evidence else GateStatus.UNKNOWN
    elif template.kind is GateKind.LICENSE:
        license_items = tuple(item for item in all_evidence if item.evidence_kind.startswith("license:"))
        expressions = tuple(sorted(item.evidence_kind.removeprefix("license:") for item in license_items))
        evidence = license_items
        if not expressions:
            status = GateStatus.UNKNOWN
        elif len(set(expressions)) != 1:
            status = GateStatus.ERROR
        elif expressions[0] in spec.license_policy.prohibited_spdx_expressions or expressions[0] not in spec.license_policy.allowed_spdx_expressions:
            status = GateStatus.FAIL
        else:
            status = GateStatus.PASS
    elif template.kind is GateKind.DEPENDENCY:
        closure = tuple(item for item in all_evidence if item.evidence_kind == "dependency-closure:complete")
        prohibited = tuple(item for item in all_evidence if item.evidence_kind in {f"dependency:{name}" for name in spec.prohibited_dependencies})
        evidence = tuple(sorted(closure + prohibited))
        status = GateStatus.FAIL if prohibited else GateStatus.PASS if closure else GateStatus.UNKNOWN
    elif template.kind is GateKind.PLATFORM:
        platform = gate_id.split(".", 1)[1]
        evidence = tuple(item for item in all_evidence if item.evidence_kind in {"platform:any", f"platform:{platform}"})
        status = GateStatus.PASS if evidence else GateStatus.UNKNOWN
    elif template.kind is GateKind.MINIMUM_EVIDENCE:
        evidence = candidate.extraction_evidence
        status = GateStatus.PASS if evidence else GateStatus.UNKNOWN
    else:  # pragma: no cover - exhaustive enum dispatch guard
        _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unsupported suitability gate", "suitability_status_conversion_v1")

    reason: BTSRejectReason | None = None
    detail: str | None = None
    if status in {GateStatus.FAIL, GateStatus.UNKNOWN, GateStatus.ERROR, GateStatus.SKIPPED}:
        reason = BTSRejectReason.REJECT_HARD_GATE_FAILED
        detail = "suitability_required_gate_failed_v1" if status is GateStatus.FAIL else "suitability_required_gate_unresolved_v1"
        if template.kind is GateKind.LICENSE and status is GateStatus.FAIL:
            reason = BTSRejectReason.REJECT_LICENSE_INCOMPATIBLE
            detail = "suitability_license_incompatible_v1"
        elif template.kind in {GateKind.IMMUTABLE_PROVENANCE, GateKind.CANDIDATE_CONTRACT} and status is GateStatus.FAIL:
            reason = BTSRejectReason.REJECT_PROVENANCE_MISMATCH
            detail = "candidate_source_provenance_v1"
    return GateResult(
        gate_id, template.kind, template.rule_id, template.rule_version, mode, status,
        AssessmentStatusEvidence("candidate_gate_evidence_v1", status.value, status), applicable,
        evidence, reason, detail,
    )


def evaluate_gates(
    candidate: CandidateProposal,
    spec: CapabilitySpec,
    recipient_profile: RecipientProfile,
    policy: SuitabilityPolicy = PINNED_SUITABILITY_POLICY,
) -> GateOutcome:
    """Evaluate every gate; no result or advisory fact can compensate for another."""

    _validate_inputs(candidate, spec, recipient_profile, policy)
    results = tuple(
        _evaluate_one(template, gate_id, mode, applicable, candidate, spec)
        for template, gate_id, mode, applicable in _expanded_gates(spec, policy)
    )
    required = tuple(result for result in results if result.mode is ConstraintMode.REQUIRED)
    has_failure = any(result.status is GateStatus.FAIL for result in required)
    unresolved = any(result.status in {GateStatus.UNKNOWN, GateStatus.ERROR, GateStatus.SKIPPED} for result in required)
    if has_failure:
        verdict = GateVerdictStatus.REJECT
    elif unresolved:
        verdict = GateVerdictStatus.INDETERMINATE
    else:
        verdict = GateVerdictStatus.PASS
    complete = not unresolved
    base = {
        "candidate_key": list(candidate.key()), "complete": complete, "policy_digest": policy.content_digest,
        "profile_digest": recipient_profile.profile_digest, "results": [_result_payload(result) for result in results],
        "schema_version": GATE_OUTCOME_SCHEMA, "spec_digest": spec.spec_digest, "verdict": verdict.value,
    }
    return GateOutcome(
        GATE_OUTCOME_SCHEMA, candidate.key(), spec.spec_digest, recipient_profile.profile_digest,
        policy.content_digest, verdict, complete, results, _content_digest(base),
    )


def build_survivor_set(
    candidates: tuple[CandidateProposal, ...],
    spec: CapabilitySpec,
    recipient_profile: RecipientProfile,
    policy: SuitabilityPolicy = PINNED_SUITABILITY_POLICY,
) -> SurvivorSet:
    """Evaluate candidates in canonical identity order and retain only C3a passes."""

    if not isinstance(candidates, tuple) or not all(isinstance(candidate, CandidateProposal) for candidate in candidates):
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "candidates must be a tuple of proposals", "suitability_required_gate_unresolved_v1")
    ordered = tuple(sorted(candidates, key=lambda candidate: candidate.key()))
    if any(left.key() == right.key() for left, right in pairwise(ordered)):
        _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "duplicate candidate supplied to gates", "candidate_identity_duplicate_v1")
    evaluated = tuple(evaluate_gates(candidate, spec, recipient_profile, policy) for candidate in ordered)
    pairs = tuple((candidate, outcome) for candidate, outcome in zip(ordered, evaluated, strict=True) if outcome.survives)
    survivors = tuple(candidate for candidate, _ in pairs)
    outcomes = tuple(outcome for _, outcome in pairs)
    base = {
        "candidates": [list(candidate.key()) for candidate in survivors], "outcomes": [_outcome_payload(outcome) for outcome in outcomes],
        "policy_digest": policy.content_digest, "profile_digest": recipient_profile.profile_digest,
        "schema_version": SURVIVOR_SET_SCHEMA, "spec_digest": spec.spec_digest,
    }
    return SurvivorSet(
        SURVIVOR_SET_SCHEMA, spec.spec_digest, recipient_profile.profile_digest, policy.content_digest,
        survivors, outcomes, _content_digest(base),
    )


def _evidence_payload(item: EvidencePointer) -> dict[str, str]:
    return {field.name: getattr(item, field.name) for field in fields(item)}


def _result_payload(result: GateResult) -> dict[str, object]:
    return {
        "applicable_fields": list(result.applicable_fields), "detail_code": result.detail_code,
        "evidence": [_evidence_payload(item) for item in result.evidence], "gate_id": result.gate_id,
        "gate_kind": result.gate_kind.value, "mode": result.mode.value, "policy_rule_id": result.policy_rule_id,
        "policy_rule_version": result.policy_rule_version, "reason": result.reason.value if result.reason else None,
        "status": result.status.value, "status_evidence": {
            "original_status": result.status_evidence.original_status, "source": result.status_evidence.source,
            "status": result.status_evidence.status.value,
        },
    }


def _outcome_payload(outcome: GateOutcome, *, omit_digest: bool = False) -> dict[str, object]:
    payload: dict[str, object] = {
        "candidate_key": list(outcome.candidate_key), "complete": outcome.complete,
        "policy_digest": outcome.policy_digest, "profile_digest": outcome.profile_digest,
        "results": [_result_payload(result) for result in outcome.results],
        "schema_version": outcome.schema_version, "spec_digest": outcome.spec_digest, "verdict": outcome.verdict.value,
    }
    if not omit_digest:
        payload["outcome_digest"] = outcome.outcome_digest
    return payload


def _survivor_payload(survivors: SurvivorSet, *, omit_digest: bool = False) -> dict[str, object]:
    payload: dict[str, object] = {
        "candidates": [list(candidate.key()) for candidate in survivors.candidates],
        "outcomes": [_outcome_payload(outcome) for outcome in survivors.outcomes],
        "policy_digest": survivors.policy_digest, "profile_digest": survivors.profile_digest,
        "schema_version": survivors.schema_version, "spec_digest": survivors.spec_digest,
    }
    if not omit_digest:
        payload["survivor_set_digest"] = survivors.survivor_set_digest
    return payload


__all__ = [
    "GATE_OUTCOME_SCHEMA", "PINNED_SUITABILITY_POLICY", "SUITABILITY_POLICY_SCHEMA", "SURVIVOR_SET_SCHEMA",
    "AssessmentStatusEvidence", "GateKind", "GateOutcome", "GateResult", "GateStatus", "GateVerdictStatus",
    "SuitabilityGate", "SuitabilityPolicy", "SurvivorSet", "build_survivor_set", "evaluate_gates",
]
