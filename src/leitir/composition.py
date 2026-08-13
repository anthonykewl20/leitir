"""Deterministic dependency-composition evidence and eligibility.

Concrete corpus-measured limits and ratified policy_digest value-pinning are deferred pending maintainer ratification per ADR-0013 §4.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from itertools import combinations
from typing import Any, TypeAlias, cast

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.lockfiles import (
    DependencyManifestPolicy,
    VerifiedManifestBytes,
    dependency_closures_from_manifest,
)

COMPOSITION_MATRIX_SCHEMA = "leitir-composition-conflict-matrix-v1"
COMPOSITION_ELIGIBILITY_SCHEMA = "leitir-composition-eligibility-v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_Key: TypeAlias = tuple[str | int, ...]


class ClosureCompleteness(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    COMPLETE = "complete"
    DIRECT_ONLY = "direct_only"
    UNKNOWN = "unknown"


class CompatibilityStatus(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class CompositionEligibilityStatus(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    ACCEPT = "accept"
    REJECT = "reject"
    INDETERMINATE = "indeterminate"


class ConflictKind(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    VERSION_CLASH = "version_clash"
    BLOCKING_CALL_IN_ASYNC_PATH = "blocking_call_in_async_path"
    UNKNOWN_ASYNC_EXTERNAL_EFFECT = "unknown_async_external_effect"
    EXACT_SEED_BYTES_DUPLICATE = "exact_seed_bytes_duplicate"
    BTS_MEMBER_SPAN_OVERLAP = "bts_member_span_overlap"
    DEPENDENCY_DECLARATION_OVERLAP = "dependency_declaration_overlap"


@dataclass(frozen=True, slots=True)
class CompositionCandidateRef:
    candidate_key: tuple[str | int, ...]
    bts_digest: str
    candidate_manifest_digest: str
    graph_digest: str


@dataclass(frozen=True, slots=True, order=True)
class EvidenceRef:
    """Canonical content-bound composition observation."""

    evidence_kind: str
    source_path: str
    source_digest: str
    rule_id: str
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class CandidateDependencyEvidence:
    subject: CompositionCandidateRef
    ecosystem: str
    name: str
    version: str
    resolved_sha: str | None
    completeness: ClosureCompleteness
    source_path: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class ConflictRecord:
    left: CompositionCandidateRef
    right: CompositionCandidateRef
    kind: ConflictKind
    status: CompatibilityStatus
    evidence_key: tuple[str | int, ...]
    evidence_digest: str
    detail_code: str


@dataclass(frozen=True, slots=True)
class ConflictMatrix:
    schema_version: str
    recipient_subject: str
    candidates: tuple[CompositionCandidateRef, ...]
    dependencies: tuple[CandidateDependencyEvidence, ...]
    architecture: tuple[object, ...]
    duplicates: tuple[object, ...]
    conflicts: tuple[ConflictRecord, ...]
    policy_digest: str
    matrix_digest: str


@dataclass(frozen=True, slots=True)
class CompositionEligibility:
    schema_version: str
    matrix_digest: str
    status: CompositionEligibilityStatus
    blocking_conflict_keys: tuple[tuple[str | int, ...], ...]
    unknown_evidence_keys: tuple[tuple[str | int, ...], ...]
    detail_code: str | None
    eligibility_digest: str


def _fail(message: str) -> None:
    raise BTSError(
        BTSRejectReason.REJECT_HARD_GATE_FAILED,
        message,
        detail_code="composition_input_missing_v1",
    )


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _json_value(item) for key, item in asdict(cast(Any, value)).items()}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    payload = _json_value(value)
    if omit and isinstance(payload, dict):
        payload = {key: item for key, item in payload.items() if key not in omit}
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8", errors="strict")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _validate_ref(subject: object) -> CompositionCandidateRef:
    if not isinstance(subject, CompositionCandidateRef):
        _fail("composition candidate reference is missing or malformed")
    assert isinstance(subject, CompositionCandidateRef)
    if not isinstance(subject.candidate_key, tuple) or not subject.candidate_key:
        _fail("composition candidate reference is missing or malformed")
    if any(type(item) not in {str, int} for item in subject.candidate_key):
        _fail("composition candidate key is malformed")
    if any(not isinstance(value, str) or _DIGEST.fullmatch(value) is None for value in (subject.bts_digest, subject.candidate_manifest_digest, subject.graph_digest)):
        _fail("composition candidate reference digest is malformed")
    return subject


def _dependency_key(item: CandidateDependencyEvidence) -> tuple[object, ...]:
    return (item.subject.candidate_key, item.ecosystem, item.name, item.version, item.resolved_sha or "", item.completeness.value, item.source_path, item.source_digest)


def _conflict_key(item: ConflictRecord) -> tuple[object, ...]:
    return (item.left.candidate_key, item.right.candidate_key, item.kind.value, item.status.value, item.evidence_key, item.evidence_digest, item.detail_code)


def _closure_evidence(
    subject: CompositionCandidateRef,
    files: tuple[VerifiedManifestBytes, ...],
    policy: DependencyManifestPolicy,
) -> tuple[tuple[CandidateDependencyEvidence, ...], tuple[tuple[str, str, str], ...]]:
    try:
        result = dependency_closures_from_manifest(files, policy)
    except (TypeError, ValueError, BTSError) as exc:
        if isinstance(exc, BTSError) and exc.evidence.detail_code == "composition_input_missing_v1":
            raise
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "composition manifest evidence is missing or malformed", detail_code="composition_input_missing_v1", cause=exc) from exc
    if result.diagnostics:
        _fail("composition manifest contains omitted or malformed dependency evidence")
    evidence: list[CandidateDependencyEvidence] = []
    unknown: list[tuple[str, str, str]] = []
    for source in result.sources:
        try:
            completeness = ClosureCompleteness(source.graph)
        except ValueError as exc:
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "composition closure completeness is unknown", detail_code="composition_input_missing_v1", cause=exc) from exc
        if completeness is not ClosureCompleteness.COMPLETE:
            unknown.append((source.ecosystem, source.path, source.source_digest))
        for dependency in source.deps:
            evidence.append(CandidateDependencyEvidence(subject, source.ecosystem, dependency.name, dependency.version, dependency.resolved_sha, completeness, source.path, source.source_digest))
    if not result.sources:
        _fail("composition candidate closure is missing")
    return tuple(sorted(evidence, key=_dependency_key)), tuple(sorted(unknown))


def _record(
    left: CompositionCandidateRef,
    right: CompositionCandidateRef,
    kind: ConflictKind,
    status: CompatibilityStatus,
    evidence_key: _Key,
    detail_code: str,
    evidence: object,
) -> ConflictRecord:
    return ConflictRecord(left, right, kind, status, evidence_key, _digest(evidence), detail_code)


def compose(
    recipient_subject: str,
    recipient: CompositionCandidateRef,
    recipient_files: tuple[VerifiedManifestBytes, ...],
    candidates: tuple[CompositionCandidateRef, ...],
    candidate_files: Mapping[_Key, tuple[VerifiedManifestBytes, ...]],
    dependency_policy: DependencyManifestPolicy,
    policy_digest: str,
) -> tuple[ConflictMatrix, CompositionEligibility]:
    if not isinstance(recipient_subject, str) or not recipient_subject or not isinstance(candidates, tuple) or not isinstance(candidate_files, Mapping) or not isinstance(dependency_policy, DependencyManifestPolicy) or not isinstance(policy_digest, str) or _DIGEST.fullmatch(policy_digest) is None:
        _fail("composition inputs are missing or malformed")
    recipient = _validate_ref(recipient)
    ordered = tuple(sorted((_validate_ref(item) for item in candidates), key=lambda item: item.candidate_key))
    keys = tuple(item.candidate_key for item in ordered)
    if len(keys) != len(set(keys)) or recipient.candidate_key in set(keys):
        _fail("composition candidate keys are duplicated")
    if set(candidate_files) != set(keys):
        _fail("composition candidate manifest evidence is incomplete")

    dependencies: list[CandidateDependencyEvidence] = []
    unknown_by_key: dict[_Key, tuple[tuple[str, str, str], ...]] = {}
    by_key: dict[_Key, tuple[CandidateDependencyEvidence, ...]] = {}
    recipient_deps, recipient_unknown = _closure_evidence(recipient, recipient_files, dependency_policy)
    dependencies.extend(recipient_deps)
    by_key[recipient.candidate_key] = recipient_deps
    unknown_by_key[recipient.candidate_key] = recipient_unknown
    for subject in ordered:
        current, unknown = _closure_evidence(subject, candidate_files[subject.candidate_key], dependency_policy)
        dependencies.extend(current)
        by_key[subject.candidate_key] = current
        unknown_by_key[subject.candidate_key] = unknown

    pairs = list(combinations(ordered, 2)) + [(subject, recipient) for subject in ordered]
    conflicts: list[ConflictRecord] = []
    for left, right in pairs:
        left_packages: dict[tuple[str, str], tuple[str, ...]] = {}
        right_packages: dict[tuple[str, str], tuple[str, ...]] = {}
        for target, destination in ((left, left_packages), (right, right_packages)):
            grouped: dict[tuple[str, str], list[str]] = {}
            for item in by_key[target.candidate_key]:
                grouped.setdefault((item.ecosystem, item.name), []).append(item.version)
            for identity in sorted(grouped):
                destination[identity] = tuple(sorted(set(grouped[identity])))
        for identity in sorted(set(left_packages) & set(right_packages)):
            versions = tuple(sorted(set(left_packages[identity]) | set(right_packages[identity])))
            if len(versions) > 1:
                key: _Key = ("dependency", *left.candidate_key, *right.candidate_key, identity[0], identity[1], *versions)
                conflicts.append(_record(left, right, ConflictKind.VERSION_CLASH, CompatibilityStatus.INCOMPATIBLE, key, "composition_version_clash_v1", key))
        for side, target in (("left", left), ("right", right)):
            for ecosystem, path, source_digest in unknown_by_key[target.candidate_key]:
                key = ("closure", *left.candidate_key, *right.candidate_key, side, *target.candidate_key, ecosystem, path, source_digest)
                conflicts.append(_record(left, right, ConflictKind.DEPENDENCY_DECLARATION_OVERLAP, CompatibilityStatus.UNKNOWN, key, "composition_transitive_closure_unknown_v1", key))

    matrix = ConflictMatrix(COMPOSITION_MATRIX_SCHEMA, recipient_subject, ordered, tuple(sorted(dependencies, key=_dependency_key)), (), (), tuple(sorted(conflicts, key=_conflict_key)), policy_digest, "")
    matrix = ConflictMatrix(matrix.schema_version, matrix.recipient_subject, matrix.candidates, matrix.dependencies, matrix.architecture, matrix.duplicates, matrix.conflicts, matrix.policy_digest, _digest(matrix, omit=frozenset({"matrix_digest"})))
    return matrix, evaluate_eligibility(matrix)


def evaluate_eligibility(matrix: ConflictMatrix) -> CompositionEligibility:
    if not isinstance(matrix, ConflictMatrix) or matrix.schema_version != COMPOSITION_MATRIX_SCHEMA or not isinstance(matrix.matrix_digest, str) or _DIGEST.fullmatch(matrix.matrix_digest) is None or matrix.matrix_digest != _digest(matrix, omit=frozenset({"matrix_digest"})):
        _fail("composition matrix is missing, malformed, or mismatched")
    if (
        not isinstance(matrix.candidates, tuple)
        or not all(isinstance(item, CompositionCandidateRef) for item in matrix.candidates)
        or tuple(sorted(matrix.candidates, key=lambda item: item.candidate_key)) != matrix.candidates
        or len({item.candidate_key for item in matrix.candidates}) != len(matrix.candidates)
        or not isinstance(matrix.dependencies, tuple)
        or not all(isinstance(item, CandidateDependencyEvidence) for item in matrix.dependencies)
        or tuple(sorted(matrix.dependencies, key=_dependency_key)) != matrix.dependencies
        or not isinstance(matrix.conflicts, tuple)
        or not all(isinstance(item, ConflictRecord) for item in matrix.conflicts)
    ):
        _fail("composition matrix records are missing or malformed")
    if tuple(sorted(matrix.conflicts, key=_conflict_key)) != matrix.conflicts:
        _fail("composition conflict records are malformed or omitted")
    conflict_keys = tuple(item.evidence_key for item in matrix.conflicts)
    if len(conflict_keys) != len(set(conflict_keys)):
        _fail("composition conflict evidence keys are duplicated")
    actual_clashes = {
        (item.left.candidate_key, item.right.candidate_key, item.evidence_key)
        for item in matrix.conflicts
        if item.kind is ConflictKind.VERSION_CLASH
        and item.status is CompatibilityStatus.INCOMPATIBLE
        and item.detail_code == "composition_version_clash_v1"
        and item.evidence_digest == _digest(item.evidence_key)
    }
    by_subject: dict[CompositionCandidateRef, dict[tuple[str, str], set[str]]] = {}
    for item in matrix.dependencies:
        packages = by_subject.setdefault(item.subject, {})
        packages.setdefault((item.ecosystem, item.name), set()).add(item.version)
    subjects = tuple(sorted(by_subject, key=lambda item: item.candidate_key))
    candidate_keys = {item.candidate_key for item in matrix.candidates}
    recipients = tuple(item for item in subjects if item.candidate_key not in candidate_keys)
    if len(recipients) > 1:
        _fail("composition matrix contains substituted dependency subjects")
    expected_clashes: set[tuple[_Key, _Key, _Key]] = set()
    pairs = list(combinations(matrix.candidates, 2))
    if recipients:
        pairs.extend((candidate, recipients[0]) for candidate in matrix.candidates)
    for left, right in pairs:
        for identity in sorted(set(by_subject.get(left, {})) & set(by_subject.get(right, {}))):
            versions = tuple(sorted(by_subject[left][identity] | by_subject[right][identity]))
            if len(versions) > 1:
                key: _Key = ("dependency", *left.candidate_key, *right.candidate_key, identity[0], identity[1], *versions)
                expected_clashes.add((left.candidate_key, right.candidate_key, key))
    if actual_clashes != expected_clashes:
        _fail("composition matrix omits or substitutes a known version clash")
    blocking_kinds = {ConflictKind.VERSION_CLASH, ConflictKind.BLOCKING_CALL_IN_ASYNC_PATH, ConflictKind.EXACT_SEED_BYTES_DUPLICATE}
    blocking = tuple(sorted(item.evidence_key for item in matrix.conflicts if item.status is CompatibilityStatus.INCOMPATIBLE and item.kind in blocking_kinds))
    unknown = tuple(sorted(item.evidence_key for item in matrix.conflicts if item.status is CompatibilityStatus.UNKNOWN))
    status = CompositionEligibilityStatus.REJECT if blocking else CompositionEligibilityStatus.INDETERMINATE if unknown else CompositionEligibilityStatus.ACCEPT
    detail = "composition_conflict_v1" if blocking else "composition_evidence_unknown_v1" if unknown else None
    result = CompositionEligibility(COMPOSITION_ELIGIBILITY_SCHEMA, matrix.matrix_digest, status, blocking, unknown, detail, "")
    return CompositionEligibility(result.schema_version, result.matrix_digest, result.status, result.blocking_conflict_keys, result.unknown_evidence_keys, result.detail_code, _digest(result, omit=frozenset({"eligibility_digest"})))


__all__ = [
    "CandidateDependencyEvidence", "ClosureCompleteness", "CompatibilityStatus",
    "CompositionCandidateRef", "CompositionEligibility", "CompositionEligibilityStatus",
    "ConflictKind", "ConflictMatrix", "ConflictRecord", "EvidenceRef", "compose",
    "evaluate_eligibility",
]
