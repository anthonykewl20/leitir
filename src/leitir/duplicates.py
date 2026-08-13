"""Deterministic, content-authoritative duplicate-abstraction detection.

The detector deliberately has no name or similarity based signal.  It consumes
already-built BTS and dependency evidence and verifies every BTS member against
the pinned donor snapshot before comparing it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from itertools import combinations, pairwise
from typing import TypeAlias

from leitir.bts import BTS, DonorSnapshot, MemberEvidence, _verified_source_digest
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import SourceRef

CandidateKey: TypeAlias = tuple[str | int, ...]


class ClosureCompleteness(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    COMPLETE = "complete"
    DIRECT_ONLY = "direct_only"
    UNKNOWN = "unknown"


class CompatibilityStatus(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class ConflictKind(str, Enum):  # noqa: UP042 - ADR-0013 pins str, Enum
    VERSION_CLASH = "version_clash"
    BLOCKING_CALL_IN_ASYNC_PATH = "blocking_call_in_async_path"
    UNKNOWN_ASYNC_EXTERNAL_EFFECT = "unknown_async_external_effect"
    EXACT_SEED_BYTES_DUPLICATE = "exact_seed_bytes_duplicate"
    BTS_MEMBER_SPAN_OVERLAP = "bts_member_span_overlap"
    DEPENDENCY_DECLARATION_OVERLAP = "dependency_declaration_overlap"


@dataclass(frozen=True, slots=True)
class CompositionCandidateRef:
    candidate_key: CandidateKey
    bts_digest: str
    candidate_manifest_digest: str
    graph_digest: str


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


@dataclass(frozen=True, slots=True, order=True)
class EvidenceRef:
    """A content-bound composition observation.

    Composition has no project-profile implementation yet, so this is the
    narrow v1 evidence reference needed by ADR-0015: kind, immutable source
    identity, and the digest of the observed record.
    """

    evidence_kind: str
    source_path: str
    source_digest: str
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class MemberSpanOverlap:
    left: CompositionCandidateRef
    right: CompositionCandidateRef
    left_source: SourceRef
    right_source: SourceRef
    intersection_lines: int
    union_lines: int
    member_span_overlap_bps: int
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class DuplicateAssessment:
    left: CompositionCandidateRef
    right: CompositionCandidateRef
    kind: ConflictKind
    status: CompatibilityStatus
    member_overlaps: tuple[MemberSpanOverlap, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    assessment_digest: str


@dataclass(frozen=True, slots=True)
class DuplicateCandidate:
    """All authoritative inputs for one selected composition candidate."""

    subject: CompositionCandidateRef
    bts: BTS
    snapshot: DonorSnapshot
    dependencies: tuple[CandidateDependencyEvidence, ...] = ()


_MISSING = object()
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _json_value(value: object, *, omit: frozenset[str] = frozenset()) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _json_value(getattr(value, item.name), omit=omit)
            for item in fields(value)
            if item.name not in omit
        }
    if isinstance(value, tuple):
        return [_json_value(item, omit=omit) for item in value]
    if value is None or isinstance(value, str) or (type(value) is int):
        return value
    raise TypeError(f"unsupported canonical duplicate value: {type(value).__name__}")


def _digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    encoded = (json.dumps(
        _json_value(value, omit=omit), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ) + "\n").encode("utf-8", errors="strict")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _candidate_key(subject: CompositionCandidateRef) -> tuple[tuple[int, str | int], ...]:
    # CandidateKey positions are permitted to contain str or int.  Tagging keeps
    # that complete key sortable even for adversarial mixed-type construction.
    return tuple((0, item) if type(item) is int else (1, item) for item in subject.candidate_key)


def _pair_key(left: CompositionCandidateRef, right: CompositionCandidateRef) -> tuple[object, ...]:
    return (_candidate_key(left), _candidate_key(right))


def _source_key(source: SourceRef) -> tuple[object, ...]:
    return (
        source.slug, source.commit_sha, source.path, source.blob_sha,
        source.start_line, source.start_col, source.end_line, source.end_col,
    )


def _member_key(member: MemberEvidence) -> tuple[object, ...]:
    node = member.node
    return (
        node.origin.value, node.kind.value, node.module, node.qualified_name,
        node.location_key, *_source_key(member.source),
        member.source_bytes_sha256, member.disposition.value,
    )


def _dependency_key(item: CandidateDependencyEvidence) -> tuple[object, ...]:
    return (
        _candidate_key(item.subject), item.ecosystem, item.name, item.version,
        item.resolved_sha or "", item.completeness.value, item.source_path,
        item.source_digest,
    )


def _reject(message: str, detail_code: str, *, duplicate: bool = False) -> BTSError:
    reason = BTSRejectReason.REJECT_DUPLICATE_RESULT if duplicate else BTSRejectReason.REJECT_HARD_GATE_FAILED
    return BTSError(reason, message, detail_code=detail_code)


def _validated(candidate: DuplicateCandidate) -> tuple[MemberEvidence, tuple[MemberEvidence, ...]]:
    subject = candidate.subject
    if (
        candidate.bts.schema_version != "leitir-bts-v1"
        or subject.bts_digest != candidate.bts.bts_digest
        or not all(_valid_digest(value) for value in (
            subject.bts_digest, subject.candidate_manifest_digest, subject.graph_digest,
        ))
    ):
        raise _reject("candidate BTS identity does not match its composition reference", "composition_input_missing_v1")
    members = tuple(sorted(candidate.bts.members, key=_member_key))
    if not members or any(left == right for left, right in pairwise(members)):
        raise _reject("candidate BTS has missing or duplicate members", "composition_input_missing_v1")
    seeds = tuple(member for member in members if member.node == candidate.bts.seed)
    if len(seeds) != 1:
        raise _reject("candidate BTS must contain exactly one seed member", "composition_input_missing_v1")
    for member in members:
        try:
            verified = _verified_source_digest(candidate.snapshot, member.source)
        except BTSError as exc:
            raise _reject(
                f"candidate member source could not be verified: {exc.evidence.message}",
                "composition_input_missing_v1",
            ) from exc
        if member.source_bytes_sha256 != verified:
            raise _reject("candidate member bytes digest is invalid", "composition_input_missing_v1")
    if not isinstance(candidate.dependencies, tuple) or not all(
        isinstance(item, CandidateDependencyEvidence) for item in candidate.dependencies
    ):
        raise _reject("dependency evidence is malformed", "composition_input_missing_v1")
    dependencies = tuple(sorted(candidate.dependencies, key=_dependency_key))
    if any(item.subject != candidate.subject for item in dependencies):
        raise _reject("dependency evidence has the wrong composition subject", "composition_input_missing_v1")
    if any(
        not all(isinstance(value, str) and value for value in (
            item.ecosystem, item.name, item.version, item.source_path,
        ))
        or not _valid_digest(item.source_digest)
        or not isinstance(item.completeness, ClosureCompleteness)
        or (item.resolved_sha is not None and (not isinstance(item.resolved_sha, str) or not item.resolved_sha))
        for item in dependencies
    ):
        raise _reject("dependency evidence is incomplete or malformed", "composition_input_missing_v1")
    if any(left == right for left, right in pairwise(dependencies)):
        raise _reject("duplicate dependency evidence", "composition_input_missing_v1")
    return seeds[0], members


def _member_overlap(
    left_ref: CompositionCandidateRef,
    right_ref: CompositionCandidateRef,
    left: MemberEvidence,
    right: MemberEvidence,
    threshold: int,
) -> MemberSpanOverlap | None:
    left_source, right_source = left.source, right.source
    if (
        left_source.slug, left_source.commit_sha, left_source.path, left_source.blob_sha
    ) != (
        right_source.slug, right_source.commit_sha, right_source.path, right_source.blob_sha
    ):
        return None
    intersection = max(0, min(left_source.end_line, right_source.end_line) - max(left_source.start_line, right_source.start_line) + 1)
    union = (
        left_source.end_line - left_source.start_line + 1
        + right_source.end_line - right_source.start_line + 1
        - intersection
    )
    if intersection * 10_000 < union * threshold:
        return None
    base = MemberSpanOverlap(left_ref, right_ref, left_source, right_source, intersection, union, threshold, "")
    return MemberSpanOverlap(
        left_ref, right_ref, left_source, right_source, intersection, union, threshold,
        _digest(base, omit=frozenset({"evidence_digest"})),
    )


def _assessment(
    left: CompositionCandidateRef,
    right: CompositionCandidateRef,
    kind: ConflictKind,
    status: CompatibilityStatus,
    overlaps: tuple[MemberSpanOverlap, ...] = (),
    evidence: tuple[EvidenceRef, ...] = (),
) -> DuplicateAssessment:
    base = DuplicateAssessment(left, right, kind, status, overlaps, evidence, "")
    return DuplicateAssessment(left, right, kind, status, overlaps, evidence, _digest(base, omit=frozenset({"assessment_digest"})))


def _assessment_key(item: DuplicateAssessment) -> tuple[object, ...]:
    return (
        *_pair_key(item.left, item.right), item.kind.value, item.status.value,
        tuple(
            (*_pair_key(overlap.left, overlap.right), *_source_key(overlap.left_source),
             *_source_key(overlap.right_source), overlap.intersection_lines,
             overlap.union_lines, overlap.member_span_overlap_bps, overlap.evidence_digest)
            for overlap in item.member_overlaps
        ),
        tuple((ref.evidence_kind, ref.source_path, ref.source_digest, ref.evidence_digest) for ref in item.evidence_refs),
        item.assessment_digest,
    )


def assess_duplicates(
    candidates: tuple[DuplicateCandidate, ...],
    *,
    member_span_overlap_bps: int | object = _MISSING,
    version_clashes: tuple[DuplicateAssessment, ...] = (),
) -> tuple[DuplicateAssessment, ...]:
    """Verify candidates and return advisory overlap assessments.

    Exact verified seed-byte equality raises ``REJECT_DUPLICATE_RESULT``.  The
    span threshold intentionally uses a sentinel solely to turn an omitted
    required policy value into the composition subsystem's typed fail-closed
    error; there is no numeric default.
    """

    if member_span_overlap_bps is _MISSING:
        raise _reject("member span overlap policy threshold is required", "composition_policy_missing_v1")
    if type(member_span_overlap_bps) is not int or not 1 <= member_span_overlap_bps <= 10_000:
        raise _reject("member span overlap policy threshold is invalid", "composition_policy_missing_v1")
    threshold = member_span_overlap_bps
    if not isinstance(candidates, tuple) or not all(isinstance(item, DuplicateCandidate) for item in candidates):
        raise TypeError("candidates must be a tuple of DuplicateCandidate values")
    if any(
        not item.subject.candidate_key
        or any(type(part) not in {str, int} for part in item.subject.candidate_key)
        for item in candidates
    ):
        raise _reject("composition contains a malformed candidate key", "composition_input_missing_v1")
    ordered = tuple(sorted(candidates, key=lambda item: _candidate_key(item.subject)))
    if any(_candidate_key(left.subject) == _candidate_key(right.subject) for left, right in pairwise(ordered)):
        raise _reject("composition contains duplicate candidate keys", "composition_input_missing_v1")
    validated = tuple(_validated(item) for item in ordered)

    output: list[DuplicateAssessment] = []
    for left_index, right_index in combinations(range(len(ordered)), 2):
        left, right = ordered[left_index], ordered[right_index]
        left_seed, left_members = validated[left_index]
        right_seed, right_members = validated[right_index]
        if left_seed.source_bytes_sha256 == right_seed.source_bytes_sha256:
            raise _reject(
                "selected candidates contain byte-identical verified seed members",
                "exact_seed_bytes_duplicate_v1", duplicate=True,
            )

        overlaps = tuple(
            overlap
            for left_member in left_members
            for right_member in tuple(sorted(right_members, key=_member_key))
            if (overlap := _member_overlap(left.subject, right.subject, left_member, right_member, threshold)) is not None
        )
        overlaps = tuple(sorted(overlaps, key=lambda item: (
            *_pair_key(item.left, item.right), *_source_key(item.left_source),
            *_source_key(item.right_source), item.intersection_lines, item.union_lines,
            item.member_span_overlap_bps, item.evidence_digest,
        )))
        if overlaps:
            output.append(_assessment(left.subject, right.subject, ConflictKind.BTS_MEMBER_SPAN_OVERLAP, CompatibilityStatus.COMPATIBLE, overlaps))

        evidence: list[EvidenceRef] = []
        for left_dep in sorted(left.dependencies, key=_dependency_key):
            for right_dep in sorted(right.dependencies, key=_dependency_key):
                if (left_dep.ecosystem, left_dep.name, left_dep.version) != (right_dep.ecosystem, right_dep.name, right_dep.version):
                    continue
                strength = "resolved_equal" if left_dep.resolved_sha is not None and left_dep.resolved_sha == right_dep.resolved_sha else "declaration_equal"
                payload = (left_dep, right_dep, strength)
                evidence.append(EvidenceRef(
                    f"dependency_declaration_overlap:{left_dep.ecosystem}:{left_dep.name}:{left_dep.version}:{strength}",
                    f"{left_dep.source_path}\0{right_dep.source_path}",
                    f"{left_dep.source_digest}\0{right_dep.source_digest}",
                    _digest(payload),
                ))
        ordered_evidence = tuple(sorted(evidence))
        if any(a == b for a, b in pairwise(ordered_evidence)):
            raise _reject("duplicate dependency overlap evidence", "composition_input_missing_v1")
        if ordered_evidence:
            output.append(_assessment(left.subject, right.subject, ConflictKind.DEPENDENCY_DECLARATION_OVERLAP, CompatibilityStatus.COMPATIBLE, evidence=ordered_evidence))

    for clash in version_clashes:
        if not isinstance(clash, DuplicateAssessment) or clash.kind is not ConflictKind.VERSION_CLASH or clash.status is not CompatibilityStatus.INCOMPATIBLE:
            raise _reject("consumed version clash is missing or malformed", "composition_input_missing_v1")
        if clash.assessment_digest != _digest(clash, omit=frozenset({"assessment_digest"})):
            raise _reject("consumed version clash digest is mismatched", "composition_input_missing_v1")
        output.append(clash)
    result = tuple(sorted(output, key=_assessment_key))
    if any(_assessment_key(left) == _assessment_key(right) for left, right in pairwise(result)):
        raise _reject("duplicate assessment exhaustive key", "composition_input_missing_v1")
    return result


detect_duplicate_abstractions = assess_duplicates


__all__ = [
    "CandidateDependencyEvidence", "ClosureCompleteness", "CompatibilityStatus",
    "CompositionCandidateRef", "ConflictKind", "DuplicateAssessment",
    "DuplicateCandidate", "EvidenceRef", "MemberSpanOverlap", "assess_duplicates",
    "detect_duplicate_abstractions",
]
