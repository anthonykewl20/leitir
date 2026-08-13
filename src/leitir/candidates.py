"""Bounded, deterministic candidate normalization for ADR-0010 C2.

The discovery subsystem remains the authority for remote search, immutable blob
verification, and hit deduplication.  This module consumes its recorded
``SearchReport`` objects together with parser-produced symbol evidence and emits
only non-authorizing proposals.  In particular, it never constructs a graph,
``NodeId``, or Behavioral Transplant Set.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, fields
from enum import StrEnum
from itertools import pairwise
from typing import NoReturn, Protocol, TypeAlias

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.capability import CapabilitySpec
from leitir.graph.model import SourceRef
from leitir.search import CoverageStatus, Predicate, PredicateKind, SearchMode, SearchReport, SearchSpec

CANDIDATE_PROPOSAL_SCHEMA = "leitir-candidate-proposal-v1"
CANDIDATE_SET_SCHEMA = "leitir-candidate-set-v1"
CANDIDATE_BUDGET_SCHEMA = "leitir-candidate-budget-v1"
CANDIDATE_BUDGET_POLICY_SCHEMA = "leitir-candidate-budget-policy-v1"
_AUTHORITY = "leitir-maintainers"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9a-f]{40}")
_MAX_TEXT = 512
_COUNTER_EQUATION = "candidate-counter-equations-v1"
_CHARGING_ORDER = "candidate-charging-order-v1"


def _canonical_bytes(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def _content_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _reject(reason: BTSRejectReason, message: str, detail: str) -> NoReturn:
    raise BTSError(reason, message, detail_code=detail)


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"{name} must be bounded non-empty text", "seed_proposal_invalid_v1")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"{name} must be strict UTF-8", "seed_proposal_invalid_v1")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, f"{name} must be a lowercase SHA-256 digest", "candidate_budget_policy_mismatch_v1")
    return value


def _positive(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10**9:
        _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"{name} must be a bounded positive integer", "candidate_budget_policy_mismatch_v1")
    return value


_LIMIT_FIELDS = (
    "max_search_plans", "max_queries", "max_pages", "max_raw_hits", "max_verified_blobs",
    "max_blob_bytes", "max_total_blob_bytes", "max_files", "max_symbols", "max_ast_nodes",
    "max_examples", "max_evidence_records", "max_context_bytes", "max_retained_candidates", "max_work_units",
)


@dataclass(frozen=True, slots=True)
class CandidateBudgetPolicy:
    schema_version: str
    authority: str
    policy_id: str
    policy_version: str
    reason_registry_digest: str
    counter_equation_version: str
    charging_order_version: str
    max_search_plans: int
    max_queries: int
    max_pages: int
    max_raw_hits: int
    max_verified_blobs: int
    max_blob_bytes: int
    max_total_blob_bytes: int
    max_files: int
    max_symbols: int
    max_ast_nodes: int
    max_examples: int
    max_evidence_records: int
    max_context_bytes: int
    max_retained_candidates: int
    max_work_units: int
    content_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != CANDIDATE_BUDGET_POLICY_SCHEMA or self.authority != _AUTHORITY:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "unsupported candidate budget policy authority", "candidate_budget_policy_mismatch_v1")
        _text(self.policy_id, "policy_id")
        _text(self.policy_version, "policy_version")
        _digest(self.reason_registry_digest, "reason_registry_digest")
        if self.counter_equation_version != _COUNTER_EQUATION or self.charging_order_version != _CHARGING_ORDER:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "unsupported candidate charging policy", "candidate_budget_policy_mismatch_v1")
        for name in _LIMIT_FIELDS:
            _positive(getattr(self, name), name)
        _digest(self.content_digest, "content_digest")
        if self.content_digest != _content_digest(self._payload(False)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "candidate budget policy digest mismatch", "candidate_budget_policy_mismatch_v1")

    @classmethod
    def create(cls, *, policy_id: str, policy_version: str, reason_registry_digest: str, **limits: int) -> CandidateBudgetPolicy:
        if set(limits) != set(_LIMIT_FIELDS):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "candidate budget policy limits are incomplete", "candidate_budget_policy_mismatch_v1")
        payload: dict[str, object] = {
            "schema_version": CANDIDATE_BUDGET_POLICY_SCHEMA, "authority": _AUTHORITY,
            "policy_id": policy_id, "policy_version": policy_version,
            "reason_registry_digest": reason_registry_digest,
            "counter_equation_version": _COUNTER_EQUATION, "charging_order_version": _CHARGING_ORDER,
            **limits,
        }
        return cls(**payload, content_digest=_content_digest(payload))  # type: ignore[arg-type]

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload = {field.name: getattr(self, field.name) for field in fields(self) if field.name != "content_digest"}
        if include_digest:
            payload["content_digest"] = self.content_digest
        return payload


PINNED_CANDIDATE_BUDGET_POLICY = CandidateBudgetPolicy.create(
    policy_id="leitir-candidate-budget",
    policy_version="v1",
    reason_registry_digest=_content_digest({"registry_id": "leitir-bts-reason-details", "version": "v1"}),
    max_search_plans=16,
    max_queries=16,
    max_pages=100,
    max_raw_hits=10_000,
    max_verified_blobs=1_000,
    max_blob_bytes=2_000_000,
    max_total_blob_bytes=64_000_000,
    max_files=1_000,
    max_symbols=10_000,
    max_ast_nodes=1_000_000,
    max_examples=10_000,
    max_evidence_records=100_000,
    max_context_bytes=64_000_000,
    max_retained_candidates=100,
    max_work_units=200_000_000,
)


@dataclass(frozen=True, slots=True)
class CandidateBudget:
    schema_version: str
    policy_id: str
    policy_version: str
    policy_digest: str
    max_search_plans: int
    max_queries: int
    max_pages: int
    max_raw_hits: int
    max_verified_blobs: int
    max_blob_bytes: int
    max_total_blob_bytes: int
    max_files: int
    max_symbols: int
    max_ast_nodes: int
    max_examples: int
    max_evidence_records: int
    max_context_bytes: int
    max_retained_candidates: int
    max_work_units: int
    budget_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != CANDIDATE_BUDGET_SCHEMA:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "unsupported candidate budget schema", "candidate_budget_policy_mismatch_v1")
        _text(self.policy_id, "policy_id")
        _text(self.policy_version, "policy_version")
        _digest(self.policy_digest, "policy_digest")
        for name in _LIMIT_FIELDS:
            _positive(getattr(self, name), name)
        _digest(self.budget_digest, "budget_digest")
        if self.budget_digest != _content_digest(self._payload(False)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "candidate budget digest mismatch", "candidate_budget_policy_mismatch_v1")

    @classmethod
    def from_policy(cls, policy: CandidateBudgetPolicy) -> CandidateBudget:
        payload: dict[str, object] = {
            "schema_version": CANDIDATE_BUDGET_SCHEMA, "policy_id": policy.policy_id,
            "policy_version": policy.policy_version, "policy_digest": policy.content_digest,
            **{name: getattr(policy, name) for name in _LIMIT_FIELDS},
        }
        return cls(**payload, budget_digest=_content_digest(payload))  # type: ignore[arg-type]

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload = {field.name: getattr(self, field.name) for field in fields(self) if field.name != "budget_digest"}
        if include_digest:
            payload["budget_digest"] = self.budget_digest
        return payload


class FunnelTermination(StrEnum):
    TARGET_REACHED = "target_reached"
    CLEAN_EOF = "clean_eof"
    PAGE_CEILING = "page_ceiling"
    FETCH_FAILURE = "fetch_failure"
    PARSER_FAILURE = "parser_failure"


class ValidationStatus(StrEnum):
    VALIDATED = "validated"
    UNRESOLVED = "unresolved"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True, order=True)
class EvidencePointer:
    evidence_kind: str
    collector_id: str
    collector_version: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _text(self.evidence_kind, "evidence_kind")
        _text(self.collector_id, "collector_id")
        _text(self.collector_version, "collector_version")
        _digest(self.evidence_digest, "evidence_digest")


@dataclass(frozen=True, slots=True)
class SymbolStageEvidence:
    """Parser-produced evidence attached to an already verified discovery hit."""

    source: SourceRef
    symbol_kind: str
    qualified_name: str
    extraction_method: str
    extraction_version: str
    proposal_rule_id: str
    proposal_rule_version: str
    validation_status: ValidationStatus
    extraction_evidence: tuple[EvidencePointer, ...]
    context_evidence: tuple[EvidencePointer, ...] = ()
    ast_nodes_visited: int = 1

    def __post_init__(self) -> None:
        for name in ("symbol_kind", "qualified_name", "extraction_method", "extraction_version", "proposal_rule_id", "proposal_rule_version"):
            _text(getattr(self, name), name)
        for name in ("extraction_evidence", "context_evidence"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not all(isinstance(item, EvidencePointer) for item in value):
                _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"{name} must contain evidence pointers", "seed_proposal_invalid_v1")
            ordered = tuple(sorted(value))
            if any(left == right for left, right in pairwise(ordered)):
                _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, f"duplicate {name}", "candidate_identity_duplicate_v1")
            object.__setattr__(self, name, ordered)
        if not self.extraction_evidence:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "extraction evidence is required", "seed_proposal_invalid_v1")
        _positive(self.ast_nodes_visited, "ast_nodes_visited")


@dataclass(frozen=True, slots=True)
class DiscoveryStageResult:
    search_spec: SearchSpec
    report: SearchReport
    symbols: tuple[SymbolStageEvidence, ...]
    termination: FunnelTermination
    pages_recorded: int
    blob_byte_lengths: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.search_spec, SearchSpec) or self.search_spec.mode is not SearchMode.GLOBAL_DISCOVERY:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "C2 requires a typed global discovery SearchSpec", "seed_proposal_invalid_v1")
        if not isinstance(self.report, SearchReport) or self.report.spec_digest != self.search_spec.digest():
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "search report does not bind its SearchSpec", "candidate_source_provenance_v1")
        if self.report.coverage.status is not CoverageStatus.INDETERMINATE_GLOBAL:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "C2 global result has invalid coverage", "candidate_source_provenance_v1")
        if not isinstance(self.symbols, tuple) or not all(isinstance(item, SymbolStageEvidence) for item in self.symbols):
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "symbols must be parser-produced evidence", "seed_proposal_invalid_v1")
        _positive(self.pages_recorded, "pages_recorded")
        file_keys = {
            (match.source.slug, match.source.commit_sha, match.source.path, match.source.blob_sha)
            for match in self.report.matches
        }
        if (
            not isinstance(self.blob_byte_lengths, tuple)
            or len(self.blob_byte_lengths) != len(file_keys)
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in self.blob_byte_lengths)
        ):
            _reject(BTSRejectReason.REJECT_COVERAGE_MISCOUNT, "blob byte accounting must cover every verified file", "candidate_source_provenance_v1")
        object.__setattr__(self, "blob_byte_lengths", tuple(sorted(self.blob_byte_lengths)))
        if self.termination in {FunnelTermination.CLEAN_EOF, FunnelTermination.TARGET_REACHED} and self.report.coverage.incomplete_results:
            _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "complete termination contradicts incomplete discovery coverage", "candidate_funnel_under_collection_v1")


@dataclass(frozen=True, slots=True)
class CandidateRetrievalPlan:
    results: tuple[DiscoveryStageResult, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.results, tuple) or not self.results:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "candidate plan requires recorded discovery results", "seed_proposal_invalid_v1")
        if not all(isinstance(item, DiscoveryStageResult) for item in self.results):
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "candidate plan contains an invalid result", "seed_proposal_invalid_v1")


class ProfileRef(Protocol):
    profile_digest: str


@dataclass(frozen=True, slots=True)
class RetrievalProvenance:
    search_spec_digest: str
    report_digest: str
    matched_kinds: tuple[str, ...]
    retrieval_score_hex: str

    def __post_init__(self) -> None:
        if not isinstance(self.search_spec_digest, str) or re.fullmatch(r"[0-9a-f]{64}", self.search_spec_digest) is None:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid retrieval SearchSpec digest", "candidate_source_provenance_v1")
        _digest(self.report_digest, "report_digest")
        if not isinstance(self.matched_kinds, tuple) or not self.matched_kinds:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "retrieval matched kinds are required", "candidate_source_provenance_v1")
        ordered = tuple(sorted(_text(item, "matched kind") for item in self.matched_kinds))
        if len(ordered) != len(set(ordered)):
            _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "duplicate retrieval matched kind", "candidate_identity_duplicate_v1")
        object.__setattr__(self, "matched_kinds", ordered)
        try:
            score = float.fromhex(self.retrieval_score_hex)
        except (TypeError, ValueError):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid retrieval score evidence", "candidate_source_provenance_v1")
        if not math.isfinite(score) or score < 0:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid retrieval score evidence", "candidate_source_provenance_v1")


CandidateKey: TypeAlias = tuple[str, str, str, str, int, int, int, int, str, str, str, str, str, str, str, str]


@dataclass(frozen=True, slots=True)
class CandidateProposal:
    """Non-authorizing source/symbol seed proposal; deliberately not a NodeId."""

    slug: str
    commit_sha: str
    path: str
    blob_sha: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    symbol_kind: str
    qualified_name: str
    extraction_method: str
    extraction_version: str
    proposal_rule_id: str
    proposal_rule_version: str
    extraction_evidence: tuple[EvidencePointer, ...]
    context_evidence: tuple[EvidencePointer, ...]
    retrieval_provenance: tuple[RetrievalProvenance, ...]
    proposal_schema: str = CANDIDATE_PROPOSAL_SCHEMA
    proposal_digest: str = ""

    def __post_init__(self) -> None:
        try:
            source = self.source_ref
        except ValueError as exc:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"invalid proposal SourceRef: {exc}", "seed_proposal_invalid_v1")
        if _SHA1.fullmatch(source.commit_sha) is None or _SHA1.fullmatch(source.blob_sha) is None:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "proposal source is not immutable git provenance", "candidate_source_provenance_v1")
        for name in ("symbol_kind", "qualified_name", "extraction_method", "extraction_version", "proposal_rule_id", "proposal_rule_version"):
            _text(getattr(self, name), name)
        if self.proposal_schema != CANDIDATE_PROPOSAL_SCHEMA:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "unsupported proposal schema", "seed_proposal_invalid_v1")
        if not self.retrieval_provenance:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "proposal lacks retrieval provenance", "candidate_source_provenance_v1")
        for name in ("extraction_evidence", "context_evidence"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not all(isinstance(item, EvidencePointer) for item in value):
                _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, f"invalid proposal {name}", "seed_proposal_invalid_v1")
            object.__setattr__(self, name, tuple(sorted(value)))
        if not self.extraction_evidence:
            _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "proposal extraction evidence is required", "seed_proposal_invalid_v1")
        if not isinstance(self.retrieval_provenance, tuple) or not all(
            isinstance(item, RetrievalProvenance) for item in self.retrieval_provenance
        ):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid proposal retrieval provenance", "candidate_source_provenance_v1")
        ordered_retrieval = tuple(sorted(self.retrieval_provenance, key=_retrieval_key))
        if len(ordered_retrieval) != len(set(ordered_retrieval)):
            _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "duplicate retrieval provenance", "candidate_identity_duplicate_v1")
        object.__setattr__(self, "retrieval_provenance", ordered_retrieval)
        computed = _content_digest(self._payload(False))
        if self.proposal_digest:
            if self.proposal_digest != computed:
                _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "proposal digest mismatch", "candidate_source_provenance_v1")
        else:
            object.__setattr__(self, "proposal_digest", computed)

    @property
    def source_ref(self) -> SourceRef:
        return SourceRef(self.slug, self.commit_sha, self.path, self.blob_sha, self.start_line, self.start_col, self.end_line, self.end_col)

    def key(self) -> CandidateKey:
        return (self.slug, self.commit_sha, self.path, self.blob_sha, self.start_line, self.start_col, self.end_line, self.end_col,
                self.proposal_schema, self.symbol_kind, self.qualified_name, self.extraction_method, self.extraction_version,
                self.proposal_rule_id, self.proposal_rule_version, self.proposal_digest)

    def _payload(self, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "blob_sha": self.blob_sha, "commit_sha": self.commit_sha,
            "context_evidence": [_evidence_payload(item) for item in self.context_evidence],
            "end_col": self.end_col, "end_line": self.end_line,
            "extraction_evidence": [_evidence_payload(item) for item in self.extraction_evidence],
            "extraction_method": self.extraction_method, "extraction_version": self.extraction_version,
            "path": self.path, "proposal_rule_id": self.proposal_rule_id,
            "proposal_rule_version": self.proposal_rule_version, "proposal_schema": self.proposal_schema,
            "qualified_name": self.qualified_name,
            "retrieval_provenance": [_retrieval_payload(item) for item in self.retrieval_provenance],
            "slug": self.slug, "start_col": self.start_col, "start_line": self.start_line,
            "symbol_kind": self.symbol_kind,
        }
        if include_digest:
            payload["proposal_digest"] = self.proposal_digest
        return payload


class CandidateSetStatus(StrEnum):
    COMPARISON_READY = "comparison_ready"
    INDETERMINATE_GLOBAL = "indeterminate_global"


@dataclass(frozen=True, slots=True)
class StageAccounting:
    stage: str
    attempted: int
    accepted: int
    excluded: int
    duplicates: int
    remaining: int


@dataclass(frozen=True, slots=True)
class CandidateCounters:
    search_plans: int
    queries: int
    pages: int
    raw_hits: int
    verified_blobs: int
    blob_bytes: int
    total_blob_bytes: int
    files: int
    symbols: int
    ast_nodes: int
    evidence_records: int
    examples: int
    context_bytes: int
    retained_candidates: int
    work_units: int


@dataclass(frozen=True, slots=True)
class CandidateSet:
    schema_version: str
    spec_digest: str
    profile_digest: str
    proposals: tuple[CandidateProposal, ...]
    status: CandidateSetStatus
    complete_for_funnel: bool
    comparison_authorized: bool
    accounting: tuple[StageAccounting, ...]
    counters: CandidateCounters
    candidate_set_digest: str

    def to_bytes(self) -> bytes:
        return _canonical_bytes(_candidate_set_payload(self))


def compile_search_specs(spec: CapabilitySpec) -> tuple[SearchSpec, ...]:
    """Compile retrieval hints to exact typed predicates, never fuzzy names."""

    searches: list[SearchSpec] = []
    for requirement in spec.required_behaviors:
        for term in requirement.evidence_terms:
            searches.append(SearchSpec(SearchMode.GLOBAL_DISCOVERY, must=(Predicate(PredicateKind.IDENTIFIER, term, spec.target_language),)))
    if not searches:
        _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "capability has no typed retrieval terms", "behavior_contract_unsupported_v1")
    return tuple(sorted(searches, key=lambda item: item.digest()))


def discover_candidates(
    spec: CapabilitySpec,
    profile: ProfileRef,
    plan: CandidateRetrievalPlan,
    budget: CandidateBudget,
    policy: CandidateBudgetPolicy,
) -> CandidateSet:
    """Normalize recorded discovery stages into a bounded proposal set."""

    profile_digest = _digest(getattr(profile, "profile_digest", None), "profile_digest")
    _validate_budget_binding(spec, budget, policy)
    expected = tuple(item.digest() for item in compile_search_specs(spec))
    observed = tuple(sorted(item.search_spec.digest() for item in plan.results))
    if observed != expected:
        _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "candidate plan is missing or duplicates a declared search stage", "candidate_funnel_under_collection_v1")
    if any(item.termination not in {FunnelTermination.CLEAN_EOF, FunnelTermination.TARGET_REACHED} for item in plan.results):
        _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "candidate discovery stopped before a valid stop condition", "candidate_funnel_under_collection_v1")

    pages = sum(item.pages_recorded for item in plan.results)
    raw_hits = sum(len(item.report.matches) for item in plan.results)
    report_files = {
        (match.source.slug, match.source.commit_sha, match.source.path, match.source.blob_sha)
        for result in plan.results for match in result.report.matches
    }
    symbols = tuple(symbol for result in plan.results for symbol in result.symbols)
    ast_nodes = sum(item.ast_nodes_visited for item in symbols)
    evidence_count = sum(len(item.extraction_evidence) + len(item.context_evidence) for item in symbols)
    blob_lengths = tuple(length for result in plan.results for length in result.blob_byte_lengths)
    context_bytes = sum(len(_canonical_bytes(_evidence_payload(item))) for symbol in symbols for item in symbol.context_evidence)
    examples = sum(item.evidence_kind == "example" for symbol in symbols for item in symbol.context_evidence)
    counters_raw = {
        "search_plans": len(plan.results), "queries": len(plan.results), "pages": pages, "raw_hits": raw_hits,
        "verified_blobs": len(report_files), "blob_bytes": max(blob_lengths, default=0),
        "total_blob_bytes": sum(blob_lengths), "files": len(report_files), "symbols": len(symbols),
        "ast_nodes": ast_nodes, "evidence_records": evidence_count, "examples": examples, "context_bytes": context_bytes,
    }
    _check_counters(counters_raw, budget)

    provenance: dict[tuple[str, str, str, str], list[RetrievalProvenance]] = {}
    for result in sorted(plan.results, key=lambda item: item.search_spec.digest()):
        report_digest = "sha256:" + result.report.identity_digest()
        for match in result.report.matches:
            if not math.isfinite(match.score) or match.score < 0:
                _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "invalid discovery retrieval score", "candidate_source_provenance_v1")
            key = (match.source.slug, match.source.commit_sha, match.source.path, match.source.blob_sha)
            provenance.setdefault(key, []).append(RetrievalProvenance(
                result.search_spec.digest(), report_digest,
                tuple(sorted(kind.value for kind in match.matched_kinds)), float(match.score).hex(),
            ))

    proposed: dict[tuple[object, ...], CandidateProposal] = {}
    duplicate_count = 0
    rejected_count = 0
    unresolved_count = 0
    for symbol in sorted(symbols, key=_symbol_key):
        file_key = (symbol.source.slug, symbol.source.commit_sha, symbol.source.path, symbol.source.blob_sha)
        refs = provenance.get(file_key)
        if not refs:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "symbol is not backed by a verified discovery match", "candidate_source_provenance_v1")
        if symbol.validation_status is ValidationStatus.REJECTED:
            rejected_count += 1
            continue
        if symbol.validation_status is ValidationStatus.UNRESOLVED:
            unresolved_count += 1
            continue
        candidate = CandidateProposal(
            slug=symbol.source.slug, commit_sha=symbol.source.commit_sha, path=symbol.source.path,
            blob_sha=symbol.source.blob_sha, start_line=symbol.source.start_line, start_col=symbol.source.start_col,
            end_line=symbol.source.end_line, end_col=symbol.source.end_col, symbol_kind=symbol.symbol_kind,
            qualified_name=symbol.qualified_name, extraction_method=symbol.extraction_method,
            extraction_version=symbol.extraction_version, proposal_rule_id=symbol.proposal_rule_id,
            proposal_rule_version=symbol.proposal_rule_version, extraction_evidence=symbol.extraction_evidence,
            context_evidence=symbol.context_evidence, retrieval_provenance=tuple(sorted(set(refs), key=_retrieval_key)),
        )
        pre_digest_key = candidate.key()[:-1]
        if pre_digest_key in proposed:
            duplicate_count += 1
            continue
        proposed[pre_digest_key] = candidate

    proposals = tuple(sorted(proposed.values(), key=lambda item: item.key()))
    if len(proposals) > budget.max_retained_candidates:
        _reject(BTSRejectReason.REJECT_BUDGET_EXCEEDED, "retained candidate budget exhausted", "candidate_work_budget_v1")
    work_units = (
        counters_raw["search_plans"] + counters_raw["queries"] + 2 * counters_raw["pages"]
        + counters_raw["raw_hits"] + counters_raw["verified_blobs"] + counters_raw["total_blob_bytes"]
        + counters_raw["files"] + counters_raw["symbols"] + counters_raw["ast_nodes"]
        + counters_raw["evidence_records"] + counters_raw["context_bytes"] + len(proposals)
    )
    if work_units > budget.max_work_units:
        _reject(BTSRejectReason.REJECT_BUDGET_EXCEEDED, "candidate work budget exhausted", "candidate_work_budget_v1")
    counters = CandidateCounters(**counters_raw, retained_candidates=len(proposals), work_units=work_units)
    target_reached = len(proposals) >= 3
    status = CandidateSetStatus.COMPARISON_READY if target_reached else CandidateSetStatus.INDETERMINATE_GLOBAL
    accounting = (
        StageAccounting("repository_discovery", raw_hits, len(report_files), raw_hits - len(report_files), 0, len(report_files)),
        StageAccounting("file_discovery", len(report_files), len(report_files), 0, 0, len(report_files)),
        StageAccounting("symbol_proposal", len(symbols), len(symbols) - duplicate_count, 0, duplicate_count, len(symbols) - duplicate_count),
        StageAccounting("local_structural_validation", len(symbols) - duplicate_count, len(proposals), rejected_count + unresolved_count, 0, len(proposals)),
        StageAccounting("context_expansion", len(proposals), len(proposals), 0, 0, len(proposals)),
    )
    base = {
        "schema_version": CANDIDATE_SET_SCHEMA, "spec_digest": spec.spec_digest, "profile_digest": profile_digest,
        "proposals": [item._payload() for item in proposals], "status": status.value,
        "complete_for_funnel": True, "comparison_authorized": target_reached,
        "accounting": [_accounting_payload(item) for item in accounting], "counters": _counters_payload(counters),
    }
    return CandidateSet(CANDIDATE_SET_SCHEMA, spec.spec_digest, profile_digest, proposals, status, True, target_reached,
                        accounting, counters, _content_digest(base))


def _validate_budget_binding(spec: CapabilitySpec, budget: CandidateBudget, policy: CandidateBudgetPolicy) -> None:
    spec_binding = (spec.max_candidate_budget_id, spec.max_candidate_budget_version, spec.max_candidate_budget_digest)
    policy_binding = (policy.policy_id, policy.policy_version, policy.content_digest)
    budget_binding = (budget.policy_id, budget.policy_version, budget.policy_digest)
    pinned_binding = (
        PINNED_CANDIDATE_BUDGET_POLICY.policy_id,
        PINNED_CANDIDATE_BUDGET_POLICY.policy_version,
        PINNED_CANDIDATE_BUDGET_POLICY.content_digest,
    )
    if policy_binding != pinned_binding or spec_binding != policy_binding or budget_binding != policy_binding:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "candidate budget does not exactly match the spec policy", "candidate_budget_policy_mismatch_v1")
    if any(getattr(budget, name) != getattr(policy, name) for name in _LIMIT_FIELDS):
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "caller candidate limits differ from authorized policy", "candidate_budget_policy_mismatch_v1")


def _check_counters(values: dict[str, int], budget: CandidateBudget) -> None:
    mapping = {
        "search_plans": "max_search_plans", "queries": "max_queries", "pages": "max_pages", "raw_hits": "max_raw_hits",
        "verified_blobs": "max_verified_blobs", "files": "max_files", "symbols": "max_symbols", "ast_nodes": "max_ast_nodes",
        "blob_bytes": "max_blob_bytes", "total_blob_bytes": "max_total_blob_bytes",
        "evidence_records": "max_evidence_records", "examples": "max_examples", "context_bytes": "max_context_bytes",
    }
    for counter, maximum in mapping.items():
        if values[counter] > getattr(budget, maximum):
            reason = BTSRejectReason.REJECT_EXTRACTION_BUDGET if counter in {"symbols", "ast_nodes"} else BTSRejectReason.REJECT_BUDGET_EXCEEDED
            detail = "candidate_extraction_budget_v1" if reason is BTSRejectReason.REJECT_EXTRACTION_BUDGET else "candidate_work_budget_v1"
            _reject(reason, f"candidate {counter} budget exhausted", detail)


def _symbol_key(item: SymbolStageEvidence) -> tuple[object, ...]:
    source = item.source
    return (source.slug, source.commit_sha, source.path, source.blob_sha, source.start_line, source.start_col,
            source.end_line, source.end_col, item.symbol_kind, item.qualified_name, item.extraction_method,
            item.extraction_version, item.proposal_rule_id, item.proposal_rule_version)


def _evidence_payload(item: EvidencePointer) -> dict[str, str]:
    return {"collector_id": item.collector_id, "collector_version": item.collector_version,
            "evidence_digest": item.evidence_digest, "evidence_kind": item.evidence_kind}


def _retrieval_key(item: RetrievalProvenance) -> tuple[object, ...]:
    return (item.search_spec_digest, item.report_digest, item.matched_kinds, item.retrieval_score_hex)


def _retrieval_payload(item: RetrievalProvenance) -> dict[str, object]:
    return {"matched_kinds": list(item.matched_kinds), "report_digest": item.report_digest,
            "retrieval_score_hex": item.retrieval_score_hex, "search_spec_digest": item.search_spec_digest}


def _accounting_payload(item: StageAccounting) -> dict[str, object]:
    return {field.name: getattr(item, field.name) for field in fields(item)}


def _counters_payload(item: CandidateCounters) -> dict[str, int]:
    return {field.name: getattr(item, field.name) for field in fields(item)}


def _candidate_set_payload(item: CandidateSet) -> dict[str, object]:
    return {
        "accounting": [_accounting_payload(value) for value in item.accounting],
        "candidate_set_digest": item.candidate_set_digest, "comparison_authorized": item.comparison_authorized,
        "complete_for_funnel": item.complete_for_funnel, "counters": _counters_payload(item.counters),
        "profile_digest": item.profile_digest, "proposals": [value._payload() for value in item.proposals],
        "schema_version": item.schema_version, "spec_digest": item.spec_digest, "status": item.status.value,
    }


__all__ = [
    "CANDIDATE_BUDGET_POLICY_SCHEMA",
    "CANDIDATE_BUDGET_SCHEMA",
    "CANDIDATE_PROPOSAL_SCHEMA",
    "CANDIDATE_SET_SCHEMA",
    "PINNED_CANDIDATE_BUDGET_POLICY",
    "CandidateBudget",
    "CandidateBudgetPolicy",
    "CandidateCounters",
    "CandidateProposal",
    "CandidateRetrievalPlan",
    "CandidateSet",
    "CandidateSetStatus",
    "DiscoveryStageResult",
    "EvidencePointer",
    "FunnelTermination",
    "ProfileRef",
    "RetrievalProvenance",
    "StageAccounting",
    "SymbolStageEvidence",
    "ValidationStatus",
    "compile_search_specs",
    "discover_candidates",
]
