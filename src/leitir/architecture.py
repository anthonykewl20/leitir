"""Deterministic structural architecture assessment (ADR-0014).

The module deliberately treats the graph and a maintainer supplied catalog as
its only authorities.  In particular, it never imports a catalogued target (or
consults :mod:`leitir.graph.runtime`) to classify an effect.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise
from typing import TypeAlias

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.composition import CandidateDependencyEvidence, CompositionCandidateRef, EvidenceRef
from leitir.graph.model import Edge, EdgeKind, Graph, NodeId, NodeKind, NodeOrigin, SourceRef

CATALOG_SCHEMA_VERSION = "leitir-blocking-call-catalog-v1"
CATALOG_AUTHORITY = "leitir-maintainers"
ARCHITECTURE_ALGORITHM_VERSION = "leitir-architecture-v1"
MAX_CATALOG_ENTRIES = 10_000
Digest: TypeAlias = str


class CompatibilityStatus(str, Enum):  # noqa: UP042 - ADR contract
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class ConflictKind(str, Enum):  # noqa: UP042 - shared ADR-0013 contract
    VERSION_CLASH = "version_clash"
    BLOCKING_CALL_IN_ASYNC_PATH = "blocking_call_in_async_path"
    UNKNOWN_ASYNC_EXTERNAL_EFFECT = "unknown_async_external_effect"
    EXACT_SEED_BYTES_DUPLICATE = "exact_seed_bytes_duplicate"
    BTS_MEMBER_SPAN_OVERLAP = "bts_member_span_overlap"
    DEPENDENCY_DECLARATION_OVERLAP = "dependency_declaration_overlap"


@dataclass(frozen=True, slots=True)
class BlockingCallCatalogEntry:
    target: NodeId
    effect_id: str
    catalog_entry_digest: str

    @classmethod
    def create(cls, target: NodeId, effect_id: str) -> BlockingCallCatalogEntry:
        return cls(target, effect_id, _digest({"effect_id": effect_id, "target": _node_dict(target)}))


@dataclass(frozen=True, slots=True)
class BlockingCallCatalog:
    """Finite, versioned, content-addressed maintainer policy envelope."""

    schema_version: str
    authority: str
    catalog_id: str
    catalog_version: str
    entries: tuple[BlockingCallCatalogEntry, ...]
    catalog_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != CATALOG_SCHEMA_VERSION or self.authority != CATALOG_AUTHORITY:
            raise _catalog_reject("catalog envelope authority or schema mismatch")
        if not self.catalog_id or not self.catalog_version or not isinstance(self.entries, tuple):
            raise _catalog_reject("catalog envelope is malformed")
        if len(self.entries) > MAX_CATALOG_ENTRIES:
            raise _catalog_reject("catalog entry limit exceeded")
        if not all(isinstance(entry, BlockingCallCatalogEntry) for entry in self.entries):
            raise _catalog_reject("catalog entry is malformed")
        keys = tuple(_entry_key(entry) for entry in self.entries)
        if keys != tuple(sorted(keys)) or any(left == right for left, right in pairwise(keys)):
            raise _catalog_reject("catalog entries must be sorted and unique")
        targets = tuple(entry.target for entry in self.entries)
        if len(set(targets)) != len(targets):
            raise _catalog_reject("catalog targets must be unique")
        for entry in self.entries:
            if not entry.effect_id:
                raise _catalog_reject("catalog entry is malformed")
            expected = _digest({"effect_id": entry.effect_id, "target": _node_dict(entry.target)})
            if entry.catalog_entry_digest != expected:
                raise _catalog_reject("catalog entry digest mismatch")
        if self.catalog_digest != _catalog_digest(self):
            raise _catalog_reject("catalog digest mismatch")

    @classmethod
    def create(
        cls,
        catalog_id: str,
        catalog_version: str,
        entries: tuple[BlockingCallCatalogEntry, ...],
    ) -> BlockingCallCatalog:
        envelope = cls.__new__(cls)
        object.__setattr__(envelope, "schema_version", CATALOG_SCHEMA_VERSION)
        object.__setattr__(envelope, "authority", CATALOG_AUTHORITY)
        object.__setattr__(envelope, "catalog_id", catalog_id)
        object.__setattr__(envelope, "catalog_version", catalog_version)
        object.__setattr__(envelope, "entries", entries)
        object.__setattr__(envelope, "catalog_digest", _catalog_digest(envelope))
        envelope.__post_init__()
        return envelope


@dataclass(frozen=True, slots=True)
class AsyncPathEvidence:
    subject: CompositionCandidateRef
    source: NodeId
    target: NodeId
    calls: tuple[Edge, ...]
    status: CompatibilityStatus
    conflict_kind: ConflictKind
    catalog_entry: BlockingCallCatalogEntry | None
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class ArchitectureAssessment:
    subject: CompositionCandidateRef
    concurrency_model: str
    async_paths: tuple[AsyncPathEvidence, ...]
    logging_observations: tuple[EvidenceRef, ...]
    error_taxonomy_observations: tuple[EvidenceRef, ...]
    config_observations: tuple[EvidenceRef, ...]
    platform_observations: tuple[EvidenceRef, ...]
    status: CompatibilityStatus
    assessment_digest: str


def assess_architecture(
    subject: CompositionCandidateRef,
    graph: Graph,
    catalog: BlockingCallCatalog,
    *,
    declared_concurrency: str | None = None,
    logging_observations: tuple[EvidenceRef, ...] = (),
    error_taxonomy_observations: tuple[EvidenceRef, ...] = (),
    config_observations: tuple[EvidenceRef, ...] = (),
    platform_observations: tuple[EvidenceRef, ...] = (),
    max_roots: int = 10_000,
    max_nodes: int = 100_000,
    max_edges: int = 500_000,
    max_path_length: int = 1_000,
    max_paths: int = 100_000,
) -> ArchitectureAssessment:
    """Assess one graph using canonical shortest provenance-complete call paths."""

    if not isinstance(subject, CompositionCandidateRef) or not isinstance(graph, Graph) or not isinstance(catalog, BlockingCallCatalog):
        raise _input_reject("architecture input is malformed")
    if min(max_roots, max_nodes, max_edges, max_path_length, max_paths) <= 0:
        raise _budget_reject()
    if len(graph.nodes) > max_nodes or len(graph.edges) > max_edges:
        raise _budget_reject()
    node_ids = {node.id for node in graph.nodes}
    roots = tuple(sorted((node.id for node in graph.nodes if node.id.kind in _ASYNC_KINDS), key=_node_key))
    if len(roots) > max_roots:
        raise _budget_reject()

    adjacency: dict[NodeId, list[Edge]] = {}
    for edge in graph.edges:
        if edge.kind is EdgeKind.CALLS:
            # Graph normally guarantees these facts.  Rechecking keeps this
            # authorization boundary fail-closed against forged instances.
            if edge.source not in node_ids or edge.target not in node_ids or edge.provenance is None:
                raise _input_reject("invalid call edge")
            adjacency.setdefault(edge.source, []).append(edge)
    for edges in adjacency.values():
        edges.sort(key=_edge_key)

    reachable_sources: set[NodeId] = set(roots)
    pending = list(roots)
    while pending:
        for edge in adjacency.get(pending.pop(), ()):
            if edge.target not in reachable_sources:
                reachable_sources.add(edge.target)
                pending.append(edge.target)
    if any(edge.kind is EdgeKind.CALLS and edge.source in reachable_sources for edge in graph.unresolved):
        raise _input_reject("async call coverage is incomplete")

    by_target = {entry.target: entry for entry in catalog.entries}
    paths: list[AsyncPathEvidence] = []
    for root in roots:
        canonical = _canonical_paths(root, adjacency, max_path_length=max_path_length)
        for target, calls in sorted(canonical.items(), key=lambda item: (_node_key(item[0]), _path_key(item[1]))):
            entry = by_target.get(target)
            if entry is not None:
                paths.append(_path_evidence(subject, root, target, calls, CompatibilityStatus.INCOMPATIBLE, ConflictKind.BLOCKING_CALL_IN_ASYNC_PATH, entry))
            elif target.origin is NodeOrigin.DECLARED_EXTERNAL:
                paths.append(_path_evidence(subject, root, target, calls, CompatibilityStatus.UNKNOWN, ConflictKind.UNKNOWN_ASYNC_EXTERNAL_EFFECT, None))
            if len(paths) > max_paths:
                raise _budget_reject()

    ordered_paths = tuple(sorted(paths, key=_async_path_key))
    observations = tuple(
        _ordered_observations(values)
        for values in (logging_observations, error_taxonomy_observations, config_observations, platform_observations)
    )
    concurrency = classify_concurrency(graph, declared_concurrency=declared_concurrency)
    status = CompatibilityStatus.INCOMPATIBLE if any(item.status is CompatibilityStatus.INCOMPATIBLE for item in ordered_paths) else (
        CompatibilityStatus.UNKNOWN if any(item.status is CompatibilityStatus.UNKNOWN for item in ordered_paths) or concurrency == "unknown" else CompatibilityStatus.COMPATIBLE
    )
    payload = _assessment_payload(subject, concurrency, ordered_paths, observations, status)
    return ArchitectureAssessment(
        subject,
        concurrency,
        ordered_paths,
        observations[0],
        observations[1],
        observations[2],
        observations[3],
        status,
        _digest(payload),
    )


def classify_concurrency(graph: Graph, *, declared_concurrency: str | None = None) -> str:
    """Classify from an explicit declaration, otherwise bounded graph syntax."""

    allowed = {"sync", "async", "mixed", "unknown"}
    if declared_concurrency is not None:
        if declared_concurrency not in allowed:
            raise _input_reject("invalid declared concurrency")
        return declared_concurrency
    has_async = any(node.id.kind in _ASYNC_KINDS for node in graph.nodes)
    has_sync = any(node.id.kind in {NodeKind.FUNCTION, NodeKind.METHOD} for node in graph.nodes)
    if has_async and has_sync:
        return "mixed"
    if has_async:
        return "async"
    if has_sync:
        return "sync"
    return "unknown"


_ASYNC_KINDS = frozenset({NodeKind.ASYNC_FUNCTION, NodeKind.ASYNC_METHOD})


def _canonical_paths(root: NodeId, adjacency: dict[NodeId, list[Edge]], *, max_path_length: int) -> dict[NodeId, tuple[Edge, ...]]:
    best: dict[NodeId, tuple[Edge, ...]] = {}
    queue: deque[tuple[NodeId, tuple[Edge, ...]]] = deque([(root, ())])
    while queue:
        current, path = queue.popleft()
        if len(path) >= max_path_length:
            if adjacency.get(current):
                raise _budget_reject()
            continue
        for edge in adjacency.get(current, ()):
            candidate = (*path, edge)
            previous = best.get(edge.target)
            if previous is None or (len(candidate), _path_key(candidate)) < (len(previous), _path_key(previous)):
                best[edge.target] = candidate
                queue.append((edge.target, candidate))
    best.pop(root, None)  # zero length and cycles back to the root are not proofs
    return best


def _path_evidence(subject: CompositionCandidateRef, source: NodeId, target: NodeId, calls: tuple[Edge, ...], status: CompatibilityStatus, kind: ConflictKind, entry: BlockingCallCatalogEntry | None) -> AsyncPathEvidence:
    payload = {"catalog_entry": None if entry is None else _entry_dict(entry), "calls": [_edge_dict(edge) for edge in calls], "conflict_kind": kind.value, "source": _node_dict(source), "status": status.value, "subject": _subject_dict(subject), "target": _node_dict(target)}
    return AsyncPathEvidence(subject, source, target, calls, status, kind, entry, _digest(payload))


def _ordered_observations(values: tuple[EvidenceRef, ...]) -> tuple[EvidenceRef, ...]:
    if not isinstance(values, tuple) or not all(isinstance(item, EvidenceRef) for item in values):
        raise _input_reject("observations must be EvidenceRef tuples")
    ordered = tuple(sorted(values, key=_observation_key))
    if any(_observation_key(left) == _observation_key(right) for left, right in pairwise(ordered)):
        raise _input_reject("duplicate architecture observation")
    return ordered


def _catalog_digest(catalog: BlockingCallCatalog) -> str:
    return _digest({"authority": catalog.authority, "catalog_id": catalog.catalog_id, "catalog_version": catalog.catalog_version, "entries": [_entry_dict(entry) for entry in catalog.entries], "schema_version": catalog.schema_version})


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _node_key(node: NodeId) -> tuple[str, str, str, str, str]:
    return node.origin.value, node.kind.value, node.module, node.qualified_name, node.location_key


def _node_dict(node: NodeId) -> dict[str, str]:
    return dict(zip(("origin", "kind", "module", "qualified_name", "location_key"), _node_key(node), strict=True))


def _source_key(source: SourceRef) -> tuple[object, ...]:
    return (source.slug, source.commit_sha, source.path, source.blob_sha, source.start_line, source.start_col, source.end_line, source.end_col)


def _provenance_key(edge: Edge) -> tuple[object, ...]:
    provenance = edge.provenance
    binding: tuple[object, ...] = (0,) if provenance.binding is None else (1, *_source_key(provenance.binding))
    return (*_source_key(provenance.site), *binding, provenance.ast_kind, provenance.resolution_rule, provenance.protocol_base)


def _edge_key(edge: Edge) -> tuple[object, ...]:
    return (*_node_key(edge.source), edge.kind.value, *_node_key(edge.target), *_provenance_key(edge))


def _path_key(path: tuple[Edge, ...]) -> tuple[tuple[object, ...], ...]:
    return tuple(_edge_key(edge) for edge in path)


def _entry_key(entry: BlockingCallCatalogEntry) -> tuple[object, ...]:
    return (*_node_key(entry.target), entry.effect_id, entry.catalog_entry_digest)


def _subject_dict(subject: CompositionCandidateRef) -> dict[str, object]:
    return {"bts_digest": subject.bts_digest, "candidate_key": list(subject.candidate_key), "candidate_manifest_digest": subject.candidate_manifest_digest, "graph_digest": subject.graph_digest}


def _entry_dict(entry: BlockingCallCatalogEntry) -> dict[str, object]:
    return {"catalog_entry_digest": entry.catalog_entry_digest, "effect_id": entry.effect_id, "target": _node_dict(entry.target)}


def _source_dict(source: SourceRef) -> dict[str, object]:
    names = ("slug", "commit_sha", "path", "blob_sha", "start_line", "start_col", "end_line", "end_col")
    return dict(zip(names, _source_key(source), strict=True))


def _edge_dict(edge: Edge) -> dict[str, object]:
    provenance = edge.provenance
    return {"kind": edge.kind.value, "provenance": {"ast_kind": provenance.ast_kind, "binding": None if provenance.binding is None else _source_dict(provenance.binding), "protocol_base": provenance.protocol_base, "resolution_rule": provenance.resolution_rule, "site": _source_dict(provenance.site)}, "source": _node_dict(edge.source), "target": _node_dict(edge.target)}


def _observation_key(item: EvidenceRef) -> tuple[object, ...]:
    return (item.evidence_kind, item.source_path, item.source_digest, item.rule_id, item.evidence_digest)


def _async_path_key(item: AsyncPathEvidence) -> tuple[object, ...]:
    entry_key: tuple[object, ...] = () if item.catalog_entry is None else _entry_key(item.catalog_entry)
    return (*item.subject.candidate_key, *_node_key(item.source), *_node_key(item.target), _path_key(item.calls), item.conflict_kind.value, item.status.value, entry_key, item.evidence_digest)


def _assessment_payload(subject: CompositionCandidateRef, concurrency: str, paths: tuple[AsyncPathEvidence, ...], observations: tuple[tuple[EvidenceRef, ...], ...], status: CompatibilityStatus) -> dict[str, object]:
    def obs(values: tuple[EvidenceRef, ...]) -> list[dict[str, object]]:
        return [{"evidence_digest": item.evidence_digest, "evidence_kind": item.evidence_kind, "rule_id": item.rule_id, "source_digest": item.source_digest, "source_path": item.source_path} for item in values]
    return {"algorithm_version": ARCHITECTURE_ALGORITHM_VERSION, "async_paths": [item.evidence_digest for item in paths], "concurrency_model": concurrency, "config_observations": obs(observations[2]), "error_taxonomy_observations": obs(observations[1]), "logging_observations": obs(observations[0]), "platform_observations": obs(observations[3]), "status": status.value, "subject": _subject_dict(subject)}


def _catalog_reject(message: str) -> BTSError:
    return BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, message, detail_code="blocking_catalog_invalid_v1")


def _input_reject(message: str) -> BTSError:
    return BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, message, detail_code="composition_input_missing_v1")


def _budget_reject() -> BTSError:
    return BTSError(BTSRejectReason.REJECT_BUDGET_EXCEEDED, "architecture assessment budget exhausted", detail_code="architecture_budget_v1")


__all__ = ["ARCHITECTURE_ALGORITHM_VERSION", "CATALOG_AUTHORITY", "CATALOG_SCHEMA_VERSION", "ArchitectureAssessment", "AsyncPathEvidence", "BlockingCallCatalog", "BlockingCallCatalogEntry", "CandidateDependencyEvidence", "CompatibilityStatus", "CompositionCandidateRef", "ConflictKind", "EvidenceRef", "assess_architecture", "classify_concurrency"]
