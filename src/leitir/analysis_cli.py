"""Fail-closed analysis artifact adapters for CLI commands.

CLI usage::

    leitir analysis-architecture graph.json --subject SUBJECT [--catalog CATALOG]
        [--declared-concurrency sync|async|mixed|unknown]
    leitir analysis-lineage manifest.json

``GRAPH`` is the exact canonical JSON written by :meth:`Graph.to_bytes`.
``CATALOG`` is JSON with exactly ``schema_version``, ``authority``,
``catalog_id``, ``catalog_version``, and ``entries``.  Each entry has exactly
``target`` and ``effect_id``; target has exactly the five ``NodeId`` fields
``origin``, ``kind``, ``module``, ``qualified_name``, and ``location_key``.
Entries must already be in the canonical order required by
``BlockingCallCatalog``.  Digest fields are intentionally derived locally,
not accepted from a user-supplied catalog.  Omitting ``CATALOG`` uses the
pinned empty catalog, which can only produce unknown external-effect findings
(apart from structural concurrency classification).

This module deliberately provides functions rather than argparse wiring so a
CLI owner can choose command spelling and output transport independently.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from leitir.architecture import (
    ARCHITECTURE_ALGORITHM_VERSION,
    CATALOG_AUTHORITY,
    CATALOG_SCHEMA_VERSION,
    ArchitectureAssessment,
    AsyncPathEvidence,
    BlockingCallCatalog,
    BlockingCallCatalogEntry,
    assess_architecture,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.composition import CompositionCandidateRef, EvidenceRef
from leitir.graph.model import Edge, Graph, NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.lineage import LineageManifest

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
ANALYSIS_ARCHITECTURE_SCHEMA_VERSION = "leitir-analysis-cli-architecture-v1"
ANALYSIS_LINEAGE_SCHEMA_VERSION = "leitir-analysis-cli-lineage-validation-v1"

# This policy has no effect entries by design.  Its schema and authority are
# pinned by architecture.py; its version records the assessment algorithm it is
# intended to accompany.
DEFAULT_BLOCKING_CATALOG = BlockingCallCatalog.create(
    "leitir-analysis-cli-empty",
    ARCHITECTURE_ALGORITHM_VERSION,
    (),
)


def load_graph_artifact(path: Path) -> Graph:
    """Load exactly one bounded canonical ``Graph.to_bytes`` artifact."""

    data = _read_artifact(path)
    try:
        # Parse once with duplicate-key detection before the graph decoder,
        # whose ordinary JSON parser otherwise retains only the last duplicate.
        json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
        graph = Graph.from_json(data)
        if graph.to_bytes() != data:
            raise ValueError("graph artifact is not canonical Graph.to_bytes output")
        return graph
    except (BTSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise _reject(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "graph artifact is malformed or fails graph validation",
            "analysis_cli_graph_invalid_v1",
            exc,
        ) from exc


def load_blocking_catalog(path: Path | None) -> BlockingCallCatalog:
    """Load the documented closed-schema catalog, or return the pinned empty policy."""

    if path is None:
        return DEFAULT_BLOCKING_CATALOG
    data = _read_artifact(path)
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or set(value) != {
            "authority", "catalog_id", "catalog_version", "entries", "schema_version"
        }:
            raise ValueError("catalog has missing or unknown fields")
        if value["schema_version"] != CATALOG_SCHEMA_VERSION or value["authority"] != CATALOG_AUTHORITY:
            raise ValueError("catalog schema or authority does not match the pinned policy")
        catalog_id = _required_text(value["catalog_id"], "catalog_id")
        catalog_version = _required_text(value["catalog_version"], "catalog_version")
        entries_value = value["entries"]
        if not isinstance(entries_value, list):
            raise ValueError("catalog entries must be a list")
        entries = tuple(_catalog_entry(item) for item in entries_value)
        # create() deliberately performs the architecture module's canonical
        # sortedness, uniqueness, entry-digest, and envelope-digest validation.
        return BlockingCallCatalog.create(catalog_id, catalog_version, entries)
    except BTSError as exc:
        raise _reject(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "blocking catalog is malformed or violates its pinned policy",
            "analysis_cli_catalog_invalid_v1",
            exc,
        ) from exc
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise _reject(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "blocking catalog is malformed or violates its pinned policy",
            "analysis_cli_catalog_invalid_v1",
            exc,
        ) from exc


def run_architecture_assessment(
    graph_path: Path,
    *,
    subject: str,
    catalog_path: Path | None = None,
    declared_concurrency: str | None = None,
) -> dict[str, object]:
    """Assess a persisted graph using default architecture budgets and project JSON data."""

    graph = load_graph_artifact(graph_path)
    catalog = load_blocking_catalog(catalog_path)
    candidate = _subject_ref(subject, graph)
    assessment = assess_architecture(
        candidate,
        graph,
        catalog,
        declared_concurrency=declared_concurrency,
    )
    return _assessment_value(assessment, assessment.concurrency_model)


def validate_lineage_manifest(path: Path) -> dict[str, object]:
    """Validate a bounded lineage manifest and return its non-resolving summary."""

    data = _read_artifact(path)
    try:
        manifest = LineageManifest.from_bytes(data)
    except BTSError as exc:
        raise _reject(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "lineage manifest is malformed, noncanonical, or digest-mismatched",
            "analysis_cli_lineage_invalid_v1",
            exc,
        ) from exc
    return {
        "schema_version": ANALYSIS_LINEAGE_SCHEMA_VERSION,
        "lineage_schema_version": manifest.schema_version,
        "member_count": len(manifest.members),
        "tracked_ref": {
            "repository_id": manifest.tracked_ref.repository_id,
            "ref_name": manifest.tracked_ref.ref_name,
            "observed_commit_sha": manifest.tracked_ref.observed_commit_sha,
            "resolver_id": manifest.tracked_ref.resolver_id,
            "resolver_version": manifest.tracked_ref.resolver_version,
        },
        "digests": {
            "bts_digest": manifest.bts_digest,
            "lineage_digest": manifest.lineage_digest,
            "predecessor_bundle_digests": list(manifest.predecessor_bundle_digests),
            "member_bytes_sha256": [member.member_bytes_sha256 for member in manifest.members],
        },
    }


def _read_artifact(path: Path) -> bytes:
    try:
        if not isinstance(path, Path):
            raise TypeError("artifact path must be a pathlib.Path")
        with path.open("rb") as artifact:
            data = artifact.read(MAX_ARTIFACT_BYTES + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise _reject(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "analysis artifact could not be read",
            "analysis_cli_artifact_read_v1",
            exc,
        ) from exc
    if len(data) > MAX_ARTIFACT_BYTES:
        raise _reject(
            BTSRejectReason.REJECT_BUDGET_EXCEEDED,
            "analysis artifact exceeds the maximum accepted size",
            "analysis_cli_artifact_read_v1",
        )
    return data


def _catalog_entry(value: object) -> BlockingCallCatalogEntry:
    if not isinstance(value, dict) or set(value) != {"effect_id", "target"}:
        raise ValueError("catalog entry has missing or unknown fields")
    target_value = value["target"]
    if not isinstance(target_value, dict) or set(target_value) != {
        "kind", "location_key", "module", "origin", "qualified_name"
    }:
        raise ValueError("catalog target has missing or unknown fields")
    target = NodeId(
        NodeOrigin(target_value["origin"]),
        NodeKind(target_value["kind"]),
        _required_text(target_value["module"], "target.module"),
        _required_text(target_value["qualified_name"], "target.qualified_name"),
        _required_text(target_value["location_key"], "target.location_key"),
    )
    return BlockingCallCatalogEntry.create(target, _required_text(value["effect_id"], "effect_id"))


def _subject_ref(subject: str, graph: Graph) -> CompositionCandidateRef:
    if not isinstance(subject, str) or not subject:
        raise _reject(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "architecture subject must be a non-empty string",
            "analysis_cli_subject_invalid_v1",
        )
    try:
        subject.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise _reject(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "architecture subject must be strict UTF-8",
            "analysis_cli_subject_invalid_v1",
            exc,
        ) from exc
    return CompositionCandidateRef(
        (subject,),
        _sha256("bts-subject-v1\x00" + subject),
        _sha256("candidate-manifest-subject-v1\x00" + subject),
        "sha256:" + hashlib.sha256(graph.to_bytes()).hexdigest(),
    )


def _assessment_value(assessment: ArchitectureAssessment, concurrency: str) -> dict[str, object]:
    return {
        "schema_version": ANALYSIS_ARCHITECTURE_SCHEMA_VERSION,
        "architecture_algorithm_version": ARCHITECTURE_ALGORITHM_VERSION,
        "subject": _subject_value(assessment.subject),
        "status": assessment.status.value,
        "concurrency_model": concurrency,
        "async_paths": [_async_path_value(item) for item in assessment.async_paths],
        "logging_observations": [_observation_value(item) for item in assessment.logging_observations],
        "error_taxonomy_observations": [_observation_value(item) for item in assessment.error_taxonomy_observations],
        "config_observations": [_observation_value(item) for item in assessment.config_observations],
        "platform_observations": [_observation_value(item) for item in assessment.platform_observations],
        "assessment_digest": assessment.assessment_digest,
    }


def _async_path_value(item: AsyncPathEvidence) -> dict[str, object]:
    """Project the public assessment value without using private serializers."""

    return {
        "subject": _subject_value(item.subject),
        "source": _node_value(item.source),
        "target": _node_value(item.target),
        "calls": [_edge_value(edge) for edge in item.calls],
        "status": item.status.value,
        "conflict_kind": item.conflict_kind.value,
        "catalog_entry": None if item.catalog_entry is None else _catalog_entry_value(item.catalog_entry),
        "evidence_digest": item.evidence_digest,
    }


def _subject_value(subject: CompositionCandidateRef) -> dict[str, object]:
    return {
        "candidate_key": list(subject.candidate_key),
        "bts_digest": subject.bts_digest,
        "candidate_manifest_digest": subject.candidate_manifest_digest,
        "graph_digest": subject.graph_digest,
    }


def _catalog_entry_value(entry: BlockingCallCatalogEntry) -> dict[str, object]:
    return {
        "target": _node_value(entry.target),
        "effect_id": entry.effect_id,
        "catalog_entry_digest": entry.catalog_entry_digest,
    }


def _node_value(node: NodeId) -> dict[str, str]:
    return {
        "origin": node.origin.value,
        "kind": node.kind.value,
        "module": node.module,
        "qualified_name": node.qualified_name,
        "location_key": node.location_key,
    }


def _source_value(source: SourceRef) -> dict[str, str | int]:
    return {
        "slug": source.slug,
        "commit_sha": source.commit_sha,
        "path": source.path,
        "blob_sha": source.blob_sha,
        "start_line": source.start_line,
        "start_col": source.start_col,
        "end_line": source.end_line,
        "end_col": source.end_col,
    }


def _edge_value(edge: Edge) -> dict[str, object]:
    return {
        "kind": edge.kind.value,
        "source": _node_value(edge.source),
        "target": _node_value(edge.target),
        "provenance": {
            "site": _source_value(edge.provenance.site),
            "binding": None if edge.provenance.binding is None else _source_value(edge.provenance.binding),
            "ast_kind": edge.provenance.ast_kind,
            "resolution_rule": edge.provenance.resolution_rule,
            "protocol_base": edge.provenance.protocol_base,
        },
    }


def _observation_value(item: EvidenceRef) -> dict[str, str]:
    return {
        "evidence_kind": item.evidence_kind,
        "source_path": item.source_path,
        "source_digest": item.source_digest,
        "rule_id": item.rule_id,
        "evidence_digest": item.evidence_digest,
    }


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    value.encode("utf-8", errors="strict")
    return value


def _reject(reason: BTSRejectReason, message: str, detail_code: str, cause: BaseException | None = None) -> BTSError:
    return BTSError(reason, message, detail_code=detail_code, cause=cause)


__all__ = [
    "ANALYSIS_ARCHITECTURE_SCHEMA_VERSION",
    "ANALYSIS_LINEAGE_SCHEMA_VERSION",
    "DEFAULT_BLOCKING_CATALOG",
    "MAX_ARTIFACT_BYTES",
    "load_blocking_catalog",
    "load_graph_artifact",
    "run_architecture_assessment",
    "validate_lineage_manifest",
]
