"""Deterministic, fail-closed Behavioral Transplant Set computation."""

from __future__ import annotations

import hashlib
import heapq
import json
import os
import re
import stat
import types
from collections.abc import Callable
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from itertools import pairwise
from pathlib import Path
from typing import TypeAlias, get_args, get_origin, get_type_hints

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import (
    GRAPH_SCHEMA_VERSION,
    Edge,
    EdgeKind,
    EdgeProvenance,  # noqa: F401 - required by get_type_hints during report reconstruction
    ExtractionBlocker,
    Graph,
    NodeId,
    NodeKind,
    NodeOrigin,
    SourceRef,
    UnresolvedEdge,
)
from leitir.materialize import _target_lock
from leitir.treehash import FULL, TREE_HASH_ALGORITHM, TreeHashError, verify_materialized_tree_hash

BTS_SCHEMA_VERSION = "leitir-bts-v1"
BTS_RESOLVER_VERSION = "leitir-bts-walk-v2"
_RUNTIME_KINDS = frozenset(
    {EdgeKind.CALLS, EdgeKind.INSTANTIATES, EdgeKind.READS, EdgeKind.INHERITS, EdgeKind.RAISES}
)
_SEED_KINDS = frozenset(
    {NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION, NodeKind.METHOD, NodeKind.ASYNC_METHOD}
)
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_BLOB_SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True, slots=True)
class DonorSnapshot:
    """Authoritative identity and lock capability for one materialized donor."""

    slug: str
    commit_sha: str
    source: str
    parity: str
    materialized_tree_hash: str
    materialized_tree_hash_algorithm: str
    materialized_tree_hash_scope: str
    materialization_root: Path
    source_root: Path

    def __post_init__(self) -> None:
        _text(self.slug, "slug")
        if self.source != "git-commit":
            reason = BTSRejectReason.REJECT_MOVING_REFERENCE if self.source in {
                "git-branch", "git-tag", "branch", "tag", "head",
            } else BTSRejectReason.REJECT_PROVENANCE_MISMATCH
            raise BTSError(reason, "donor source is not an immutable Git commit", detail_code="bts_donor_source_v1")
        if not isinstance(self.commit_sha, str) or _COMMIT_SHA.fullmatch(self.commit_sha) is None:
            raise BTSError(
                BTSRejectReason.REJECT_MOVING_REFERENCE,
                "donor commit is not an immutable 40-character SHA",
                detail_code="bts_commit_sha_v1",
            )
        if self.parity != "exact" or self.materialized_tree_hash_scope != FULL:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "donor snapshot does not have exact, full-tree parity",
                detail_code="bts_snapshot_parity_scope_v1",
            )
        if self.materialized_tree_hash_algorithm != TREE_HASH_ALGORITHM or not self.materialized_tree_hash:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "donor snapshot has missing or unsupported tree-hash integrity",
                detail_code="bts_tree_hash_identity_v1",
            )
        if not isinstance(self.materialization_root, Path) or not isinstance(self.source_root, Path):
            raise TypeError("snapshot roots must be pathlib.Path values")
        materialization_root = self.materialization_root.expanduser().absolute()
        source_root = self.source_root.expanduser().absolute()
        try:
            source_root.relative_to(materialization_root)
        except ValueError as exc:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "source root is outside its materialization lock root",
                detail_code="bts_source_root_confinement_v1",
                cause=exc,
            ) from exc
        object.__setattr__(self, "materialization_root", materialization_root)
        object.__setattr__(self, "source_root", source_root)


class BTSDisposition(str, Enum):  # noqa: UP042 - ADR-0008 pins str, Enum
    INCLUDE = "include"
    MAP = "map"
    ADAPT = "adapt"
    REPLACE = "replace"
    EXTERNAL = "external"
    REJECT = "reject"


class BTSStatus(str, Enum):  # noqa: UP042 - ADR-0008 pins str, Enum
    COMPLETE = "complete"
    PARTIAL = "partial"
    REJECT = "reject"


def _text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be strict UTF-8") from exc


def _integer(value: object, name: str, minimum: int, maximum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be an integer >= {minimum}{suffix}")


def _digest_text(value: object, name: str) -> None:
    _text(value, name)
    assert isinstance(value, str)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"{name} must be a lowercase sha256 digest")
    try:
        decoded = bytes.fromhex(value[7:])
    except ValueError as exc:
        raise ValueError(f"{name} must be a lowercase sha256 digest") from exc
    if len(decoded) != 32 or value[7:] != value[7:].lower():
        raise ValueError(f"{name} must be a lowercase sha256 digest")


@dataclass(frozen=True, slots=True)
class BTSBudget:
    max_input_bytes: int
    max_file_bytes: int
    max_ast_nodes_per_file: int
    max_files: int
    max_edges: int
    max_nodes: int
    max_queue_entries: int
    max_depth: int
    max_work_units: int
    max_symbols: int
    max_source_lines: int
    max_external_interfaces: int
    max_config_entries: int
    max_donor_source_bps: int = 4000

    def __post_init__(self) -> None:
        for item in fields(self):
            minimum = 0 if item.name in {"max_depth", "max_donor_source_bps"} else 1
            maximum = 10_000 if item.name == "max_donor_source_bps" else None
            _integer(getattr(self, item.name), item.name, minimum, maximum)


@dataclass(frozen=True, slots=True, order=True)
class StdlibInterface:
    module: str
    qualified_name: str
    effect_kind: str = "pure"

    def __post_init__(self) -> None:
        _text(self.module, "module")
        _text(self.qualified_name, "qualified_name")
        if self.effect_kind != "pure":
            raise ValueError("a default stdlib interface must have effect_kind='pure'")


@dataclass(frozen=True, slots=True)
class StdlibIdentity:
    implementation: str
    python_constraint: str
    policy_version: str
    allowlist_digest: str
    allowlist_entries: tuple[StdlibInterface, ...] = ()

    def __post_init__(self) -> None:
        for name in ("implementation", "python_constraint", "policy_version", "allowlist_digest"):
            _text(getattr(self, name), name)
        _digest_text(self.allowlist_digest, "allowlist_digest")
        if not isinstance(self.allowlist_entries, tuple) or not all(
            isinstance(item, StdlibInterface) for item in self.allowlist_entries
        ):
            raise ValueError("allowlist_entries must be a tuple of StdlibInterface values")
        ordered = tuple(sorted(self.allowlist_entries))
        if any(left == right for left, right in pairwise(ordered)):
            raise ValueError("duplicate stdlib allowlist entry")
        object.__setattr__(self, "allowlist_entries", ordered)


@dataclass(frozen=True, slots=True, order=True)
class InterfaceContract:
    contract_id: str
    contract_version: str
    content_digest: str

    def __post_init__(self) -> None:
        for item in fields(self):
            _text(getattr(self, item.name), item.name)
        _digest_text(self.content_digest, "content_digest")


@dataclass(frozen=True, slots=True, order=True)
class EnvironmentContract:
    contract_id: str
    effect_kind: str
    constraints: tuple[str, ...]
    content_digest: str

    def __post_init__(self) -> None:
        for name in ("contract_id", "effect_kind", "content_digest"):
            _text(getattr(self, name), name)
        _digest_text(self.content_digest, "content_digest")
        if not isinstance(self.constraints, tuple) or not all(isinstance(item, str) and item for item in self.constraints):
            raise ValueError("constraints must be a tuple of non-empty strings")
        object.__setattr__(self, "constraints", tuple(sorted(self.constraints)))


@dataclass(frozen=True, slots=True, order=True)
class AdapterCatalogEntry:
    adapter_id: str
    template: str
    template_bytes_sha256: str
    parameter_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("adapter_id", "template", "template_bytes_sha256"):
            _text(getattr(self, name), name)
        _digest_text(self.template_bytes_sha256, "template_bytes_sha256")
        if not isinstance(self.parameter_names, tuple) or not all(isinstance(item, str) and item for item in self.parameter_names):
            raise ValueError("parameter_names must be a tuple of non-empty strings")
        ordered = tuple(sorted(self.parameter_names))
        if len(set(ordered)) != len(ordered):
            raise ValueError("duplicate adapter parameter name")
        object.__setattr__(self, "parameter_names", ordered)


@dataclass(frozen=True, slots=True)
class AdapterCatalog:
    catalog_id: str
    catalog_version: str
    content_digest: str
    entries: tuple[AdapterCatalogEntry, ...] = ()

    def __post_init__(self) -> None:
        for name in ("catalog_id", "catalog_version", "content_digest"):
            _text(getattr(self, name), name)
        _digest_text(self.content_digest, "content_digest")
        if not isinstance(self.entries, tuple) or not all(isinstance(item, AdapterCatalogEntry) for item in self.entries):
            raise ValueError("entries must be a tuple of AdapterCatalogEntry values")
        ordered = tuple(sorted(self.entries))
        if any(left.adapter_id == right.adapter_id for left, right in pairwise(ordered)):
            raise ValueError("duplicate adapter catalog id")
        object.__setattr__(self, "entries", ordered)


@dataclass(frozen=True, slots=True)
class MapRule:
    target: NodeId
    target_identity: str
    contract: InterfaceContract

    def __post_init__(self) -> None:
        if not isinstance(self.target, NodeId) or not isinstance(self.contract, InterfaceContract):
            raise ValueError("MAP target/contract has an invalid type")
        _text(self.target_identity, "target_identity")


@dataclass(frozen=True, slots=True)
class AdaptRule:
    adapter_id: str
    parameters: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _text(self.adapter_id, "adapter_id")
        if not isinstance(self.parameters, tuple) or not all(
            isinstance(item, tuple) and len(item) == 2 and all(isinstance(value, str) and value for value in item)
            for item in self.parameters
        ):
            raise ValueError("parameters must be a tuple of non-empty string pairs")
        ordered = tuple(sorted(self.parameters))
        if any(left[0] == right[0] for left, right in pairwise(ordered)):
            raise ValueError("duplicate adapter parameter")
        object.__setattr__(self, "parameters", ordered)


@dataclass(frozen=True, slots=True)
class ReplaceRule:
    target: NodeId
    target_identity: str
    contract: InterfaceContract

    def __post_init__(self) -> None:
        if not isinstance(self.target, NodeId) or not isinstance(self.contract, InterfaceContract):
            raise ValueError("REPLACE target/contract has an invalid type")
        _text(self.target_identity, "target_identity")


@dataclass(frozen=True, slots=True)
class ExternalRule:
    target: NodeId
    requirement: str
    environment: EnvironmentContract | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, NodeId):
            raise ValueError("EXTERNAL target must be a NodeId")
        _text(self.requirement, "requirement")
        if self.environment is not None and not isinstance(self.environment, EnvironmentContract):
            raise ValueError("environment must be an EnvironmentContract or None")


@dataclass(frozen=True, slots=True)
class RejectRule:
    reason: BTSRejectReason
    detail_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, BTSRejectReason):
            raise ValueError("REJECT reason must be a BTSRejectReason")
        _text(self.detail_code, "detail_code")


RulePayload: TypeAlias = MapRule | AdaptRule | ReplaceRule | ExternalRule | RejectRule


@dataclass(frozen=True, slots=True)
class DispositionRule:
    rule_id: str
    source: NodeId
    disposition: BTSDisposition
    payload: RulePayload
    evidence_digest: str

    def __post_init__(self) -> None:
        _text(self.rule_id, "rule_id")
        _digest_text(self.evidence_digest, "evidence_digest")
        if not isinstance(self.source, NodeId) or not isinstance(self.disposition, BTSDisposition):
            raise ValueError("rule source/disposition has an invalid type")
        expected: dict[BTSDisposition, type[object]] = {
            BTSDisposition.MAP: MapRule,
            BTSDisposition.ADAPT: AdaptRule,
            BTSDisposition.REPLACE: ReplaceRule,
            BTSDisposition.EXTERNAL: ExternalRule,
            BTSDisposition.REJECT: RejectRule,
        }
        if self.disposition not in expected or not isinstance(self.payload, expected[self.disposition]):
            raise ValueError("rule payload does not match its disposition")


def _node_id_key(node: NodeId) -> tuple[str, str, str, str, str]:
    return node.origin.value, node.kind.value, node.module, node.qualified_name, node.location_key


def _source_key(source: SourceRef) -> tuple[object, ...]:
    return (
        source.slug, source.commit_sha, source.path, source.blob_sha,
        source.start_line, source.start_col, source.end_line, source.end_col,
    )


def _provenance_key(edge: Edge) -> tuple[object, ...]:
    binding: tuple[object, ...] = (0,) if edge.provenance.binding is None else (1, *_source_key(edge.provenance.binding))
    return (
        *_source_key(edge.provenance.site), *binding, edge.provenance.ast_kind,
        edge.provenance.resolution_rule, edge.provenance.protocol_base,
    )


def _edge_key(edge: Edge) -> tuple[object, ...]:
    return (*_node_id_key(edge.source), edge.kind.value, *_node_id_key(edge.target), *_provenance_key(edge))


def _rule_key(rule: DispositionRule) -> tuple[object, ...]:
    return (*_node_id_key(rule.source), rule.disposition.value, rule.rule_id, rule.evidence_digest)


@dataclass(frozen=True, slots=True)
class ResolutionPolicy:
    schema_version: str
    authority: str
    policy_id: str
    policy_digest: str
    stdlib_identity: StdlibIdentity
    adapter_catalog: AdapterCatalog
    rules: tuple[DispositionRule, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != BTS_SCHEMA_VERSION:
            raise ValueError(f"policy schema_version must be {BTS_SCHEMA_VERSION!r}")
        for name in ("authority", "policy_id", "policy_digest"):
            _text(getattr(self, name), name)
        _digest_text(self.policy_digest, "policy_digest")
        if not isinstance(self.stdlib_identity, StdlibIdentity) or not isinstance(self.adapter_catalog, AdapterCatalog):
            raise ValueError("policy identities have invalid types")
        if not isinstance(self.rules, tuple) or not all(isinstance(item, DispositionRule) for item in self.rules):
            raise ValueError("rules must be a tuple of DispositionRule values")
        ordered = tuple(sorted(self.rules, key=_rule_key))
        for left, right in pairwise(ordered):
            if left.source == right.source:
                raise ValueError("contradictory or duplicate exact disposition rules")
        adapter_ids = {entry.adapter_id for entry in self.adapter_catalog.entries}
        adapters = {entry.adapter_id: entry for entry in self.adapter_catalog.entries}
        for rule in ordered:
            if isinstance(rule.payload, AdaptRule) and rule.payload.adapter_id not in adapter_ids:
                raise ValueError("ADAPT rule refers to an unknown adapter")
            if isinstance(rule.payload, AdaptRule) and rule.payload.adapter_id in adapters and tuple(name for name, _ in rule.payload.parameters) != adapters[rule.payload.adapter_id].parameter_names:
                raise ValueError("ADAPT parameters do not exactly match the pinned adapter")
            if isinstance(rule.payload, ExternalRule) and rule.payload.target != rule.source:
                raise ValueError("EXTERNAL rule target must equal its exact source key")
        object.__setattr__(self, "rules", ordered)


@dataclass(frozen=True, slots=True, order=True)
class MemberEvidence:
    node: NodeId
    source: SourceRef
    source_bytes_sha256: str
    disposition: BTSDisposition = BTSDisposition.INCLUDE


@dataclass(frozen=True, slots=True)
class DispositionEvidence:
    edge: Edge | None
    target: NodeId
    disposition: BTSDisposition
    rule_id: str | None
    reason: BTSRejectReason | None = None
    detail_code: str | None = None
    evidence_digest: str | None = None
    rule_payload: RulePayload | None = None


@dataclass(frozen=True, slots=True)
class EdgeEvidence:
    depth: int
    edge: Edge
    disposition: BTSDisposition
    rule_id: str | None


@dataclass(frozen=True, slots=True)
class FrontierEvidence:
    depth: int
    node: NodeId
    incoming: Edge | None


@dataclass(frozen=True, slots=True, order=True)
class RequiredFileEvidence:
    path: str
    blob_sha: str
    source_bytes_sha256: str


@dataclass(frozen=True, slots=True, order=True)
class RequiredSymbolEvidence:
    node: NodeId
    source: SourceRef | None


@dataclass(frozen=True, slots=True)
class BudgetCounters:
    input_bytes: int = 0
    files: int = 0
    file_bytes: tuple[tuple[str, int], ...] = ()
    ast_nodes_per_file: tuple[tuple[str, int], ...] = ()
    edges: int = 0
    nodes: int = 0
    queue_entries: int = 0
    peak_queue_entries: int = 0
    depth: int = 0
    work_units: int = 0
    symbols: int = 0
    source_lines: int = 0
    external_interfaces: int = 0
    config_entries: int = 0


@dataclass(frozen=True, slots=True)
class AnalysisInputs:
    seed: NodeId
    donor_slug: str
    donor_commit_sha: str
    materialized_tree_hash: str
    materialized_tree_hash_algorithm: str
    graph_schema_version: str
    graph_digest: str
    resolver_version: str
    budget: BTSBudget
    policy_id: str
    policy_digest: str
    policy_envelope_digest: str
    stdlib_allowlist_digest: str
    adapter_catalog_digest: str


BlockerEvidence: TypeAlias = ExtractionBlocker | UnresolvedEdge | DispositionEvidence


@dataclass(frozen=True, slots=True)
class BTSReport:
    schema_version: str
    status: BTSStatus
    inputs: AnalysisInputs
    members: tuple[MemberEvidence, ...]
    dispositions: tuple[DispositionEvidence, ...]
    traversed_edges: tuple[EdgeEvidence, ...]
    unresolved: tuple[UnresolvedEdge, ...]
    blockers: tuple[BlockerEvidence, ...]
    frontier: tuple[FrontierEvidence, ...]
    counters: BudgetCounters
    analysis_digest: str

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)

    @classmethod
    def from_json(cls, value: str | bytes) -> BTSReport:
        """Reconstruct and re-derive a canonical report, never trusting its digest."""
        try:
            text = value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value
            raw = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
            report = _from_json_value(raw, cls)
            if not isinstance(report, cls):
                raise ValueError("decoded value is not a BTS report")
            expected = _digest(report, omit=frozenset({"analysis_digest"}))
            if report.analysis_digest != expected:
                raise ValueError("BTS report analysis_digest mismatch")
            if report.to_bytes().decode("utf-8") != text:
                raise ValueError("BTS report is not canonical JSON")
            return report
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, BTSError) as exc:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "invalid or noncanonical BTS report artifact",
                detail_code="bts_report_cache_v1",
                cause=exc,
            ) from exc


@dataclass(frozen=True, slots=True)
class BTS:
    schema_version: str
    seed: NodeId
    members: tuple[MemberEvidence, ...]
    dispositions: tuple[DispositionEvidence, ...]
    required_files: tuple[RequiredFileEvidence, ...]
    required_symbols: tuple[RequiredSymbolEvidence, ...]
    bts_digest: str
    member_equivalence_digest: str

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


def load_bts_artifact(data: str | bytes) -> BTS:
    """Load a canonical complete :class:`BTSReport` as its BTS artifact.

    Reports deliberately retain all of the member source evidence needed to
    re-derive the complete BTS.  Rebuilding the two derived BTS digests here
    keeps occupied attachment callers from treating a report's cached fields
    as authority.
    """

    try:
        if not isinstance(data, (str, bytes)):
            raise TypeError("BTS artifact must be str or bytes")
        report = BTSReport.from_json(data)
        if report.schema_version != BTS_SCHEMA_VERSION or report.status is not BTSStatus.COMPLETE:
            raise ValueError("BTS artifact must be a complete current-schema report")
        required_files = tuple(
            sorted({RequiredFileEvidence(item.source.path, item.source.blob_sha, item.source_bytes_sha256) for item in report.members})
        )
        required_symbols = tuple(
            sorted((RequiredSymbolEvidence(item.node, item.source) for item in report.members), key=lambda item: _node_id_key(item.node))
        )
        equivalent = BTS(
            BTS_SCHEMA_VERSION,
            report.inputs.seed,
            report.members,
            report.dispositions,
            required_files,
            required_symbols,
            "",
            "",
        )
        equivalence = _digest(equivalent, omit=frozenset({"bts_digest", "member_equivalence_digest"}))
        primary = _digest(
            (report, equivalent),
            omit=frozenset({"analysis_digest", "bts_digest", "member_equivalence_digest"}),
        )
        return BTS(
            BTS_SCHEMA_VERSION,
            equivalent.seed,
            equivalent.members,
            equivalent.dispositions,
            equivalent.required_files,
            equivalent.required_symbols,
            primary,
            equivalence,
        )
    except (TypeError, ValueError, BTSError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "invalid BTS artifact for occupied validation",
            detail_code="bts_artifact_invalid_v1",
            cause=exc,
        ) from exc


@dataclass(frozen=True, slots=True)
class BTSResult:
    status: BTSStatus
    report: BTSReport
    bts: BTS | None


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
    if value is None or isinstance(value, (str, bool)) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _from_json_value(value: object, target: object) -> object:
    origin = get_origin(target)
    arguments = get_args(target)
    if origin in (types.UnionType, TypeAlias):
        last: Exception | None = None
        for option in arguments:
            try:
                return _from_json_value(value, option)
            except (TypeError, ValueError, BTSError) as exc:
                last = exc
        raise ValueError("value does not match a canonical union") from last
    if origin is tuple:
        if not isinstance(value, list) or len(arguments) != 2 or arguments[1] is not Ellipsis:
            raise ValueError("canonical tuple must be an array")
        return tuple(_from_json_value(item, arguments[0]) for item in value)
    if isinstance(target, type) and issubclass(target, Enum):
        if not isinstance(value, str):
            raise ValueError("enum value must be a string")
        return target(value)
    if isinstance(target, type) and is_dataclass(target):
        if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
            raise ValueError("canonical dataclass must be an object")
        hints = get_type_hints(target, globalns=globals(), localns=globals())
        if set(value) != set(hints):
            raise ValueError("canonical dataclass has missing or unknown fields")
        return target(**{name: _from_json_value(value[name], field_type) for name, field_type in hints.items()})
    if target is type(None):
        if value is not None:
            raise ValueError("expected null")
        return None
    if target is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("expected integer")
        return value
    if target is bool:
        if not isinstance(value, bool):
            raise ValueError("expected boolean")
        return value
    if target is str:
        if not isinstance(value, str):
            raise ValueError("expected string")
        return value
    raise TypeError(f"unsupported canonical target: {target!r}")


def _canonical_bytes(value: object, *, omit: frozenset[str] = frozenset()) -> bytes:
    return (
        json.dumps(_json_value(value, omit=omit), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8", errors="strict")


def _digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    return f"sha256:{hashlib.sha256(_canonical_bytes(value, omit=omit)).hexdigest()}"


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def _source_span(data: bytes, source: SourceRef) -> bytes:
    lines = data.splitlines(keepends=True) or [b""]
    if data.endswith((b"\n", b"\r")):
        lines.append(b"")
    if source.start_line > len(lines) or source.end_line > len(lines):
        raise ValueError("source line is outside the file")
    starts: list[int] = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line)
    start_line = lines[source.start_line - 1]
    end_line = lines[source.end_line - 1]
    if source.start_col > len(start_line) or source.end_col > len(end_line):
        raise ValueError("source byte column is outside the line")
    start = starts[source.start_line - 1] + source.start_col
    end = starts[source.end_line - 1] + source.end_col
    if end < start:
        raise ValueError("source span end precedes start")
    return data[start:end]


def _read_regular_file(root: Path, relative: str) -> bytes:
    path = root.joinpath(*relative.split("/"))
    try:
        path.relative_to(root)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("included source is not a regular file")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                return handle.read()
        finally:
            if fd >= 0:
                os.close(fd)
    except (OSError, ValueError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            f"cannot read included donor source: {relative}",
            detail_code="bts_source_read_v1",
            cause=exc,
        ) from exc


def _verified_source_digest(snapshot: DonorSnapshot, source: SourceRef) -> str:
    if source.slug != snapshot.slug or source.commit_sha != snapshot.commit_sha:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "graph source identity does not match the donor snapshot",
            detail_code="bts_graph_snapshot_identity_v1",
        )
    if _BLOB_SHA.fullmatch(source.blob_sha) is None:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "graph source has a malformed Git blob SHA",
            detail_code="bts_blob_sha_format_v1",
        )
    data = _read_regular_file(snapshot.source_root, source.path)
    if _git_blob_sha(data) != source.blob_sha:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "included source bytes do not match the recorded Git blob",
            detail_code="bts_blob_sha_mismatch_v1",
        )
    try:
        span = _source_span(data, source)
    except ValueError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "included source span does not match the recorded bytes",
            detail_code="bts_source_span_v1",
            cause=exc,
        ) from exc
    return f"sha256:{hashlib.sha256(span).hexdigest()}"


def _graph_sources(graph: Graph) -> tuple[SourceRef, ...]:
    sources: set[SourceRef] = set(graph.coverage.files) | set(graph.coverage.parsed_files)
    sources.update(node.source for node in graph.nodes if node.source is not None)
    for graph_edge in graph.edges:
        sources.add(graph_edge.provenance.site)
        if graph_edge.provenance.binding is not None:
            sources.add(graph_edge.provenance.binding)
    for unresolved_edge in graph.unresolved:
        sources.add(unresolved_edge.provenance.site)
        if unresolved_edge.provenance.binding is not None:
            sources.add(unresolved_edge.provenance.binding)
    return tuple(sorted(sources, key=_source_key))


def _line_union(members: list[MemberEvidence]) -> tuple[int, dict[str, set[int]]]:
    lines: dict[str, set[int]] = {}
    for member in members:
        lines.setdefault(member.source.path, set()).update(range(member.source.start_line, member.source.end_line + 1))
    return sum(len(values) for values in lines.values()), lines


def _total_donor_lines(graph: Graph) -> int:
    by_path: dict[str, set[int]] = {}
    for source in graph.coverage.files:
        if source.path.endswith(".py"):
            by_path.setdefault(source.path, set()).update(range(source.start_line, source.end_line + 1))
    return sum(len(values) for values in by_path.values())


def _frontier_key(item: FrontierEvidence) -> tuple[object, ...]:
    incoming = (0,) if item.incoming is None else (1, *_edge_key(item.incoming))
    return item.depth, *_node_id_key(item.node), *incoming


def _disposition_key(item: DispositionEvidence) -> tuple[object, ...]:
    edge = (0,) if item.edge is None else (1, *_edge_key(item.edge))
    return (*edge, *_node_id_key(item.target), item.disposition.value, item.rule_id or "", item.detail_code or "")


def _blocker_key(item: BlockerEvidence) -> tuple[object, ...]:
    if isinstance(item, ExtractionBlocker):
        return ("extraction", item.path, item.start_line, item.start_col, item.reason.value, item.detail_code)
    if isinstance(item, UnresolvedEdge):
        return ("unresolved", *_node_id_key(item.source), item.kind.value, *_source_key(item.provenance.site), item.detail_code)
    return ("disposition", *_disposition_key(item))


def _classify(target: NodeId, edge: Edge | None, policy_rules: dict[NodeId, DispositionRule], pure: set[tuple[str, str]]) -> DispositionEvidence:
    rule = policy_rules.get(target)
    if rule is not None:
        reason = rule.payload.reason if isinstance(rule.payload, RejectRule) else None
        detail = rule.payload.detail_code if isinstance(rule.payload, RejectRule) else None
        return DispositionEvidence(edge, target, rule.disposition, rule.rule_id, reason, detail, rule.evidence_digest, rule.payload)
    if target.origin is NodeOrigin.DONOR:
        return DispositionEvidence(edge, target, BTSDisposition.INCLUDE, None)
    if target.origin is NodeOrigin.STDLIB and (target.module, target.qualified_name) in pure:
        return DispositionEvidence(edge, target, BTSDisposition.EXTERNAL, None)
    return DispositionEvidence(
        edge, target, BTSDisposition.REJECT, None, BTSRejectReason.REJECT_UNRESOLVED_EDGE,
        "no_exact_disposition_v1",
    )


def _report(
    status: BTSStatus,
    inputs: AnalysisInputs,
    members: list[MemberEvidence],
    dispositions: list[DispositionEvidence],
    traversed: list[EdgeEvidence],
    unresolved: list[UnresolvedEdge],
    blockers: list[BlockerEvidence],
    frontier: list[FrontierEvidence],
    counters: BudgetCounters,
) -> BTSReport:
    unique_dispositions = { _disposition_key(item): item for item in dispositions }
    unique_traversed = { (item.depth, *_edge_key(item.edge)): item for item in traversed }
    base = BTSReport(
        BTS_SCHEMA_VERSION, status, inputs, tuple(sorted(members)),
        tuple(unique_dispositions[key] for key in sorted(unique_dispositions)),
        tuple(unique_traversed[key] for key in sorted(unique_traversed)),
        tuple(sorted(unresolved, key=lambda item: (*_node_id_key(item.source), item.kind.value, *_source_key(item.provenance.site)))),
        tuple(sorted(blockers, key=_blocker_key)), tuple(sorted(frontier, key=_frontier_key)), counters, "",
    )
    return BTSReport(**{**asdict(base), "inputs": base.inputs, "members": base.members, "dispositions": base.dispositions,
                        "traversed_edges": base.traversed_edges, "unresolved": base.unresolved, "blockers": base.blockers,
                        "frontier": base.frontier, "counters": base.counters, "analysis_digest": _digest(base, omit=frozenset({"analysis_digest"}))})


def _compute_bts(
    snapshot: DonorSnapshot,
    seed: NodeId,
    graph: Graph,
    budget: BTSBudget,
    policy: ResolutionPolicy,
) -> BTSResult:
    """Compute the deterministic static BTS reachable from ``seed``.

    Semantic rejects discovered at a reached node are evaluated before walker
    budget checks and therefore dominate a simultaneous bounded under-collection.
    """
    if not isinstance(seed, NodeId) or not isinstance(graph, Graph) or not isinstance(budget, BTSBudget) or not isinstance(policy, ResolutionPolicy):
        raise TypeError("compute_bts requires validated NodeId, Graph, BTSBudget, and ResolutionPolicy values")
    if graph.schema_version != GRAPH_SCHEMA_VERSION:
        raise ValueError("unsupported graph schema")

    graph_digest = _digest(graph)
    inputs = AnalysisInputs(
        seed, snapshot.slug, snapshot.commit_sha, snapshot.materialized_tree_hash,
        snapshot.materialized_tree_hash_algorithm, graph.schema_version, graph_digest, BTS_RESOLVER_VERSION, budget,
        policy.policy_id, policy.policy_digest, _digest(policy), policy.stdlib_identity.allowlist_digest,
        policy.adapter_catalog.content_digest,
    )
    nodes = {node.id: node for node in graph.nodes}
    seed_node = nodes.get(seed)
    initial_counters = BudgetCounters(config_entries=len(policy.rules) + len(policy.stdlib_identity.allowlist_entries) + len(policy.adapter_catalog.entries))
    if seed_node is None or seed.origin is not NodeOrigin.DONOR or seed.kind not in _SEED_KINDS or seed_node.source is None:
        disposition = DispositionEvidence(None, seed, BTSDisposition.REJECT, None, BTSRejectReason.REJECT_UNRESOLVED_EDGE, "invalid_or_ambiguous_seed_v1")
        report = _report(BTSStatus.REJECT, inputs, [], [disposition], [], [], [disposition], [], initial_counters)
        return BTSResult(BTSStatus.REJECT, report, None)

    # Index lexical ownership once. A whole definition carries the runtime
    # dependencies of its nested source, even when no call targets that owner.
    lexical = {(item.id.origin, item.id.module, item.id.qualified_name): item for item in graph.nodes}
    nested_owners: dict[NodeId, list[NodeId]] = {}
    definition_kinds = {NodeKind.CLASS, NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION,
                        NodeKind.METHOD, NodeKind.ASYNC_METHOD}
    for lexical_node in graph.nodes:
        ref = lexical_node.source
        if ref is None:
            continue
        prefix = lexical_node.id.qualified_name.rpartition(".")[0]
        while prefix:
            parent = lexical.get((lexical_node.id.origin, lexical_node.id.module, prefix))
            if parent is not None and parent.id.kind in definition_kinds and parent.source is not None:
                outer = parent.source
                if ((ref.slug, ref.commit_sha, ref.path, ref.blob_sha)
                    == (outer.slug, outer.commit_sha, outer.path, outer.blob_sha)
                    and (outer.start_line, outer.start_col) <= (ref.start_line, ref.start_col)
                    and (ref.end_line, ref.end_col) <= (outer.end_line, outer.end_col)):
                    nested_owners.setdefault(parent.id, []).append(lexical_node.id)
            prefix = prefix.rpartition(".")[0]

    outgoing: dict[NodeId, list[Edge]] = {}
    imports: list[Edge] = []
    for edge in graph.edges:
        if edge.kind in _RUNTIME_KINDS:
            outgoing.setdefault(edge.source, []).append(edge)
        elif edge.kind is EdgeKind.IMPORTS:
            imports.append(edge)
    unresolved_by_source: dict[NodeId, list[UnresolvedEdge]] = {}
    for item in graph.unresolved:
        if item.kind in _RUNTIME_KINDS or item.kind is EdgeKind.IMPORTS:
            unresolved_by_source.setdefault(item.source, []).append(item)
    rules = {rule.source: rule for rule in policy.rules}
    pure = {(item.module, item.qualified_name) for item in policy.stdlib_identity.allowlist_entries}

    members: list[MemberEvidence] = []
    dispositions: list[DispositionEvidence] = []
    traversed: list[EdgeEvidence] = []
    reached_unresolved: list[UnresolvedEdge] = []
    blockers: list[BlockerEvidence] = []
    frontier: list[FrontierEvidence] = []
    visited: dict[NodeId, int] = {}
    queue: list[tuple[tuple[object, ...], int, NodeId, Edge | None]] = []
    serial = 0
    seed_frontier = FrontierEvidence(0, seed, None)
    heapq.heappush(queue, (_frontier_key(seed_frontier), serial, seed, None))
    peak_queue = 1
    work_units = 1  # seed queue proposal
    edges_examined = 0
    external: set[NodeId] = set()
    budget_hit = initial_counters.config_entries > budget.max_config_entries or budget.max_queue_entries < 1 or work_units > budget.max_work_units
    total_lines = _total_donor_lines(graph)

    while queue and not budget_hit:
        _, _, current, incoming = heapq.heappop(queue)
        depth = 0 if incoming is None else visited.get(incoming.source, -1) + 1
        work_units += 1
        if work_units > budget.max_work_units:
            heapq.heappush(queue, (_frontier_key(FrontierEvidence(depth, current, incoming)), serial, current, incoming))
            budget_hit = True
            break
        previous_depth = visited.get(current)
        if previous_depth is not None and previous_depth <= depth:
            continue
        visited[current] = depth
        node = nodes[current]
        if node.source is None:
            reject = DispositionEvidence(incoming, current, BTSDisposition.REJECT, None, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "included_node_missing_source_v1")
            dispositions.append(reject)
            blockers.append(reject)
            continue
        try:
            source_digest = _verified_source_digest(snapshot, node.source)
        except BTSError as exc:
            reject = DispositionEvidence(
                incoming, current, BTSDisposition.REJECT, None, exc.reason,
                exc.evidence.detail_code or "bts_source_verification_v1",
            )
            dispositions.append(reject)
            blockers.append(reject)
            continue
        candidate = MemberEvidence(current, node.source, source_digest)
        prospective = [*members, candidate]
        source_lines, _ = _line_union(prospective)
        files = len({member.source.path for member in prospective})
        # The strict ratio comparison deliberately uses the caller's bps field;
        # 4,000 is the required policy value, while tests can exercise boundaries.
        ratio_exceeded = total_lines <= 0 or source_lines * 10_000 > total_lines * budget.max_donor_source_bps
        if len(prospective) > budget.max_nodes or len(prospective) > budget.max_symbols or files > budget.max_files or source_lines > budget.max_source_lines or ratio_exceeded:
            frontier.append(FrontierEvidence(depth, current, incoming))
            budget_hit = True
            break
        members.append(candidate)

        # Including a definition includes its entire source span, including
        # constructors, class assignments and nested definitions. Their graph
        # owners remain distinct, but their runtime dependencies cannot vanish
        # merely because the enclosing definition is the selected member.
        owners = [current]
        for nested_id in sorted(nested_owners.get(current, []), key=lambda item: (item.origin.value, item.module, item.qualified_name, item.kind.value, item.location_key)):
            work_units += 1
            if work_units > budget.max_work_units:
                frontier.append(FrontierEvidence(depth, current, incoming))
                budget_hit = True
                break
            if nested_id not in visited or visited[nested_id] > depth:
                owners.append(nested_id)
                visited[nested_id] = depth
        if budget_hit:
            break
        local_unresolved = [item for owner in owners for item in unresolved_by_source.get(owner, [])]
        reached_unresolved.extend(local_unresolved)
        blockers.extend(local_unresolved)
        current_edges = sorted(
            (edge for owner in owners for edge in outgoing.get(owner, [])), key=_edge_key,
        )
        for edge in current_edges:
            work_units += 2  # examined edge + exact policy lookup
            edges_examined += 1
            disposition = _classify(edge.target, edge, rules, pure)
            dispositions.append(disposition)
            traversed.append(EdgeEvidence(depth + 1, edge, disposition.disposition, disposition.rule_id))
            if disposition.disposition is BTSDisposition.REJECT:
                blockers.append(disposition)
                continue
            if disposition.disposition is BTSDisposition.EXTERNAL:
                external.add(edge.target)
            if work_units > budget.max_work_units or edges_examined > budget.max_edges or len(external) > budget.max_external_interfaces:
                frontier.append(FrontierEvidence(depth + 1, edge.target, edge))
                budget_hit = True
                continue
            if disposition.disposition is BTSDisposition.INCLUDE:
                next_depth = depth + 1
                if next_depth > budget.max_depth or len(queue) + 1 > budget.max_queue_entries:
                    frontier.append(FrontierEvidence(next_depth, edge.target, edge))
                    budget_hit = True
                    continue
                serial += 1
                queued = FrontierEvidence(next_depth, edge.target, edge)
                heapq.heappush(queue, (_frontier_key(queued), serial, edge.target, edge))
                work_units += 1
                peak_queue = max(peak_queue, len(queue))

            # Keep only the import statement which supports this reached runtime
            # binding.  Exact SourceRef equality is the binding proof.
            binding = edge.provenance.binding
            if binding is not None:
                for support in imports:
                    if support.provenance.binding == binding or support.provenance.site == binding:
                        work_units += 2
                        support_disposition = _classify(support.target, support, rules, pure)
                        dispositions.append(support_disposition)
                        traversed.append(EdgeEvidence(depth + 1, support, support_disposition.disposition, support_disposition.rule_id))
                        if support_disposition.disposition is BTSDisposition.REJECT:
                            blockers.append(support_disposition)
                        elif support_disposition.disposition is BTSDisposition.EXTERNAL:
                            external.add(support.target)

    for _, _, node_id, incoming in queue:
        depth = 0 if incoming is None else visited.get(incoming.source, -1) + 1
        frontier.append(FrontierEvidence(depth, node_id, incoming))

    semantic_reject = bool(blockers)
    # R2: GraphCoverage is the B4 producer's extraction certificate in v1.  A
    # graph without a complete files==parsed_files certificate cannot succeed.
    r2_complete = bool(graph.coverage.files) and graph.coverage.files == graph.coverage.parsed_files
    under_collection = not r2_complete and not semantic_reject
    if under_collection:
        r2 = DispositionEvidence(None, seed, BTSDisposition.REJECT, None, BTSRejectReason.REJECT_UNDER_COLLECTION, "b4_runtime_references_incomplete_v1")
        blockers.append(r2)

    source_lines, _ = _line_union(members)
    counter = BudgetCounters(
        files=len({member.source.path for member in members}), edges=edges_examined, nodes=len(members),
        queue_entries=len(frontier), peak_queue_entries=peak_queue,
        depth=max(visited.values(), default=0), work_units=work_units, symbols=len(members),
        source_lines=source_lines, external_interfaces=len(external), config_entries=initial_counters.config_entries,
    )
    if semantic_reject:
        status = BTSStatus.REJECT
    elif budget_hit or under_collection:
        status = BTSStatus.PARTIAL
        if budget_hit:
            budget_blocker = DispositionEvidence(None, seed, BTSDisposition.REJECT, None, BTSRejectReason.REJECT_BUDGET_EXCEEDED, "bts_walk_budget_v1")
            blockers.append(budget_blocker)
    else:
        status = BTSStatus.COMPLETE
    report = _report(status, inputs, members, dispositions, traversed, reached_unresolved, blockers, frontier, counter)
    if status is not BTSStatus.COMPLETE:
        return BTSResult(status, report, None)

    required_files = tuple(sorted({RequiredFileEvidence(item.source.path, item.source.blob_sha, item.source_bytes_sha256) for item in members}))
    required_symbols = tuple(sorted((RequiredSymbolEvidence(item.node, item.source) for item in members), key=lambda item: _node_id_key(item.node)))
    equivalent_base = BTS(BTS_SCHEMA_VERSION, seed, tuple(sorted(members)), tuple(sorted(dispositions, key=_disposition_key)), required_files, required_symbols, "", "")
    equivalence = _digest(equivalent_base, omit=frozenset({"bts_digest", "member_equivalence_digest"}))
    primary_payload = (report, equivalent_base)
    primary = _digest(primary_payload, omit=frozenset({"analysis_digest", "bts_digest", "member_equivalence_digest"}))
    bts = BTS(
        BTS_SCHEMA_VERSION, seed, equivalent_base.members, equivalent_base.dispositions,
        required_files, required_symbols, primary, equivalence,
    )
    return BTSResult(BTSStatus.COMPLETE, report, bts)


GraphProvider: TypeAlias = Graph | Callable[[Path], Graph]


def compute_bts(
    snapshot: DonorSnapshot,
    seed: NodeId,
    graph: GraphProvider,
    budget: BTSBudget,
    policy: ResolutionPolicy,
) -> BTSResult:
    """Compute from one verified donor generation under its materialization lock.

    A provider callable is invoked under the same lock as tree verification and
    included-byte reads, allowing extraction to be enclosed by the authoritative
    R6 critical section. A prebuilt frozen ``Graph`` is accepted for composition,
    but all of its reached source claims are re-derived from locked tree bytes.
    """
    if not isinstance(snapshot, DonorSnapshot):
        raise TypeError("compute_bts requires a validated DonorSnapshot as its first argument")
    try:
        with _target_lock(snapshot.materialization_root, snapshot.source_root, snapshot.commit_sha):
            verify_materialized_tree_hash(
                snapshot.source_root,
                snapshot.materialized_tree_hash,
                algorithm=snapshot.materialized_tree_hash_algorithm,
                scope=snapshot.materialized_tree_hash_scope,
            )
            extracted = graph(snapshot.source_root) if callable(graph) else graph
            if not isinstance(extracted, Graph):
                raise TypeError("graph provider must return a validated Graph")
            for source_ref in _graph_sources(extracted):
                _verified_source_digest(snapshot, source_ref)
            return _compute_bts(snapshot, seed, extracted, budget, policy)
    except TreeHashError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "materialized donor tree integrity verification failed",
            detail_code="bts_materialized_tree_hash_v1",
            cause=exc,
        ) from exc


__all__ = [
    "BTS",
    "BTS_RESOLVER_VERSION",
    "BTS_SCHEMA_VERSION",
    "AdaptRule",
    "AdapterCatalog",
    "AdapterCatalogEntry",
    "AnalysisInputs",
    "BTSBudget",
    "BTSDisposition",
    "BTSReport",
    "BTSResult",
    "BTSStatus",
    "BudgetCounters",
    "DispositionEvidence",
    "DispositionRule",
    "DonorSnapshot",
    "EdgeEvidence",
    "EnvironmentContract",
    "ExternalRule",
    "FrontierEvidence",
    "InterfaceContract",
    "MapRule",
    "MemberEvidence",
    "RejectRule",
    "ReplaceRule",
    "RequiredFileEvidence",
    "RequiredSymbolEvidence",
    "ResolutionPolicy",
    "StdlibIdentity",
    "StdlibInterface",
    "compute_bts",
    "load_bts_artifact",
]
