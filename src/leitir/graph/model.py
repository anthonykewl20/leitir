"""Immutable and canonically ordered BTS graph model from ADR-0008 section 1."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from itertools import pairwise
from pathlib import PurePosixPath, PureWindowsPath
from typing import TypeAlias, TypeVar, cast

from leitir.apisurface import ApiIndex
from leitir.bts_errors import BTSError, BTSRejectReason

GRAPH_SCHEMA_VERSION = "leitir-bts-graph-v1"
_NONE_SOURCE_KEY: tuple[int] = (0,)
_JsonScalar: TypeAlias = str | int | bool | None
JsonValue: TypeAlias = _JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
_T = TypeVar("_T")


class NodeKind(str, Enum):  # noqa: UP042 - ADR-0008 pins str, Enum
    MODULE = "module"
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    CLASS = "class"
    METHOD = "method"
    ASYNC_METHOD = "async_method"
    CONSTANT = "constant"
    TEST = "test"
    RESOURCE = "resource"


class NodeOrigin(str, Enum):  # noqa: UP042 - ADR-0008 pins str, Enum
    DONOR = "donor"
    STDLIB = "stdlib"
    DECLARED_EXTERNAL = "declared_external"
    TEST = "test"
    RESOURCE = "resource"


class EdgeKind(str, Enum):  # noqa: UP042 - ADR-0008 pins str, Enum
    IMPORTS = "imports"
    INHERITS = "inherits"
    RAISES = "raises"
    CALLS = "calls"
    INSTANTIATES = "instantiates"
    READS = "reads"
    TESTED_BY = "tested_by"


def _require_text(value: object, name: str, *, empty: bool = False) -> None:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be strict UTF-8") from exc


def _require_int(value: object, name: str, *, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


def _validate_relative_posix_path(value: str) -> None:
    _require_text(value, "path")
    path = PurePosixPath(value)
    if (
        "\x00" in value
        or path.is_absolute()
        or PureWindowsPath(value).drive
        or "\\" in value
        or value == "."
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise ValueError("path must be a normalized relative POSIX path")


@dataclass(frozen=True, slots=True, order=True)
class SourceRef:
    slug: str
    commit_sha: str
    path: str
    blob_sha: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __post_init__(self) -> None:
        _require_text(self.slug, "slug")
        _require_text(self.commit_sha, "commit_sha")
        _validate_relative_posix_path(self.path)
        _require_text(self.blob_sha, "blob_sha")
        _require_int(self.start_line, "start_line", minimum=1)
        _require_int(self.start_col, "start_col", minimum=0)
        _require_int(self.end_line, "end_line", minimum=1)
        _require_int(self.end_col, "end_col", minimum=0)
        if (self.end_line, self.end_col) < (self.start_line, self.start_col):
            raise ValueError("source end must not precede source start")


@dataclass(frozen=True, slots=True, order=True)
class NodeId:
    origin: NodeOrigin
    kind: NodeKind
    module: str
    qualified_name: str
    location_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.origin, NodeOrigin):
            raise ValueError("origin must be a NodeOrigin")
        if not isinstance(self.kind, NodeKind):
            raise ValueError("kind must be a NodeKind")
        _require_text(self.module, "module")
        _require_text(self.qualified_name, "qualified_name")
        _require_text(self.location_key, "location_key")


@dataclass(frozen=True, slots=True)
class Node:
    id: NodeId
    source: SourceRef | None
    extraction_method: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, NodeId):
            raise ValueError("id must be a NodeId")
        if self.source is not None and not isinstance(self.source, SourceRef):
            raise ValueError("source must be a SourceRef or None")
        _require_text(self.extraction_method, "extraction_method")


@dataclass(frozen=True, slots=True)
class EdgeProvenance:
    site: SourceRef
    binding: SourceRef | None
    ast_kind: str
    resolution_rule: str
    protocol_base: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.site, SourceRef):
            raise ValueError("site must be a SourceRef")
        if self.binding is not None and not isinstance(self.binding, SourceRef):
            raise ValueError("binding must be a SourceRef or None")
        _require_text(self.ast_kind, "ast_kind")
        _require_text(self.resolution_rule, "resolution_rule")
        if not isinstance(self.protocol_base, bool):
            raise ValueError("protocol_base must be a bool")

    @property
    def source(self) -> SourceRef:
        """Compatibility spelling for callers that describe provenance as source."""
        return self.site


@dataclass(frozen=True, slots=True)
class Edge:
    kind: EdgeKind
    source: NodeId
    target: NodeId
    provenance: EdgeProvenance

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EdgeKind):
            raise ValueError("kind must be an EdgeKind")
        if not isinstance(self.source, NodeId) or not isinstance(self.target, NodeId):
            raise ValueError("edge endpoints must be NodeId values")
        if not isinstance(self.provenance, EdgeProvenance):
            raise ValueError("provenance must be EdgeProvenance")
        if self.provenance.protocol_base and self.kind is not EdgeKind.INHERITS:
            raise ValueError("protocol_base is valid only for INHERITS edges")


@dataclass(frozen=True, slots=True)
class UnresolvedEdge:
    kind: EdgeKind
    source: NodeId
    expression: str
    provenance: EdgeProvenance
    reason: BTSRejectReason
    detail_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EdgeKind):
            raise ValueError("kind must be an EdgeKind")
        if not isinstance(self.source, NodeId):
            raise ValueError("source must be a NodeId")
        _require_text(self.expression, "expression")
        if not isinstance(self.provenance, EdgeProvenance):
            raise ValueError("provenance must be EdgeProvenance")
        if self.provenance.protocol_base and self.kind is not EdgeKind.INHERITS:
            raise ValueError("protocol_base is valid only for INHERITS edges")
        if not isinstance(self.reason, BTSRejectReason):
            raise ValueError("reason must be a BTSRejectReason")
        _require_text(self.detail_code, "detail_code")


@dataclass(frozen=True, slots=True)
class ExtractionBlocker:
    path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    ast_kind: str
    resolution_rule: str
    reason: BTSRejectReason
    detail_code: str

    def __post_init__(self) -> None:
        _validate_relative_posix_path(self.path)
        _require_int(self.start_line, "start_line", minimum=1)
        _require_int(self.start_col, "start_col", minimum=0)
        _require_int(self.end_line, "end_line", minimum=1)
        _require_int(self.end_col, "end_col", minimum=0)
        if (self.end_line, self.end_col) < (self.start_line, self.start_col):
            raise ValueError("blocker end must not precede blocker start")
        _require_text(self.ast_kind, "ast_kind")
        _require_text(self.resolution_rule, "resolution_rule")
        if not isinstance(self.reason, BTSRejectReason):
            raise ValueError("reason must be a BTSRejectReason")
        _require_text(self.detail_code, "detail_code")


def _source_ref_key(source: SourceRef) -> tuple[str, str, str, str, int, int, int, int]:
    return (
        source.slug,
        source.commit_sha,
        source.path,
        source.blob_sha,
        source.start_line,
        source.start_col,
        source.end_line,
        source.end_col,
    )


def _optional_source_key(source: SourceRef | None) -> tuple[object, ...]:
    return _NONE_SOURCE_KEY if source is None else (1, *_source_ref_key(source))


def _node_id_key(node_id: NodeId) -> tuple[str, str, str, str, str]:
    return (
        node_id.origin.value,
        node_id.kind.value,
        node_id.module,
        node_id.qualified_name,
        node_id.location_key,
    )


def _node_key(node: Node) -> tuple[object, ...]:
    return (*_node_id_key(node.id), *_optional_source_key(node.source), node.extraction_method)


def _provenance_key(provenance: EdgeProvenance) -> tuple[object, ...]:
    return (
        *_source_ref_key(provenance.site),
        *_optional_source_key(provenance.binding),
        provenance.ast_kind,
        provenance.resolution_rule,
        provenance.protocol_base,
    )


def _edge_key(edge: Edge) -> tuple[object, ...]:
    return (*_node_id_key(edge.source), edge.kind.value, *_node_id_key(edge.target), *_provenance_key(edge.provenance))


def _unresolved_key(edge: UnresolvedEdge) -> tuple[object, ...]:
    return (
        *_node_id_key(edge.source),
        edge.kind.value,
        *_provenance_key(edge.provenance),
        edge.expression,
        edge.reason.value,
        edge.detail_code,
    )


def _blocker_key(blocker: ExtractionBlocker) -> tuple[object, ...]:
    return (
        blocker.path,
        blocker.start_line,
        blocker.start_col,
        blocker.end_line,
        blocker.end_col,
        blocker.ast_kind,
        blocker.resolution_rule,
        blocker.reason.value,
        blocker.detail_code,
    )


@dataclass(frozen=True, slots=True)
class GraphCoverage:
    files: tuple[SourceRef, ...] = ()
    parsed_files: tuple[SourceRef, ...] = ()
    blockers: tuple[ExtractionBlocker, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.files, tuple) or not all(isinstance(item, SourceRef) for item in self.files):
            raise ValueError("coverage files must be a tuple of SourceRef values")
        if not isinstance(self.parsed_files, tuple) or not all(isinstance(item, SourceRef) for item in self.parsed_files):
            raise ValueError("parsed_files must be a tuple of SourceRef values")
        if not isinstance(self.blockers, tuple) or not all(isinstance(item, ExtractionBlocker) for item in self.blockers):
            raise ValueError("blockers must be a tuple of ExtractionBlocker values")
        object.__setattr__(self, "files", _sort_unique(self.files, _source_ref_key, "coverage file"))
        object.__setattr__(self, "parsed_files", _sort_unique(self.parsed_files, _source_ref_key, "parsed coverage file"))
        object.__setattr__(self, "blockers", _sort_unique(self.blockers, _blocker_key, "extraction blocker"))


def _duplicate_error(record_type: str) -> BTSError:
    return BTSError(
        BTSRejectReason.REJECT_DUPLICATE_RESULT,
        f"duplicate {record_type}",
        detail_code=f"record_type={record_type}",
    )


def _sort_unique(
    items: tuple[_T, ...], key: Callable[[_T], tuple[object, ...]], record_type: str
) -> tuple[_T, ...]:
    ordered = tuple(sorted(items, key=key))
    for previous, current in pairwise(ordered):
        if key(previous) == key(current):
            raise _duplicate_error(record_type)
    return ordered


@dataclass(frozen=True, slots=True)
class Graph:
    schema_version: str
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    unresolved: tuple[UnresolvedEdge, ...]
    coverage: GraphCoverage = field(default_factory=GraphCoverage)

    def __post_init__(self) -> None:
        if self.schema_version != GRAPH_SCHEMA_VERSION:
            raise BTSError(
                BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                "unsupported graph schema_version",
                detail_code=f"schema_version={self.schema_version if isinstance(self.schema_version, str) else '<invalid>'}",
            )
        if not isinstance(self.nodes, tuple) or not all(isinstance(item, Node) for item in self.nodes):
            raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "nodes must be a tuple of Node values")
        if not isinstance(self.edges, tuple) or not all(isinstance(item, Edge) for item in self.edges):
            raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "edges must be a tuple of Edge values")
        if not isinstance(self.unresolved, tuple) or not all(isinstance(item, UnresolvedEdge) for item in self.unresolved):
            raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "unresolved must be a tuple of UnresolvedEdge values")
        if not isinstance(self.coverage, GraphCoverage):
            raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "coverage must be GraphCoverage")

        ordered_nodes = tuple(sorted(self.nodes, key=_node_key))
        node_ids: set[NodeId] = set()
        for node in ordered_nodes:
            if node.id in node_ids:
                raise _duplicate_error("node id")
            node_ids.add(node.id)
        ordered_edges = _sort_unique(self.edges, _edge_key, "edge")
        ordered_unresolved = _sort_unique(self.unresolved, _unresolved_key, "unresolved edge")
        for edge in ordered_edges:
            if edge.source not in node_ids or edge.target not in node_ids:
                raise BTSError(
                    BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                    "edge has a dangling endpoint",
                    detail_code=f"edge_kind={edge.kind.value}",
                )
        for unresolved_edge in ordered_unresolved:
            if unresolved_edge.source not in node_ids:
                raise BTSError(
                    BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                    "unresolved edge has a dangling source",
                    detail_code=f"edge_kind={unresolved_edge.kind.value}",
                )
        object.__setattr__(self, "nodes", ordered_nodes)
        object.__setattr__(self, "edges", ordered_edges)
        object.__setattr__(self, "unresolved", ordered_unresolved)

    def __iter__(self) -> Iterator[Node]:
        return iter(self.nodes)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "coverage": _coverage_to_dict(self.coverage),
            "edges": [_edge_to_dict(edge) for edge in self.edges],
            "nodes": [_node_to_dict(node) for node in self.nodes],
            "schema_version": self.schema_version,
            "unresolved": [_unresolved_to_dict(edge) for edge in self.unresolved],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8", errors="strict")

    @classmethod
    def from_json(cls, value: str | bytes) -> Graph:
        try:
            text = value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value
            raw = json.loads(text)
            return _graph_from_dict(_mapping(raw, "graph"))
        except BTSError:
            raise
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "invalid graph JSON") from exc


def _source_to_dict(source: SourceRef) -> dict[str, JsonValue]:
    return {
        "blob_sha": source.blob_sha,
        "commit_sha": source.commit_sha,
        "end_col": source.end_col,
        "end_line": source.end_line,
        "path": source.path,
        "slug": source.slug,
        "start_col": source.start_col,
        "start_line": source.start_line,
    }


def _node_id_to_dict(node_id: NodeId) -> dict[str, JsonValue]:
    return {
        "kind": node_id.kind.value,
        "location_key": node_id.location_key,
        "module": node_id.module,
        "origin": node_id.origin.value,
        "qualified_name": node_id.qualified_name,
    }


def _node_to_dict(node: Node) -> dict[str, JsonValue]:
    return {
        "extraction_method": node.extraction_method,
        "id": _node_id_to_dict(node.id),
        "source": None if node.source is None else _source_to_dict(node.source),
    }


def _provenance_to_dict(provenance: EdgeProvenance) -> dict[str, JsonValue]:
    return {
        "ast_kind": provenance.ast_kind,
        "binding": None if provenance.binding is None else _source_to_dict(provenance.binding),
        "protocol_base": provenance.protocol_base,
        "resolution_rule": provenance.resolution_rule,
        "site": _source_to_dict(provenance.site),
    }


def _edge_to_dict(edge: Edge) -> dict[str, JsonValue]:
    return {
        "kind": edge.kind.value,
        "provenance": _provenance_to_dict(edge.provenance),
        "source": _node_id_to_dict(edge.source),
        "target": _node_id_to_dict(edge.target),
    }


def _unresolved_to_dict(edge: UnresolvedEdge) -> dict[str, JsonValue]:
    return {
        "detail_code": edge.detail_code,
        "expression": edge.expression,
        "kind": edge.kind.value,
        "provenance": _provenance_to_dict(edge.provenance),
        "reason": edge.reason.value,
        "source": _node_id_to_dict(edge.source),
    }


def _blocker_to_dict(blocker: ExtractionBlocker) -> dict[str, JsonValue]:
    return {
        "ast_kind": blocker.ast_kind,
        "detail_code": blocker.detail_code,
        "end_col": blocker.end_col,
        "end_line": blocker.end_line,
        "path": blocker.path,
        "reason": blocker.reason.value,
        "resolution_rule": blocker.resolution_rule,
        "start_col": blocker.start_col,
        "start_line": blocker.start_line,
    }


def _coverage_to_dict(coverage: GraphCoverage) -> dict[str, JsonValue]:
    return {
        "blockers": [_blocker_to_dict(item) for item in coverage.blockers],
        "files": [_source_to_dict(item) for item in coverage.files],
        "parsed_files": [_source_to_dict(item) for item in coverage.parsed_files],
    }


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    return cast("Mapping[str, object]", value)


def _exact(raw: Mapping[str, object], fields: set[str], name: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{name} has missing or unknown fields")


def _text(raw: Mapping[str, object], field_name: str) -> str:
    value = raw[field_name]
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


def _integer(raw: Mapping[str, object], field_name: str) -> int:
    value = raw[field_name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    return value


def _source_from_dict(value: object) -> SourceRef:
    raw = _mapping(value, "source")
    _exact(raw, {"slug", "commit_sha", "path", "blob_sha", "start_line", "start_col", "end_line", "end_col"}, "source")
    return SourceRef(
        slug=_text(raw, "slug"), commit_sha=_text(raw, "commit_sha"), path=_text(raw, "path"), blob_sha=_text(raw, "blob_sha"),
        start_line=_integer(raw, "start_line"), start_col=_integer(raw, "start_col"), end_line=_integer(raw, "end_line"), end_col=_integer(raw, "end_col"),
    )


def _node_id_from_dict(value: object) -> NodeId:
    raw = _mapping(value, "node id")
    _exact(raw, {"origin", "kind", "module", "qualified_name", "location_key"}, "node id")
    return NodeId(NodeOrigin(_text(raw, "origin")), NodeKind(_text(raw, "kind")), _text(raw, "module"), _text(raw, "qualified_name"), _text(raw, "location_key"))


def _optional_source(value: object) -> SourceRef | None:
    return None if value is None else _source_from_dict(value)


def _node_from_dict(value: object) -> Node:
    raw = _mapping(value, "node")
    _exact(raw, {"id", "source", "extraction_method"}, "node")
    return Node(_node_id_from_dict(raw["id"]), _optional_source(raw["source"]), _text(raw, "extraction_method"))


def _provenance_from_dict(value: object) -> EdgeProvenance:
    raw = _mapping(value, "provenance")
    _exact(raw, {"site", "binding", "ast_kind", "resolution_rule", "protocol_base"}, "provenance")
    protocol_base = raw["protocol_base"]
    if not isinstance(protocol_base, bool):
        raise ValueError("protocol_base must be a bool")
    return EdgeProvenance(_source_from_dict(raw["site"]), _optional_source(raw["binding"]), _text(raw, "ast_kind"), _text(raw, "resolution_rule"), protocol_base)


def _edge_from_dict(value: object) -> Edge:
    raw = _mapping(value, "edge")
    _exact(raw, {"kind", "source", "target", "provenance"}, "edge")
    return Edge(EdgeKind(_text(raw, "kind")), _node_id_from_dict(raw["source"]), _node_id_from_dict(raw["target"]), _provenance_from_dict(raw["provenance"]))


def _unresolved_from_dict(value: object) -> UnresolvedEdge:
    raw = _mapping(value, "unresolved edge")
    _exact(raw, {"kind", "source", "expression", "provenance", "reason", "detail_code"}, "unresolved edge")
    return UnresolvedEdge(EdgeKind(_text(raw, "kind")), _node_id_from_dict(raw["source"]), _text(raw, "expression"), _provenance_from_dict(raw["provenance"]), BTSRejectReason(_text(raw, "reason")), _text(raw, "detail_code"))


def _blocker_from_dict(value: object) -> ExtractionBlocker:
    raw = _mapping(value, "blocker")
    _exact(raw, {"path", "start_line", "start_col", "end_line", "end_col", "ast_kind", "resolution_rule", "reason", "detail_code"}, "blocker")
    return ExtractionBlocker(_text(raw, "path"), _integer(raw, "start_line"), _integer(raw, "start_col"), _integer(raw, "end_line"), _integer(raw, "end_col"), _text(raw, "ast_kind"), _text(raw, "resolution_rule"), BTSRejectReason(_text(raw, "reason")), _text(raw, "detail_code"))


def _array(raw: Mapping[str, object], field_name: str) -> list[object]:
    value = raw[field_name]
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be an array")
    return value


def _coverage_from_dict(value: object) -> GraphCoverage:
    raw = _mapping(value, "coverage")
    _exact(raw, {"files", "parsed_files", "blockers"}, "coverage")
    return GraphCoverage(tuple(_source_from_dict(item) for item in _array(raw, "files")), tuple(_source_from_dict(item) for item in _array(raw, "parsed_files")), tuple(_blocker_from_dict(item) for item in _array(raw, "blockers")))


def _graph_from_dict(raw: Mapping[str, object]) -> Graph:
    _exact(raw, {"schema_version", "nodes", "edges", "unresolved", "coverage"}, "graph")
    return Graph(_text(raw, "schema_version"), tuple(_node_from_dict(item) for item in _array(raw, "nodes")), tuple(_edge_from_dict(item) for item in _array(raw, "edges")), tuple(_unresolved_from_dict(item) for item in _array(raw, "unresolved")), _coverage_from_dict(raw["coverage"]))


_API_KINDS: dict[str, NodeKind] = {
    kind.value: kind
    for kind in (
        NodeKind.FUNCTION,
        NodeKind.ASYNC_FUNCTION,
        NodeKind.CLASS,
        NodeKind.METHOD,
        NodeKind.ASYNC_METHOD,
        NodeKind.CONSTANT,
        NodeKind.TEST,
        NodeKind.RESOURCE,
    )
}


def build_from_api_index(index: ApiIndex) -> Graph:
    """Build discovery nodes from a flat API index without mutating it."""
    if not isinstance(index, dict) or index.get("schema_version") != 1 or isinstance(index.get("schema_version"), bool):
        raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "unsupported ApiIndex schema")
    symbols = index.get("symbols")
    if not isinstance(symbols, list) or not all(isinstance(item, dict) for item in symbols):
        raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "ApiIndex symbols must be a list of objects")
    nodes: list[Node] = []
    try:
        for value in symbols:
            symbol = cast("dict[str, object]", value)
            kind_value = symbol.get("kind")
            module = symbol.get("module")
            qualified_name = symbol.get("qualified_name")
            path = symbol.get("path")
            line = symbol.get("line")
            if not isinstance(kind_value, str) or kind_value not in _API_KINDS:
                raise ValueError("unsupported API symbol kind")
            if not isinstance(module, str) or not isinstance(qualified_name, str) or not isinstance(path, str):
                raise ValueError("API symbol identity fields must be strings")
            _validate_relative_posix_path(path)
            _require_int(line, "line", minimum=1)
            kind = _API_KINDS[kind_value]
            origin = NodeOrigin.TEST if kind is NodeKind.TEST else NodeOrigin.RESOURCE if kind is NodeKind.RESOURCE else NodeOrigin.DONOR
            node_id = NodeId(origin, kind, module, qualified_name, f"{path}:{line}")
            nodes.append(Node(node_id, None, "api_index"))
        return Graph(GRAPH_SCHEMA_VERSION, tuple(nodes), (), ())
    except BTSError:
        raise
    except (TypeError, ValueError) as exc:
        raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "invalid ApiIndex symbol") from exc


__all__ = [
    "GRAPH_SCHEMA_VERSION", "Edge", "EdgeKind", "EdgeProvenance", "ExtractionBlocker", "Graph", "GraphCoverage",
    "Node", "NodeId", "NodeKind", "NodeOrigin", "SourceRef", "UnresolvedEdge", "build_from_api_index",
]
