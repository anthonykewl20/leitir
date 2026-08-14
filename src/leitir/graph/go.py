"""Conservative Go tree-sitter graph producer for ADR-0012 v1.

Go compiles packages, not individual files.  Consequently one MODULE node is
made for every in-scope directory, using the whole-file span of that directory's
lexicographically first parsed ``.go`` file as its canonical representative.
This avoids duplicate NodeIds for files in the same package.  Imports resolve
only when their literal path exactly equals an in-scope directory relative to
``source_root``; module-path prefixes and external packages are deliberately
outside this v1 subset.  Build tags are parsed as ordinary files: conditional
compilation is not modeled.

Interfaces map to CLASS because the graph contract has no INTERFACE kind; the
syntax kind in edge provenance distinguishes them.  Go has no static exception
relationship: ``panic`` produces unresolved RAISES evidence, never a RAISES
edge.  Similarly, identifier calls that could be conversions are blocked rather
than guessed.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import (
    GRAPH_SCHEMA_VERSION,
    Edge,
    EdgeKind,
    EdgeProvenance,
    Graph,
    GraphCoverage,
    Node,
    NodeId,
    NodeKind,
    NodeOrigin,
    SourceRef,
    UnresolvedEdge,
)
from leitir.graph.policy import GraphExtractionRequest
from leitir.graph.ts_kernel import (
    BudgetCounters,
    assert_producer_identity,
    assert_query_identity,
    blocker_from_ref,
    load_runtime,
    read_verified_source,
    source_ref,
    walk_nodes,
)

GRAMMAR_ABI_VERSION = 15
GRAMMAR_ID = f"tree-sitter-go-0.25.0-abi{GRAMMAR_ABI_VERSION}-v1"
PRODUCER_ID = "leitir.graph.go"
PRODUCER_VERSION = "stage-2-v1"
RESOLUTION_RULE_VERSION = "go_tree_sitter_resolution_v1"
QUERY_ID = "go-graph-query-v1"
# Probed against the installed tree-sitter-go 0.25.0 grammar.  In particular,
# import paths are ``import_spec path: (interpreted_string_literal)``; matching
# a ``name: (identifier)`` silently misses ordinary Go imports.
QUERY_TEXT = """(function_declaration name: (identifier) @def.function)
(method_declaration receiver: (parameter_list) name: (field_identifier) @def.method)
(type_spec name: (type_identifier) type: (struct_type) @def.struct)
(type_spec name: (type_identifier) type: (interface_type) @def.interface)
(import_spec path: (interpreted_string_literal) @import.path)
(call_expression function: (identifier) @call.bare)
(call_expression function: (selector_expression operand: (identifier) @call.receiver field: (field_identifier) @call.field))
"""

_BUILTINS = frozenset({"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover"})
_PREDECLARED_TYPES = frozenset({"any", "bool", "byte", "comparable", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr"})


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="strict")


def _child(node: Any, field: str) -> Any | None:
    return node.child_by_field_name(field)


def _whole(ref: SourceRef, data: bytes) -> SourceRef:
    return source_ref(ref, data, 0, len(data))


def _directory(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "." if parent == "." else parent


def _package_name(root: Any, data: bytes) -> str:
    clause = next((item for item in root.named_children if item.type == "package_clause"), None)
    name = _child(clause, "name") if clause is not None else None
    if name is None and clause is not None:
        name = next((item for item in clause.named_children if item.type == "package_identifier"), None)
    return _text(name, data) if name is not None else "unknown"


def extract_graph(request: GraphExtractionRequest) -> Graph:
    """Extract only Go edges whose package and lexical binding are proven."""

    assert_query_identity("go", request.policy, query_id=QUERY_ID, query_text=QUERY_TEXT)
    assert_producer_identity(request.policy, producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version=RESOLUTION_RULE_VERSION)
    runtime, language, parser, query_type = load_runtime(
        request.policy.grammar_factory,
        request.policy.grammar_abi_version,
        grammar_module="tree_sitter_go", runtime_distribution="tree-sitter",
        runtime_version=request.policy.runtime_version, grammar_distribution="tree-sitter-go",
        grammar_version=request.policy.grammar_version,
    )
    try:
        query = query_type(language, QUERY_TEXT)
        cursor_type = runtime.QueryCursor
    except Exception as exc:
        raise BTSError(BTSRejectReason.REJECT_UNSUPPORTED_EXTRA, "tree-sitter optional extra is broken for graph production", detail_code="tree_sitter_extra_broken_v1", cause=exc) from exc

    counters = BudgetCounters(request.policy)
    parsed: list[tuple[SourceRef, bytes, Any, str]] = []
    blockers = []
    for file_ref in request.source_files:
        data = read_verified_source(request.source_root / file_ref.path, file_ref, maximum=request.policy.max_file_bytes)
        root = parser.parse(data).root_node
        counters.add_file(root)
        cursor = cursor_type(query, match_limit=request.policy.max_query_matches)
        captures = cursor.captures(root)
        if cursor.did_exceed_match_limit:
            counters.add_query_matches(request.policy.max_query_matches + 1)
        counters.add_query_matches(sum(len(items) for items in captures.values()))
        error = next((item for item in walk_nodes(root) if item.type == "ERROR"), None)
        if root.has_error or error is not None:
            error = root if error is None else error
            ref = source_ref(file_ref, data, error.start_byte, error.end_byte)
            blockers.append(blocker_from_ref(ref, error.type, RESOLUTION_RULE_VERSION, BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree_sitter_parse_error_v1"))
            continue
        parsed.append((file_ref, data, root, _package_name(root, data)))

    nodes: dict[NodeId, Node] = {}
    module_ids: dict[str, NodeId] = {}
    definitions: dict[str, dict[str, list[tuple[NodeId, SourceRef, str]]]] = {}

    def add_node(identity: NodeId, ref: SourceRef) -> None:
        candidate = Node(identity, ref, f"{PRODUCER_ID}@{PRODUCER_VERSION}")
        existing = nodes.get(identity)
        if existing is not None and existing != candidate:
            raise BTSError(BTSRejectReason.REJECT_DUPLICATE_RESULT, "conflicting Go graph node", detail_code="tree_sitter_duplicate_symbol_v1")
        if existing is None:
            counters.add_symbol()
            nodes[identity] = candidate

    # The request's source refs are already sorted, so first() is the documented
    # canonical file representative for each package directory.
    directories: dict[str, list[tuple[SourceRef, bytes, Any, str]]] = {}
    for item in parsed:
        directories.setdefault(_directory(item[0].path), []).append(item)
    for directory in sorted(directories):
        representative = min(directories[directory], key=lambda item: item[0].path)
        package = representative[3]
        module_qualified = directory if package == "unknown" else f"{directory} ({package})"
        identity = NodeId(NodeOrigin.DONOR, NodeKind.MODULE, directory, module_qualified, f"{directory}:module")
        add_node(identity, _whole(representative[0], representative[1]))
        module_ids[directory] = identity
        definitions[directory] = {}

    for file_ref, data, root, _package in parsed:
        directory = _directory(file_ref.path)
        entries = definitions[directory]
        for item in walk_nodes(root):
            kind: NodeKind | None = None
            name: Any | None = None
            ast_kind = item.type
            symbol_qualified: str | None = None
            if item.type == "function_declaration":
                kind, name = NodeKind.FUNCTION, _child(item, "name")
            elif item.type == "method_declaration":
                kind, name = NodeKind.METHOD, _child(item, "name")
                receiver = _child(item, "receiver")
                receiver_type = next((child for child in walk_nodes(receiver) if child.type == "type_identifier"), None) if receiver is not None else None
                if receiver_type is not None and name is not None:
                    symbol_qualified = f"{directory}.{_text(receiver_type, data)}.{_text(name, data)}"
            elif item.type == "type_spec":
                declared_type = _child(item, "type")
                if declared_type is not None and declared_type.type in {"struct_type", "interface_type"}:
                    kind, name, ast_kind = NodeKind.CLASS, _child(item, "name"), declared_type.type
            if kind is None or name is None:
                continue
            symbol = _text(name, data)
            symbol_qualified = symbol_qualified or f"{directory}.{symbol}"
            ref = source_ref(file_ref, data, item.start_byte, item.end_byte)
            identity = NodeId(NodeOrigin.DONOR, kind, directory, symbol_qualified, f"{file_ref.path}:{ref.start_line}:{ref.start_col}:{symbol_qualified}")
            add_node(identity, ref)
            entries.setdefault(symbol, []).append((identity, ref, ast_kind))

    edges: list[Edge] = []
    unresolved: list[UnresolvedEdge] = []

    def emit_unresolved(kind: EdgeKind, owner: NodeId, item: Any, data: bytes, file_ref: SourceRef, detail: str, *, reason: BTSRejectReason = BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT) -> None:
        counters.add_edge()
        ref = source_ref(file_ref, data, item.start_byte, item.end_byte)
        provenance = EdgeProvenance(ref, None, item.type, RESOLUTION_RULE_VERSION)
        unresolved.append(UnresolvedEdge(kind, owner, _text(item, data), provenance, reason, detail))
        blockers.append(blocker_from_ref(ref, item.type, RESOLUTION_RULE_VERSION, reason, detail))

    def emit_edge(kind: EdgeKind, owner: NodeId, target: NodeId, site: Any, data: bytes, file_ref: SourceRef, binding: SourceRef, rule: str, *, protocol_base: bool = False) -> None:
        counters.add_edge()
        edges.append(Edge(kind, owner, target, EdgeProvenance(source_ref(file_ref, data, site.start_byte, site.end_byte), binding, site.type, rule, protocol_base)))

    for file_ref, data, root, _package in parsed:
        directory = _directory(file_ref.path)
        own_module = module_ids[directory]
        imports: dict[str, list[tuple[NodeId, SourceRef]]] = {}
        for spec in (item for item in walk_nodes(root) if item.type == "import_spec"):
            path_node = _child(spec, "path")
            if path_node is None or path_node.type != "interpreted_string_literal":
                emit_unresolved(EdgeKind.IMPORTS, own_module, spec, data, file_ref, "tree_sitter_external_import_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            literal = _text(path_node, data)
            # Escaped interpreted literals require Go's literal decoder.  This
            # producer has no such semantic decoder, so cannot prove a package.
            package_path = literal[1:-1] if len(literal) >= 2 and literal.startswith('"') and literal.endswith('"') and "\\" not in literal else ""
            name_node = _child(spec, "name")
            name = _text(name_node, data) if name_node is not None else None
            if name == ".":
                emit_unresolved(EdgeKind.IMPORTS, own_module, spec, data, file_ref, "tree_sitter_star_import_v1")
                continue
            target = module_ids.get(package_path)
            if target is None:
                emit_unresolved(EdgeKind.IMPORTS, own_module, spec, data, file_ref, "tree_sitter_external_import_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            binding = source_ref(file_ref, data, spec.start_byte, spec.end_byte)
            emit_edge(EdgeKind.IMPORTS, own_module, target, spec, data, file_ref, binding, "go_static_import_v1")
            if name == "_":
                continue  # Static side-effect dependency, intentionally no binding.
            binding_name = name
            if binding_name is None:
                target_package = next((item[3] for item in directories[package_path]), "unknown")
                binding_name = target_package if target_package != "unknown" else None
            if binding_name is not None:
                imports.setdefault(binding_name, []).append((target, binding))

        def owner_for(
            item: Any,
            local_file_ref: SourceRef = file_ref,
            local_data: bytes = data,
            local_directory: str = directory,
            local_own_module: NodeId = own_module,
        ) -> NodeId:
            point = source_ref(local_file_ref, local_data, item.start_byte, item.end_byte)
            candidates: list[NodeId] = []
            for identity, node in nodes.items():
                ref = node.source
                if ref is not None and ref.path == local_file_ref.path and identity.module == local_directory and identity.kind in {NodeKind.FUNCTION, NodeKind.METHOD, NodeKind.CLASS} and (ref.start_line, ref.start_col) <= (point.start_line, point.start_col) and (point.end_line, point.end_col) <= (ref.end_line, ref.end_col):
                    candidates.append(identity)

            def source_for(identity: NodeId) -> SourceRef:
                ref = nodes[identity].source
                assert ref is not None
                return ref

            return min(candidates, key=lambda identity: ((source_for(identity).end_line - source_for(identity).start_line, source_for(identity).end_col - source_for(identity).start_col), identity.location_key)) if candidates else local_own_module

        def resolve_local(name: str, *, ast_kinds: set[str], local_entries: dict[str, list[tuple[NodeId, SourceRef, str]]] = definitions[directory]) -> tuple[NodeId, SourceRef] | None:
            matches = [(identity, ref) for identity, ref, ast_kind in local_entries.get(name, []) if ast_kind in ast_kinds]
            return matches[0] if len(matches) == 1 else None

        for item in walk_nodes(root):
            owner = owner_for(item)
            if item.type == "type_spec":
                declared = _child(item, "type")
                name = _child(item, "name")
                if declared is None or name is None or declared.type not in {"struct_type", "interface_type"}:
                    continue
                source_class = resolve_local(_text(name, data), ast_kinds={declared.type})
                if source_class is None:
                    continue
                if declared.type == "interface_type":
                    for element in (child for child in declared.named_children if child.type == "type_elem"):
                        base = element.named_children[0] if len(element.named_children) == 1 else None
                        if base is None or base.type != "type_identifier":
                            emit_unresolved(EdgeKind.INHERITS, source_class[0], element, data, file_ref, "tree_sitter_unresolved_base_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                            continue
                        resolved = resolve_local(_text(base, data), ast_kinds={"interface_type"})
                        if resolved is None:
                            emit_unresolved(EdgeKind.INHERITS, source_class[0], base, data, file_ref, "tree_sitter_unresolved_base_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        else:
                            emit_edge(EdgeKind.INHERITS, source_class[0], resolved[0], base, data, file_ref, resolved[1], "go_interface_embedding_v1", protocol_base=True)
                else:
                    fields = next((child for child in declared.named_children if child.type == "field_declaration_list"), None)
                    if fields is None:
                        continue
                    for field in (child for child in fields.named_children if child.type == "field_declaration"):
                        field_type = _child(field, "type")
                        embedded = _child(field, "name") is None
                        if not embedded:
                            continue
                        text = _text(field, data)
                        if field_type is None or field_type.type != "type_identifier" or text.startswith("*"):
                            emit_unresolved(EdgeKind.INHERITS, source_class[0], field, data, file_ref, "tree_sitter_unresolved_base_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                            continue
                        resolved = resolve_local(_text(field_type, data), ast_kinds={"struct_type"})
                        if resolved is None:
                            emit_unresolved(EdgeKind.INHERITS, source_class[0], field_type, data, file_ref, "tree_sitter_unresolved_base_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        else:
                            emit_edge(EdgeKind.INHERITS, source_class[0], resolved[0], field_type, data, file_ref, resolved[1], "go_struct_embedding_v1")
            elif item.type == "call_expression":
                function = _child(item, "function")
                if function is None:
                    continue
                if function.type == "identifier":
                    name = _text(function, data)
                    if name == "panic":
                        emit_unresolved(EdgeKind.RAISES, owner, function, data, file_ref, "tree_sitter_unresolved_throw_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    elif name in _BUILTINS:
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_builtin_call_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    elif name in _PREDECLARED_TYPES or resolve_local(name, ast_kinds={"struct_type", "interface_type"}) is not None:
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_type_conversion_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    else:
                        resolved = resolve_local(name, ast_kinds={"function_declaration"})
                        if resolved is None:
                            emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_ambiguous_callee_binding_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        else:
                            emit_edge(EdgeKind.CALLS, owner, resolved[0], function, data, file_ref, resolved[1], "go_bare_call_v1")
                elif function.type == "selector_expression":
                    operand, field = _child(function, "operand"), _child(function, "field")
                    if operand is None or field is None or operand.type != "identifier" or field.type != "field_identifier":
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_receiver_dispatch_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        continue
                    bindings = imports.get(_text(operand, data), [])
                    if len(bindings) != 1:
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_receiver_dispatch_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        continue
                    target_module, binding = bindings[0]
                    matches = [(identity, ref) for identity, ref, ast_kind in definitions[target_module.module].get(_text(field, data), []) if ast_kind == "function_declaration"]
                    if len(matches) != 1:
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_unresolved_qualified_call_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    else:
                        emit_edge(EdgeKind.CALLS, owner, matches[0][0], function, data, file_ref, binding, "go_qualified_call_v1")
                else:
                    # Parenthesized function literals and all other callee values
                    # need data-flow/type information to bind.
                    emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_ambiguous_callee_binding_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)

    return Graph(GRAPH_SCHEMA_VERSION, tuple(nodes.values()), tuple(edges), tuple(unresolved), GraphCoverage(request.source_files, tuple(item[0] for item in parsed), tuple(blockers)))


__all__ = ["GRAMMAR_ABI_VERSION", "GRAMMAR_ID", "PRODUCER_ID", "PRODUCER_VERSION", "QUERY_ID", "QUERY_TEXT", "RESOLUTION_RULE_VERSION", "extract_graph"]
