"""Conservative TypeScript tree-sitter graph producer for ADR-0012 v1.

The graph model has no interface kind, so TypeScript interfaces deliberately map
to ``NodeKind.CLASS``.  Their syntax kind is retained in source provenance and
inheritance edges targeting them set ``protocol_base=True``.  ``import type`` is
treated as a static import: its binding is syntactically explicit even though it
is erased at TypeScript runtime.
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
    build_js_ts_binding_index,
    load_runtime,
    read_verified_source,
    source_ref,
    walk_nodes,
)

GRAMMAR_ID = "tree-sitter-typescript-0.23.2-abi14-v1"
PRODUCER_ID = "leitir.graph.typescript"
PRODUCER_VERSION = "stage-2-v1"
RESOLUTION_RULE_VERSION = "typescript_tree_sitter_resolution_v1"
QUERY_ID = "typescript-graph-query-v1"
# Every shape below was compiled against tree-sitter-typescript 0.23.2.  In
# particular declaration names are type_identifier, while extends bases are
# identifier and implementation bases are type_identifier.
QUERY_TEXT = """(function_declaration name: (identifier) @def.function)
(class_declaration name: (type_identifier) @def.class)
(method_definition name: (property_identifier) @def.method)
(interface_declaration name: (type_identifier) @def.interface)
(import_specifier (identifier) @import.specifier)
(extends_clause (identifier) @inherit.base)
(implements_clause (type_identifier) @inherit.interface)
(call_expression function: (identifier) @call.callee)
(new_expression constructor: (identifier) @raise.constructor)
"""


def _module(path: str) -> str:
    return PurePosixPath(path).with_suffix("").as_posix()


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="strict")


def _child(node: Any, field: str) -> Any | None:
    return node.child_by_field_name(field)


def _first(node: Any, node_type: str) -> Any | None:
    return next((item for item in node.children if item.type == node_type), None)


def _whole(ref: SourceRef, data: bytes) -> SourceRef:
    return source_ref(ref, data, 0, len(data))


def _is_async(node: Any) -> bool:
    return any(child.type == "async" for child in node.children)


def _children_of_type(node: Any, node_type: str) -> tuple[Any, ...]:
    return tuple(child for child in node.children if child.type == node_type)


def extract_graph(request: GraphExtractionRequest) -> Graph:
    """Extract only statically proven TypeScript module relationships."""

    assert_query_identity("typescript", request.policy, query_id=QUERY_ID, query_text=QUERY_TEXT)
    assert_producer_identity(request.policy, producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version=RESOLUTION_RULE_VERSION)
    runtime, language, parser, query_type = load_runtime(
        request.policy.grammar_factory,
        request.policy.grammar_abi_version,
        grammar_module="tree_sitter_typescript", runtime_distribution="tree-sitter",
        runtime_version=request.policy.runtime_version, grammar_distribution="tree-sitter-typescript",
        grammar_version=request.policy.grammar_version,
    )
    try:
        query = query_type(language, QUERY_TEXT)
        cursor_type = runtime.QueryCursor
    except Exception as exc:
        raise BTSError(BTSRejectReason.REJECT_UNSUPPORTED_EXTRA, "tree-sitter optional extra is broken for graph production", detail_code="tree_sitter_extra_broken_v1", cause=exc) from exc
    counters = BudgetCounters(request.policy)
    parsed: list[tuple[SourceRef, bytes, Any]] = []
    blockers = []
    for file_ref in request.source_files:
        data = read_verified_source(request.source_root / file_ref.path, file_ref, maximum=request.policy.max_file_bytes)
        root = parser.parse(data).root_node
        counters.add_file(root)
        cursor = cursor_type(query, match_limit=request.policy.max_query_matches)
        captures = cursor.captures(root)
        if cursor.did_exceed_match_limit:
            counters.add_query_matches(request.policy.max_query_matches + 1)
        counters.add_query_matches(sum(len(nodes) for nodes in captures.values()))
        error = next((node for node in walk_nodes(root) if node.type == "ERROR"), None)
        if root.has_error or error is not None:
            error = root if error is None else error
            error_ref = source_ref(file_ref, data, error.start_byte, error.end_byte)
            blockers.append(blocker_from_ref(error_ref, error.type, RESOLUTION_RULE_VERSION, BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree_sitter_parse_error_v1"))
            continue
        parsed.append((file_ref, data, root))

    nodes: dict[NodeId, Node] = {}
    definitions: dict[str, dict[str, list[tuple[NodeId, SourceRef]]]] = {}
    module_ids: dict[str, list[NodeId]] = {}
    interfaces: set[NodeId] = set()

    def add_node(node_id: NodeId, ref: SourceRef) -> None:
        candidate = Node(node_id, ref, f"{PRODUCER_ID}@{PRODUCER_VERSION}")
        existing = nodes.get(node_id)
        if existing is not None and existing != candidate:
            raise BTSError(BTSRejectReason.REJECT_DUPLICATE_RESULT, "conflicting TypeScript graph node", detail_code="tree_sitter_duplicate_symbol_v1")
        if existing is None:
            counters.add_symbol()
            nodes[node_id] = candidate

    for file_ref, data, root in parsed:
        module = _module(file_ref.path)
        module_id = NodeId(NodeOrigin.DONOR, NodeKind.MODULE, module, module, f"{file_ref.path}:module")
        add_node(module_id, _whole(file_ref, data))
        module_ids.setdefault(module, []).append(module_id)
        entries = definitions.setdefault(module, {})
        for top_level in root.named_children:
            statement = _child(top_level, "declaration") if top_level.type == "export_statement" else top_level
            if statement is None or statement.type not in {"function_declaration", "class_declaration", "interface_declaration"}:
                continue
            name_node = _child(statement, "name")
            if name_node is None:
                continue
            name = _text(name_node, data)
            kind = NodeKind.CLASS if statement.type in {"class_declaration", "interface_declaration"} else (NodeKind.ASYNC_FUNCTION if _is_async(statement) else NodeKind.FUNCTION)
            qualified = f"{module}.{name}"
            ref = source_ref(file_ref, data, statement.start_byte, statement.end_byte)
            symbol_id = NodeId(NodeOrigin.DONOR, kind, module, qualified, f"{file_ref.path}:{ref.start_line}:{ref.start_col}:{qualified}")
            add_node(symbol_id, ref)
            entries.setdefault(name, []).append((symbol_id, ref))
            if statement.type == "interface_declaration":
                interfaces.add(symbol_id)
            if statement.type == "class_declaration":
                body = _child(statement, "body")
                if body is not None:
                    for method in _children_of_type(body, "method_definition"):
                        method_name = _child(method, "name")
                        if method_name is None:
                            continue
                        method_text = _text(method_name, data)
                        method_kind = NodeKind.ASYNC_METHOD if _is_async(method) else NodeKind.METHOD
                        method_qualified = f"{qualified}.{method_text}"
                        method_ref = source_ref(file_ref, data, method.start_byte, method.end_byte)
                        add_node(NodeId(NodeOrigin.DONOR, method_kind, module, method_qualified, f"{file_ref.path}:{method_ref.start_line}:{method_ref.start_col}:{method_qualified}"), method_ref)

    edges: list[Edge] = []
    unresolved: list[UnresolvedEdge] = []

    def emit_unresolved(kind: EdgeKind, owner: NodeId, node: Any, data: bytes, ref_base: SourceRef, detail: str, *, reason: BTSRejectReason = BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT) -> None:
        counters.add_edge()
        ref = source_ref(ref_base, data, node.start_byte, node.end_byte)
        unresolved.append(UnresolvedEdge(kind, owner, _text(node, data), EdgeProvenance(ref, None, node.type, RESOLUTION_RULE_VERSION), reason, detail))
        blockers.append(blocker_from_ref(ref, node.type, RESOLUTION_RULE_VERSION, reason, detail))

    def emit_edge(kind: EdgeKind, owner: NodeId, target: NodeId, site: Any, data: bytes, file_ref: SourceRef, binding: SourceRef, rule: str, *, protocol_base: bool = False) -> None:
        counters.add_edge()
        edges.append(Edge(kind, owner, target, EdgeProvenance(source_ref(file_ref, data, site.start_byte, site.end_byte), binding, site.type, rule, protocol_base)))

    def resolve_module(specifier: str, from_path: str) -> tuple[NodeId, SourceRef] | None:
        if not specifier.startswith("."):
            return None
        candidate = _module((PurePosixPath(from_path).parent / specifier).as_posix())
        matches = sorted(module_ids.get(candidate, []), key=lambda value: value.location_key)
        if len(matches) == 1:
            target = matches[0]
            target_source = nodes[target].source
            assert target_source is not None
            return target, target_source
        if len(matches) > 1:
            raise BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "ambiguous TypeScript import module identity", detail_code="tree_sitter_ambiguous_import_v1")
        return None

    for file_ref, data, root in parsed:
        module = _module(file_ref.path)
        own_module = module_ids[module][0]
        imports: dict[str, list[tuple[NodeId, SourceRef, str]]] = {}
        shadow_index = build_js_ts_binding_index(root, data)
        for statement in root.named_children:
            if statement.type == "export_statement" and _first(statement, "string") is not None:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_reexport_v1")
                continue
            if statement.type != "import_statement":
                continue
            import_clause = _first(statement, "import_clause")
            string = _first(statement, "string")
            if string is None:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_dynamic_import_v1")
                continue
            if import_clause is not None and _first(import_clause, "namespace_import") is not None:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_star_import_v1")
                continue
            resolved = resolve_module(_text(string, data)[1:-1], file_ref.path)
            if resolved is None:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_unresolved_import_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            target_module, _target_ref = resolved
            # IMPORTS records the statement for both site and binding.  The
            # statement is the single syntactic fact that proves this relation;
            # individual specifiers only establish local name bindings below.
            binding = source_ref(file_ref, data, statement.start_byte, statement.end_byte)
            emit_edge(EdgeKind.IMPORTS, own_module, target_module, statement, data, file_ref, binding, "typescript_static_import_v1")
            named = _first(import_clause, "named_imports") if import_clause is not None else None
            if named is not None:
                for item in _children_of_type(named, "import_specifier"):
                    identifiers = _children_of_type(item, "identifier")
                    imported = identifiers[0] if identifiers else None
                    alias = identifiers[-1] if identifiers else None
                    if imported is not None and alias is not None:
                        imports.setdefault(_text(alias, data), []).append((target_module, source_ref(file_ref, data, item.start_byte, item.end_byte), _text(imported, data)))

        def owner_for(
            node: Any,
            local_data: bytes = data,
            local_file_ref: SourceRef = file_ref,
            local_module: str = module,
            local_own_module: NodeId = own_module,
        ) -> NodeId:
            point = source_ref(local_file_ref, local_data, node.start_byte, node.end_byte)
            candidates: list[NodeId] = []
            for identity, value in nodes.items():
                item_source = value.source
                if identity.module == local_module and identity.kind in {NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION, NodeKind.CLASS, NodeKind.METHOD, NodeKind.ASYNC_METHOD} and item_source is not None and (item_source.start_line, item_source.start_col) <= (point.start_line, point.start_col) and (point.end_line, point.end_col) <= (item_source.end_line, item_source.end_col):
                    candidates.append(identity)
            def source_for(value: NodeId) -> SourceRef:
                result = nodes[value].source
                assert result is not None
                return result
            return min(candidates, key=lambda value: ((source_for(value).end_line - source_for(value).start_line, source_for(value).end_col - source_for(value).start_col), value.location_key)) if candidates else local_own_module

        def resolve_symbol(
            name: str,
            *,
            expected: set[NodeKind],
            local_module: str = module,
            local_imports: dict[str, list[tuple[NodeId, SourceRef, str]]] = imports,
        ) -> tuple[NodeId, SourceRef] | None:
            local = [(identity, ref) for identity, ref in definitions[local_module].get(name, []) if identity.kind in expected]
            imported: list[tuple[NodeId, SourceRef]] = []
            for target_module, binding, exported in local_imports.get(name, []):
                imported.extend((identity, binding) for identity, _ in definitions.get(target_module.module, {}).get(exported, []) if identity.kind in expected)
            matches = local + imported
            return matches[0] if len(matches) == 1 else None

        def resolve_constructor(
            expression: Any,
            local_data: bytes = data,
            local_shadow_index=shadow_index,
        ) -> tuple[Any | None, tuple[NodeId, SourceRef] | None, bool]:
            """Resolve a bare ``new`` constructor through the normal binding rule.

            Both ``throw new X`` and standalone construction deliberately use
            this one path so their class-resolution semantics cannot drift.
            """

            constructor = _child(expression, "constructor")
            if constructor is None or constructor.type != "identifier":
                return constructor, None, False
            if local_shadow_index.is_shadowed(constructor, _text(constructor, local_data)):
                return constructor, None, True
            return constructor, resolve_symbol(_text(constructor, local_data), expected={NodeKind.CLASS}), True

        def decorator_owner(node: Any) -> NodeId:
            parent = node.parent
            if parent is not None and parent.type == "class_body":
                children = parent.children
                index = next((position for position, child in enumerate(children) if child.id == node.id), -1)
                following = next((child for child in children[index + 1:] if child.type == "method_definition"), None)
                if following is not None:
                    return owner_for(following)
            return owner_for(node)

        for item in walk_nodes(root):
            owner = owner_for(item)
            if item.type == "decorator":
                emit_unresolved(EdgeKind.CALLS, decorator_owner(item), item, data, file_ref, "tree_sitter_decorator_v1")
            elif item.type == "class_declaration":
                heritage = _first(item, "class_heritage")
                if heritage is None:
                    continue
                for clause in heritage.named_children:
                    if clause.type not in {"extends_clause", "implements_clause"}:
                        continue
                    base = next((child for child in clause.named_children if child.type in {"identifier", "type_identifier"}), None)
                    if base is None:
                        emit_unresolved(EdgeKind.INHERITS, owner, clause, data, file_ref, "tree_sitter_dynamic_base_v1")
                    elif clause.type == "extends_clause" and _first(clause, "type_arguments") is not None:
                        emit_unresolved(EdgeKind.INHERITS, owner, clause, data, file_ref, "tree_sitter_unresolved_base_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    else:
                        shadowed = shadow_index.is_shadowed(base, _text(base, data))
                        resolved = None if shadowed else resolve_symbol(_text(base, data), expected={NodeKind.CLASS})
                        if resolved is None:
                            emit_unresolved(EdgeKind.INHERITS, owner, base, data, file_ref, "tree_sitter_shadowed_binding_v1" if shadowed else "tree_sitter_unresolved_base_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        else:
                            target, binding = resolved
                            emit_edge(EdgeKind.INHERITS, owner, target, base, data, file_ref, binding, "typescript_imported_base_v1", protocol_base=clause.type == "implements_clause" or target in interfaces)
            elif item.type == "call_expression":
                function = _child(item, "function")
                if function is None:
                    continue
                if function.type == "import" or (function.type == "identifier" and _text(function, data) == "require"):
                    emit_unresolved(EdgeKind.IMPORTS, owner, item, data, file_ref, "tree_sitter_dynamic_import_v1")
                elif function.type != "identifier" or _first(item, "type_arguments") is not None:
                    emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_receiver_dispatch_v1")
                else:
                    shadowed = shadow_index.is_shadowed(function, _text(function, data))
                    resolved = None if shadowed else resolve_symbol(_text(function, data), expected={NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION})
                    if resolved is None:
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_shadowed_binding_v1" if shadowed else "tree_sitter_ambiguous_callee_binding_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    else:
                        target, binding = resolved
                        emit_edge(EdgeKind.CALLS, owner, target, function, data, file_ref, binding, "typescript_bare_call_v1")
            elif item.type == "throw_statement":
                expression = next((child for child in item.named_children if child.type == "new_expression"), None)
                constructor, resolved, bare_constructor = resolve_constructor(expression) if expression is not None else (None, None, False)
                if not bare_constructor:
                    emit_unresolved(EdgeKind.RAISES, owner, item, data, file_ref, "tree_sitter_unresolved_throw_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                else:
                    if resolved is None:
                        assert constructor is not None
                        detail = "tree_sitter_shadowed_binding_v1" if shadow_index.is_shadowed(constructor, _text(constructor, data)) else "tree_sitter_unresolved_throw_v1"
                        emit_unresolved(EdgeKind.RAISES, owner, constructor, data, file_ref, detail, reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    else:
                        assert constructor is not None
                        target, binding = resolved
                        emit_edge(EdgeKind.RAISES, owner, target, constructor, data, file_ref, binding, "typescript_throw_new_v1")
            elif item.type == "new_expression":
                # ``throw new X`` is exception evidence, not a second
                # instantiation relation for the same constructor occurrence.
                if item.parent is not None and item.parent.type == "throw_statement":
                    continue
                constructor, resolved, bare_constructor = resolve_constructor(item)
                if not bare_constructor:
                    emit_unresolved(EdgeKind.INSTANTIATES, owner, constructor if constructor is not None else item, data, file_ref, "tree_sitter_dynamic_instantiation_v1")
                elif resolved is None:
                    assert constructor is not None
                    detail = "tree_sitter_shadowed_binding_v1" if shadow_index.is_shadowed(constructor, _text(constructor, data)) else "tree_sitter_unresolved_instantiation_v1"
                    emit_unresolved(EdgeKind.INSTANTIATES, owner, constructor, data, file_ref, detail, reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                else:
                    assert constructor is not None
                    target, binding = resolved
                    emit_edge(EdgeKind.INSTANTIATES, owner, target, constructor, data, file_ref, binding, "typescript_new_constructor_v1")

    return Graph(GRAPH_SCHEMA_VERSION, tuple(nodes.values()), tuple(edges), tuple(unresolved), GraphCoverage(request.source_files, tuple(item[0] for item in parsed), tuple(blockers)))


__all__ = ["GRAMMAR_ID", "PRODUCER_ID", "PRODUCER_VERSION", "QUERY_ID", "QUERY_TEXT", "RESOLUTION_RULE_VERSION", "extract_graph"]
