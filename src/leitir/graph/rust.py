"""Conservative Rust tree-sitter graph producer for ADR-0012 v1.

Rust modules are files in this producer: ``mod`` declarations intentionally do
not create edges or synthetic inline-module nodes.  ``use`` only proves a
module relationship when its literal path maps to exactly one declared file.
Traits and enums use ``CLASS`` because the graph model has no TRAIT/ENUM kind;
their Rust AST kinds remain in their source provenance.  Rust v1 emits no
``RAISES`` edges: ``Result`` is data flow and ``panic!`` is a macro, not static
exception provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
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

GRAMMAR_ID = "tree-sitter-rust-0.24.2-abi15-v1"
PRODUCER_ID = "leitir.graph.rust"
PRODUCER_VERSION = "stage-2-v1"
RESOLUTION_RULE_VERSION = "rust_tree_sitter_resolution_v1"
QUERY_ID = "rust-graph-query-v1"
# Every pattern was compiled against tree-sitter-rust 0.24.2 (grammar ABI 15).
QUERY_TEXT = """(function_item name: (identifier) @def.function)
(struct_item name: (type_identifier) @def.struct)
(enum_item name: (type_identifier) @def.enum)
(trait_item name: (type_identifier) @def.trait)
(impl_item trait: (type_identifier) @impl.trait)
(use_declaration (scoped_identifier) @import.specifier)
(call_expression function: (identifier) @call.callee)
(macro_invocation macro: (identifier) @call.macro)
"""


def _module(path: str) -> str:
    return PurePosixPath(path).with_suffix("").as_posix()


@dataclass(frozen=True, slots=True)
class _CrateContext:
    """Syntax-and-scope-only Rust crate boundary for one declared file."""

    root_directory: tuple[str, ...] | None
    semantic_module: tuple[str, ...] | None


def _crate_context(path: str, root_directories: frozenset[tuple[str, ...]]) -> _CrateContext:
    """Determine a file's nearest declared crate root without filesystem reads.

    A root file is itself authoritative. For every other file, only an ancestor
    directory containing a *declared* ``main.rs`` or ``lib.rs`` establishes a
    boundary. No Cargo metadata or undeclared path is consulted.
    """

    file_path = PurePosixPath(path)
    directory = file_path.parent.parts
    if file_path.name in {"main.rs", "lib.rs"}:
        return _CrateContext(directory, ())
    ancestor = directory
    while True:
        if ancestor in root_directories:
            relative = file_path.relative_to(PurePosixPath(*ancestor))
            semantic = relative.parent.parts if relative.name == "mod.rs" else relative.with_suffix("").parts
            return _CrateContext(ancestor, semantic)
        if not ancestor:
            return _CrateContext(None, None)
        ancestor = ancestor[:-1]


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="strict")


def _child(node: Any, field: str) -> Any | None:
    return node.child_by_field_name(field)


def _whole(ref: SourceRef, data: bytes) -> SourceRef:
    return source_ref(ref, data, 0, len(data))


def _is_async(node: Any) -> bool:
    return any(child.type == "async" for child in node.children)


def _contains(node: Any, ancestor_type: str) -> bool:
    current = node.parent
    while current is not None:
        if current.type == ancestor_type:
            return True
        current = current.parent
    return False


def _path_components(node: Any, data: bytes) -> tuple[str, ...] | None:
    """Return only grammar-proved, non-generic Rust path components."""

    if node.type in {"crate", "self", "super", "identifier", "type_identifier"}:
        return (_text(node, data),)
    if node.type == "scoped_identifier":
        path = _child(node, "path")
        name = _child(node, "name")
        if path is None or name is None:
            return None
        prefix = _path_components(path, data)
        suffix = _path_components(name, data)
        return None if prefix is None or suffix is None else prefix + suffix
    return None


def _use_paths(node: Any, data: bytes, prefix: tuple[str, ...] = ()) -> tuple[tuple[tuple[str, ...], Any, str], ...] | None:
    """Flatten a literal use tree, rejecting glob and unmodelled leaves."""

    if node.type == "use_wildcard":
        return ()
    if node.type in {"identifier", "scoped_identifier"}:
        parts = _path_components(node, data)
        full_path = prefix + parts if parts is not None else None
        return None if full_path is None else ((full_path, node, full_path[-1]),)
    if node.type == "use_as_clause":
        path = _child(node, "path")
        alias = _child(node, "alias")
        # Grammar 0.24.2 exposes this exact shape.  Do not guess at any other
        # alias representation: an uncertain import binds no names at all.
        if path is None or alias is None or alias.type != "identifier":
            return None
        parts = _path_components(path, data)
        full_path = prefix + parts if parts is not None else None
        return None if full_path is None else ((full_path, node, _text(alias, data)),)
    if node.type == "scoped_use_list":
        path = _child(node, "path")
        group = next((child for child in node.named_children if child.type == "use_list"), None)
        if path is None or group is None:
            return None
        parts = _path_components(path, data)
        return None if parts is None else _use_paths(group, data, prefix + parts)
    if node.type == "use_list":
        result: list[tuple[tuple[str, ...], Any, str]] = []
        for child in node.named_children:
            leaf = _use_paths(child, data, prefix)
            if leaf is None:
                return None
            result.extend(leaf)
        return tuple(result)
    return None


def extract_graph(request: GraphExtractionRequest) -> Graph:
    """Extract only Rust relationships proven by declared files and bindings."""

    assert_query_identity("rust", request.policy, query_id=QUERY_ID, query_text=QUERY_TEXT)
    assert_producer_identity(request.policy, producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version=RESOLUTION_RULE_VERSION)
    runtime, language, parser, query_type = load_runtime(
        request.policy.grammar_factory, request.policy.grammar_abi_version,
        grammar_module="tree_sitter_rust", runtime_distribution="tree-sitter",
        runtime_version=request.policy.runtime_version, grammar_distribution="tree-sitter-rust",
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
        counters.add_query_matches(sum(len(values) for values in captures.values()))
        error = next((node for node in walk_nodes(root) if node.type == "ERROR"), None)
        if root.has_error or error is not None:
            error = root if error is None else error
            ref = source_ref(file_ref, data, error.start_byte, error.end_byte)
            blockers.append(blocker_from_ref(ref, error.type, RESOLUTION_RULE_VERSION, BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree_sitter_parse_error_v1"))
            continue
        parsed.append((file_ref, data, root))

    nodes: dict[NodeId, Node] = {}
    definitions: dict[str, dict[str, list[tuple[NodeId, SourceRef]]]] = {}
    module_ids: dict[str, NodeId] = {}
    # Root discovery is strictly over the complete declared request scope, not
    # parsed bytes or the donor filesystem.  A malformed root file therefore
    # still defines the syntactic boundary of the bounded analysis scope.
    root_directories = frozenset(
        PurePosixPath(file_ref.path).parent.parts
        for file_ref in request.source_files
        if PurePosixPath(file_ref.path).name in {"main.rs", "lib.rs"}
    )
    crate_contexts = {file_ref.path: _crate_context(file_ref.path, root_directories) for file_ref in request.source_files}
    semantic_modules: dict[tuple[tuple[str, ...], tuple[str, ...]], list[NodeId]] = {}

    def add_node(node_id: NodeId, ref: SourceRef) -> None:
        candidate = Node(node_id, ref, f"{PRODUCER_ID}@{PRODUCER_VERSION}")
        existing = nodes.get(node_id)
        if existing is not None and existing != candidate:
            raise BTSError(BTSRejectReason.REJECT_DUPLICATE_RESULT, "conflicting Rust graph node", detail_code="tree_sitter_duplicate_symbol_v1")
        if existing is None:
            counters.add_symbol()
            nodes[node_id] = candidate

    for file_ref, data, root in parsed:
        module = _module(file_ref.path)
        module_id = NodeId(NodeOrigin.DONOR, NodeKind.MODULE, module, module, f"{file_ref.path}:module")
        add_node(module_id, _whole(file_ref, data))
        module_ids[module] = module_id
        context = crate_contexts[file_ref.path]
        if context.root_directory is not None and context.semantic_module is not None:
            semantic_modules.setdefault((context.root_directory, context.semantic_module), []).append(module_id)
        entries = definitions.setdefault(module, {})
        for item in walk_nodes(root):
            if item.type not in {"function_item", "struct_item", "enum_item", "trait_item"}:
                continue
            name = _child(item, "name")
            if name is None:
                continue
            is_method = item.type == "function_item" and _contains(item, "impl_item")
            if item.type == "function_item":
                kind = (NodeKind.ASYNC_METHOD if _is_async(item) else NodeKind.METHOD) if is_method else (NodeKind.ASYNC_FUNCTION if _is_async(item) else NodeKind.FUNCTION)
            else:
                # NodeKind deliberately has neither TRAIT nor ENUM.
                kind = NodeKind.CLASS
            name_text = _text(name, data)
            qualified = f"{module}.{name_text}"
            ref = source_ref(file_ref, data, item.start_byte, item.end_byte)
            identity = NodeId(NodeOrigin.DONOR, kind, module, qualified, f"{file_ref.path}:{ref.start_line}:{ref.start_col}:{qualified}")
            add_node(identity, ref)
            entries.setdefault(name_text, []).append((identity, ref))

    edges: list[Edge] = []
    unresolved: list[UnresolvedEdge] = []

    def emit_unresolved(kind: EdgeKind, owner: NodeId, node: Any, data: bytes, file_ref: SourceRef, detail: str, *, reason: BTSRejectReason = BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT) -> None:
        counters.add_edge()
        ref = source_ref(file_ref, data, node.start_byte, node.end_byte)
        unresolved.append(UnresolvedEdge(kind, owner, _text(node, data), EdgeProvenance(ref, None, node.type, RESOLUTION_RULE_VERSION), reason, detail))
        blockers.append(blocker_from_ref(ref, node.type, RESOLUTION_RULE_VERSION, reason, detail))

    def emit_edge(kind: EdgeKind, owner: NodeId, target: NodeId, site: Any, data: bytes, file_ref: SourceRef, binding: SourceRef, rule: str, *, protocol_base: bool = False) -> None:
        counters.add_edge()
        edges.append(Edge(kind, owner, target, EdgeProvenance(source_ref(file_ref, data, site.start_byte, site.end_byte), binding, site.type, rule, protocol_base)))

    def resolve_module(parts: tuple[str, ...], context: _CrateContext) -> tuple[NodeId | None, str | None]:
        if not parts:
            return None, None
        first, *remaining_parts = parts
        remaining = tuple(remaining_parts)
        if first == "crate":
            if context.root_directory is None:
                return None, "tree_sitter_unresolved_import_v1"
            base: tuple[str, ...] = ()
        elif first == "self":
            if context.root_directory is None or context.semantic_module is None:
                return None, "tree_sitter_unresolved_import_v1"
            base = context.semantic_module
        elif first == "super":
            if context.root_directory is None or context.semantic_module is None:
                # Without a declared root, even one pop may cross an unprovable
                # crate boundary.  Reject instead of joining donor-relative paths.
                return None, "tree_sitter_unresolved_import_v1"
            levels = 1
            while remaining and remaining[0] == "super":
                levels += 1
                remaining = remaining[1:]
            if levels > len(context.semantic_module):
                return None, "tree_sitter_super_above_crate_root_v1"
            base = context.semantic_module[:-levels]
        else:
            return None, None
        assert context.root_directory is not None
        if not remaining:
            matches = semantic_modules.get((context.root_directory, base), [])
            return (matches[0] if len(matches) == 1 else None), None
        matches = semantic_modules.get((context.root_directory, base + remaining), [])
        return (matches[0] if len(matches) == 1 else None), None

    for file_ref, data, root in parsed:
        module = _module(file_ref.path)
        crate_context = crate_contexts[file_ref.path]
        own_module = module_ids[module]
        # A Rust ``use`` binds either a module or one named item; a module
        # binding must never be retroactively treated as a callable it contains.
        imports: dict[str, list[tuple[NodeId, SourceRef]]] = {}
        for statement in (node for node in root.named_children if node.type == "use_declaration"):
            argument = _child(statement, "argument")
            if argument is None:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_unresolved_import_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            if any(node.type == "use_wildcard" for node in walk_nodes(argument)):
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_glob_import_v1")
                continue
            paths = _use_paths(argument, data)
            has_alias = any(node.type == "use_as_clause" for node in walk_nodes(argument))
            if paths is None or not paths:
                detail = "tree_sitter_alias_import_v1" if has_alias else "tree_sitter_unresolved_import_v1"
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, detail, reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            grouped = argument.type in {"scoped_use_list", "use_list"}
            external = any(parts[0] not in {"crate", "self", "super"} for parts, _leaf, _binding_name in paths)
            if external and not grouped:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_external_use_v1")
                continue
            if external:
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, "tree_sitter_unresolved_import_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            resolved: list[tuple[str, Any, str, NodeId, NodeId | None]] = []
            unresolved_detail = "tree_sitter_unresolved_import_v1"
            for parts, leaf, binding_name in paths:
                # Module-prefix splitting is intentionally literal: a full path
                # to a file imports that module; otherwise only its direct
                # parent module can supply the final named item.
                full_module, full_detail = resolve_module(parts, crate_context)
                if full_module is not None:
                    resolved.append(("module", leaf, binding_name, full_module, None))
                    continue
                parent_module, parent_detail = resolve_module(parts[:-1], crate_context)
                if parent_module is None:
                    resolved = []
                    unresolved_detail = full_detail or parent_detail or "tree_sitter_unresolved_import_v1"
                    break
                item_name = parts[-1]
                matches = definitions.get(parent_module.module, {}).get(item_name, [])
                if len(matches) != 1 or matches[0][0].kind not in {NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION, NodeKind.CLASS}:
                    resolved = []
                    break
                resolved.append(("item", leaf, binding_name, parent_module, matches[0][0]))
            if len(resolved) != len(paths):
                emit_unresolved(EdgeKind.IMPORTS, own_module, statement, data, file_ref, unresolved_detail, reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                continue
            for shape, leaf, binding_name, target_module, target_item in resolved:
                binding = source_ref(file_ref, data, leaf.start_byte, leaf.end_byte)
                emit_edge(EdgeKind.IMPORTS, own_module, target_module, leaf, data, file_ref, binding, "rust_literal_use_v1")
                if shape == "item":
                    assert target_item is not None
                    imports.setdefault(binding_name, []).append((target_item, binding))

        def owner_for(
            node: Any,
            local_file_ref: SourceRef = file_ref,
            local_data: bytes = data,
            local_module: str = module,
            local_own_module: NodeId = own_module,
        ) -> NodeId:
            point = source_ref(local_file_ref, local_data, node.start_byte, node.end_byte)
            candidates = [
                identity for identity, value in nodes.items()
                if identity.module == local_module and identity.kind in {NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION, NodeKind.CLASS, NodeKind.METHOD, NodeKind.ASYNC_METHOD}
                and value.source is not None
                and (value.source.start_line, value.source.start_col) <= (point.start_line, point.start_col)
                and (point.end_line, point.end_col) <= (value.source.end_line, value.source.end_col)
            ]
            def size(identity: NodeId) -> tuple[int, int, str]:
                value = nodes[identity].source
                assert value is not None
                return (value.end_line - value.start_line, value.end_col - value.start_col, identity.location_key)
            return min(candidates, key=size) if candidates else local_own_module

        def resolve_symbol(
            name: str,
            expected: set[NodeKind],
            local_module: str = module,
            local_imports: dict[str, list[tuple[NodeId, SourceRef]]] = imports,
        ) -> tuple[NodeId, SourceRef] | None:
            local = [(identity, ref) for identity, ref in definitions[local_module].get(name, []) if identity.kind in expected]
            imported: list[tuple[NodeId, SourceRef]] = []
            for target, binding in local_imports.get(name, []):
                if target.kind in expected:
                    imported.append((target, binding))
            all_matches = local + imported
            return all_matches[0] if len(all_matches) == 1 else None

        for item in walk_nodes(root):
            owner = owner_for(item)
            if item.type == "impl_item":
                trait = _child(item, "trait")
                self_type = _child(item, "type")
                if trait is None:  # inherent impl: deliberately no edge.
                    continue
                if trait.type != "type_identifier" or self_type is None or self_type.type != "type_identifier":
                    emit_unresolved(EdgeKind.INHERITS, owner, item, data, file_ref, "tree_sitter_trait_selection_v1")
                    continue
                source = resolve_symbol(_text(self_type, data), {NodeKind.CLASS})
                trait_target = resolve_symbol(_text(trait, data), {NodeKind.CLASS})
                if source is None or trait_target is None:
                    emit_unresolved(EdgeKind.INHERITS, owner, item, data, file_ref, "tree_sitter_unresolved_impl_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                else:
                    source_id, _source_binding = source
                    target_id, target_binding = trait_target
                    emit_edge(EdgeKind.INHERITS, source_id, target_id, trait, data, file_ref, target_binding, "rust_impl_trait_v1", protocol_base=True)
            elif item.type == "trait_item":
                bounds = _child(item, "bounds")
                if bounds is not None:
                    for base in bounds.named_children:
                        if base.type != "type_identifier":
                            emit_unresolved(EdgeKind.INHERITS, owner, base, data, file_ref, "tree_sitter_trait_selection_v1")
                            continue
                        base_target = resolve_symbol(_text(base, data), {NodeKind.CLASS})
                        if base_target is None:
                            emit_unresolved(EdgeKind.INHERITS, owner, base, data, file_ref, "tree_sitter_unresolved_impl_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                        else:
                            target_id, binding = base_target
                            emit_edge(EdgeKind.INHERITS, owner, target_id, base, data, file_ref, binding, "rust_supertrait_v1", protocol_base=True)
            elif item.type == "call_expression":
                function = _child(item, "function")
                if function is None:
                    continue
                if function.type == "identifier":
                    call_target = resolve_symbol(_text(function, data), {NodeKind.FUNCTION, NodeKind.ASYNC_FUNCTION})
                    if call_target is None:
                        emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_ambiguous_callee_binding_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                    else:
                        target_id, binding = call_target
                        emit_edge(EdgeKind.CALLS, owner, target_id, function, data, file_ref, binding, "rust_bare_call_v1")
                elif function.type in {"scoped_identifier", "scoped_type_identifier"}:
                    emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_unresolved_path_call_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                elif function.type == "closure_expression":
                    emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_ambiguous_callee_binding_v1", reason=BTSRejectReason.REJECT_UNRESOLVED_EDGE)
                else:
                    emit_unresolved(EdgeKind.CALLS, owner, function, data, file_ref, "tree_sitter_receiver_dispatch_v1")
            elif item.type == "macro_invocation":
                emit_unresolved(EdgeKind.CALLS, owner, item, data, file_ref, "tree_sitter_macro_call_v1")

    return Graph(GRAPH_SCHEMA_VERSION, tuple(nodes.values()), tuple(edges), tuple(unresolved), GraphCoverage(request.source_files, tuple(item[0] for item in parsed), tuple(blockers)))


__all__ = ["GRAMMAR_ID", "PRODUCER_ID", "PRODUCER_VERSION", "QUERY_ID", "QUERY_TEXT", "RESOLUTION_RULE_VERSION", "extract_graph"]
