"""Import-safe shared mechanics for the optional tree-sitter graph producers.

Native modules are deliberately imported only by :func:`load_runtime`.  Tree
node budgets count *all* nodes (named and anonymous) reached through
``Node.children``.  A budget failure raises rather than returning a partial
graph: a partial graph cannot be complete authorization evidence.

Each producer's pinned query is a canonical identity, budget, and canonical-input
artifact.  Extraction itself is driven by validated AST-node-type traversal, not
query captures; behavior tests pin the bounded correspondence between query
coverage and traversal types.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import ExtractionBlocker, SourceRef
from leitir.graph.policy import GraphExtractionPolicy

# RATIFIED 2026-08-14 from docs/evidence/oq3-tree-sitter-limits-2026-08-14.md.
# No per-file depth cap is imposed: nesting was linear through depth 100,000,
# with zero crashes and <=216 ms parse time; byte and all-node caps already
# bound the exposure more directly.
DEFAULT_MAX_FILES = 2_000
DEFAULT_MAX_FILE_BYTES = 2_097_152
DEFAULT_MAX_TREE_NODES_PER_FILE = 250_000
DEFAULT_MAX_QUERY_MATCHES = 1_100_000
DEFAULT_MAX_SYMBOLS = 200_000
DEFAULT_MAX_EDGES = 900_000
DEFAULT_MAX_WORK_UNITS = 10_000


def query_sha256(text: str) -> str:
    """Return the exact UTF-8 query identity digest."""

    return hashlib.sha256(text.encode("utf-8", errors="strict")).hexdigest()


def assert_query_identity(language: str, policy: GraphExtractionPolicy, *, query_id: str, query_text: str) -> None:
    """Reject before native loading unless the canonical producer query is pinned.

    The query's captures are deliberately not extraction control flow.  Native
    query execution remains canonical input and budget evidence, while producers
    walk validated AST node types for context-sensitive ownership and binding.
    """

    if policy.language != language or policy.query_id != query_id or policy.query_sha256 != query_sha256(query_text):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "tree-sitter query identity does not match the extraction policy",
            detail_code="tree_sitter_query_identity_mismatch_v1",
        )


def assert_producer_identity(
    policy: GraphExtractionPolicy,
    *,
    producer_id: str,
    producer_version: str,
    resolution_rule_version: str,
) -> None:
    """Require the policy to name the built-in producer being invoked.

    This deliberately precedes all native imports.  Explicit registry replacements
    are a test/plugin authority boundary and are not treated as built-ins.
    """

    if (
        policy.producer_id != producer_id
        or policy.producer_version != producer_version
        or policy.resolution_rule_version != resolution_rule_version
    ):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "tree-sitter policy does not identify this built-in producer",
            detail_code="tree_sitter_policy_producer_mismatch_v1",
        )


def _installed_distribution_version(distribution: str, detail_code: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except Exception as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            f"installed {distribution} distribution version is unavailable",
            detail_code=detail_code,
            cause=exc,
        ) from exc


def load_runtime(
    grammar_factory: str,
    abi_version: int,
    *,
    grammar_module: str,
    runtime_distribution: str,
    runtime_version: str,
    grammar_distribution: str,
    grammar_version: str,
) -> tuple[Any, Any, Any, Any]:
    """Load one exact native tuple after the registry's optional-extra check.

    Distribution metadata, rather than module ``__version__`` attributes, is
    the native wheel identity authority.  py-tree-sitter 0.25.2 exposes
    ``Language.abi_version`` but no certified module version attribute.
    """

    try:
        actual_runtime_version = _installed_distribution_version(runtime_distribution, "tree_sitter_runtime_version_mismatch_v1")
        if actual_runtime_version != runtime_version:
            raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "installed tree-sitter runtime version differs from policy", detail_code="tree_sitter_runtime_version_mismatch_v1")
        actual_grammar_version = _installed_distribution_version(grammar_distribution, "tree_sitter_grammar_version_mismatch_v1")
        if actual_grammar_version != grammar_version:
            raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "installed tree-sitter grammar version differs from policy", detail_code="tree_sitter_grammar_version_mismatch_v1")
        runtime = importlib.import_module("tree_sitter")
        grammar = importlib.import_module(grammar_module)
        factory = getattr(grammar, grammar_factory)
        language = runtime.Language(factory())
        actual_abi = getattr(language, "abi_version", None)
        if actual_abi != abi_version:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "loaded tree-sitter grammar ABI differs from policy",
                detail_code="tree_sitter_grammar_abi_mismatch_v1",
            )
        return runtime, language, runtime.Parser(language), runtime.Query
    except BTSError:
        raise
    except Exception as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_EXTRA,
            "tree-sitter optional extra is broken for graph production",
            detail_code="tree_sitter_extra_broken_v1",
            cause=exc,
        ) from exc


def read_verified_source(path: Path, ref: SourceRef, *, maximum: int) -> bytes:
    """Read one declared regular file and bind its bytes to its git blob id."""

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "declared graph source is not a regular file", detail_code="tree_sitter_source_read_v1")
            if metadata.st_size > maximum:
                raise BTSError(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "graph source exceeds max_file_bytes", detail_code="tree_sitter_max_file_bytes_v1")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                data = handle.read(maximum + 1)
        finally:
            if fd >= 0:
                os.close(fd)
    except BTSError:
        raise
    except OSError as exc:
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot safely read declared graph source", detail_code="tree_sitter_source_read_v1", cause=exc) from exc
    if len(data) > maximum:
        raise BTSError(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "graph source exceeds max_file_bytes", detail_code="tree_sitter_max_file_bytes_v1")
    blob_sha = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if blob_sha != ref.blob_sha:
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "declared graph source bytes changed after request construction", detail_code="tree_sitter_source_bytes_changed_v1")
    return data


def byte_point(source: bytes, offset: int) -> tuple[int, int]:
    """Convert a byte offset to ADR-0008's (one-based line, byte column)."""

    if offset < 0 or offset > len(source):
        raise ValueError("offset is outside source")
    before = source[:offset]
    return before.count(b"\n") + 1, offset - (before.rfind(b"\n") + 1)


def byte_offset(source: bytes, line: int, col: int) -> int:
    """Test helper inverse of :func:`byte_point` for valid byte coordinates."""

    if line < 1 or col < 0:
        raise ValueError("invalid source coordinate")
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    if line > len(starts):
        raise ValueError("line is outside source")
    offset = starts[line - 1] + col
    if offset > len(source) or (line < len(starts) and offset >= starts[line]):
        raise ValueError("column is outside source line")
    return offset


def source_ref(base: SourceRef, source: bytes, start_byte: int, end_byte: int) -> SourceRef:
    """Build a span while retaining tree-sitter's UTF-8-byte coordinate rule."""

    start_line, start_col = byte_point(source, start_byte)
    end_line, end_col = byte_point(source, end_byte)
    return SourceRef(base.slug, base.commit_sha, base.path, base.blob_sha, start_line, start_col, end_line, end_col)


def blocker_from_ref(ref: SourceRef, ast_kind: str, rule: str, reason: BTSRejectReason, detail: str) -> ExtractionBlocker:
    return ExtractionBlocker(ref.path, ref.start_line, ref.start_col, ref.end_line, ref.end_col, ast_kind, rule, reason, detail)


def walk_nodes(root: Any) -> Iterator[Any]:
    """Yield a deterministic preorder traversal including unnamed nodes."""

    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.children))


# Audited 2026-08-14 with the certified wheels by parsing function, class,
# generator/async-generator, abstract-class, enum, module/namespace, catch,
# and for-of-let probes in /tmp (not repository inputs), then printing every
# emitted node.type and its name/parameter fields. The runtime value-binding
# declarations emitted by those grammars are represented below; interface and
# type_alias declarations are intentionally excluded because they bind only a
# TypeScript type and cannot replace a runtime imported value at these sites.
_JS_TS_FUNCTION_SCOPES = frozenset({
    "arrow_function", "function_declaration", "function_expression",
    "generator_function", "generator_function_declaration", "method_definition",
})
_JS_TS_CLASS_DECLARATIONS = frozenset({"abstract_class_declaration", "class_declaration"})
_JS_TS_VALUE_DECLARATIONS = _JS_TS_CLASS_DECLARATIONS | frozenset({
    "enum_declaration", "internal_module", "module", "variable_declarator",
    "import_specifier",
})
_JS_TS_LOOP_SCOPES = frozenset({"for_in_statement", "for_statement"})
_JS_TS_SCOPE_TYPES = _JS_TS_FUNCTION_SCOPES | frozenset({
    "catch_clause", "class_body", "class_static_block", "statement_block",
}) | _JS_TS_LOOP_SCOPES | frozenset({"internal_module", "module"})


@dataclass(slots=True)
class _JsTsScope:
    """One lexical scope in a file-local JavaScript/TypeScript binding index."""

    parent: _JsTsScope | None
    kind: str
    bindings: set[str]


@dataclass(slots=True)
class JsTsBindingIndex:
    """One-pass lexical binding index with O(depth) reference lookup.

    The node-to-scope table deliberately maps a node to its innermost containing
    scope rather than retaining ancestor tuples.  This makes index construction
    linear in AST size while preserving lexical lookup through ``parent`` links.
    """

    root: _JsTsScope
    node_scopes: dict[int, _JsTsScope]

    def is_shadowed(self, reference: Any, name: str) -> bool:
        """Whether ``name`` resolves to a non-module lexical binding at a site."""

        scope = self.node_scopes.get(reference.id)
        while scope is not None:
            if name in scope.bindings:
                return scope is not self.root
            scope = scope.parent
        return False


def _binding_names(node: Any | None, data: bytes) -> set[str]:
    """Extract grammar-proved binding identifiers from one declaration pattern.

    Declaration/parameter patterns are disjoint leaves of the primary index
    traversal.  This bounded pattern walk preserves fail-closed destructuring
    coverage without ever walking a file once per reference site.
    """

    if node is None:
        return set()
    return {
        data[item.start_byte:item.end_byte].decode("utf-8", errors="strict")
        for item in walk_nodes(node)
        if item.type in {"identifier", "type_identifier"}
    }


def _nearest_var_scope(scope: _JsTsScope) -> _JsTsScope:
    """Return the closest grammar-audited owner for a ``var`` binding.

    Audited against tree-sitter-javascript 0.25.0 and
    tree-sitter-typescript 0.23.2.  The var-owning boundary node types are the
    function/method forms ``arrow_function``, ``function_declaration``,
    ``function_expression``, ``generator_function``,
    ``generator_function_declaration``, and ``method_definition``; the root or
    declared ``module`` scope; TypeScript ``internal_module`` (emitted for a
    ``namespace`` declaration); and ``class_static_block``.  Function forms
    are normalized to ``function`` when scopes are created, leaving these four
    scope kinds as the complete ownership rule below.
    """

    current: _JsTsScope | None = scope
    while current is not None and current.kind not in {"module", "function", "internal_module", "class_static_block"}:
        current = current.parent
    assert current is not None
    return current


def build_js_ts_binding_index(root: Any, data: bytes) -> JsTsBindingIndex:
    """Build the complete lexical binding index in one deterministic AST pass.

    A scope is entered for every function/method/arrow, class body, catch clause,
    static class block, statement block, namespace/module, and loop declaration.
    Declarations bind to the scope dictated by their grammar form; in particular
    ``var`` binds to a function or module while ``let``/``const`` bind to the
    current lexical block or loop.  The dedicated var-scope rule retains
    TypeScript namespace/module and class-static-block ownership rather than
    incorrectly hoisting their bindings to the file root.
    """

    module = _JsTsScope(None, "module", set())
    node_scopes: dict[int, _JsTsScope] = {}
    pending: list[tuple[Any, _JsTsScope]] = [(root, module)]
    while pending:
        node, enclosing = pending.pop()
        scope = enclosing
        if node.type in _JS_TS_SCOPE_TYPES:
            kind = "function" if node.type in _JS_TS_FUNCTION_SCOPES else node.type
            scope = _JsTsScope(enclosing, kind, set())
        node_scopes[node.id] = scope

        # Function/class declaration names bind outside their own body.  A named
        # expression's own name is visible only inside that expression's body.
        if node.type in _JS_TS_FUNCTION_SCOPES:
            name = node.child_by_field_name("name")
            if node.type in {"function_expression", "generator_function"}:
                scope.bindings.update(_binding_names(name, data))
            else:
                enclosing.bindings.update(_binding_names(name, data))
            parameters = node.child_by_field_name("parameters")
            if parameters is None:
                parameters = node.child_by_field_name("parameter")
            scope.bindings.update(_binding_names(parameters, data))
        elif node.type in _JS_TS_CLASS_DECLARATIONS:
            enclosing.bindings.update(_binding_names(node.child_by_field_name("name"), data))
        elif node.type == "class_body" and node.parent is not None and node.parent.type == "class_expression":
            scope.bindings.update(_binding_names(node.parent.child_by_field_name("name"), data))
        elif node.type in {"enum_declaration", "internal_module", "module"}:
            # Enum members are deliberately not bindings in this lexical scope:
            # their grammar nodes are property identifiers, and only the enum or
            # namespace/module declaration name can shadow a bare import.
            enclosing.bindings.update(_binding_names(node.child_by_field_name("name"), data))
        elif node.type == "catch_clause":
            scope.bindings.update(_binding_names(node.child_by_field_name("parameter"), data))
        elif node.type in _JS_TS_LOOP_SCOPES:
            target = _nearest_var_scope(enclosing) if any(child.type == "var" for child in node.children) else scope
            target.bindings.update(_binding_names(node.child_by_field_name("left"), data))
        elif node.type == "variable_declarator":
            target = enclosing
            if node.parent is not None and node.parent.type == "variable_declaration":
                target = _nearest_var_scope(enclosing)
            target.bindings.update(_binding_names(node.child_by_field_name("name"), data))
        elif node.type == "import_specifier":
            # Imported aliases are module bindings.  The direct children are
            # grammar-proved names; treating both import and alias as bindings is
            # conservative for malformed/unsupported alias shapes.
            module.bindings.update(_binding_names(node, data))

        pending.extend((child, scope) for child in reversed(node.children))
    return JsTsBindingIndex(module, node_scopes)


@dataclass(slots=True)
class BudgetCounters:
    """Request-wide counters with distinct stable failure identities."""

    policy: GraphExtractionPolicy
    query_matches: int = 0
    symbols: int = 0
    edges: int = 0
    work_units: int = 0

    def _check(self, value: int, maximum: int, detail: str) -> None:
        if value > maximum:
            raise BTSError(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "tree-sitter extraction budget exceeded", detail_code=detail)

    def add_file(self, root: Any) -> None:
        # One work unit is exactly one declared file's parse + walk + query.
        self.work_units += 1
        self._check(self.work_units, self.policy.max_work_units, "tree_sitter_max_work_units_v1")
        # Streaming early abort avoids retaining ~240 B/node (about 1 GiB for a
        # bytes-cap-compliant adversarial tree) before rejection.
        for count, _node in enumerate(walk_nodes(root), start=1):
            self._check(count, self.policy.max_tree_nodes_per_file, "tree_sitter_max_tree_nodes_v1")

    def add_query_matches(self, count: int) -> None:
        self.query_matches += count
        self._check(self.query_matches, self.policy.max_query_matches, "tree_sitter_max_query_matches_v1")

    def add_symbol(self) -> None:
        self.symbols += 1
        self._check(self.symbols, self.policy.max_symbols, "tree_sitter_max_symbols_v1")

    def add_edge(self) -> None:
        self.edges += 1
        self._check(self.edges, self.policy.max_edges, "tree_sitter_max_edges_v1")


__all__ = [
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_QUERY_MATCHES",
    "DEFAULT_MAX_SYMBOLS",
    "DEFAULT_MAX_TREE_NODES_PER_FILE",
    "DEFAULT_MAX_WORK_UNITS",
    "BudgetCounters",
    "assert_producer_identity",
    "assert_query_identity",
    "blocker_from_ref",
    "build_js_ts_binding_index",
    "byte_offset",
    "byte_point",
    "load_runtime",
    "query_sha256",
    "read_verified_source",
    "source_ref",
    "walk_nodes",
]
