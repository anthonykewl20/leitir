"""Deterministic Python 3.11 static edges for the ADR-0008 v1 subset.

This module intentionally resolves only bindings proved by the complete module's
AST and symbol tables.  It does not import analyzed modules or consult the host
environment to guess whether a reference is donor, stdlib, or installed.
"""

from __future__ import annotations

import ast
import symtable
from dataclasses import dataclass
from pathlib import PurePosixPath

from leitir.bts_errors import BTSError, BTSEvidence, BTSRejectReason
from leitir.graph.model import (
    GRAPH_SCHEMA_VERSION,
    Edge,
    EdgeKind,
    EdgeProvenance,
    ExtractionBlocker,
    Graph,
    GraphCoverage,
    Node,
    NodeId,
    NodeKind,
    NodeOrigin,
    SourceRef,
    UnresolvedEdge,
)

GRAMMAR_ID = "python-3.11-v1"

# This is a grammar-policy list, not host discovery.  Names not in this finite
# Python 3.11 exception set remain unresolved.
_BUILTIN_EXCEPTIONS = frozenset(
    {
        "ArithmeticError", "AssertionError", "AttributeError", "BaseException",
        "BaseExceptionGroup", "BlockingIOError", "BrokenPipeError", "BufferError",
        "BytesWarning", "ChildProcessError", "ConnectionAbortedError",
        "ConnectionError", "ConnectionRefusedError", "ConnectionResetError",
        "DeprecationWarning", "EOFError", "EncodingWarning", "EnvironmentError",
        "Exception", "ExceptionGroup", "FileExistsError", "FileNotFoundError",
        "FloatingPointError", "FutureWarning", "GeneratorExit", "IOError",
        "ImportError", "ImportWarning", "IndentationError", "IndexError",
        "InterruptedError", "IsADirectoryError", "KeyError", "KeyboardInterrupt",
        "LookupError", "MemoryError", "ModuleNotFoundError", "NameError",
        "NotADirectoryError", "NotImplementedError", "OSError", "OverflowError",
        "PendingDeprecationWarning", "PermissionError", "ProcessLookupError",
        "RecursionError", "ReferenceError", "ResourceWarning", "RuntimeError",
        "RuntimeWarning", "StopAsyncIteration", "StopIteration", "SyntaxError",
        "SyntaxWarning", "SystemError", "SystemExit", "TabError", "TimeoutError",
        "TypeError", "UnboundLocalError", "UnicodeDecodeError", "UnicodeEncodeError",
        "UnicodeError", "UnicodeTranslateError", "UnicodeWarning", "UserWarning",
        "ValueError", "Warning", "ZeroDivisionError",
    }
)


@dataclass(frozen=True, slots=True)
class StaticExtraction:
    """Resolved records, blockers, and graph endpoints for one source file."""

    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    unresolved: tuple[UnresolvedEdge, ...]
    coverage: GraphCoverage
    grammar_id: str = GRAMMAR_ID

    def __post_init__(self) -> None:
        if self.grammar_id != GRAMMAR_ID:
            raise ValueError(f"grammar_id must be {GRAMMAR_ID!r}")
        graph = Graph(GRAPH_SCHEMA_VERSION, self.nodes, self.edges, self.unresolved, self.coverage)
        object.__setattr__(self, "nodes", graph.nodes)
        object.__setattr__(self, "edges", graph.edges)
        object.__setattr__(self, "unresolved", graph.unresolved)

    def to_graph(self) -> Graph:
        return Graph(GRAPH_SCHEMA_VERSION, self.nodes, self.edges, self.unresolved, self.coverage)


@dataclass(frozen=True, slots=True)
class _Binding:
    target: NodeId | None
    reference: SourceRef
    path: str | None
    rule: str


@dataclass(slots=True, eq=False)
class _Scope:
    table: symtable.SymbolTable
    parent: _Scope | None
    owner: NodeId
    bindings: dict[str, list[_Binding]]
    class_body: bool = False


def _module_name(path: str, package_root: str) -> str:
    source_path = PurePosixPath(path)
    root_value = PurePosixPath(package_root)
    if package_root and (
        root_value.is_absolute()
        or "\\" in package_root
        or ".." in root_value.parts
        or root_value.as_posix() != package_root
        or package_root == "."
    ):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "package_root must be a normalized relative POSIX directory",
            detail_code="invalid_package_root",
        )
    root = PurePosixPath(package_root) if package_root else PurePosixPath(".")
    try:
        relative = source_path.relative_to(root)
    except ValueError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            f"source path {path!r} is outside package root {package_root!r}",
            detail_code="path_outside_package_root",
            cause=exc,
        ) from exc
    if relative.suffix != ".py":
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
            "static Python extraction requires an in-scope .py file",
            detail_code="non_python_source",
        )
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if not parts:
        # A root __init__.py has no inferable package prefix.  Refusing is safer
        # than inventing one from a filesystem parent outside the pinned root.
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
            "package-root __init__.py requires an explicit enclosing package root",
            detail_code="empty_module_name",
        )
    return ".".join(parts)


def _whole_source_ref(source: bytes, *, slug: str, commit_sha: str, path: str, blob_sha: str) -> SourceRef:
    lines = source.splitlines(keepends=True)
    if not lines:
        end_line, end_col = 1, 0
    else:
        end_line = len(lines)
        last = lines[-1]
        end_col = len(last.rstrip(b"\r\n"))
        if last.endswith((b"\n", b"\r")):
            end_line += 1
            end_col = 0
    return SourceRef(slug, commit_sha, path, blob_sha, 1, 0, end_line, end_col)


class _Extractor(ast.NodeVisitor):
    def __init__(
        self,
        tree: ast.Module,
        symbols: symtable.SymbolTable,
        text: str,
        source: bytes,
        *,
        slug: str,
        commit_sha: str,
        path: str,
        blob_sha: str,
        module: str,
    ) -> None:
        self.tree = tree
        self.text = text
        self.source_bytes = source
        self.slug = slug
        self.commit_sha = commit_sha
        self.path = path
        self.blob_sha = blob_sha
        self.module = module
        self.edges: list[Edge] = []
        self.unresolved: list[UnresolvedEdge] = []
        self.blockers: list[ExtractionBlocker] = []
        self.nodes: dict[NodeId, Node] = {}
        self._used_tables: set[int] = set()
        self._conditional_depth = 0
        self._handlers: list[ast.expr | None] = []
        self._type_only_depth = 0
        self._definition_ids: dict[ast.AST, NodeId] = {}

        module_id = NodeId(NodeOrigin.DONOR, NodeKind.MODULE, module, module, f"{path}:module")
        self.module_id = module_id
        self._add_node(module_id, _whole_source_ref(source, slug=slug, commit_sha=commit_sha, path=path, blob_sha=blob_sha), "ast")
        self.scope = _Scope(symbols, None, module_id, {})
        self.module_scope = self.scope
        self._scope_for_node: dict[ast.AST, _Scope] = {tree: self.scope}
        self._index_block(tree.body, self.scope, module, conditional=False)

    def _ref(self, node: ast.AST) -> SourceRef:
        return SourceRef(
            self.slug,
            self.commit_sha,
            self.path,
            self.blob_sha,
            int(getattr(node, "lineno", 1)),
            int(getattr(node, "col_offset", 0)),
            int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
            int(getattr(node, "end_col_offset", getattr(node, "col_offset", 0))),
        )

    def _add_node(self, node_id: NodeId, source: SourceRef | None, method: str) -> None:
        existing = self.nodes.get(node_id)
        candidate = Node(node_id, source, method)
        if existing is not None and existing != candidate:
            raise BTSError(
                BTSRejectReason.REJECT_DUPLICATE_RESULT,
                f"conflicting graph node {node_id.qualified_name}",
                detail_code="conflicting_static_node",
            )
        self.nodes[node_id] = candidate

    def _child_table(self, name: str, lineno: int) -> symtable.SymbolTable:
        matches = [
            child
            for child in self.scope.table.get_children()
            if child.get_name() == name and child.get_lineno() == lineno and child.get_id() not in self._used_tables
        ]
        if len(matches) != 1:
            raise BTSError(
                BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                f"AST/symtable scope mismatch for {name!r}",
                detail_code="symtable_scope_mismatch",
            )
        child = matches[0]
        self._used_tables.add(child.get_id())
        return child

    def _bind(self, scope: _Scope, name: str, binding: _Binding) -> None:
        scope.bindings.setdefault(name, []).append(binding)

    def _unknown_targets(self, target: ast.AST) -> list[tuple[str, SourceRef]]:
        if isinstance(target, ast.Name):
            return [(target.id, self._ref(target))]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [item for child in target.elts for item in self._unknown_targets(child)]
        return []

    def _index_block(self, statements: list[ast.stmt], scope: _Scope, prefix: str, *, conditional: bool) -> None:
        previous = self.scope
        self.scope = scope
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = NodeKind.ASYNC_FUNCTION if isinstance(statement, ast.AsyncFunctionDef) else NodeKind.FUNCTION
                if scope.class_body:
                    kind = NodeKind.ASYNC_METHOD if isinstance(statement, ast.AsyncFunctionDef) else NodeKind.METHOD
                qualified = f"{prefix}.{statement.name}"
                node_id = NodeId(NodeOrigin.DONOR, kind, self.module, qualified, f"{self.path}:{statement.lineno}:{qualified}")
                ref = self._ref(statement)
                self._add_node(node_id, ref, "ast")
                self._definition_ids[statement] = node_id
                self._bind(scope, statement.name, _Binding(node_id, ref, qualified, "lexical_definition_v1"))
                child = _Scope(self._child_table(statement.name, statement.lineno), scope, node_id, {})
                self._scope_for_node[statement] = child
                self._index_arguments(statement.args, child)
                self._index_block(statement.body, child, qualified, conditional=False)
            elif isinstance(statement, ast.ClassDef):
                qualified = f"{prefix}.{statement.name}"
                node_id = NodeId(NodeOrigin.DONOR, NodeKind.CLASS, self.module, qualified, f"{self.path}:{statement.lineno}:{qualified}")
                ref = self._ref(statement)
                self._add_node(node_id, ref, "ast")
                self._definition_ids[statement] = node_id
                self._bind(scope, statement.name, _Binding(node_id, ref, qualified, "lexical_definition_v1"))
                child = _Scope(self._child_table(statement.name, statement.lineno), scope, scope.owner, {}, class_body=True)
                self._scope_for_node[statement] = child
                self._index_block(statement.body, child, qualified, conditional=False)
            elif isinstance(statement, (ast.Import, ast.ImportFrom)):
                self._index_import(statement, scope, conditional=conditional)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets: list[ast.AST]
                if isinstance(statement, ast.Assign):
                    targets = list(statement.targets)
                else:
                    targets = [statement.target]
                for target in targets:
                    for name, ref in self._unknown_targets(target):
                        self._bind(scope, name, _Binding(None, ref, None, "assigned_binding_v1"))
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                for name, ref in self._unknown_targets(statement.target):
                    self._bind(scope, name, _Binding(None, ref, None, "assigned_binding_v1"))
                self._index_block(statement.body, scope, prefix, conditional=True)
                self._index_block(statement.orelse, scope, prefix, conditional=True)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if item.optional_vars is not None:
                        for name, ref in self._unknown_targets(item.optional_vars):
                            self._bind(scope, name, _Binding(None, ref, None, "assigned_binding_v1"))
                self._index_block(statement.body, scope, prefix, conditional=conditional)
            elif isinstance(statement, (ast.Try, ast.TryStar)):
                self._index_block(statement.body, scope, prefix, conditional=True)
                for handler in statement.handlers:
                    if handler.name is not None:
                        self._bind(scope, handler.name, _Binding(None, self._ref(handler), None, "handler_binding_v1"))
                    self._index_block(handler.body, scope, prefix, conditional=True)
                self._index_block(statement.orelse, scope, prefix, conditional=True)
                self._index_block(statement.finalbody, scope, prefix, conditional=True)
            elif isinstance(statement, ast.If):
                self._index_block(statement.body, scope, prefix, conditional=True)
                self._index_block(statement.orelse, scope, prefix, conditional=True)
            elif isinstance(statement, (ast.While, ast.Match)):
                nested = statement.body if isinstance(statement, ast.While) else [item for case in statement.cases for item in case.body]
                self._index_block(nested, scope, prefix, conditional=True)
                if isinstance(statement, ast.While):
                    self._index_block(statement.orelse, scope, prefix, conditional=True)
        self.scope = previous

    def _index_arguments(self, arguments: ast.arguments, scope: _Scope) -> None:
        values = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        if arguments.vararg is not None:
            values.append(arguments.vararg)
        if arguments.kwarg is not None:
            values.append(arguments.kwarg)
        for argument in values:
            self._bind(scope, argument.arg, _Binding(None, self._ref(argument), None, "parameter_binding_v1"))

    def _absolute_from(self, node: ast.ImportFrom) -> str | None:
        if node.level == 0:
            return node.module
        package = self.module.split(".")
        if not self.path.endswith("/__init__.py"):
            package.pop()
        if node.level > len(package):
            return None
        base = package[: len(package) - node.level + 1]
        if node.module:
            base.extend(node.module.split("."))
        return ".".join(base) or None

    def _index_import(self, node: ast.Import | ast.ImportFrom, scope: _Scope, *, conditional: bool) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", maxsplit=1)[0]
                path = alias.name if alias.asname else bound
                self._bind(scope, bound, _Binding(None, self._ref(alias), None if conditional else path, "import_binding_v1"))
            return
        base = self._absolute_from(node)
        for alias in node.names:
            if alias.name == "*" or base is None:
                continue
            bound = alias.asname or alias.name
            binding_path = None if conditional else f"{base}.{alias.name}"
            self._bind(scope, bound, _Binding(None, self._ref(alias), binding_path, "from_import_binding_v1"))

    def _external(self, path: str, *, kind: NodeKind) -> NodeId:
        module, _, name = path.rpartition(".")
        if kind is NodeKind.MODULE:
            module, name = path, path
        elif not module:
            module = "builtins"
        node_id = NodeId(NodeOrigin.DECLARED_EXTERNAL, kind, module, path if "." in path else name, f"external:{path}")
        self._add_node(node_id, None, "ast")
        return node_id

    def _builtin(self, name: str, *, kind: NodeKind = NodeKind.CLASS) -> NodeId:
        node_id = NodeId(NodeOrigin.STDLIB, kind, "builtins", f"builtins.{name}", f"stdlib:builtins:{name}")
        self._add_node(node_id, None, "ast")
        return node_id

    def _lookup_scope(self, name: str) -> _Scope | None:
        try:
            symbol = self.scope.table.lookup(name)
        except KeyError:
            return None
        if symbol.is_parameter() or symbol.is_imported() or symbol.is_local() or symbol.is_assigned():
            return self.scope
        if symbol.is_global():
            return self.module_scope
        if symbol.is_free() or symbol.is_nonlocal():
            parent = self.scope.parent
            while parent is not None:
                if name in parent.bindings and not parent.class_body:
                    return parent
                parent = parent.parent
        return None

    def _chain(self, expression: ast.expr) -> tuple[str, tuple[str, ...]] | None:
        attrs: list[str] = []
        current = expression
        while isinstance(current, ast.Attribute):
            attrs.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        attrs.reverse()
        return current.id, tuple(attrs)

    def _resolve(self, expression: ast.expr, *, kind: NodeKind) -> tuple[NodeId, SourceRef | None, str] | None:
        chain = self._chain(expression)
        if chain is None:
            return None
        name, attrs = chain
        binding_scope = self._lookup_scope(name)
        if binding_scope is None:
            if not attrs and name in _BUILTIN_EXCEPTIONS:
                return self._builtin(name), None, "builtin_exception_v1"
            if not attrs and name == "object" and kind is NodeKind.CLASS:
                return self._builtin(name), None, "builtin_class_v1"
            return None
        bindings = binding_scope.bindings.get(name, [])
        if not bindings and not attrs and name in _BUILTIN_EXCEPTIONS:
            return self._builtin(name), None, "builtin_exception_v1"
        if not bindings and not attrs and name == "object" and kind is NodeKind.CLASS:
            return self._builtin(name), None, "builtin_class_v1"
        if len(bindings) != 1:
            return None
        binding = bindings[0]
        if binding.target is not None:
            if attrs:
                return None
            return binding.target, binding.reference, binding.rule
        if binding.path is None:
            return None
        path = ".".join((binding.path, *attrs))
        return self._external(path, kind=kind), binding.reference, binding.rule

    def _expression(self, node: ast.AST | None) -> str:
        if node is None:
            return "<bare raise>"
        segment = ast.get_source_segment(self.text, node)
        return segment if segment is not None else ast.dump(node, annotate_fields=True, include_attributes=False)

    def _record_unresolved(
        self,
        kind: EdgeKind,
        owner: NodeId,
        node: ast.AST,
        expression: str,
        reason: BTSRejectReason,
        detail: str,
        rule: str,
    ) -> None:
        provenance = EdgeProvenance(self._ref(node), None, type(node).__name__, rule)
        self.unresolved.append(UnresolvedEdge(kind, owner, expression, provenance, reason, detail))
        ref = provenance.site
        self.blockers.append(
            ExtractionBlocker(
                ref.path, ref.start_line, ref.start_col, ref.end_line, ref.end_col,
                provenance.ast_kind, rule, reason, detail,
            )
        )

    def _edge(
        self,
        kind: EdgeKind,
        source: NodeId,
        target: NodeId,
        node: ast.AST,
        binding: SourceRef | None,
        rule: str,
        *,
        protocol: bool = False,
    ) -> None:
        self.edges.append(Edge(kind, source, target, EdgeProvenance(self._ref(node), binding, type(node).__name__, rule, protocol)))

    def _with_scope(self, node: ast.AST, body: list[ast.stmt], *, reset_handlers: bool = False) -> None:
        previous = self.scope
        previous_handlers = self._handlers
        self.scope = self._scope_for_node[node]
        if reset_handlers:
            self._handlers = []
        for statement in body:
            self.visit(statement)
        self.scope = previous
        self._handlers = previous_handlers

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        self._with_scope(node, node.body, reset_handlers=True)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        self._with_scope(node, node.body, reset_handlers=True)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_id = self._definition_ids[node]
        for base in node.bases:
            resolved = self._resolve(base, kind=NodeKind.CLASS)
            if resolved is None:
                self._record_unresolved(
                    EdgeKind.INHERITS, class_id, base, self._expression(base),
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT if self._chain(base) is None else BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                    "dynamic_base_v1" if self._chain(base) is None else "ambiguous_base_binding_v1",
                    "direct_base_binding_v1",
                )
            else:
                target, binding, rule = resolved
                protocol = target.qualified_name == "typing.Protocol"
                self._edge(EdgeKind.INHERITS, class_id, target, base, binding, rule, protocol=protocol)
        for keyword in node.keywords:
            detail = "metaclass_keyword_v1" if keyword.arg == "metaclass" else "dynamic_class_keyword_v1"
            self._record_unresolved(
                EdgeKind.INHERITS, class_id, keyword, self._expression(keyword.value),
                BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, detail, "class_keyword_v1",
            )
        self._with_scope(node, node.body)

    def visit_Import(self, node: ast.Import) -> None:
        if self._type_only_depth:
            return
        for alias in node.names:
            if self._conditional_depth:
                self._record_unresolved(
                    EdgeKind.IMPORTS, self.module_id, alias, alias.name,
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "conditional_import_v1", "import_statement_v1",
                )
                continue
            target = self._external(alias.name, kind=NodeKind.MODULE)
            bound = alias.asname or alias.name.split(".", maxsplit=1)[0]
            rule = f"import_statement_v1;binding={bound};alias={alias.asname or ''}"
            self._edge(EdgeKind.IMPORTS, self.module_id, target, alias, self._ref(alias), rule)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self._type_only_depth:
            return
        base = self._absolute_from(node)
        for alias in node.names:
            if alias.name == "*":
                self._record_unresolved(
                    EdgeKind.IMPORTS, self.module_id, alias, "*",
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "star_import_v1", "from_import_statement_v1",
                )
            elif self._conditional_depth:
                self._record_unresolved(
                    EdgeKind.IMPORTS, self.module_id, alias, self._expression(node),
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "conditional_import_v1", "from_import_statement_v1",
                )
            elif base is None:
                self._record_unresolved(
                    EdgeKind.IMPORTS, self.module_id, alias, self._expression(node),
                    BTSRejectReason.REJECT_UNRESOLVED_EDGE, "relative_import_outside_root_v1", "relative_import_v1",
                )
            else:
                target = self._external(base, kind=NodeKind.MODULE)
                bound = alias.asname or alias.name
                rule = f"from_import_statement_v1;binding={bound};alias={alias.asname or ''};symbol={alias.name}"
                self._edge(EdgeKind.IMPORTS, self.module_id, target, alias, self._ref(alias), rule)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        if self._is_type_checking_guard(node.test):
            self._type_only_depth += 1
            for statement in node.body:
                self.visit(statement)
            self._type_only_depth -= 1
            self._conditional_depth += 1
            for statement in node.orelse:
                self.visit(statement)
            self._conditional_depth -= 1
            return
        self._conditional_depth += 1
        for statement in (*node.body, *node.orelse):
            self.visit(statement)
        self._conditional_depth -= 1

    def _is_type_checking_guard(self, expression: ast.expr) -> bool:
        chain = self._chain(expression)
        if chain is None:
            return False
        name, attrs = chain
        scope = self._lookup_scope(name)
        if scope is None:
            return False
        bindings = scope.bindings.get(name, [])
        return len(bindings) == 1 and bindings[0].path is not None and ".".join((bindings[0].path, *attrs)) == "typing.TYPE_CHECKING"

    def _visit_conditional_statements(self, statements: list[ast.stmt]) -> None:
        self._conditional_depth += 1
        for statement in statements:
            self.visit(statement)
        self._conditional_depth -= 1

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._visit_conditional_statements(node.body)
        self._visit_conditional_statements(node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._visit_conditional_statements(node.body)
        self._visit_conditional_statements(node.orelse)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        self._visit_conditional_statements(node.body)
        self._visit_conditional_statements(node.orelse)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        for case in node.cases:
            if case.guard is not None:
                self.visit(case.guard)
            self._visit_conditional_statements(case.body)

    def visit_Try(self, node: ast.Try) -> None:
        self._conditional_depth += 1
        for statement in node.body:
            self.visit(statement)
        self._conditional_depth -= 1
        for handler in node.handlers:
            if handler.type is not None:
                self.visit(handler.type)
            self._handlers.append(handler.type)
            self._conditional_depth += 1
            for statement in handler.body:
                self.visit(statement)
            self._conditional_depth -= 1
            self._handlers.pop()
        for statement in (*node.orelse, *node.finalbody):
            self.visit(statement)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._conditional_depth += 1
        for statement in node.body:
            self.visit(statement)
        self._conditional_depth -= 1
        for handler in node.handlers:
            if handler.type is not None:
                self.visit(handler.type)
            self._handlers.append(handler.type)
            self._conditional_depth += 1
            for statement in handler.body:
                self.visit(statement)
            self._conditional_depth -= 1
            self._handlers.pop()
        for statement in (*node.orelse, *node.finalbody):
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        chain = self._chain(node.func)
        resolved_path: str | None = None
        if chain is not None:
            name, attrs = chain
            scope = self._lookup_scope(name)
            bindings = [] if scope is None else scope.bindings.get(name, [])
            if len(bindings) == 1 and bindings[0].path is not None:
                resolved_path = ".".join((bindings[0].path, *attrs))
        dynamic = chain is not None and (
            chain == ("__import__", ())
            or chain == ("importlib", ("import_module",))
            or (chain[0] in {"exec", "eval"} and not chain[1])
            or resolved_path == "importlib.import_module"
        )
        if dynamic:
            self._record_unresolved(
                EdgeKind.IMPORTS, self.module_id, node, self._expression(node),
                BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "dynamic_import_v1", "dynamic_import_call_v1",
            )
        self.generic_visit(node)

    def _raise_expression(self, expression: ast.expr, node: ast.Raise) -> None:
        target_expression = expression.func if isinstance(expression, ast.Call) else expression
        resolved = self._resolve(target_expression, kind=NodeKind.CLASS)
        if resolved is None:
            self._record_unresolved(
                EdgeKind.RAISES, self.scope.owner, expression, self._expression(expression),
                BTSRejectReason.REJECT_UNRESOLVED_EDGE, "unresolved_exception_binding_v1", "raise_binding_v1",
            )
            return
        target, binding, rule = resolved
        self._edge(EdgeKind.RAISES, self.scope.owner, target, expression, binding, rule)
        if isinstance(expression, ast.Call):
            for argument in (*expression.args, *(keyword.value for keyword in expression.keywords)):
                self.visit(argument)

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.exc is None:
            handler_type = self._handlers[-1] if self._handlers else None
            if handler_type is None or isinstance(handler_type, ast.Tuple):
                self._record_unresolved(
                    EdgeKind.RAISES, self.scope.owner, node, "<bare raise>",
                    BTSRejectReason.REJECT_UNRESOLVED_EDGE, "bare_raise_unresolved_handler_v1", "bare_raise_handler_v1",
                )
            else:
                resolved = self._resolve(handler_type, kind=NodeKind.CLASS)
                if resolved is None:
                    self._record_unresolved(
                        EdgeKind.RAISES, self.scope.owner, node, "<bare raise>",
                        BTSRejectReason.REJECT_UNRESOLVED_EDGE, "bare_raise_unresolved_handler_v1", "bare_raise_handler_v1",
                    )
                else:
                    target, binding, rule = resolved
                    self._edge(EdgeKind.RAISES, self.scope.owner, target, node, binding, f"bare_raise_{rule}")
            return
        self._raise_expression(node.exc, node)
        if node.cause is not None and not (isinstance(node.cause, ast.Constant) and node.cause.value is None):
            self._raise_expression(node.cause, node)

    def run(self) -> None:
        for statement in self.tree.body:
            self.visit(statement)


def _syntax_detail(text: str) -> str:
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("type ") and "=" in stripped:
            return "pep695_type_alias_v1"
        if (stripped.startswith("class ") or stripped.startswith("def ") or stripped.startswith("async def ")) and "[" in stripped.split(":", maxsplit=1)[0]:
            return "pep695_type_parameters_v1"
    return "python_311_syntax_v1"


def extract_static_edges(
    source: bytes,
    /,
    *,
    slug: str,
    commit_sha: str,
    path: str,
    blob_sha: str,
    package_root: str,
) -> StaticExtraction:
    """Extract one file under the fixed ``python-3.11-v1`` grammar.

    ``package_root`` is a normalized donor-root-relative directory, such as
    ``"src"``.  It is required even for absolute imports so callers cannot
    accidentally analyze a file under an implicit filesystem-derived root.
    """

    whole = _whole_source_ref(source, slug=slug, commit_sha=commit_sha, path=path, blob_sha=blob_sha)
    module = _module_name(path, package_root)
    module_id = NodeId(NodeOrigin.DONOR, NodeKind.MODULE, module, module, f"{path}:module")
    module_node = Node(module_id, whole, "ast")
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
            BTSEvidence(
                "Python source is not strict UTF-8", slug, commit_sha, path, blob_sha,
                1, 0, 1, 0, "invalid_utf8_source_v1",
            ),
            cause=exc,
        ) from exc
    try:
        tree = ast.parse(text, filename=path, mode="exec", feature_version=(3, 11))
        symbols = symtable.symtable(text, path, "exec")
    except SyntaxError as exc:
        line = exc.lineno or 1
        col = max((exc.offset or 1) - 1, 0)
        end_line = exc.end_lineno or line
        end_col = max((exc.end_offset or exc.offset or 1) - 1, col)
        site = SourceRef(slug, commit_sha, path, blob_sha, line, col, end_line, end_col)
        detail = _syntax_detail(text)
        provenance = EdgeProvenance(site, None, "SyntaxError", "python_311_grammar_gate_v1")
        unresolved = UnresolvedEdge(
            EdgeKind.IMPORTS, module_id, "<grammar gate>", provenance,
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, detail,
        )
        blocker = ExtractionBlocker(
            path, line, col, end_line, end_col, "SyntaxError", "python_311_grammar_gate_v1",
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, detail,
        )
        return StaticExtraction((module_node,), (), (unresolved,), GraphCoverage((whole,), (), (blocker,)))
    except (ValueError, RecursionError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
            "Python parser rejected source",
            detail_code="python_parser_failure_v1",
            cause=exc,
        ) from exc

    extractor = _Extractor(
        tree, symbols, text, source, slug=slug, commit_sha=commit_sha, path=path,
        blob_sha=blob_sha, module=module,
    )
    extractor.run()
    coverage = GraphCoverage((whole,), (whole,), tuple(extractor.blockers))
    return StaticExtraction(tuple(extractor.nodes.values()), tuple(extractor.edges), tuple(extractor.unresolved), coverage)


__all__ = ["GRAMMAR_ID", "StaticExtraction", "extract_static_edges"]
