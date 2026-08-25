"""Purely static Python usage resolver (issue #257).

Given a small consumer source tree and a mapping of top-level import roots to
provider distribution names, this module resolves which lines of consumer
code reference which provider distribution -- using nothing but ``ast.parse``
over the source text. It never imports, execs, evals, or otherwise runs any
byte of consumer code, and it never shells out to run consumer code either.

The resolver tracks name bindings through a simplified but scope-aware model
(module / function / class / comprehension scopes, ``global``/``nonlocal``
redirection, branch-sensitive binding for ``if``/``try`` so a name bound
differently on two branches is flagged ambiguous rather than guessed) so
that aliasing, attribute/call usage, and local shadowing are handled without
needing to execute anything.

Anything the resolver cannot statically pin down -- a dynamic import, a star
import, an ambiguous multi-branch binding, a name that flows through another
local module's re-export, unparsable source, or a declared cap being hit --
is reported as one of the closed :class:`~leitir.usage.UnresolvedState`
members. A guess is never reported as ``resolved``.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from leitir.safeio import read_regular_file

from ._canonical import digest_bytes
from .contract import (
    CODE_REFERENCE_SCHEMA_VERSION,
    COVERAGE_RECORD_SCHEMA_VERSION,
    COVERAGE_SUMMARY_SCHEMA_VERSION,
    MAX_COVERAGE_CAP,
    MAX_REFERENCES,
    CodeReference,
    CoverageRecord,
    CoverageSummary,
    SourceSpan,
    UnresolvedState,
)

# --------------------------------------------------------------------------
# Caps -- declared near their consumer, per the shared engineering brief.
# Every one of these is overridable per-call (defaults below) so callers and
# tests can exercise cap-exceeded behaviour deterministically without having
# to manufacture huge fixture files.
# --------------------------------------------------------------------------

MAX_RESOLVER_FILES = 200
"""Maximum number of consumer source files resolved in one run."""

MAX_RESOLVER_FILE_BYTES = 1_048_576
"""Maximum bytes read from any single consumer source file (1 MiB)."""

MAX_RESOLVER_AST_NODES_PER_FILE = 20_000
"""Maximum AST node count tolerated for one file before it is capped."""

MAX_RESOLVER_REFERENCES = MAX_REFERENCES
"""Maximum resolved references kept for one run (mirrors the report cap)."""

MAX_RESOLVER_COVERAGE_RECORDS = MAX_COVERAGE_CAP
"""The coverage cap declared for a resolver run (mirrors the contract cap)."""

RESOLVER_RESULT_SCHEMA_VERSION = "leitir-usage-resolver-result-v1"


# --------------------------------------------------------------------------
# Public result type.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolverResult:
    """The static resolver's output for one consumer source tree.

    ``references`` are only ever emitted for usage sites the resolver could
    pin down to a tracked provider distribution with certainty; every other
    usage site instead contributes to a typed-unresolved ``coverage``
    record. ``coverage`` is explicit about every file examined (one record
    each) and every file that was not (``exclusions``, e.g. oversized or
    beyond the declared file-count cap).
    """

    schema_version: str
    references: tuple[CodeReference, ...]
    coverage: CoverageSummary

    def __post_init__(self) -> None:
        if self.schema_version != RESOLVER_RESULT_SCHEMA_VERSION:
            raise ValueError("resolver_result.schema_version is unsupported")
        if len(self.references) > MAX_RESOLVER_REFERENCES:
            raise ValueError("resolver_result.references exceeds the resolver cap")
        if not isinstance(self.coverage, CoverageSummary):
            raise ValueError("resolver_result.coverage must be a CoverageSummary")


# --------------------------------------------------------------------------
# Internal binding model.
# --------------------------------------------------------------------------

# A name binding is one of:
#   "import"   -- currently bound to a tracked provider distribution.
#   "reexport" -- was bound to a provider import, then flowed through a local
#                 rebind (shadow) or another local module's forwarding
#                 import; usage is intentionally typed-unresolved, never a
#                 guess.
#   "ambiguous"-- bound to two different provider imports (directly, or via
#                 disagreeing branches of an if/try).
#   "shadow"   -- an ordinary local name never meaningfully tied to a
#                 tracked provider import; never emits a reference or an
#                 issue.
_BindingKind = str


@dataclass(frozen=True)
class _Binding:
    kind: _BindingKind
    distribution: str | None = None


@dataclass
class _Scope:
    kind: str  # "module" | "function" | "class" | "comprehension"
    parent: _Scope | None
    bindings: dict[str, _Binding] = field(default_factory=dict)
    globals_: set[str] = field(default_factory=set)
    nonlocals_: set[str] = field(default_factory=set)


_STATE_PRIORITY: dict[UnresolvedState, int] = {
    UnresolvedState.CAP_EXCEEDED: 0,
    UnresolvedState.UNSUPPORTED_SYNTAX: 1,
    UnresolvedState.STAR_IMPORT: 2,
    UnresolvedState.DYNAMIC_IMPORT: 3,
    UnresolvedState.AMBIGUOUS_BINDING: 4,
    UnresolvedState.RE_EXPORT: 5,
    UnresolvedState.RESOLVED: 6,
}


def _merge_binding(existing: _Binding | None, new: _Binding) -> _Binding:
    if existing is None:
        return new
    if existing.kind == "import" and new.kind == "import":
        return _Binding(kind="ambiguous")
    if existing.kind == "import" and new.kind == "shadow":
        return _Binding(kind="reexport")
    return new


def _module_dotted_name(relpath: str) -> str:
    parts = list(PurePosixPath(relpath).parts)
    if parts and parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][: -len(".py")]
    return ".".join(parts)


def _resolve_relative_module(relpath: str, level: int, module: str | None) -> str | None:
    """Return the dotted module name a relative ``from`` import refers to, or ``None``."""

    parts = list(PurePosixPath(relpath).parts)
    package_parts = parts[:-1]
    if level - 1 > len(package_parts):
        return None
    base = package_parts[: len(package_parts) - (level - 1)] if level > 1 else package_parts
    dotted = list(base)
    if module:
        dotted.extend(module.split("."))
    if not dotted:
        return None
    return ".".join(dotted)


_BindFn = Callable[[str, _Binding], None]


def _bind_store_targets(expr: ast.expr, bind: _BindFn) -> None:
    if isinstance(expr, ast.Name):
        bind(expr.id, _Binding(kind="shadow"))
    elif isinstance(expr, ast.Starred):
        _bind_store_targets(expr.value, bind)
    elif isinstance(expr, (ast.Tuple, ast.List)):
        for elt in expr.elts:
            _bind_store_targets(elt, bind)
    # Attribute/Subscript targets (``obj.attr = ...``, ``obj[k] = ...``) do
    # not introduce or rebind a name; nothing to do.


def _scan_module_level_bindings(tree: ast.Module, import_roots: Mapping[str, str]) -> dict[str, _Binding]:
    """A shallow, module-top-level-only scan used to build the cross-file re-export index.

    Only literal ``import``/``from ... import`` statements directly in the
    module body are considered; this is deliberately not scope- or
    control-flow-aware (unlike the full per-file visitor below) because it
    only needs to answer one question for another file's benefit: "does
    this local module forward a name that came from a tracked provider
    import?".
    """

    bindings: dict[str, _Binding] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                root = alias.name.split(".")[0]
                bound = alias.asname or root
                distribution = import_roots.get(root)
                bindings[bound] = _Binding(kind="import", distribution=distribution) if distribution else _Binding(kind="shadow")
        elif isinstance(stmt, ast.ImportFrom):
            if any(alias.name == "*" for alias in stmt.names):
                continue
            from_root = stmt.module.split(".")[0] if stmt.module and stmt.level == 0 else None
            distribution = import_roots.get(from_root) if from_root else None
            for alias in stmt.names:
                bound = alias.asname or alias.name
                bindings[bound] = _Binding(kind="import", distribution=distribution) if distribution else _Binding(kind="shadow")
    return bindings


def _is_dynamic_import_call(func: ast.expr) -> bool:
    if isinstance(func, ast.Name) and func.id == "__import__":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "import_module" and isinstance(func.value, ast.Name) and func.value.id == "importlib"


def _extract_snippet(source_text: str, span: SourceSpan) -> str:
    lines = source_text.splitlines(keepends=True)
    if span.end_line > len(lines):
        raise ValueError("span end_line is beyond the end of the file")
    selected = lines[span.start_line - 1 : span.end_line]
    if len(selected) == 1:
        return selected[0][span.start_col : span.end_col]
    selected[0] = selected[0][span.start_col :]
    selected[-1] = selected[-1][: span.end_col]
    return "".join(selected)


# --------------------------------------------------------------------------
# The per-file scope-aware visitor.
# --------------------------------------------------------------------------


class _ScopeVisitor(ast.NodeVisitor):
    """Walks one file's AST, tracking bindings and collecting usage evidence.

    Never evaluates anything: every decision is made from the shape of the
    AST alone.
    """

    def __init__(
        self,
        *,
        relpath: str,
        source_text: str,
        import_roots: Mapping[str, str],
        module_index: Mapping[str, dict[str, _Binding]],
        distribution_for_relpath: str,
    ) -> None:
        self.relpath = relpath
        self.source_text = source_text
        self.import_roots = import_roots
        self.module_index = module_index
        self.file_field = distribution_for_relpath
        self.scope_stack: list[_Scope] = [_Scope(kind="module", parent=None)]
        self.references: list[CodeReference] = []
        self.issue_states: set[UnresolvedState] = set()
        self.star_import_seen = False
        self.dynamic_import_seen = False

    # -- scope plumbing -----------------------------------------------

    @property
    def _scope(self) -> _Scope:
        return self.scope_stack[-1]

    def _assignment_scope(self, name: str) -> _Scope:
        scope = self._scope
        if name in scope.globals_:
            root = scope
            while root.parent is not None:
                root = root.parent
            return root
        if name in scope.nonlocals_:
            candidate = scope.parent
            while candidate is not None:
                if candidate.kind == "function":
                    return candidate
                candidate = candidate.parent
        return scope

    def _bind(self, name: str, binding: _Binding) -> None:
        target = self._assignment_scope(name)
        target.bindings[name] = _merge_binding(target.bindings.get(name), binding)

    def _lookup(self, name: str) -> _Binding | None:
        scope = self._scope
        if name in scope.globals_:
            root = scope
            while root.parent is not None:
                root = root.parent
            return root.bindings.get(name)
        if name in scope.nonlocals_:
            candidate = scope.parent
            while candidate is not None:
                if candidate.kind == "function" and name in candidate.bindings:
                    return candidate.bindings[name]
                candidate = candidate.parent
            return None
        node: _Scope | None = scope
        origin = True
        while node is not None:
            if name in node.bindings and (origin or node.kind != "class"):
                return node.bindings[name]
            origin = False
            node = node.parent
        return None

    def _visit_stmts(self, stmts: Sequence[ast.stmt]) -> None:
        for stmt in stmts:
            self.visit(stmt)

    def _visit_branches(self, thunks: list[Callable[[], None]]) -> None:
        """Run each ``thunks[i]()`` from the same starting bindings, then merge.

        A name bound to two different provider distributions across
        mutually-exclusive branches becomes ``ambiguous``; a name bound
        consistently (or in only one branch) keeps that binding.
        """

        scope = self._scope
        base = dict(scope.bindings)
        results: list[dict[str, _Binding]] = []
        for thunk in thunks:
            scope.bindings = dict(base)
            thunk()
            results.append(scope.bindings)
        merged = dict(base)
        touched: set[str] = set()
        for result in results:
            touched |= result.keys()
        for key in touched:
            base_value = base.get(key)
            # Only branches that actually *changed* this name (relative to
            # what it was before the if/try) count toward disagreement --
            # an untouched copy of the pre-branch value is not a competing
            # binding, just an unmodified branch.
            changed_values = [result[key] for result in results if key in result and result[key] != base_value]
            if not changed_values:
                continue
            distinct = {(value.kind, value.distribution) for value in changed_values}
            merged[key] = _Binding(kind="ambiguous") if len(distinct) > 1 else changed_values[0]
        scope.bindings = merged

    # -- imports --------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            bound = alias.asname or root
            distribution = self.import_roots.get(root)
            self._bind(bound, _Binding(kind="import", distribution=distribution) if distribution else _Binding(kind="shadow"))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self.star_import_seen = True
            return
        root = node.module.split(".")[0] if node.module and node.level == 0 else None
        tracked_distribution = self.import_roots.get(root) if root else None
        effective_module = node.module if node.level == 0 else _resolve_relative_module(self.relpath, node.level, node.module)
        local_bindings = None if tracked_distribution is not None or effective_module is None else self.module_index.get(effective_module)
        for alias in node.names:
            bound = alias.asname or alias.name
            if tracked_distribution is not None:
                binding = _Binding(kind="import", distribution=tracked_distribution)
            elif local_bindings is not None and local_bindings.get(alias.name) is not None and local_bindings[alias.name].kind == "import":
                binding = _Binding(kind="reexport")
            else:
                binding = _Binding(kind="shadow")
            self._bind(bound, binding)

    # -- names ------------------------------------------------------------

    def visit_Name(self, node: ast.Name) -> None:
        if not isinstance(node.ctx, ast.Load):
            return
        binding = self._lookup(node.id)
        if binding is None or binding.kind == "shadow":
            return
        if binding.kind == "import":
            assert binding.distribution is not None
            span = SourceSpan(
                file=self.file_field,
                start_line=node.lineno,
                start_col=node.col_offset,
                end_line=node.end_lineno or node.lineno,
                end_col=node.end_col_offset if node.end_col_offset is not None else node.col_offset,
            )
            snippet = _extract_snippet(self.source_text, span)
            self.references.append(
                CodeReference(
                    schema_version=CODE_REFERENCE_SCHEMA_VERSION,
                    distribution=binding.distribution,
                    span=span,
                    code_digest=digest_bytes(snippet.encode("utf-8")),
                )
            )
        elif binding.kind == "ambiguous":
            self.issue_states.add(UnresolvedState.AMBIGUOUS_BINDING)
        elif binding.kind == "reexport":
            self.issue_states.add(UnresolvedState.RE_EXPORT)

    # -- calls (dynamic import detection) ----------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        if _is_dynamic_import_call(node.func):
            self.dynamic_import_seen = True
            for arg in node.args:
                self.visit(arg)
            for keyword in node.keywords:
                self.visit(keyword.value)
            return
        self.generic_visit(node)

    # -- assignment-like binding sites ------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            _bind_store_targets(target, self._bind)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        _bind_store_targets(node.target, self._bind)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        _bind_store_targets(node.target, self._bind)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        _bind_store_targets(node.target, self._bind)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        _bind_store_targets(node.target, self._bind)
        self._visit_stmts(node.body)
        self._visit_stmts(node.orelse)

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                _bind_store_targets(item.optional_vars, self._bind)
        self._visit_stmts(node.body)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_Global(self, node: ast.Global) -> None:
        self._scope.globals_.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self._scope.nonlocals_.update(node.names)

    # -- branch-sensitive control flow -------------------------------------

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self._visit_branches([lambda: self._visit_stmts(node.body), lambda: self._visit_stmts(node.orelse)])

    def visit_Try(self, node: ast.Try) -> None:
        thunks: list[Callable[[], None]] = [lambda: self._visit_stmts(node.body)]
        for handler in node.handlers:
            thunks.append(self._make_handler_thunk(handler))
        self._visit_branches(thunks)
        self._visit_stmts(node.orelse)
        self._visit_stmts(node.finalbody)

    def _make_handler_thunk(self, handler: ast.ExceptHandler) -> Callable[[], None]:
        def thunk() -> None:
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self._bind(handler.name, _Binding(kind="shadow"))
            self._visit_stmts(handler.body)

        return thunk

    # -- scoped constructs ---------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_like(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_like(node)

    def _visit_function_like(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        args = node.args
        for default in (*args.defaults, *args.kw_defaults):
            if default is not None:
                self.visit(default)
        self._bind(node.name, _Binding(kind="shadow"))
        scope = _Scope(kind="function", parent=self._scope)
        self.scope_stack.append(scope)
        for arg_group in (args.posonlyargs, args.args, args.kwonlyargs):
            for arg in arg_group:
                self._bind(arg.arg, _Binding(kind="shadow"))
        if args.vararg is not None:
            self._bind(args.vararg.arg, _Binding(kind="shadow"))
        if args.kwarg is not None:
            self._bind(args.kwarg.arg, _Binding(kind="shadow"))
        self._visit_stmts(node.body)
        self.scope_stack.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        args = node.args
        for default in (*args.defaults, *args.kw_defaults):
            if default is not None:
                self.visit(default)
        scope = _Scope(kind="function", parent=self._scope)
        self.scope_stack.append(scope)
        for arg_group in (args.posonlyargs, args.args, args.kwonlyargs):
            for arg in arg_group:
                self._bind(arg.arg, _Binding(kind="shadow"))
        if args.vararg is not None:
            self._bind(args.vararg.arg, _Binding(kind="shadow"))
        if args.kwarg is not None:
            self._bind(args.kwarg.arg, _Binding(kind="shadow"))
        self.visit(node.body)
        self.scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind(node.name, _Binding(kind="shadow"))
        scope = _Scope(kind="class", parent=self._scope)
        self.scope_stack.append(scope)
        self._visit_stmts(node.body)
        self.scope_stack.pop()

    def _visit_comprehension(self, node: ast.expr, generators: list[ast.comprehension], elts: list[ast.expr]) -> None:
        scope = _Scope(kind="comprehension", parent=self._scope)
        self.scope_stack.append(scope)
        for generator in generators:
            self.visit(generator.iter)
            _bind_store_targets(generator.target, self._bind)
            for condition in generator.ifs:
                self.visit(condition)
        for elt in elts:
            self.visit(elt)
        self.scope_stack.pop()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node, node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node, node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node, node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node, node.generators, [node.key, node.value])


@dataclass(frozen=True, slots=True)
class _FileOutcome:
    file: str
    state: UnresolvedState
    references: tuple[CodeReference, ...]


def _resolve_one_file(
    *,
    relpath: str,
    source_text: str,
    import_roots: Mapping[str, str],
    module_index: Mapping[str, dict[str, _Binding]],
    file_field: str,
    max_ast_nodes: int,
) -> _FileOutcome:
    try:
        tree = ast.parse(source_text, filename=relpath)
    except (SyntaxError, ValueError):
        return _FileOutcome(file=file_field, state=UnresolvedState.UNSUPPORTED_SYNTAX, references=())

    node_count = sum(1 for _ in ast.walk(tree))
    if node_count > max_ast_nodes:
        return _FileOutcome(file=file_field, state=UnresolvedState.CAP_EXCEEDED, references=())

    visitor = _ScopeVisitor(
        relpath=relpath,
        source_text=source_text,
        import_roots=import_roots,
        module_index=module_index,
        distribution_for_relpath=file_field,
    )
    visitor.visit(tree)

    if visitor.star_import_seen:
        return _FileOutcome(file=file_field, state=UnresolvedState.STAR_IMPORT, references=())

    candidates = set(visitor.issue_states)
    if visitor.dynamic_import_seen:
        candidates.add(UnresolvedState.DYNAMIC_IMPORT)
    if candidates:
        state = min(candidates, key=lambda member: _STATE_PRIORITY[member])
    else:
        state = UnresolvedState.RESOLVED
    return _FileOutcome(file=file_field, state=state, references=tuple(visitor.references))


def _reference_sort_key(reference: CodeReference) -> tuple[str, int, int, int, int, str]:
    span = reference.span
    return (span.file, span.start_line, span.start_col, span.end_line, span.end_col, reference.distribution)


def resolve_consumer(
    *,
    consumer_root: Path,
    import_roots: Mapping[str, str],
    files: Sequence[str] | None = None,
    path_prefix: str = "",
    max_files: int = MAX_RESOLVER_FILES,
    max_file_bytes: int = MAX_RESOLVER_FILE_BYTES,
    max_ast_nodes_per_file: int = MAX_RESOLVER_AST_NODES_PER_FILE,
    max_references: int = MAX_RESOLVER_REFERENCES,
) -> ResolverResult:
    """Statically resolve which lines of a consumer source tree use which provider.

    ``consumer_root`` is a directory of local, stdlib-only Python source
    (never imported or executed). ``import_roots`` maps a top-level import
    root name (e.g. ``"widgetlib"``) to the distribution name it should be
    attributed to. ``files`` is the set of file paths to resolve, relative
    to ``consumer_root`` in POSIX form; when omitted, every ``*.py`` file
    under ``consumer_root`` is discovered and sorted. ``path_prefix`` is
    prepended to every emitted ``file``/``span.file`` value (e.g.
    ``"consumer/"``) to match the caller's report layout.

    Every declared cap is deterministic and overridable per call so tests
    (and callers with different corpora) can exercise cap-exceeded behaviour
    without needing to manufacture huge fixtures. Exceeding a cap never
    aborts the run: the affected file(s) are recorded as typed unresolved
    (``cap-exceeded``) or excluded, and resolution continues for the rest.
    """

    if not consumer_root.is_dir():
        raise ValueError("consumer_root must be an existing directory")

    if files is None:
        discovered = sorted(
            path.relative_to(consumer_root).as_posix() for path in consumer_root.rglob("*.py") if path.is_file()
        )
    else:
        discovered = sorted(set(files))

    capped = False
    kept = discovered
    excluded: list[str] = []
    if len(discovered) > max_files:
        kept = discovered[:max_files]
        excluded = discovered[max_files:]
        capped = True

    sources: dict[str, str] = {}
    for relpath in kept:
        full_path = consumer_root / relpath
        try:
            raw = read_regular_file(full_path, maximum_bytes=max_file_bytes, no_follow=True)
            sources[relpath] = raw.decode("utf-8")
        except (OSError, ValueError, UnicodeDecodeError):
            excluded.append(relpath)
            capped = True

    examined = sorted(sources)

    module_index: dict[str, dict[str, _Binding]] = {}
    for relpath in examined:
        try:
            tree = ast.parse(sources[relpath], filename=relpath)
        except (SyntaxError, ValueError):
            continue
        module_index[_module_dotted_name(relpath)] = _scan_module_level_bindings(tree, import_roots)

    outcomes: list[_FileOutcome] = []
    for relpath in examined:
        outcome = _resolve_one_file(
            relpath=relpath,
            source_text=sources[relpath],
            import_roots=import_roots,
            module_index=module_index,
            file_field=f"{path_prefix}{relpath}",
            max_ast_nodes=max_ast_nodes_per_file,
        )
        outcomes.append(outcome)
        if outcome.state == UnresolvedState.CAP_EXCEEDED:
            capped = True

    all_references = sorted(
        (reference for outcome in outcomes for reference in outcome.references), key=_reference_sort_key
    )
    if len(all_references) > max_references:
        all_references = all_references[:max_references]
        capped = True

    records = tuple(
        CoverageRecord(schema_version=COVERAGE_RECORD_SCHEMA_VERSION, file=outcome.file, state=outcome.state)
        for outcome in sorted(outcomes, key=lambda item: item.file)
    )
    exclusions = tuple(sorted({f"{path_prefix}{relpath}" for relpath in excluded}))

    coverage = CoverageSummary(
        schema_version=COVERAGE_SUMMARY_SCHEMA_VERSION,
        records=records,
        exclusions=exclusions,
        cap=MAX_RESOLVER_COVERAGE_RECORDS,
        capped=capped,
    )
    return ResolverResult(
        schema_version=RESOLVER_RESULT_SCHEMA_VERSION,
        references=tuple(all_references),
        coverage=coverage,
    )
