from __future__ import annotations

import ast
import builtins
import symtable
from dataclasses import dataclass
from enum import StrEnum

from leitir._python_ast import (
    parse_python,
    python_signature,
    python_symtable,
)
from leitir.adapters import (
    AdapterMatchResult,
    MatchMethod,
    PythonAdapter,
    SpanMatch,
)
from leitir.search import Predicate, PredicateKind

_STRUCTURAL_KINDS = frozenset(
    {
        PredicateKind.SYMBOL_DEFINITION,
        PredicateKind.SYMBOL_REFERENCE,
        PredicateKind.CALL,
        PredicateKind.IMPORT,
        PredicateKind.SIGNATURE,
    }
)

_BUILTIN_NAMES = frozenset(vars(builtins))


class LexicalClassification(StrEnum):
    BUILTIN = "builtin"
    GLOBAL = "global"
    LOCAL_ASSIGNED = "local/assigned"
    PARAMETER = "parameter"
    FREE = "free"
    IMPORTED = "imported"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ReferenceProvenance:
    name: str
    classification: LexicalClassification
    start_col: int | None
    end_col: int | None


@dataclass(frozen=True, slots=True)
class PythonAstSpanMatch(SpanMatch):
    """AST span with optional lexical detail for loaded-name references."""

    reference_provenance: tuple[ReferenceProvenance, ...] = ()


class _NameScopeVisitor(ast.NodeVisitor):
    def __init__(self, root: symtable.SymbolTable) -> None:
        self._scope = root
        self.scopes: dict[ast.Name, symtable.SymbolTable] = {}
        self._used_tables: set[int] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.scopes[node] = self._scope

    def _child(self, name: str, lineno: int) -> symtable.SymbolTable | None:
        for child in self._scope.get_children():
            child_id = child.get_id()
            if (
                child_id not in self._used_tables
                and child.get_name() == name
                and child.get_lineno() == lineno
            ):
                self._used_tables.add(child_id)
                return child
        return None

    def _visit_in(self, table: symtable.SymbolTable | None, nodes: list[ast.AST]) -> None:
        previous = self._scope
        if table is not None:
            self._scope = table
        for node in nodes:
            self.visit(node)
        self._scope = previous

    def _visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ):
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        for type_param in getattr(node, "type_params", ()):
            self.visit(type_param)
        self._visit_in(self._child(node.name, node.lineno), list(node.body))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for type_param in getattr(node, "type_params", ()):
            self.visit(type_param)
        self._visit_in(self._child(node.name, node.lineno), list(node.body))

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        self._visit_in(self._child("lambda", node.lineno), [node.body])

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        name: str,
        result_nodes: list[ast.AST],
    ) -> None:
        first, *remaining = node.generators
        self.visit(first.iter)
        child = self._child(name, node.lineno)
        scoped_nodes: list[ast.AST] = [first.target, *first.ifs]
        for generator in remaining:
            scoped_nodes.extend((generator.iter, generator.target, *generator.ifs))
        scoped_nodes.extend(result_nodes)
        self._visit_in(child, scoped_nodes)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node, "listcomp", [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node, "setcomp", [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node, "dictcomp", [node.key, node.value])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node, "genexpr", [node.elt])


class PythonAstAdapter:
    def __init__(self, regex: PythonAdapter) -> None:
        self._regex = regex

    @property
    def language(self) -> str:
        return "python"

    def eligible(self, path: str) -> bool:
        return path.endswith(".py")

    def find_matches(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> tuple[SpanMatch, ...]:
        return self.find_matches_ex(
            content, predicates, whole_file=whole_file
        ).spans

    def find_matches_ex(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> AdapterMatchResult:
        must = tuple(
            predicate
            for predicate in predicates
            if predicate.kind is not PredicateKind.PATH
        )
        if not must:
            return AdapterMatchResult(())
        structural = tuple(
            predicate for predicate in must if predicate.kind in _STRUCTURAL_KINDS
        )
        if not structural:
            return self._regex.find_matches_ex(
                content, predicates, whole_file=whole_file
            )
        try:
            tree = parse_python(content)
        except (SyntaxError, ValueError, RecursionError):
            return AdapterMatchResult(
                self._regex.find_matches(
                    content, predicates, whole_file=whole_file
                ),
                parser_unavailable=True,
            )
        parser_unavailable = False
        reference_provenance: dict[ast.Name, ReferenceProvenance] = {}
        try:
            symbols = python_symtable(content)
        except Exception:
            # The AST remains useful, but completeness requires both parser-backed
            # structure and the promised lexical classification.
            parser_unavailable = True
            reference_provenance = self._unknown_reference_provenance(tree)
        else:
            try:
                reference_provenance = self._reference_provenance(tree, symbols)
            except Exception:
                parser_unavailable = True
                reference_provenance = self._unknown_reference_provenance(tree)
        lines = content.split("\n")
        if lines and lines[-1] == "" and (content == "" or content.endswith("\n")):
            lines.pop()
        hits: list[dict[int, list[ast.AST] | None]] = []
        nodes = tuple(ast.walk(tree))
        for predicate in must:
            if predicate.kind not in _STRUCTURAL_KINDS:
                hits.append(
                    {
                        line + 1: None
                        for line in self._regex._lines_for_predicate(lines, predicate)
                    }
                )
                continue
            predicate_hits: dict[int, list[ast.AST] | None] = {}
            for node in nodes:
                candidates, render_unavailable = self._candidates(node)
                parser_unavailable = parser_unavailable or render_unavailable
                values = candidates.get(predicate.kind, ())
                line = getattr(node, "lineno", None)
                if predicate.value in values and isinstance(line, int):
                    existing = predicate_hits.setdefault(line, [])
                    if existing is not None:
                        existing.append(node)
            hits.append(predicate_hits)
        if any(not predicate_hits for predicate_hits in hits):
            return AdapterMatchResult((), parser_unavailable=parser_unavailable)
        selected_lines = (
            set().union(*(set(predicate_hits) for predicate_hits in hits))
            if whole_file
            else set.intersection(*(set(predicate_hits) for predicate_hits in hits))
        )
        return AdapterMatchResult(
            self._spans_for_lines(
                selected_lines, must, hits, reference_provenance
            ),
            parser_unavailable=parser_unavailable,
        )

    def _unknown_reference_provenance(
        self, tree: ast.Module
    ) -> dict[ast.Name, ReferenceProvenance]:
        return {
            node: self._provenance(node, LexicalClassification.UNKNOWN)
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }

    def _reference_provenance(
        self, tree: ast.Module, symbols: symtable.SymbolTable
    ) -> dict[ast.Name, ReferenceProvenance]:
        visitor = _NameScopeVisitor(symbols)
        visitor.visit(tree)
        return {
            node: self._provenance(
                node, self._classify_reference(node.id, table, symbols)
            )
            for node, table in sorted(
                visitor.scopes.items(),
                key=lambda item: (
                    item[0].lineno,
                    item[0].col_offset,
                    item[0].id,
                ),
            )
        }

    def _classify_reference(
        self,
        name: str,
        table: symtable.SymbolTable,
        module: symtable.SymbolTable,
    ) -> LexicalClassification:
        try:
            symbol = table.lookup(name)
        except KeyError:
            return LexicalClassification.UNKNOWN
        if symbol.is_parameter():
            return LexicalClassification.PARAMETER
        if symbol.is_imported():
            return LexicalClassification.IMPORTED
        if symbol.is_free():
            return LexicalClassification.FREE
        if symbol.is_local() or symbol.is_assigned():
            return LexicalClassification.LOCAL_ASSIGNED
        if symbol.is_global():
            try:
                module_symbol = module.lookup(name)
            except KeyError:
                module_symbol = None
            if module_symbol is not None and module_symbol.is_imported():
                return LexicalClassification.IMPORTED
            module_bound = module_symbol is not None and (
                module_symbol.is_local()
                or module_symbol.is_assigned()
                or module_symbol.is_parameter()
            )
            if not module_bound and name in _BUILTIN_NAMES:
                return LexicalClassification.BUILTIN
            return LexicalClassification.GLOBAL
        return LexicalClassification.UNKNOWN

    def _provenance(
        self, node: ast.Name, classification: LexicalClassification
    ) -> ReferenceProvenance:
        end_col = getattr(node, "end_col_offset", None)
        return ReferenceProvenance(
            name=node.id,
            classification=classification,
            start_col=node.col_offset,
            end_col=end_col if isinstance(end_col, int) else None,
        )

    def _candidates(
        self, node: ast.AST
    ) -> tuple[dict[PredicateKind, tuple[str, ...]], bool]:
        candidates: dict[PredicateKind, tuple[str, ...]] = {}
        render_unavailable = False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            candidates[PredicateKind.SYMBOL_DEFINITION] = (node.name,)
            try:
                candidates[PredicateKind.SIGNATURE] = (python_signature(node),)
            except Exception:
                render_unavailable = True
        elif isinstance(node, ast.ClassDef):
            candidates[PredicateKind.SYMBOL_DEFINITION] = (node.name,)
        elif isinstance(node, ast.Assign):
            candidates[PredicateKind.SYMBOL_DEFINITION] = tuple(
                self._target_names(node.targets)
            )
        elif isinstance(node, ast.AnnAssign):
            candidates[PredicateKind.SYMBOL_DEFINITION] = tuple(
                self._target_names((node.target,))
            )
        elif isinstance(node, ast.Import):
            imported = tuple(
                name
                for alias in node.names
                for name in (alias.name, alias.asname)
                if name is not None
            )
            candidates[PredicateKind.IMPORT] = imported
            candidates[PredicateKind.SYMBOL_DEFINITION] = tuple(
                alias.asname or alias.name.split(".", maxsplit=1)[0]
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            candidates[PredicateKind.IMPORT] = tuple(
                name
                for name in (
                    node.module,
                    *(
                        value
                        for alias in node.names
                        for value in (alias.name, alias.asname)
                    ),
                )
                if name is not None
            )
            candidates[PredicateKind.SYMBOL_DEFINITION] = tuple(
                alias.asname or alias.name
                for alias in node.names
                if alias.name != "*"
            )
        elif isinstance(node, ast.Call):
            call_names, call_render_unavailable = self._call_names(node.func)
            candidates[PredicateKind.CALL] = call_names
            render_unavailable = render_unavailable or call_render_unavailable
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            candidates[PredicateKind.SYMBOL_REFERENCE] = (node.id,)
        return candidates, render_unavailable

    def _target_names(self, targets: tuple[ast.expr, ...] | list[ast.expr]) -> list[str]:
        names: list[str] = []
        pending = list(targets)
        while pending:
            target = pending.pop(0)
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                pending[0:0] = target.elts
        return names

    def _call_names(self, function: ast.expr) -> tuple[tuple[str, ...], bool]:
        if isinstance(function, ast.Name):
            return (function.id,), False
        if isinstance(function, ast.Attribute):
            names = [function.attr]
            try:
                names.append(ast.unparse(function))
            except Exception:
                return tuple(names), True
            return tuple(dict.fromkeys(names)), False
        return (), False

    def _spans_for_lines(
        self,
        selected_lines: set[int],
        predicates: tuple[Predicate, ...],
        hits: list[dict[int, list[ast.AST] | None]],
        reference_provenance: dict[ast.Name, ReferenceProvenance],
    ) -> tuple[SpanMatch, ...]:
        spans: list[SpanMatch] = []
        for line in sorted(selected_lines):
            kinds: set[PredicateKind] = set()
            nodes: list[ast.AST] = []
            heuristic = False
            for predicate, predicate_hits in zip(predicates, hits, strict=True):
                if line not in predicate_hits:
                    continue
                kinds.add(predicate.kind)
                matched_nodes = predicate_hits[line]
                if matched_nodes is None:
                    heuristic = True
                else:
                    nodes.extend(matched_nodes)
            start_cols = [
                col
                for node in nodes
                if isinstance((col := getattr(node, "col_offset", None)), int)
            ]
            end_cols = [
                col
                for node in nodes
                if getattr(node, "end_lineno", None) == getattr(node, "lineno", None)
                and isinstance((col := getattr(node, "end_col_offset", None)), int)
            ]
            coherent_end_cols = len(end_cols) == len(nodes)
            provenance = tuple(
                sorted(
                    {
                        reference_provenance[node]
                        for node in nodes
                        if isinstance(node, ast.Name)
                        and node in reference_provenance
                    },
                    key=lambda detail: (
                        detail.start_col,
                        detail.end_col if detail.end_col is not None else -1,
                        detail.name,
                        detail.classification.value,
                    ),
                )
            )
            spans.append(
                PythonAstSpanMatch(
                    start_line=line,
                    end_line=line,
                    matched_kinds=tuple(sorted(kinds, key=lambda kind: kind.value)),
                    start_col=min(start_cols) if start_cols else None,
                    end_col=(
                        max(end_cols) if end_cols and coherent_end_cols else None
                    ),
                    method=(MatchMethod.HEURISTIC if heuristic else MatchMethod.AST),
                    reference_provenance=provenance,
                )
            )
        return tuple(spans)
