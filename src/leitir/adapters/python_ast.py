from __future__ import annotations

import ast

from leitir._python_ast import (
    parse_python,
    python_signature,
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
                values = self._candidates(node).get(predicate.kind, ())
                line = getattr(node, "lineno", None)
                if predicate.value in values and isinstance(line, int):
                    existing = predicate_hits.setdefault(line, [])
                    if existing is not None:
                        existing.append(node)
            hits.append(predicate_hits)
        if any(not predicate_hits for predicate_hits in hits):
            return AdapterMatchResult(())
        selected_lines = (
            set().union(*(set(predicate_hits) for predicate_hits in hits))
            if whole_file
            else set.intersection(*(set(predicate_hits) for predicate_hits in hits))
        )
        return AdapterMatchResult(self._spans_for_lines(selected_lines, must, hits))

    def _candidates(self, node: ast.AST) -> dict[PredicateKind, tuple[str, ...]]:
        candidates: dict[PredicateKind, tuple[str, ...]] = {}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            candidates[PredicateKind.SYMBOL_DEFINITION] = (node.name,)
            try:
                candidates[PredicateKind.SIGNATURE] = (python_signature(node),)
            except RecursionError:
                pass
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
            candidates[PredicateKind.CALL] = self._call_names(node.func)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            candidates[PredicateKind.SYMBOL_REFERENCE] = (node.id,)
        return candidates

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

    def _call_names(self, function: ast.expr) -> tuple[str, ...]:
        if isinstance(function, ast.Name):
            return (function.id,)
        if isinstance(function, ast.Attribute):
            names = [function.attr]
            try:
                names.append(ast.unparse(function))
            except RecursionError:
                pass
            return tuple(dict.fromkeys(names))
        return ()

    def _spans_for_lines(
        self,
        selected_lines: set[int],
        predicates: tuple[Predicate, ...],
        hits: list[dict[int, list[ast.AST] | None]],
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
            spans.append(
                SpanMatch(
                    start_line=line,
                    end_line=line,
                    matched_kinds=tuple(sorted(kinds, key=lambda kind: kind.value)),
                    start_col=min(start_cols) if start_cols else None,
                    end_col=(
                        max(end_cols) if end_cols and coherent_end_cols else None
                    ),
                    method=(MatchMethod.HEURISTIC if heuristic else MatchMethod.AST),
                )
            )
        return tuple(spans)
