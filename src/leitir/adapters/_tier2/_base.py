"""Shared implementation for tier-2 regex adapters."""

from __future__ import annotations

import re
from dataclasses import dataclass

from leitir._regex_budget import RegexBudgetExceeded, bounded_matching_lines
from leitir.adapters import AdapterMatchResult, MatchMethod, SpanMatch
from leitir.adapters._tier2_patterns import mask_comments_and_strings
from leitir.search import Predicate, PredicateKind

_Pattern = re.Pattern[str]
_IDENTIFIER = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)(?![\w$])")
_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)(?![\w$])\s*\(")


@dataclass(frozen=True, slots=True)
class RegexInventory:
    language: str
    extensions: tuple[str, ...]
    definitions: tuple[_Pattern, ...]
    calls: tuple[_Pattern, ...]
    imports: tuple[_Pattern, ...]
    references: tuple[_Pattern, ...] = (_IDENTIFIER,)


class Tier2RegexAdapter:
    _inventory: RegexInventory

    def __init__(self, inventory: RegexInventory) -> None:
        self._inventory = inventory

    @property
    def language(self) -> str:
        return self._inventory.language

    def eligible(self, path: str) -> bool:
        return path.casefold().endswith(self._inventory.extensions)

    def find_matches(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> tuple[SpanMatch, ...]:
        lines = mask_comments_and_strings(content).split("\n")
        if lines and lines[-1] == "" and (content == "" or content.endswith("\n")):
            lines.pop()
        must_preds = [pred for pred in predicates if pred.kind is not PredicateKind.PATH]
        if not must_preds:
            return ()
        per_predicate_hits = [self._lines_for_predicate(lines, pred) for pred in must_preds]
        if any(not hits for hits in per_predicate_hits):
            return ()
        evidence: dict[int, set[PredicateKind]] = {}
        if whole_file:
            for pred, hits in zip(must_preds, per_predicate_hits, strict=True):
                for line_index in hits:
                    evidence.setdefault(line_index, set()).add(pred.kind)
        else:
            for line_index in set.intersection(*per_predicate_hits):
                evidence[line_index] = {
                    pred.kind
                    for pred, hits in zip(must_preds, per_predicate_hits, strict=True)
                    if line_index in hits
                }
        spans = {
            (line_index + 1, line_index + 1): SpanMatch(
                start_line=line_index + 1,
                end_line=line_index + 1,
                matched_kinds=tuple(sorted(kinds, key=lambda kind: kind.value)),
                method=MatchMethod.HEURISTIC,
            )
            for line_index, kinds in evidence.items()
        }
        return tuple(
            sorted(
                spans.values(),
                key=lambda span: (
                    span.start_line,
                    -1 if span.start_col is None else span.start_col,
                    span.end_line,
                    -1 if span.end_col is None else span.end_col,
                    tuple(kind.value for kind in span.matched_kinds),
                ),
            )
        )

    def find_matches_ex(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> AdapterMatchResult:
        try:
            spans = self.find_matches(content, predicates, whole_file=whole_file)
        except RegexBudgetExceeded:
            # A regex/signature predicate could not be matched within its time budget for
            # this file. Report no spans from this file *and* flag it -- never silently drop
            # the file as an ordinary "no match".
            return AdapterMatchResult(spans=(), parser_unavailable=True)
        return AdapterMatchResult(spans=spans, parser_unavailable=False)

    def _lines_for_predicate(self, lines: list[str], pred: Predicate) -> set[int]:
        if pred.kind is PredicateKind.EXACT_TEXT:
            return {index for index, line in enumerate(lines) if pred.value in line}
        if pred.kind is PredicateKind.REGEX:
            pattern = re.compile(pred.value)
            return bounded_matching_lines(lines, pattern)
        if pred.kind is PredicateKind.IDENTIFIER:
            pattern = re.compile(r"\b" + re.escape(pred.value) + r"\b")
            return {index for index, line in enumerate(lines) if pattern.search(line)}
        if pred.kind is PredicateKind.TOKEN_SEQUENCE:
            tokens = pred.value.split()
            if not tokens:
                return set()
            pattern = re.compile(r"\b" + r"\s+".join(re.escape(token) for token in tokens) + r"\b")
            return {index for index, line in enumerate(lines) if pattern.search(line)}
        if pred.kind is PredicateKind.SYMBOL_DEFINITION:
            return self._inventory_lines(lines, self._inventory.definitions, pred.value)
        if pred.kind is PredicateKind.SYMBOL_REFERENCE:
            references = self._inventory_lines(lines, self._inventory.references, pred.value)
            return references - self._inventory_lines(lines, self._inventory.definitions, pred.value)
        if pred.kind is PredicateKind.SIGNATURE:
            pattern = re.compile(pred.value)
            return bounded_matching_lines(lines, pattern, extra=self._matches_any_definition)
        if pred.kind is PredicateKind.CALL:
            return self._inventory_lines(lines, self._inventory.calls, pred.value)
        if pred.kind is PredicateKind.IMPORT:
            return {
                index
                for index, line in enumerate(lines)
                if pred.value in line and any(pattern.search(line) for pattern in self._inventory.imports)
            }
        return set()

    def _matches_any_definition(self, line: str) -> bool:
        return any(pattern.search(line) for pattern in self._inventory.definitions)

    @staticmethod
    def _inventory_lines(lines: list[str], patterns: tuple[_Pattern, ...], value: str) -> set[int]:
        hits: set[int] = set()
        for index, line in enumerate(lines):
            for pattern in patterns:
                for match in pattern.finditer(line):
                    if match.group(1) == value:
                        hits.add(index)
                        break
                if index in hits:
                    break
        return hits
