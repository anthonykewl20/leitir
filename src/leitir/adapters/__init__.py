"""Language adapters for predicate matching against source blobs.

ADR-001 P2: each adapter knows one language's syntax well enough to evaluate
the typed predicates from ``leitir.search`` against raw source text and return
line-level spans.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from leitir.search import Predicate, PredicateKind


@dataclass(frozen=True, slots=True)
class SpanMatch:
    """One matched span within a blob."""

    start_line: int
    end_line: int
    matched_kinds: tuple[PredicateKind, ...]

    def __post_init__(self) -> None:
        if self.start_line < 1:
            raise ValueError("start_line must be >= 1")
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if not self.matched_kinds:
            raise ValueError("must record at least one matched kind")


@runtime_checkable
class LanguageAdapter(Protocol):
    """Port: evaluate predicates against source text for one language."""

    @property
    def language(self) -> str: ...

    def eligible(self, path: str) -> bool:
        """True if this adapter handles files at *path*."""
        ...

    def find_matches(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> tuple[SpanMatch, ...]:
        """Return all spans satisfying every must-predicate."""
        ...


_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")

_DEF_RE = re.compile(
    r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)", re.MULTILINE
)
_ASSIGN_DEF_RE = re.compile(
    r"^([A-Za-z_]\w*)\s*[:=]", re.MULTILINE
)
_CALL_RE_TEMPLATE = r"\b{name}\s*\("
_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+[\w.]+\s+)?import\s+(.+)$", re.MULTILINE
)


class PythonAdapter:
    """Predicate matching for Python source files."""

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
        lines = content.split("\n")
        if lines and lines[-1] == "" and (content == "" or content.endswith("\n")):
            lines.pop()
        must_preds = [
            p for p in predicates if p.kind is not PredicateKind.PATH
        ]
        if not must_preds:
            return ()

        per_predicate_hits = [
            self._lines_for_predicate(lines, pred) for pred in must_preds
        ]
        if any(not hit_lines for hit_lines in per_predicate_hits):
            return ()
        if whole_file:
            evidence: dict[int, set[PredicateKind]] = {}
            for pred, hit_lines in zip(must_preds, per_predicate_hits, strict=True):
                for line_idx in hit_lines:
                    evidence.setdefault(line_idx, set()).add(pred.kind)
            return tuple(
                SpanMatch(
                    start_line=line_idx + 1,
                    end_line=line_idx + 1,
                    matched_kinds=tuple(sorted(kinds, key=lambda kind: kind.value)),
                )
                for line_idx, kinds in sorted(evidence.items())
            )

        candidate_lines = set.intersection(*per_predicate_hits)
        if not candidate_lines:
            return ()

        spans: list[SpanMatch] = []
        for line_idx in sorted(candidate_lines):
            matched = self._line_matches(lines, line_idx, must_preds)
            if matched:
                spans.append(
                    SpanMatch(
                        start_line=line_idx + 1,
                        end_line=line_idx + 1,
                        matched_kinds=tuple(sorted(set(matched), key=lambda k: k.value)),
                    )
                )
        return tuple(spans)

    def _lines_for_predicate(
        self, lines: list[str], pred: Predicate
    ) -> set[int]:
        kind = pred.kind
        value = pred.value

        if kind is PredicateKind.EXACT_TEXT:
            return {i for i, line in enumerate(lines) if value in line}

        if kind is PredicateKind.REGEX:
            pattern = re.compile(value)
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.IDENTIFIER:
            pattern = re.compile(r"\b" + re.escape(value) + r"\b")
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.TOKEN_SEQUENCE:
            tokens = value.split()
            if not tokens:
                return set()
            pattern = re.compile(
                r"\b" + r"\s+".join(re.escape(t) for t in tokens) + r"\b"
            )
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.SYMBOL_DEFINITION:
            return self._definition_lines(lines, value)

        if kind is PredicateKind.SYMBOL_REFERENCE:
            all_hits = {
                i
                for i, line in enumerate(lines)
                if re.search(r"\b" + re.escape(value) + r"\b", line)
            }
            defs = self._definition_lines(lines, value)
            return all_hits - defs

        if kind is PredicateKind.SIGNATURE:
            pattern = re.compile(value)
            return {
                i
                for i, line in enumerate(lines)
                if ("def " in line or "class " in line)
                and pattern.search(line)
            }

        if kind is PredicateKind.CALL:
            pattern = re.compile(_CALL_RE_TEMPLATE.format(name=re.escape(value)))
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.IMPORT:
            return self._import_lines(lines, value)

        return set()

    def _definition_lines(self, lines: list[str], name: str) -> set[int]:
        results: set[int] = set()
        for i, line in enumerate(lines):
            m = re.match(
                r"\s*(?:async\s+)?(?:def|class)\s+" + re.escape(name) + r"\b",
                line,
            )
            if m:
                results.add(i)
                continue
            m = re.match(r"\s*" + re.escape(name) + r"\s*[:=]", line)
            if m:
                results.add(i)
        return results

    def _import_lines(self, lines: list[str], value: str) -> set[int]:
        results: set[int] = set()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            if value in stripped:
                results.add(i)
        return results

    def _line_matches(
        self, lines: list[str], line_idx: int, predicates: list[Predicate]
    ) -> tuple[PredicateKind, ...]:
        matched: list[PredicateKind] = []
        for pred in predicates:
            hits = self._lines_for_predicate(lines, pred)
            if line_idx in hits:
                matched.append(pred.kind)
        return tuple(matched)


class RustAdapter:
    """Predicate matching for Rust source files."""

    @property
    def language(self) -> str:
        return "rust"

    def eligible(self, path: str) -> bool:
        return path.endswith(".rs")

    def find_matches(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> tuple[SpanMatch, ...]:
        lines = content.split("\n")
        if lines and lines[-1] == "" and (content == "" or content.endswith("\n")):
            lines.pop()
        must_preds = [
            p for p in predicates if p.kind is not PredicateKind.PATH
        ]
        if not must_preds:
            return ()

        per_predicate_hits = [
            self._lines_for_predicate(lines, pred) for pred in must_preds
        ]
        if any(not hit_lines for hit_lines in per_predicate_hits):
            return ()
        if whole_file:
            evidence: dict[int, set[PredicateKind]] = {}
            for pred, hit_lines in zip(must_preds, per_predicate_hits, strict=True):
                for line_idx in hit_lines:
                    evidence.setdefault(line_idx, set()).add(pred.kind)
            return tuple(
                SpanMatch(
                    start_line=line_idx + 1,
                    end_line=line_idx + 1,
                    matched_kinds=tuple(sorted(kinds, key=lambda kind: kind.value)),
                )
                for line_idx, kinds in sorted(evidence.items())
            )

        candidates = set.intersection(*per_predicate_hits)

        spans: list[SpanMatch] = []
        for line_idx in sorted(candidates or set()):
            matched = [
                pred.kind
                for pred in must_preds
                if line_idx in self._lines_for_predicate(lines, pred)
            ]
            if matched:
                spans.append(
                    SpanMatch(
                        start_line=line_idx + 1,
                        end_line=line_idx + 1,
                        matched_kinds=tuple(
                            sorted(set(matched), key=lambda k: k.value)
                        ),
                    )
                )
        return tuple(spans)

    def _lines_for_predicate(
        self, lines: list[str], pred: Predicate
    ) -> set[int]:
        kind = pred.kind
        value = pred.value

        if kind is PredicateKind.EXACT_TEXT:
            return {i for i, line in enumerate(lines) if value in line}

        if kind is PredicateKind.REGEX:
            pattern = re.compile(value)
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.IDENTIFIER:
            pattern = re.compile(r"\b" + re.escape(value) + r"\b")
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.TOKEN_SEQUENCE:
            tokens = value.split()
            if not tokens:
                return set()
            pattern = re.compile(
                r"\b" + r"\s+".join(re.escape(t) for t in tokens) + r"\b"
            )
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.SYMBOL_DEFINITION:
            return self._definition_lines(lines, value)

        if kind is PredicateKind.SYMBOL_REFERENCE:
            all_hits = {
                i
                for i, line in enumerate(lines)
                if re.search(r"\b" + re.escape(value) + r"\b", line)
            }
            return all_hits - self._definition_lines(lines, value)

        if kind is PredicateKind.SIGNATURE:
            pattern = re.compile(value)
            return {
                i
                for i, line in enumerate(lines)
                if ("fn " in line or "struct " in line or "trait " in line)
                and pattern.search(line)
            }

        if kind is PredicateKind.CALL:
            pattern = re.compile(r"\b" + re.escape(value) + r"\s*[(<]")
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.IMPORT:
            return {
                i
                for i, line in enumerate(lines)
                if line.strip().startswith("use ") and value in line
            }

        return set()

    def _definition_lines(self, lines: list[str], name: str) -> set[int]:
        results: set[int] = set()
        patterns = [
            re.compile(
                r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
                r"(?:fn|struct|enum|trait|type|mod)\s+" + re.escape(name) + r"\b"
            ),
            re.compile(
                r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+"
                + re.escape(name)
                + r"\b"
            ),
            re.compile(
                r"\s*impl\s+(?:<[^>]*>\s+)?" + re.escape(name) + r"\b"
            ),
        ]
        for i, line in enumerate(lines):
            for pat in patterns:
                if pat.match(line):
                    results.add(i)
                    break
        return results


class GoAdapter:
    """Predicate matching for Go source files."""

    @property
    def language(self) -> str:
        return "go"

    def eligible(self, path: str) -> bool:
        return path.endswith(".go")

    def find_matches(
        self,
        content: str,
        predicates: tuple[Predicate, ...],
        *,
        whole_file: bool = False,
    ) -> tuple[SpanMatch, ...]:
        lines = content.split("\n")
        if lines and lines[-1] == "" and (content == "" or content.endswith("\n")):
            lines.pop()
        must_preds = [
            p for p in predicates if p.kind is not PredicateKind.PATH
        ]
        if not must_preds:
            return ()

        per_predicate_hits = [
            self._lines_for_predicate(lines, pred) for pred in must_preds
        ]
        if any(not hit_lines for hit_lines in per_predicate_hits):
            return ()
        if whole_file:
            evidence: dict[int, set[PredicateKind]] = {}
            for pred, hit_lines in zip(must_preds, per_predicate_hits, strict=True):
                for line_idx in hit_lines:
                    evidence.setdefault(line_idx, set()).add(pred.kind)
            return tuple(
                SpanMatch(
                    start_line=line_idx + 1,
                    end_line=line_idx + 1,
                    matched_kinds=tuple(sorted(kinds, key=lambda kind: kind.value)),
                )
                for line_idx, kinds in sorted(evidence.items())
            )

        candidates = set.intersection(*per_predicate_hits)

        spans: list[SpanMatch] = []
        for line_idx in sorted(candidates or set()):
            matched = [
                pred.kind
                for pred in must_preds
                if line_idx in self._lines_for_predicate(lines, pred)
            ]
            if matched:
                spans.append(
                    SpanMatch(
                        start_line=line_idx + 1,
                        end_line=line_idx + 1,
                        matched_kinds=tuple(
                            sorted(set(matched), key=lambda k: k.value)
                        ),
                    )
                )
        return tuple(spans)

    def _lines_for_predicate(
        self, lines: list[str], pred: Predicate
    ) -> set[int]:
        kind = pred.kind
        value = pred.value

        if kind is PredicateKind.EXACT_TEXT:
            return {i for i, line in enumerate(lines) if value in line}

        if kind is PredicateKind.REGEX:
            pattern = re.compile(value)
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.IDENTIFIER:
            pattern = re.compile(r"\b" + re.escape(value) + r"\b")
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.TOKEN_SEQUENCE:
            tokens = value.split()
            if not tokens:
                return set()
            pattern = re.compile(
                r"\b" + r"\s+".join(re.escape(t) for t in tokens) + r"\b"
            )
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.SYMBOL_DEFINITION:
            return self._definition_lines(lines, value)

        if kind is PredicateKind.SYMBOL_REFERENCE:
            all_hits = {
                i
                for i, line in enumerate(lines)
                if re.search(r"\b" + re.escape(value) + r"\b", line)
            }
            return all_hits - self._definition_lines(lines, value)

        if kind is PredicateKind.SIGNATURE:
            pattern = re.compile(value)
            return {
                i
                for i, line in enumerate(lines)
                if ("func " in line or "type " in line)
                and pattern.search(line)
            }

        if kind is PredicateKind.CALL:
            pattern = re.compile(r"\b" + re.escape(value) + r"\s*\(")
            return {i for i, line in enumerate(lines) if pattern.search(line)}

        if kind is PredicateKind.IMPORT:
            return {
                i
                for i, line in enumerate(lines)
                if ("import" in line or "\t\"" in line)
                and value in line
            }

        return set()

    def _definition_lines(self, lines: list[str], name: str) -> set[int]:
        results: set[int] = set()
        patterns = [
            re.compile(r"\s*func\s+(?:\([^)]*\)\s+)?" + re.escape(name) + r"\b"),
            re.compile(
                r"\s*type\s+" + re.escape(name) + r"\s+(?:struct|interface)\b"
            ),
            re.compile(r"\s*(?:const|var)\s+" + re.escape(name) + r"\b"),
        ]
        for i, line in enumerate(lines):
            for pat in patterns:
                if pat.match(line):
                    results.add(i)
                    break
        return results
