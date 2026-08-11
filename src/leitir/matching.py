"""Shared predicate-evaluation capabilities for search implementations."""

from __future__ import annotations

from leitir.adapters import LanguageAdapter
from leitir.search import Predicate, PredicateKind


def document_excluded_ex(
    content: str,
    adapter: LanguageAdapter,
    must_not: tuple[Predicate, ...],
) -> tuple[bool, bool]:
    """Return whether any content exclusion matches and parser availability."""
    parser_unavailable = False
    for predicate in must_not:
        if predicate.kind is PredicateKind.PATH:
            continue
        result = adapter.find_matches_ex(content, (predicate,))
        parser_unavailable = parser_unavailable or result.parser_unavailable
        if result.spans:
            return True, parser_unavailable
    return False, parser_unavailable
