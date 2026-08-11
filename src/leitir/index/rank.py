"""Deterministic index result deduplication before public ranking."""

from __future__ import annotations

from collections.abc import Iterable

from leitir.ranking import source_identity
from leitir.search import SourceMatch


def dedupe_source_matches(matches: Iterable[SourceMatch]) -> tuple[SourceMatch, ...]:
    """Keep one deterministic match for each complete ``SourceRef`` identity."""
    selected: dict[tuple[str, str, str, str, int, int], SourceMatch] = {}
    for match in matches:
        identity = source_identity(match.source)
        current = selected.get(identity)
        if current is None or (match.score, tuple(kind.value for kind in match.matched_kinds)) > (
            current.score,
            tuple(kind.value for kind in current.matched_kinds),
        ):
            selected[identity] = match
    return tuple(selected[identity] for identity in sorted(selected))
