"""Deterministic score normalization and provenance-stable ranking."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_EVEN, localcontext

from leitir.search import PredicateKind, SourceMatch, SourceRef


_NORMALIZED_QUANTUM = Decimal("0.000000000001")


def source_identity(source: SourceRef) -> tuple[str, str, str, str, int, int]:
    """Return ADR-002's canonical result identity tuple."""
    if not isinstance(source, SourceRef):
        raise TypeError("source must be a SourceRef")
    return (
        source.slug,
        source.commit_sha,
        source.path,
        source.blob_sha,
        source.start_line,
        source.end_line,
    )


def normalize_scores(matches: tuple[SourceMatch, ...]) -> tuple[float, ...]:
    """Min-max normalize finite scores to stable values in ``[0, 1]``.

    Decimal conversion through the score's text form avoids dependence on
    binary floating-point evaluation order. Results are rounded half-even to
    twelve decimal places. A constant score population normalizes to ``1.0``
    because every result has the population's maximum score.
    """
    if isinstance(matches, (str, bytes)) or not isinstance(matches, tuple):
        raise TypeError("matches must be a tuple of SourceMatch")
    if any(not isinstance(match, SourceMatch) for match in matches):
        raise TypeError("matches must contain only SourceMatch values")
    if not matches:
        return ()

    scores = tuple(Decimal(str(match.score)) for match in matches)
    if any(not score.is_finite() for score in scores):
        raise ValueError("scores must be finite")

    lowest = min(scores)
    highest = max(scores)
    if lowest == highest:
        return tuple(1.0 for _ in scores)

    spread = highest - lowest
    normalized: list[float] = []
    with localcontext() as context:
        context.prec = 50
        for score in scores:
            value = ((score - lowest) / spread).quantize(
                _NORMALIZED_QUANTUM,
                rounding=ROUND_HALF_EVEN,
            )
            normalized.append(float(value))
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class RankedMatch:
    """One match after deterministic normalization and total ordering."""

    source: SourceRef
    score: float
    normalized_score: float
    rank: int
    rank_score: int
    matched_kinds: tuple[PredicateKind, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceRef):
            raise TypeError("source must be a SourceRef")
        for name in ("score", "normalized_score"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number")
            if not Decimal(str(value)).is_finite():
                raise ValueError(f"{name} must be finite")
        if not 0.0 <= self.normalized_score <= 1.0:
            raise ValueError("normalized_score must be between 0 and 1")
        for name in ("rank", "rank_score"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.matched_kinds, (str, bytes)) or not isinstance(
            self.matched_kinds, tuple
        ):
            raise TypeError("matched_kinds must be a tuple")
        if any(not isinstance(kind, PredicateKind) for kind in self.matched_kinds):
            raise TypeError("matched_kinds must contain only PredicateKind")
        if not self.matched_kinds:
            raise ValueError("a ranked match must record matched predicates")

    @property
    def result_id(self) -> tuple[str, str, str, str, int, int]:
        return source_identity(self.source)

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source.to_dict(),
            "score": self.score,
            "normalized_score": self.normalized_score,
            "rank": self.rank,
            "rank_score": self.rank_score,
            "matched_kinds": [kind.value for kind in self.matched_kinds],
        }


def rank_matches(matches: tuple[SourceMatch, ...]) -> tuple[RankedMatch, ...]:
    """Apply ADR-002's exact total order and assign unique rank scores.

    Duplicate canonical result identities are rejected because no ordering of
    identical identities could satisfy the strict-total-order contract.
    ``rank_score`` is task-local, positive, unique, and decreasing with rank so
    a pytrec adapter can preserve this order without equal-score tie handling.
    """
    normalized = normalize_scores(matches)
    decorated = list(zip(matches, normalized, strict=True))

    identities = [source_identity(match.source) for match in matches]
    if len(set(identities)) != len(identities):
        raise ValueError("matches contain duplicate SourceRef identities")

    decorated.sort(
        key=lambda item: (
            -item[1],
            *source_identity(item[0].source),
        )
    )
    count = len(decorated)
    return tuple(
        RankedMatch(
            source=match.source,
            score=float(match.score),
            normalized_score=normalized_score,
            rank=index,
            rank_score=count - index + 1,
            matched_kinds=match.matched_kinds,
        )
        for index, (match, normalized_score) in enumerate(decorated, start=1)
    )


__all__ = [
    "RankedMatch",
    "normalize_scores",
    "rank_matches",
    "source_identity",
]
