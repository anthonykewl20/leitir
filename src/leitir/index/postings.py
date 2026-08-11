"""Canonical byte-trigram postings and sorted intersection."""

from __future__ import annotations

from collections.abc import Iterable, Sequence


def iter_trigrams(data: bytes) -> tuple[str, ...]:
    """Return sorted distinct hexadecimal byte trigrams in *data*."""
    return tuple(sorted({data[offset : offset + 3].hex() for offset in range(max(0, len(data) - 2))}))


def intersect_sorted(*postings: Sequence[int]) -> tuple[int, ...]:
    """Intersect sorted posting lists without depending on hash iteration."""
    if not postings:
        return ()
    result = tuple(postings[0])
    for values in postings[1:]:
        left = right = 0
        merged: list[int] = []
        while left < len(result) and right < len(values):
            if result[left] == values[right]:
                merged.append(result[left])
                left += 1
                right += 1
            elif result[left] < values[right]:
                left += 1
            else:
                right += 1
        result = tuple(merged)
        if not result:
            break
    return result


def build_postings(documents: Iterable[bytes]) -> dict[str, list[int]]:
    """Build ``gram -> sorted[doc_id]`` from documents in caller-defined order."""
    result: dict[str, list[int]] = {}
    for doc_id, data in enumerate(documents):
        for gram in iter_trigrams(data):
            result.setdefault(gram, []).append(doc_id)
    return {gram: result[gram] for gram in sorted(result)}
