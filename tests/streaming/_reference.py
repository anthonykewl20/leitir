"""REFERENCE/SPEC helpers, not the S9 implementation."""

from __future__ import annotations

import codecs
import hashlib
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, order=True, slots=True)
class ReferenceSpan:
    """Absolute decoded-character coordinates for one reference match."""

    start: int
    end: int


def git_blob_sha(chunks: Iterable[bytes], declared_size: int) -> str:
    """Compute Git's canonical blob object SHA-1 incrementally."""
    digest = hashlib.sha1(b"blob %d\0" % declared_size)
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def chunk_emitter(data: bytes, boundaries: Sequence[int]) -> Iterator[bytes]:
    """Emit *data* according to ordered exclusive-end byte boundaries."""
    ordered = tuple(boundaries)
    if ordered != tuple(sorted(set(ordered))):
        raise ValueError("chunk boundaries must be strictly increasing")
    if ordered and (ordered[0] <= 0 or ordered[-1] >= len(data)):
        raise ValueError("chunk boundaries must be inside the payload")
    start = 0
    for end in (*ordered, len(data)):
        yield data[start:end]
        start = end


def bounded_overlap_matches(
    chunks: Iterable[bytes], pattern: str, *, overlap_chars: int
) -> tuple[ReferenceSpan, ...]:
    """Decode incrementally and match through a bounded, deduplicated overlap.

    ``overlap_chars`` is the caller's proven finite maximum match width. This
    helper intentionally does not attempt regex-width analysis.
    """
    if overlap_chars < 1:
        raise ValueError("overlap_chars must be positive")
    compiled = re.compile(pattern)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    window = ""
    origin = 0
    pending: set[ReferenceSpan] = set()

    def inspect() -> None:
        for match in compiled.finditer(window):
            pending.add(ReferenceSpan(origin + match.start(), origin + match.end()))

    for chunk in chunks:
        window += decoder.decode(chunk, final=False)
        inspect()
        if len(window) > overlap_chars:
            removed = len(window) - overlap_chars
            window = window[removed:]
            origin += removed
    window += decoder.decode(b"", final=True)
    inspect()
    return tuple(sorted(pending))
