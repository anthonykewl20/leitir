"""REFERENCE/SPEC helpers, not the S8 implementation.

These deliberately small helpers define the fixture contract independently of
``leitir.index``.  Production code must reproduce the observable results; it
must not import this test module.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

EXPECTED_SCHEMA_VERSION = "leitir-trigram-index-v1"


def iter_trigrams(s: str) -> tuple[str, ...]:
    """Return sorted unique Unicode three-character windows from *s*."""
    return tuple(sorted({s[offset : offset + 3] for offset in range(max(0, len(s) - 2))}))


def intersect_sorted(*lists: Sequence[int]) -> tuple[int, ...]:
    """Intersect already-sorted integer sequences without hash iteration."""
    if not lists:
        return ()
    result = tuple(lists[0])
    for values in lists[1:]:
        left = right = 0
        intersection: list[int] = []
        while left < len(result) and right < len(values):
            if result[left] == values[right]:
                intersection.append(result[left])
                left += 1
                right += 1
            elif result[left] < values[right]:
                left += 1
            else:
                right += 1
        result = tuple(intersection)
    return result


def sound_required_literal_runs(pattern: str) -> tuple[str, ...]:
    """Conservatively extract literals required by every regex match.

    Empty means "no sound literal run".  Alternation, character classes,
    lookarounds, optional/repeated groups, and case folding intentionally make
    this reference planner give up rather than risk a false negative.
    """
    try:
        parsed = sre_parse.parse(pattern)
    except re.error:
        return ()
    if parsed.state.flags & sre_constants.SRE_FLAG_IGNORECASE:
        return ()

    runs: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if current:
            runs.append("".join(current))
            current.clear()

    for operation, argument in parsed:
        if operation is sre_constants.LITERAL:
            current.append(chr(argument))
        elif operation is sre_constants.SUBPATTERN:
            flush()
            _group, add_flags, delete_flags, child = argument
            if add_flags or delete_flags:
                return ()
            child_pattern = sre_parse.SubPattern(parsed.state, data=child)
            child_runs = _required_runs_from_tokens(child_pattern)
            if child_runs is None:
                return ()
            runs.extend(child_runs)
        elif operation is sre_constants.AT:
            flush()
        else:
            return ()
    flush()
    return tuple(run for run in runs if len(run) >= 3)


def _required_runs_from_tokens(tokens: Sequence[tuple[Any, Any]]) -> tuple[str, ...] | None:
    current: list[str] = []
    runs: list[str] = []
    for operation, argument in tokens:
        if operation is sre_constants.LITERAL:
            current.append(chr(argument))
        elif operation is sre_constants.AT:
            if current:
                runs.append("".join(current))
                current.clear()
        else:
            return None
    if current:
        runs.append("".join(current))
    return tuple(run for run in runs if len(run) >= 3)


def build_reference_postings(contents: Sequence[str]) -> dict[str, list[int]]:
    """Build canonical postings from caller-supplied deterministic doc order."""
    postings: dict[str, list[int]] = {}
    for doc_id, content in enumerate(contents):
        for gram in iter_trigrams(content):
            postings.setdefault(gram, []).append(doc_id)
    return {gram: postings[gram] for gram in sorted(postings)}


def atomic_write_json(path: Path, payload: Mapping[str, object]) -> None:
    """Write canonical fixture JSON with the production atomic-write shape."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def refuse_unknown_schema(schema_version: object) -> None:
    """Reference fail-closed schema check; reads never upgrade artifacts."""
    if schema_version != EXPECTED_SCHEMA_VERSION:
        raise ValueError(f"unsupported trigram index schema: {schema_version!r}")
