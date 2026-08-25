"""Catastrophic-backtracking (ReDoS) protection for user-supplied regex predicates.

``regex:`` (and ``signature:``) predicate values come directly from the search request and
are matched with the stdlib ``re`` module, which has no built-in defense against catastrophic
backtracking: a pattern like ``(a+)+$`` against a long enough run of a single repeated
character can make a single ``.search()`` call take longer than the age of the universe. Any
corpus containing a long uniform-character line (a minified bundle, a base64 blob, an ASCII
banner -- all common in real repos) combined with such a pattern would hang the process with
no recourse.

Two defenses are applied, in order:

1. **Compile-time shape rejection** (see ``leitir.search.Predicate.__post_init__``, which
   calls :func:`has_catastrophic_shape`): the textbook catastrophic shape is a quantified
   group nested inside another quantifier, e.g. ``(a+)+``, ``(a*)+``, ``([a-z]+)*``. This is a
   heuristic scan over the pattern *text* itself (not the corpus content), so it costs nothing
   measurable and rejects the disclosed proof-of-concept, and the wider well-known family of
   nested-quantifier ReDoS patterns, before a single byte of the corpus is scanned. It is
   deliberately simple (no nested-paren support) so the heuristic itself can never become
   slow; it is a first line of defense, not a complete ReDoS detector.

2. **A per-line length cap** (:func:`bounded_matching_lines`), as a backstop for shapes the
   heuristic misses (via alternation, for example, or a ``signature:`` value, which is not
   regex-shape-checked at construction time the way ``regex:`` is). Backtracking blowup is a
   function of input length, so refusing to run a regex-family predicate against a line longer
   than the cap bounds the worst case for *any* pattern, not just ones we recognize.

   This is a length cap rather than a time-based budget on purpose: CPython's ``re`` engine
   does not release the GIL while matching, so a background-thread-plus-timeout ("run the
   match on a thread, stop waiting after N seconds") does not actually work here -- the
   runaway match holds the GIL for its entire (potentially unbounded) duration and starves
   every other thread in the process, including the one meant to be enforcing the timeout.
   A dedicated subprocess per match *would* work (a killed OS process reliably reclaims its
   CPU), but spawning one per line, or even per file, is prohibitively expensive at corpus
   scale -- particularly on Windows, where process creation is far more expensive than
   POSIX ``fork``. A length cap needs no interruption mechanism at all: it is a cheap,
   deterministic check made *before* ``re.search`` is ever called, so it is exactly as fast
   and portable as the matching it protects.

   4096 characters is comfortably beyond any line QA's byte-exact grep-parity corpora
   exercised (ordinary source lines run to a few hundred characters at most), so ordinary
   matches are completely unaffected; only the extreme case the bug report itself calls out
   -- a minified bundle or base64 blob crammed onto one line -- is skipped. A skip is always
   reported as an incomplete result (see ``RegexBudgetExceeded`` and the adapters'
   ``parser_unavailable`` handling), never silently.

Neither layer is a mathematical guarantee against every conceivable catastrophic pattern (that
would require either a non-backtracking engine such as RE2, which is a new dependency this
project disallows, or a forced-preemption mechanism this module cannot portably provide). They
are deliberately chosen, low-cost, honestly-scoped mitigations for the concrete, disclosed risk.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# Beyond this many characters, a single line is not run through re.search() for a
# regex-family predicate at all. See the module docstring for why this is a length cap
# rather than a time-based interruption.
MAX_REGEX_LINE_LENGTH = 4096

# A parenthesized group containing its own `+`, `*`, or `{m,n}` repeat, immediately wrapped by
# another repeat -- the classic catastrophic-backtracking shape (`(a+)+`, `(a*)+`,
# `([a-z]+){2,}`, ...).
_INNER_REPEAT = r"(?:[+*]|\{\d*,\d*\})"
_CATASTROPHIC_SHAPE = re.compile(r"\((?:\?:)?[^()]*" + _INNER_REPEAT + r"[^()]*\)" + _INNER_REPEAT)


class RegexRejectedError(ValueError):
    """A pattern's text has a known catastrophic-backtracking shape."""


class RegexBudgetExceeded(Exception):
    """A regex-family predicate skipped one or more lines that exceeded the length cap."""


def has_catastrophic_shape(pattern: str) -> bool:
    """Return whether ``pattern`` contains an obvious nested-quantifier ReDoS shape."""
    return _CATASTROPHIC_SHAPE.search(pattern) is not None


def bounded_matching_lines(
    lines: list[str],
    pattern: re.Pattern[str],
    *,
    extra: Callable[[str], bool] | None = None,
    max_length: int = MAX_REGEX_LINE_LENGTH,
) -> set[int]:
    """Return indices of ``lines`` matched by ``pattern`` (and ``extra``, if given).

    A line longer than ``max_length`` is never handed to ``pattern.search`` -- raises
    :class:`RegexBudgetExceeded` after checking every line so a caller can flag the result
    incomplete rather than silently drop, truncate, or hang on it. Every line at or under the
    cap is matched exactly as before; this is a no-op for ordinary source content.
    """
    hits: set[int] = set()
    skipped = False
    for index, line in enumerate(lines):
        if len(line) > max_length:
            skipped = True
            continue
        if extra is not None and not extra(line):
            continue
        if pattern.search(line):
            hits.add(index)
    if skipped:
        raise RegexBudgetExceeded(
            f"one or more lines exceeded the {max_length}-character regex matching cap"
        )
    return hits


__all__ = [
    "MAX_REGEX_LINE_LENGTH",
    "RegexBudgetExceeded",
    "RegexRejectedError",
    "bounded_matching_lines",
    "has_catastrophic_shape",
]
