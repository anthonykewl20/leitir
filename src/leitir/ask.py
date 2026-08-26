"""Task-shaped entry point: compile free text into deterministic predicates.

Issue #266 A3. ``leitir ask`` answers "how do I do X with Y" in one call by
(1) resolving the exact version of a named package from the caller's own
project lockfile -- never from agent-supplied input, never from a registry
"latest" fallback -- and (2) compiling the free-text task description into
the same typed, deterministic predicate kinds ``leitir search`` already
uses.

ADR-001 removed semantic/embedding search. This module does not reintroduce
it: the compilation rule below is a small set of syntactic regexes over the
task text, not a model or a similarity score, and it is stated in full in
``compile_task_predicates``'s docstring so a human can predict its output
and re-run it by hand with ``leitir search``.
"""

from __future__ import annotations

import re

from .search import Predicate, PredicateKind

# A closed set of English function words that are common in a task
# description but are not, on their own, useful search terms. Anything not
# in this list that looks like a code identifier is treated as a candidate.
_STOPWORDS = frozenset(
    {
        "a", "an", "the", "how", "do", "does", "did", "doing", "to", "with",
        "using", "use", "used", "in", "on", "at", "of", "and", "or", "for",
        "from", "is", "are", "was", "were", "be", "been", "can", "could",
        "should", "would", "will", "you", "your", "i", "me", "my", "it",
        "its", "this", "that", "these", "those", "what", "when", "where",
        "why", "which", "who", "please", "task", "need", "needs", "want",
        "wants", "like", "via", "by", "as", "into", "onto", "not", "new",
        "one", "if", "then", "else", "so", "up", "out", "about",
        "get", "set", "make", "run", "call", "code", "example", "examples",
    }
)

# A code-shaped token: a dotted identifier path such as ``requests.get`` or
# ``connect``. Punctuation, whitespace, and quoting are never part of a
# token.
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
# A single- or double-quoted literal in the task text, taken verbatim as an
# exact-text predicate (e.g. a flag name, an error message, a file mode).
_QUOTED = re.compile(r"'([^'\n]{1,200})'|\"([^\"\n]{1,200})\"")

_MIN_IDENTIFIER_LENGTH = 3


def compile_task_predicates(task: str) -> tuple[Predicate, ...]:
    """Deterministically compile a free-text task into ``must`` predicates.

    The rule, in full:

    1. Every single- or double-quoted substring in ``task`` becomes an
       ``exact_text`` predicate, verbatim, in order of first appearance.
    2. Every token matching ``[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*``
       that is immediately followed by ``(`` (a call-shaped token, e.g.
       ``requests.get(``) becomes a ``call`` predicate on the token (without
       the parenthesis), in order of first appearance.
    3. If steps 1 and 2 together produced no predicate, every remaining
       token of at least 3 characters whose final dotted segment is not in
       a fixed, closed stopword list of common English function words (see
       ``_STOPWORDS``) is a candidate. The single strongest candidate --
       longest first, ties broken lexicographically -- becomes one
       ``identifier`` predicate.
    4. If no candidate survives step 3 either, the task cannot be compiled:
       this function returns an empty tuple and the caller must say so
       rather than guess.

    Every predicate produced here is exactly what ``leitir search --must
    <kind>:<value>`` would accept, so the compiled query is always
    inspectable and re-runnable by hand.
    """

    predicates: list[Predicate] = []
    seen: set[tuple[PredicateKind, str]] = set()

    def add(kind: PredicateKind, value: str) -> None:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            predicates.append(Predicate(kind=kind, value=value))

    for match in _QUOTED.finditer(task):
        literal = match.group(1) if match.group(1) is not None else match.group(2)
        if literal and literal.strip():
            add(PredicateKind.EXACT_TEXT, literal)

    call_candidates: list[str] = []
    identifier_candidates: list[str] = []
    for match in _TOKEN.finditer(task):
        token = match.group(0)
        is_call = match.end() < len(task) and task[match.end()] == "("
        final_segment = token.rsplit(".", 1)[-1].lower()
        if is_call:
            call_candidates.append(token)
        elif len(token) >= _MIN_IDENTIFIER_LENGTH and final_segment not in _STOPWORDS:
            identifier_candidates.append(token)

    for token in call_candidates:
        add(PredicateKind.CALL, token)

    if not predicates and identifier_candidates:
        best = min(identifier_candidates, key=lambda token: (-len(token), token))
        add(PredicateKind.IDENTIFIER, best)

    return tuple(predicates)


def rerun_search_command(
    *,
    package: str,
    version: str,
    ecosystem: str,
    predicates: tuple[Predicate, ...],
) -> str:
    """A literal ``leitir search`` invocation reproducing the compiled query."""

    parts = [
        "leitir", "search",
        "--package", package,
        "--version", version,
        "--ecosystem", ecosystem,
    ]
    for predicate in predicates:
        value = f"{predicate.kind.value}:{predicate.value}"
        parts.extend(["--must", value])
    return " ".join(_shell_quote(part) for part in parts)


def _shell_quote(value: str) -> str:
    if value and all(
        character.isalnum() or character in "-_.:/@" for character in value
    ):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


__all__ = ["compile_task_predicates", "rerun_search_command"]
