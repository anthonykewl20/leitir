"""ReDoS protection for regex-family predicates (leitir._regex_budget)."""

from __future__ import annotations

import re
import time

import pytest

from leitir._regex_budget import (
    MAX_REGEX_LINE_LENGTH,
    RegexBudgetExceeded,
    bounded_matching_lines,
    has_catastrophic_shape,
)


def test_has_catastrophic_shape_flags_nested_quantifiers():
    assert has_catastrophic_shape(r"(a+)+$")
    assert has_catastrophic_shape(r"(a*)+")
    assert has_catastrophic_shape(r"([a-z]+)*")
    assert has_catastrophic_shape(r"(x{2,4})+")


def test_has_catastrophic_shape_allows_ordinary_patterns():
    assert not has_catastrophic_shape(r"(ab)+c")
    assert not has_catastrophic_shape(r"(?:foo|bar)+")
    assert not has_catastrophic_shape(r"\d{2,4}-\d{2,4}")
    assert not has_catastrophic_shape(r"def \w+\(")


def test_bounded_matching_lines_finds_ordinary_matches_unaffected():
    lines = ["def foo():", "    return 1", "class Bar:", "    pass"]
    hits = bounded_matching_lines(lines, re.compile(r"def \w+"))
    assert hits == {0}


def test_bounded_matching_lines_respects_extra_predicate():
    lines = ["def foo():", "x = def", "class Bar(def):"]
    hits = bounded_matching_lines(
        lines, re.compile(r"def"), extra=lambda line: line.startswith(("def ", "class "))
    )
    assert hits == {0, 2}


def test_bounded_matching_lines_terminates_on_pattern_that_evades_the_shape_check():
    """ReDoS regression: a shape the compile-time heuristic misses (here, via alternation)
    must still not hang the process when matched against a long, repetitive line -- the
    length cap must stop it from ever reaching re.search at all.
    """
    pattern_text = r"^(a|a)*b"
    assert not has_catastrophic_shape(pattern_text)  # confirms this exercises the backstop
    pattern = re.compile(pattern_text)
    long_line = "a" * (MAX_REGEX_LINE_LENGTH + 1)
    lines = ["short line", long_line, "another short line"]

    start = time.monotonic()
    with pytest.raises(RegexBudgetExceeded):
        bounded_matching_lines(lines, pattern)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"regex matching was not bounded: took {elapsed:.2f}s"


def test_bounded_matching_lines_at_exactly_the_cap_is_unaffected():
    line = "a" * (MAX_REGEX_LINE_LENGTH - 1) + "!"
    assert len(line) == MAX_REGEX_LINE_LENGTH
    hits = bounded_matching_lines([line], re.compile(r"!$"))
    assert hits == {0}


def test_bounded_matching_lines_over_the_cap_raises_even_without_a_dangerous_pattern():
    # The cap is a blanket bound on what gets matched, not conditional on pattern shape --
    # an over-length line is always reported incomplete, never silently skipped.
    line = "a" * (MAX_REGEX_LINE_LENGTH + 1)
    with pytest.raises(RegexBudgetExceeded):
        bounded_matching_lines([line], re.compile(r"a"))
