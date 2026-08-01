"""Invariants of the deterministic code-search contracts (ADR-001)."""

from __future__ import annotations

import pytest

from leitir.search import (
    Coverage,
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchReport,
    SearchSpec,
    SourceMatch,
    SourceRef,
)


SHA = "a" * 40
BLOB = "b" * 40


def _spec(**overrides):
    base = dict(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),),
        scopes=(RepoScope("python/cpython", SHA),),
    )
    base.update(overrides)
    return SearchSpec(**base)


def test_spec_requires_a_must_predicate():
    with pytest.raises(ValueError):
        _spec(must=())


def test_scoped_exhaustive_requires_a_scope():
    with pytest.raises(ValueError):
        _spec(scopes=())


def test_global_discovery_allows_no_scope():
    spec = _spec(mode=SearchMode.GLOBAL_DISCOVERY, scopes=())
    assert spec.mode is SearchMode.GLOBAL_DISCOVERY


def test_invalid_commit_sha_is_rejected():
    with pytest.raises(ValueError):
        RepoScope("python/cpython", "not-a-sha")


def test_invalid_slug_is_rejected():
    with pytest.raises(ValueError):
        RepoScope("no-slash", SHA)


def test_regex_predicate_must_compile():
    with pytest.raises(ValueError):
        Predicate(PredicateKind.REGEX, "([")


def test_spec_digest_is_stable_and_order_sensitive():
    assert _spec().digest() == _spec().digest()
    other = _spec(must=(Predicate(PredicateKind.IDENTIFIER, "doseq"),))
    assert _spec().digest() != other.digest()


def test_source_ref_permalink_uses_commit_not_branch():
    ref = SourceRef("python/cpython", SHA, "Lib/urllib/parse.py", BLOB, 10, 20)
    assert f"/blob/{SHA}/" in ref.permalink
    assert "#L10-L20" in ref.permalink


def test_source_ref_rejects_bad_line_range():
    with pytest.raises(ValueError):
        SourceRef("python/cpython", SHA, "x.py", BLOB, 20, 10)


def test_match_requires_a_matched_predicate():
    ref = SourceRef("python/cpython", SHA, "x.py", BLOB, 1, 2)
    with pytest.raises(ValueError):
        SourceMatch(ref, 1.0, ())


def test_complete_coverage_requires_full_indexing():
    with pytest.raises(ValueError):
        Coverage(
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
            files_eligible=10,
            files_indexed=9,
            files_excluded=0,
        )


def test_complete_coverage_rejects_partial_results():
    with pytest.raises(ValueError):
        Coverage(
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
            files_eligible=10,
            files_indexed=10,
            files_excluded=0,
            incomplete_results=True,
        )


def test_report_round_trip_holds():
    ref = SourceRef("python/cpython", SHA, "x.py", BLOB, 1, 2)
    match = SourceMatch(ref, 1.0, (PredicateKind.IDENTIFIER,))
    coverage = Coverage(
        CoverageStatus.PARTIAL,
        files_eligible=10,
        files_indexed=9,
        files_excluded=1,
    )
    report = SearchReport(_spec().digest(), coverage, (match,))
    assert report.matches[0].source is ref
