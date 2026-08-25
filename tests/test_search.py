"""Invariants of the deterministic code-search contracts (ADR-001)."""

from __future__ import annotations

import pytest

from leitir.search import (
    Coverage,
    CoverageStatus,
    Predicate,
    PredicateKind,
    QueryTranslation,
    RepoScope,
    Resolution,
    ResolutionStrategy,
    SearchMode,
    SearchReport,
    SearchSpec,
    SearchSpecError,
    SourceMatch,
    SourceRef,
)

SHA = "a" * 40
BLOB = "b" * 40


def _spec(**overrides):
    base = {
        "mode": SearchMode.SCOPED_EXHAUSTIVE,
        "must": (Predicate(PredicateKind.IDENTIFIER, "urlencode"),),
        "scopes": (RepoScope("python/cpython", SHA),),
    }
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


@pytest.mark.parametrize(
    ("mode", "scopes"),
    (
        (SearchMode.GLOBAL_DISCOVERY, ()),
        (SearchMode.SCOPED_EXHAUSTIVE, (RepoScope("python/cpython", SHA),)),
    ),
)
def test_spec_rejects_conflicting_canonical_required_languages(mode, scopes):
    with pytest.raises(
        SearchSpecError, match="conflicting required predicate languages"
    ):
        SearchSpec(
            mode=mode,
            must=(
                Predicate(PredicateKind.IDENTIFIER, "first", "js"),
                Predicate(PredicateKind.IDENTIFIER, "second", "python"),
            ),
            scopes=scopes,
        )


@pytest.mark.parametrize(
    ("mode", "scopes"),
    (
        (SearchMode.GLOBAL_DISCOVERY, ()),
        (SearchMode.SCOPED_EXHAUSTIVE, (RepoScope("python/cpython", SHA),)),
    ),
)
def test_spec_accepts_alias_equivalent_required_languages(mode, scopes):
    spec = SearchSpec(
        mode=mode,
        must=(
            Predicate(PredicateKind.IDENTIFIER, "first", "js"),
            Predicate(PredicateKind.IDENTIFIER, "second", "javascript"),
        ),
        scopes=scopes,
    )
    assert len(spec.must) == 2


def test_invalid_commit_sha_is_rejected():
    with pytest.raises(ValueError):
        RepoScope("python/cpython", "not-a-sha")


def test_invalid_slug_is_rejected():
    with pytest.raises(ValueError):
        RepoScope("no-slash", SHA)
    with pytest.raises(ValueError):
        RepoScope("group/../repo", SHA)


def test_source_ref_rejects_unsafe_slug_segments():
    with pytest.raises(ValueError):
        SourceRef("group/../repo", SHA, "x.py", BLOB, 1, 2)
    with pytest.raises(ValueError):
        SourceRef("a/./b", SHA, "x.py", BLOB, 1, 2)


def test_regex_predicate_must_compile():
    with pytest.raises(ValueError):
        Predicate(PredicateKind.REGEX, "([")


def test_regex_predicate_rejects_catastrophic_backtracking_shape():
    """ReDoS regression: a nested-quantifier pattern is rejected at spec-construction time,
    before it is ever run against any corpus content, so this terminates instantly rather
    than hanging.
    """
    with pytest.raises(ValueError, match="catastrophic-backtracking"):
        Predicate(PredicateKind.REGEX, r"(a+)+$")
    with pytest.raises(ValueError, match="catastrophic-backtracking"):
        Predicate(PredicateKind.REGEX, r"([a-z]*)+")


def test_regex_predicate_allows_ordinary_nested_groups():
    """A group repeat is only rejected when the group's own content also repeats."""
    Predicate(PredicateKind.REGEX, r"(ab)+c")
    Predicate(PredicateKind.REGEX, r"(?:foo|bar)+")
    Predicate(PredicateKind.REGEX, r"\d{2,4}-\d{2,4}")


def test_spec_digest_is_stable_and_order_sensitive():
    assert _spec().digest() == _spec().digest()
    other = _spec(must=(Predicate(PredicateKind.IDENTIFIER, "doseq"),))
    assert _spec().digest() != other.digest()


def test_whole_file_must_is_validated_and_changes_digest():
    assert _spec().digest() != _spec(whole_file_must=True).digest()
    with pytest.raises(TypeError, match="whole_file_must must be bool"):
        _spec(whole_file_must=1)


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


def test_coverage_rejects_exclusion_breakdown_over_total():
    with pytest.raises(ValueError, match="cannot exceed"):
        Coverage(
            CoverageStatus.PARTIAL,
            files_eligible=10,
            files_indexed=5,
            files_excluded=1,
            exclusions={"no_adapter": 2},
        )


@pytest.mark.parametrize(
    "exclusions",
    [
        {1: 1},
        {"fetch_failed": True},
        {"fetch_failed": -1},
        {"unknown_reason": 1},
    ],
)
def test_coverage_rejects_invalid_exclusion_breakdown(exclusions):
    with pytest.raises((TypeError, ValueError)):
        Coverage(
            CoverageStatus.PARTIAL,
            files_eligible=10,
            files_indexed=5,
            files_excluded=1,
            exclusions=exclusions,
        )


def test_coverage_serializes_exclusions_deterministically():
    coverage = Coverage(
        CoverageStatus.PARTIAL,
        files_eligible=10,
        files_indexed=5,
        files_excluded=2,
        exclusions={"provenance_mismatch": 1, "decode_failed": 1},
    )

    assert list(coverage.to_dict()["exclusions"]) == [
        "decode_failed",
        "provenance_mismatch",
    ]


def test_report_round_trip_holds():
    ref = SourceRef("python/cpython", SHA, "x.py", BLOB, 1, 2)
    match = SourceMatch(ref, 1.0, (PredicateKind.IDENTIFIER,))
    coverage = Coverage(
        CoverageStatus.PARTIAL,
        files_eligible=10,
        files_indexed=9,
        files_excluded=1,
    )
    report = SearchReport(
        _spec().digest(),
        coverage,
        (match,),
        Resolution(ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"),
    )
    assert report.matches[0].source is ref


def test_query_translation_serializes_machine_readable_disposition():
    translation = QueryTranslation(
        clause="must",
        predicate_index=0,
        kind=PredicateKind.IDENTIFIER,
        strategy="github_query",
        emitted_syntax="urlencode",
    )
    assert translation.to_dict() == {
        "clause": "must",
        "predicate_index": 0,
        "kind": "identifier",
        "strategy": "github_query",
        "emitted_syntax": "urlencode",
    }
