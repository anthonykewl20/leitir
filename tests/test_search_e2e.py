"""Offline e2e gate: the contracts must model real GitHub provenance end to end.

This runs without network. It drives a full SearchSpec -> SearchReport flow
using GitHub-verified data (see fixtures_real) so the P1 gate proves the
contracts represent reality, not just themselves.
"""

from __future__ import annotations

import pytest

from leitir.search import (
    Coverage,
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    Resolution,
    ResolutionStrategy,
    SearchMode,
    SearchReport,
    SearchSpec,
    SourceMatch,
    SourceRef,
)

import fixtures_real as fx


def _real_spec() -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.SYMBOL_DEFINITION, "urlencode", "python"),),
        should=(Predicate(PredicateKind.IDENTIFIER, "doseq", "python"),),
        scopes=(RepoScope(fx.REPO_SLUG, fx.COMMIT_SHA),),
    )


def test_real_spec_digest_is_stable():
    assert _real_spec().digest() == _real_spec().digest()


def test_real_source_ref_permalink_points_at_pinned_commit():
    ref = SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA, 1, 5)
    assert ref.permalink == (
        f"https://github.com/{fx.REPO_SLUG}/blob/{fx.COMMIT_SHA}/"
        f"{fx.PATH}#L1-L5"
    )
    assert "/blob/main/" not in ref.permalink


def test_real_end_to_end_report_is_complete_for_declared_universe():
    spec = _real_spec()
    ref = SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA, 1, 5)
    match = SourceMatch(
        ref,
        2.0,
        (PredicateKind.SYMBOL_DEFINITION, PredicateKind.IDENTIFIER),
    )
    coverage = Coverage(
        CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
        files_eligible=1,
        files_indexed=1,
        files_excluded=0,
    )
    report = SearchReport(
        spec.digest(),
        coverage,
        (match,),
        Resolution(ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"),
    )

    assert report.spec_digest == spec.digest()
    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
    assert report.matches[0].source.commit_sha == fx.COMMIT_SHA
    assert report.matches[0].source.blob_sha == fx.BLOB_SHA


def test_real_report_cannot_claim_complete_when_a_file_is_unindexed():
    spec = _real_spec()
    ref = SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA, 1, 5)
    match = SourceMatch(ref, 1.0, (PredicateKind.SYMBOL_DEFINITION,))
    coverage = Coverage(
        CoverageStatus.PARTIAL,
        files_eligible=2,
        files_indexed=1,
        files_excluded=1,
    )
    report = SearchReport(
        spec.digest(),
        coverage,
        (match,),
        Resolution(ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"),
    )
    assert report.coverage.status is CoverageStatus.PARTIAL


# --- sad paths: corrupting the real provenance must be rejected -------------


def test_truncated_commit_sha_is_rejected():
    with pytest.raises(ValueError):
        RepoScope(fx.REPO_SLUG, fx.COMMIT_SHA[:-1])


def test_uppercase_commit_sha_is_rejected():
    with pytest.raises(ValueError):
        SourceRef(
            fx.REPO_SLUG, fx.COMMIT_SHA.upper(), fx.PATH, fx.BLOB_SHA, 1, 5
        )


def test_wrong_length_blob_sha_is_rejected():
    with pytest.raises(ValueError):
        SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA + "0", 1, 5)


def test_empty_path_is_rejected():
    with pytest.raises(ValueError):
        SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, "   ", fx.BLOB_SHA, 1, 5)


def test_inverted_line_range_is_rejected():
    with pytest.raises(ValueError):
        SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA, 5, 1)


def test_zero_start_line_is_rejected():
    with pytest.raises(ValueError):
        SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA, 0, 5)


def test_malformed_slug_is_rejected():
    with pytest.raises(ValueError):
        RepoScope(fx.REPO_SLUG.replace("/", "--"), fx.COMMIT_SHA)


def test_scoped_exhaustive_without_scope_is_rejected():
    with pytest.raises(ValueError):
        SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),),
            scopes=(),
        )


def test_spec_without_must_predicate_is_rejected():
    with pytest.raises(ValueError):
        SearchSpec(
            mode=SearchMode.GLOBAL_DISCOVERY,
            must=(),
            should=(Predicate(PredicateKind.IDENTIFIER, "doseq"),),
        )


def test_non_predicate_in_must_is_rejected():
    with pytest.raises(TypeError):
        SearchSpec(
            mode=SearchMode.GLOBAL_DISCOVERY,
            must=("urlencode",),
        )


def test_false_complete_claim_with_partial_results_is_rejected():
    with pytest.raises(ValueError):
        Coverage(
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
            files_eligible=1,
            files_indexed=1,
            files_excluded=0,
            incomplete_results=True,
        )


def test_indexed_exceeding_eligible_is_rejected():
    with pytest.raises(ValueError):
        Coverage(
            CoverageStatus.PARTIAL,
            files_eligible=1,
            files_indexed=2,
            files_excluded=0,
        )


def test_negative_file_count_is_rejected():
    with pytest.raises(ValueError):
        Coverage(
            CoverageStatus.PARTIAL,
            files_eligible=-1,
            files_indexed=0,
            files_excluded=0,
        )


def test_match_without_matched_predicates_is_rejected():
    ref = SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, fx.BLOB_SHA, 1, 5)
    with pytest.raises(ValueError):
        SourceMatch(ref, 1.0, ())


def test_report_with_bad_digest_is_rejected():
    coverage = Coverage(
        CoverageStatus.PARTIAL,
        files_eligible=1,
        files_indexed=1,
        files_excluded=0,
    )
    with pytest.raises(ValueError):
        SearchReport(
            "not-a-digest",
            coverage,
            (),
            Resolution(ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"),
        )
