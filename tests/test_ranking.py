"""Deterministic ranking tests for ADR-001 P6 / ADR-002 section 7."""

from __future__ import annotations

from itertools import permutations

import pytest

from leitir.ranking import RankedMatch, normalize_scores, rank_matches
from leitir.search import PredicateKind, SourceMatch, SourceRef


SHA_A = "a" * 40
SHA_B = "b" * 40
BLOB_A = "c" * 40
BLOB_B = "d" * 40


def _match(
    *,
    score: float = 1.0,
    slug: str = "a/repo",
    commit_sha: str = SHA_A,
    path: str = "a.py",
    blob_sha: str = BLOB_A,
    start_line: int = 1,
    end_line: int = 1,
) -> SourceMatch:
    return SourceMatch(
        source=SourceRef(
            slug=slug,
            commit_sha=commit_sha,
            path=path,
            blob_sha=blob_sha,
            start_line=start_line,
            end_line=end_line,
        ),
        score=score,
        matched_kinds=(PredicateKind.IDENTIFIER,),
    )


def test_min_max_normalization_is_stable_and_bounded():
    matches = (
        _match(score=-5.0, path="low.py"),
        _match(score=0.0, path="mid.py"),
        _match(score=5.0, path="high.py"),
    )
    assert normalize_scores(matches) == (0.0, 0.5, 1.0)


def test_constant_scores_normalize_to_one():
    matches = (_match(path="a.py"), _match(path="b.py"))
    assert normalize_scores(matches) == (1.0, 1.0)


def test_empty_population_normalizes_to_empty():
    assert normalize_scores(()) == ()


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_scores_are_rejected(score):
    with pytest.raises(ValueError, match="finite"):
        rank_matches((_match(score=score),))


def test_exact_adr_total_order_breaks_every_equal_score_tie():
    matches = (
        _match(slug="b/repo"),
        _match(slug="a/repo", commit_sha=SHA_B),
        _match(path="b.py"),
        _match(blob_sha=BLOB_B),
        _match(start_line=2, end_line=2),
        _match(end_line=2),
        _match(),
    )
    ranked = rank_matches(matches)
    assert [item.result_id for item in ranked] == sorted(
        (
            match.source.slug,
            match.source.commit_sha,
            match.source.path,
            match.source.blob_sha,
            match.source.start_line,
            match.source.end_line,
        )
        for match in matches
    )


def test_higher_normalized_score_precedes_provenance():
    ranked = rank_matches(
        (
            _match(score=1.0, slug="a/repo"),
            _match(score=2.0, slug="z/repo"),
        )
    )
    assert [item.source.slug for item in ranked] == ["z/repo", "a/repo"]
    assert [item.normalized_score for item in ranked] == [1.0, 0.0]


def test_every_input_permutation_has_identical_ranked_output():
    matches = (
        _match(score=3.0, path="z.py"),
        _match(score=3.0, path="a.py"),
        _match(score=1.0, path="m.py"),
    )
    expected = [item.to_dict() for item in rank_matches(matches)]
    for permutation in permutations(matches):
        assert [item.to_dict() for item in rank_matches(permutation)] == expected


def test_rank_scores_are_unique_positive_and_descending():
    ranked = rank_matches(
        tuple(_match(score=float(index), path=f"{index}.py") for index in range(5))
    )
    assert [item.rank for item in ranked] == [1, 2, 3, 4, 5]
    assert [item.rank_score for item in ranked] == [5, 4, 3, 2, 1]
    assert len({item.rank_score for item in ranked}) == len(ranked)


def test_duplicate_source_identity_is_rejected():
    with pytest.raises(ValueError, match="duplicate SourceRef"):
        rank_matches((_match(score=2.0), _match(score=1.0)))


def test_ranking_rejects_non_tuple_and_wrong_member_types():
    with pytest.raises(TypeError, match="tuple"):
        rank_matches([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="SourceMatch"):
        rank_matches((object(),))  # type: ignore[arg-type]


def test_ranked_match_validates_normalized_score_and_rank():
    base = _match()
    with pytest.raises(ValueError, match="between 0 and 1"):
        RankedMatch(
            source=base.source,
            score=base.score,
            normalized_score=1.1,
            rank=1,
            rank_score=1,
            matched_kinds=base.matched_kinds,
        )
    with pytest.raises(ValueError, match="rank must be"):
        RankedMatch(
            source=base.source,
            score=base.score,
            normalized_score=1.0,
            rank=0,
            rank_score=1,
            matched_kinds=base.matched_kinds,
        )
