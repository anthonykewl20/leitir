"""Opt-in live gate for the scoped-exhaustive engine (ADR-001 P2).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Drives the real GitHubTreeSource
against python/cpython@v3.11.0 and verifies the engine finds the known symbols
with correct provenance. Includes a sad path with a corrupted commit.
"""

from __future__ import annotations

import os

import pytest

from leitir.adapters import PythonAdapter
from leitir.engine import ScopedSearcher
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
)
from leitir.tree import GitHubTreeSource, TreeTruncatedError

import fixtures_real as fx

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
)


def _token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def _searcher() -> ScopedSearcher:
    return ScopedSearcher(
        tree_source=GitHubTreeSource(token=_token()),
        adapters=(PythonAdapter(),),
    )


def _spec(**overrides) -> SearchSpec:
    base = dict(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(
            Predicate(PredicateKind.PATH, "Lib/urllib/parse.py"),
            Predicate(PredicateKind.SYMBOL_DEFINITION, "urlencode", "python"),
        ),
        should=(Predicate(PredicateKind.IDENTIFIER, "doseq", "python"),),
        scopes=(RepoScope(fx.REPO_SLUG, fx.COMMIT_SHA),),
    )
    base.update(overrides)
    return SearchSpec(**base)


def test_live_engine_finds_urlencode_definition():
    report = _searcher().search(_spec())
    assert len(report.matches) > 0
    top = report.matches[0]
    assert top.source.slug == fx.REPO_SLUG
    assert top.source.commit_sha == fx.COMMIT_SHA
    assert top.source.path == fx.PATH
    assert top.source.blob_sha == fx.BLOB_SHA
    assert PredicateKind.SYMBOL_DEFINITION in top.matched_kinds


def test_live_permalink_is_immutable():
    report = _searcher().search(_spec())
    permalink = report.matches[0].source.permalink
    assert f"/blob/{fx.COMMIT_SHA}/" in permalink
    assert "/blob/main/" not in permalink


def test_live_coverage_is_honest():
    report = _searcher().search(_spec())
    assert report.coverage.files_eligible >= 1
    assert report.coverage.files_indexed >= 1
    assert report.coverage.files_indexed <= report.coverage.files_eligible
    if report.coverage.files_indexed == report.coverage.files_eligible:
        assert (
            report.coverage.status
            is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        )


def test_live_known_symbols_present_in_blob():
    source = GitHubTreeSource(token=_token())
    data = source.read_blob_by_path(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH)
    for symbol in fx.KNOWN_SYMBOLS:
        assert symbol.encode() in data


def test_live_corrupted_commit_yields_no_results():
    bad_sha = "0" * 40
    spec = _spec(scopes=(RepoScope(fx.REPO_SLUG, bad_sha),))
    with pytest.raises(Exception):
        _searcher().search(spec)
