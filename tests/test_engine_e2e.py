"""Offline e2e gate for the scoped-exhaustive engine (ADR-001 P2).

Runs without network. Drives a full SearchSpec -> ScopedSearcher -> SearchReport
flow using the real GitHub-verified provenance from fixtures_real, served by an
in-memory tree source. Proves the engine threads real commit/blob/path provenance
correctly and reports honest coverage.
"""

from __future__ import annotations

import fixtures_real as fx
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
from leitir.tree import BlobEntry

REPRESENTATIVE_CONTENT = """\
def urlencode(query, doseq=False, safe='', encoding=None, errors=None,
              quote_via=quote_plus):
    if doseq:
        for k, v in query:
            if isinstance(v, (str, bytes)):
                v = quote_via(v, safe, encoding, errors)
            else:
                v = quote_via(str(v), safe, encoding, errors)
            l.append(k + '=' + v)
    else:
        if isinstance(query, bytes):
            query = query.decode(encoding, errors)
        query = quote_via(query, safe, encoding, errors)
    return '&'.join(l)
"""


class _RealFixtureTree:
    """Serves the real fixture blob offline."""

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        assert slug == fx.REPO_SLUG
        assert commit_sha == fx.COMMIT_SHA
        return (
            BlobEntry(fx.PATH, fx.BLOB_SHA, fx.BLOB_SIZE),
            BlobEntry("README.rst", "c" * 40, 100),
        )

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        if blob_sha == fx.BLOB_SHA:
            return REPRESENTATIVE_CONTENT.encode()
        return b"not python"


def _searcher() -> ScopedSearcher:
    return ScopedSearcher(
        tree_source=_RealFixtureTree(),
        adapters=(PythonAdapter(),),
    )


def _spec(**overrides) -> SearchSpec:
    base = dict(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.SYMBOL_DEFINITION, "urlencode", "python"),),
        should=(Predicate(PredicateKind.IDENTIFIER, "doseq", "python"),),
        scopes=(RepoScope(fx.REPO_SLUG, fx.COMMIT_SHA),),
    )
    base.update(overrides)
    return SearchSpec(**base)


class TestRealProvenanceHappyPath:
    def test_report_carries_real_commit_sha(self):
        report = _searcher().search(_spec())
        assert len(report.matches) > 0
        assert report.matches[0].source.commit_sha == fx.COMMIT_SHA

    def test_report_carries_real_blob_sha(self):
        report = _searcher().search(_spec())
        assert report.matches[0].source.blob_sha == fx.BLOB_SHA

    def test_report_carries_real_path(self):
        report = _searcher().search(_spec())
        assert report.matches[0].source.path == fx.PATH

    def test_report_carries_real_slug(self):
        report = _searcher().search(_spec())
        assert report.matches[0].source.slug == fx.REPO_SLUG

    def test_permalink_points_at_pinned_commit(self):
        report = _searcher().search(_spec())
        permalink = report.matches[0].source.permalink
        assert f"/blob/{fx.COMMIT_SHA}/" in permalink
        assert fx.PATH in permalink
        assert "/blob/main/" not in permalink

    def test_finds_symbol_definition_at_line_one(self):
        report = _searcher().search(_spec())
        defs = [
            m for m in report.matches
            if PredicateKind.SYMBOL_DEFINITION in m.matched_kinds
        ]
        assert len(defs) == 1
        assert defs[0].source.start_line == 1

    def test_should_boosts_score_on_doseq_lines(self):
        report = _searcher().search(_spec())
        def_match = report.matches[0]
        assert def_match.score >= 2.0

    def test_coverage_is_complete_for_declared_universe(self):
        report = _searcher().search(_spec())
        assert (
            report.coverage.status
            is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        )
        assert report.coverage.files_eligible == 1
        assert report.coverage.files_indexed == 1
        assert report.coverage.files_excluded == 0

    def test_spec_digest_is_stable(self):
        assert _spec().digest() == _spec().digest()

    def test_report_digest_matches_spec(self):
        spec = _spec()
        report = _searcher().search(spec)
        assert report.spec_digest == spec.digest()


class TestRealProvenanceSadPaths:
    def test_wrong_commit_sha_rejected_at_spec_level(self):
        with pytest.raises(ValueError):
            RepoScope(fx.REPO_SLUG, fx.COMMIT_SHA[:-1])

    def test_wrong_blob_sha_rejected_at_source_ref_level(self):
        from leitir.search import SourceRef

        with pytest.raises(ValueError):
            SourceRef(fx.REPO_SLUG, fx.COMMIT_SHA, fx.PATH, "x" * 40, 1, 5)

    def test_no_match_for_absent_symbol_still_complete(self):
        spec = _spec(
            must=(Predicate(PredicateKind.IDENTIFIER, "zzz_absent"),),
            should=(),
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 0
        assert (
            report.coverage.status
            is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        )

    def test_must_not_excludes_all_matches(self):
        spec = _spec(
            must_not=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),),
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 0

    def test_global_discovery_mode_rejected(self):
        spec = SearchSpec(
            mode=SearchMode.GLOBAL_DISCOVERY,
            must=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),),
        )
        with pytest.raises(ValueError, match="scoped_exhaustive"):
            _searcher().search(spec)
