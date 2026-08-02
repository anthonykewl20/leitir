"""Offline unit tests for the scoped-exhaustive engine (ADR-001 P2).

Uses an in-memory fake TreeSource so no network is needed. Covers happy paths,
sad paths, coverage accounting, must_not exclusion, should-boosting, and the
adapter protocol.
"""

from __future__ import annotations

import hashlib

import pytest

from leitir.adapters import PythonAdapter, SpanMatch
from leitir.engine import ScopedSearcher
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
)
from leitir.tree import BlobEntry, TreeSource

SHA = "a" * 40

SAMPLE_PY = """\
import os
from urllib.parse import urlencode

def urlencode(query, doseq=False):
    if doseq:
        return '&'.join(query)
    return str(query)

class Encoder:
    def encode(self, params):
        return urlencode(params, doseq=True)
"""

SAMPLE_OTHER = "just some text\nno python here\n"


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


PY_BLOB_SHA = _blob_sha(SAMPLE_PY.encode())
OTHER_BLOB_SHA = _blob_sha(SAMPLE_OTHER.encode())


class FakeTreeSource:
    def __init__(
        self,
        blobs: dict[str, tuple[BlobEntry, bytes]] | None = None,
        fail_reads: set[str] | None = None,
    ) -> None:
        self._blobs = blobs or {}
        self._fail_reads = fail_reads or set()

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return tuple(entry for entry, _ in self._blobs.values())

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        if blob_sha in self._fail_reads:
            raise OSError("simulated read failure")
        for entry, data in self._blobs.values():
            if entry.blob_sha == blob_sha:
                return data
        raise KeyError(blob_sha)


def _fake_source(**kwargs) -> FakeTreeSource:
    blobs = {
        "parse.py": (
            BlobEntry("Lib/urllib/parse.py", PY_BLOB_SHA, len(SAMPLE_PY)),
            SAMPLE_PY.encode(),
        ),
        "readme.txt": (
            BlobEntry("README.txt", OTHER_BLOB_SHA, len(SAMPLE_OTHER)),
            SAMPLE_OTHER.encode(),
        ),
    }
    return FakeTreeSource(blobs=blobs, **kwargs)


def _searcher(source: FakeTreeSource | None = None) -> ScopedSearcher:
    return ScopedSearcher(
        tree_source=source or _fake_source(),
        adapters=(PythonAdapter(),),
    )


def _spec(**overrides) -> SearchSpec:
    base = dict(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),),
        scopes=(RepoScope("python/cpython", SHA),),
    )
    base.update(overrides)
    return SearchSpec(**base)


class TestHappyPath:
    def test_finds_identifier_in_python_file(self):
        report = _searcher().search(_spec())
        assert len(report.matches) > 0
        assert all(
            m.source.path == "Lib/urllib/parse.py" for m in report.matches
        )

    def test_coverage_is_complete_for_declared_universe(self):
        report = _searcher().search(_spec())
        assert (
            report.coverage.status
            is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        )
        assert report.coverage.files_eligible == 1
        assert report.coverage.files_indexed == 1
        assert report.coverage.files_excluded == 0
        assert report.coverage.incomplete_results is False

    def test_non_python_files_are_not_eligible(self):
        report = _searcher().search(_spec())
        assert report.coverage.files_eligible == 1

    def test_spec_digest_is_threaded_into_report(self):
        spec = _spec()
        report = _searcher().search(spec)
        assert report.spec_digest == spec.digest()

    def test_symbol_definition_finds_def_line(self):
        spec = _spec(
            must=(Predicate(PredicateKind.SYMBOL_DEFINITION, "urlencode"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 1
        assert report.matches[0].source.start_line == 4

    def test_import_predicate_matches_import_lines(self):
        spec = _spec(
            must=(Predicate(PredicateKind.IMPORT, "urlencode"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 1
        assert report.matches[0].source.start_line == 2

    def test_call_predicate_matches_call_sites(self):
        spec = _spec(must=(Predicate(PredicateKind.CALL, "urlencode"),))
        report = _searcher().search(spec)
        lines = {m.source.start_line for m in report.matches}
        assert 6 in lines or 11 in lines

    def test_regex_predicate_works(self):
        spec = _spec(
            must=(Predicate(PredicateKind.REGEX, r"def\s+urlencode"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 1
        assert report.matches[0].source.start_line == 4

    def test_exact_text_predicate(self):
        spec = _spec(
            must=(Predicate(PredicateKind.EXACT_TEXT, "doseq=False"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 1
        assert report.matches[0].source.start_line == 4

    def test_blob_sha_in_source_ref_matches_tree(self):
        report = _searcher().search(_spec())
        assert report.matches[0].source.blob_sha == PY_BLOB_SHA

    def test_commit_sha_in_source_ref_matches_scope(self):
        report = _searcher().search(_spec())
        assert report.matches[0].source.commit_sha == SHA


class TestMustNot:
    def test_must_not_excludes_matching_files(self):
        spec = _spec(
            must_not=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 0

    def test_must_not_on_absent_symbol_keeps_matches(self):
        spec = _spec(
            must_not=(Predicate(PredicateKind.IDENTIFIER, "nonexistent"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) > 0


class TestShould:
    def test_should_boosts_score(self):
        spec_no_should = _spec()
        spec_with_should = _spec(
            should=(Predicate(PredicateKind.IDENTIFIER, "doseq"),)
        )
        r1 = _searcher().search(spec_no_should)
        r2 = _searcher().search(spec_with_should)
        max1 = max(m.score for m in r1.matches)
        max2 = max(m.score for m in r2.matches)
        assert max2 > max1


class TestSadPaths:
    def test_rejects_global_discovery_mode(self):
        spec = SearchSpec(
            mode=SearchMode.GLOBAL_DISCOVERY,
            must=(Predicate(PredicateKind.IDENTIFIER, "x"),),
        )
        with pytest.raises(ValueError, match="scoped_exhaustive"):
            _searcher().search(spec)

    def test_read_failure_marks_partial(self):
        source = _fake_source(fail_reads={PY_BLOB_SHA})
        report = _searcher(source).search(_spec())
        assert report.coverage.status is CoverageStatus.PARTIAL
        assert report.coverage.incomplete_results is True
        assert report.coverage.files_excluded == 1
        assert len(report.matches) == 0

    def test_oversized_blob_is_excluded(self):
        searcher = ScopedSearcher(
            tree_source=_fake_source(),
            adapters=(PythonAdapter(),),
            max_blob_size=10,
        )
        report = searcher.search(_spec())
        assert report.coverage.status is CoverageStatus.PARTIAL
        assert report.coverage.files_excluded == 1
        assert report.coverage.files_indexed == 0

    def test_no_matches_returns_empty_with_complete_coverage(self):
        spec = _spec(
            must=(Predicate(PredicateKind.IDENTIFIER, "zzz_not_here"),)
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 0
        assert (
            report.coverage.status
            is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        )


class TestPathPredicate:
    def test_path_predicate_filters_files(self):
        spec = _spec(
            must=(
                Predicate(PredicateKind.PATH, "urllib"),
                Predicate(PredicateKind.IDENTIFIER, "urlencode"),
            )
        )
        report = _searcher().search(spec)
        assert len(report.matches) > 0
        assert all("urllib" in m.source.path for m in report.matches)

    def test_path_predicate_no_match_yields_empty(self):
        spec = _spec(
            must=(
                Predicate(PredicateKind.PATH, "nonexistent_dir"),
                Predicate(PredicateKind.IDENTIFIER, "urlencode"),
            )
        )
        report = _searcher().search(spec)
        assert len(report.matches) == 0
        assert report.coverage.files_eligible == 0


class TestAdapterProtocol:
    def test_python_adapter_eligible_for_py_files(self):
        adapter = PythonAdapter()
        assert adapter.eligible("foo/bar.py")
        assert not adapter.eligible("foo/bar.rs")
        assert not adapter.eligible("foo/bar.txt")

    def test_python_adapter_language(self):
        assert PythonAdapter().language == "python"

    def test_span_match_validates_lines(self):
        with pytest.raises(ValueError):
            SpanMatch(0, 1, (PredicateKind.IDENTIFIER,))
        with pytest.raises(ValueError):
            SpanMatch(5, 2, (PredicateKind.IDENTIFIER,))
        with pytest.raises(ValueError):
            SpanMatch(1, 1, ())


class TestTreeSourceProtocol:
    def test_fake_satisfies_protocol(self):
        assert isinstance(_fake_source(), TreeSource)

    def test_blob_entry_validates(self):
        with pytest.raises(ValueError):
            BlobEntry("", "a" * 40, 10)
        with pytest.raises(ValueError):
            BlobEntry("x.py", "short", 10)
        with pytest.raises(ValueError):
            BlobEntry("x.py", "a" * 40, -1)
