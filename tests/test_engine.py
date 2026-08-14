"""Offline unit tests for the scoped-exhaustive engine (ADR-001 P2).

Uses an in-memory fake TreeSource so no network is needed. Covers happy paths,
sad paths, coverage accounting, must_not exclusion, should-boosting, and the
adapter protocol.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from itertools import permutations
from pathlib import Path

import pytest
from _http_server import json_body, routed_server

from leitir.adapters import PythonAdapter, RustAdapter, SpanMatch
from leitir.engine import ScopedSearcher, score_content
from leitir.materialize import (
    VerificationError,
    manifest_digest_fields,
    target_path,
)
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
    SearchSpecError,
)
from leitir.tree import BlobEntry, GitHubTreeSource, TreeSource

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
        self.list_calls = 0
        self.read_calls: list[str] = []

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        self.list_calls += 1
        return tuple(entry for entry, _ in self._blobs.values())

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return self.list_blobs(slug, commit_sha), False

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        self.read_calls.append(blob_sha)
        if blob_sha in self._fail_reads:
            raise OSError("simulated read failure")
        for entry, data in self._blobs.values():
            if entry.blob_sha == blob_sha:
                return data
        raise KeyError(blob_sha)

    def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
        yield self.read_blob(slug, blob_sha)


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


def _write_shelf(
    root: Path, *, files: dict[str, bytes], commit_sha: str = SHA
) -> Path:
    from leitir.treehash import compute_materialized_tree_hash

    target = target_path(root, "python", "cpython", commit_sha)
    target.mkdir(parents=True)
    for relative, data in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    digest, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": commit_sha,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-14T00:00:00Z",
        "host": "github.com",
        "owner": "python",
        "repo": "cpython",
        "repo_url": "https://github.com/python/cpython",
        "source": "git-commit",
        "spec": "github:python/cpython",
        "tag": None,
        "verified": True,
        "verified_at": "2026-08-14T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / "leitir-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return target


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

    def test_report_order_and_identity_are_input_order_independent(self, monkeypatch):
        monkeypatch.setattr("leitir.engine._utc_now", lambda: "2026-08-06T12:00:00Z")
        contents = {
            "z.py": b"def urlencode(doseq=False):\n    pass\n",
            "a.py": b"def urlencode():\n    return None\n",
        }
        entries = tuple(
            (
                BlobEntry(path, _blob_sha(content), len(content)),
                content,
            )
            for path, content in contents.items()
        )
        reports = []
        for permutation in permutations(entries):
            source = FakeTreeSource(
                blobs={entry.path: (entry, content) for entry, content in permutation}
            )
            reports.append(
                _searcher(source).search(
                    _spec(should=(Predicate(PredicateKind.IDENTIFIER, "doseq"),))
                )
            )

        expected = reports[0]
        assert [match.source.path for match in expected.matches] == ["z.py", "a.py"]
        for report in reports[1:]:
            assert report.matches == expected.matches
            assert report.to_dict() == expected.to_dict()
            assert report.to_json(indent=None).encode() == expected.to_json(
                indent=None
            ).encode()
            assert report.identity_digest() == expected.identity_digest()

    def test_duplicate_source_identity_is_rejected(self):
        source = _fake_source()
        entry = source.list_blobs("python/cpython", SHA)[0]

        class DuplicateTreeSource(FakeTreeSource):
            def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
                return (entry, entry)

        duplicate_source = DuplicateTreeSource(
            blobs={"parse.py": (entry, SAMPLE_PY.encode())}
        )
        with pytest.raises(ValueError, match="duplicate SourceRef"):
            _searcher(duplicate_source).search(_spec())


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


def test_score_content_whole_file_uses_file_bound_should_and_must_not():
    content = "def build():\n    boost = True\nrun()\n"
    required = (
        Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
        Predicate(PredicateKind.CALL, "run"),
    )
    should = (Predicate(PredicateKind.IDENTIFIER, "boost"),)
    args = (content, PythonAdapter(), "owner/repo", SHA, "x.py", "b" * 40)

    assert score_content(*args, required, should, (), whole_file=False) == []
    matches = score_content(*args, required, should, (), whole_file=True)
    assert [match.source.start_line for match in matches] == [1, 3]
    assert [match.score for match in matches] == [3.0, 3.0]
    assert all(PredicateKind.IDENTIFIER in match.matched_kinds for match in matches)

    excluded = score_content(
        *args,
        required,
        should,
        (Predicate(PredicateKind.EXACT_TEXT, "boost = True"),),
        whole_file=True,
    )
    assert excluded == []


def test_score_content_default_should_and_must_not_remain_line_bound():
    content = "target\nboost forbidden\ntarget\n"
    matches = score_content(
        content,
        PythonAdapter(),
        "owner/repo",
        SHA,
        "x.py",
        "b" * 40,
        (Predicate(PredicateKind.IDENTIFIER, "target"),),
        (Predicate(PredicateKind.IDENTIFIER, "boost"),),
        (Predicate(PredicateKind.IDENTIFIER, "forbidden"),),
    )
    assert [match.source.start_line for match in matches] == [1, 3]
    assert [match.score for match in matches] == [1.0, 1.0]


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

    def test_oversized_blob_is_streamed(self):
        searcher = ScopedSearcher(
            tree_source=_fake_source(),
            adapters=(PythonAdapter(),),
            max_blob_size=10,
        )
        report = searcher.search(_spec())
        assert (
            report.coverage.status
            is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        )
        assert report.coverage.files_excluded == 0
        assert report.coverage.files_indexed == 1

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

    def test_required_language_shrinks_eligible_universe(self):
        rust = b"fn urlencode() {}\n"
        rust_sha = _blob_sha(rust)
        source = FakeTreeSource(
            blobs={
                "parse.py": (
                    BlobEntry("parse.py", PY_BLOB_SHA, len(SAMPLE_PY)),
                    SAMPLE_PY.encode(),
                ),
                "parse.rs": (BlobEntry("parse.rs", rust_sha, len(rust)), rust),
            }
        )
        searcher = ScopedSearcher(source, (PythonAdapter(), RustAdapter()))
        report = searcher.search(
            _spec(
                must=(
                    Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),
                )
            )
        )
        assert report.coverage.files_eligible == 1
        assert report.coverage.files_indexed == 1
        assert report.coverage.files_excluded == 0
        assert {match.source.path for match in report.matches} == {"parse.py"}
        assert source.read_calls == [PY_BLOB_SHA]

    def test_unsupported_required_language_rejects_before_blob_reads(self):
        source = _fake_source()
        with pytest.raises(
            SearchSpecError, match="unsupported required predicate language"
        ):
            _searcher(source).search(
                _spec(
                    must=(
                        Predicate(
                            PredicateKind.IDENTIFIER, "urlencode", "brainfuck"
                        ),
                    )
                )
            )
        assert source.list_calls == 0
        assert source.read_calls == []

    def test_python_requirement_cannot_route_rust_path(self):
        searcher = ScopedSearcher(_fake_source(), (PythonAdapter(), RustAdapter()))
        assert searcher._adapter_for("source.rs", "python") is None

    def test_tampered_python_predicate_language_cannot_route_rust_path(self):
        rust = b"fn urlencode() {}\n"
        rust_sha = _blob_sha(rust)
        source = FakeTreeSource(
            blobs={
                "parse.rs": (BlobEntry("parse.rs", rust_sha, len(rust)), rust),
            }
        )
        searcher = ScopedSearcher(source, (PythonAdapter(), RustAdapter()))

        report = searcher.search(
            _spec(
                must=(
                    Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),
                )
            )
        )

        assert report.matches == ()
        assert report.coverage.files_eligible == 0
        assert report.coverage.files_indexed == 0
        assert source.read_calls == []


class TestLocalMaterializedShelf:
    def test_valid_shelf_avoids_blob_http_gets(self, tmp_path):
        data = SAMPLE_PY.encode()
        blob_sha = _blob_sha(data)
        _write_shelf(tmp_path, files={"Lib/urllib/parse.py": data})
        tree_path = f"/repos/python/cpython/git/trees/{SHA}"
        with routed_server(
            {
                tree_path: (
                    200,
                    {"Content-Type": "application/json"},
                    json_body(
                        {
                            "sha": SHA,
                            "truncated": False,
                            "tree": [
                                {
                                    "path": "Lib/urllib/parse.py",
                                    "type": "blob",
                                    "sha": blob_sha,
                                    "size": len(data),
                                }
                            ],
                        }
                    ),
                )
            }
        ) as server:
            source = GitHubTreeSource(base_url=server.base_url, max_attempts=1)
            report = ScopedSearcher(
                source, (PythonAdapter(),), corpus_root=tmp_path
            ).search(_spec())

        assert report.matches
        assert server.state.request_paths == [tree_path]

    def test_valid_shelf_serves_regular_blob_without_api_read(self, tmp_path):
        data = SAMPLE_PY.encode()
        source = FakeTreeSource(
            blobs={
                "parse.py": (
                    BlobEntry("Lib/urllib/parse.py", _blob_sha(data), len(data)),
                    data,
                )
            }
        )
        _write_shelf(tmp_path, files={"Lib/urllib/parse.py": data})

        report = ScopedSearcher(
            source, (PythonAdapter(),), corpus_root=tmp_path
        ).search(_spec())

        assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        assert report.matches
        assert source.read_calls == []

    def test_tampered_local_blob_fails_without_api_fallback(self, tmp_path, monkeypatch):
        data = SAMPLE_PY.encode()
        source = FakeTreeSource(
            blobs={
                "parse.py": (
                    BlobEntry("Lib/urllib/parse.py", _blob_sha(data), len(data)),
                    data,
                )
            }
        )
        target = _write_shelf(
            tmp_path, files={"Lib/urllib/parse.py": data}
        )
        from leitir.materialize import read_valid_manifest as original

        def verify_then_tamper(*args, **kwargs):
            manifest = original(*args, **kwargs)
            (target / "Lib/urllib/parse.py").write_bytes(b"tampered\n")
            return manifest

        monkeypatch.setattr("leitir.engine.read_valid_manifest", verify_then_tamper)

        with pytest.raises(VerificationError, match="local blob"):
            ScopedSearcher(source, (PythonAdapter(),), corpus_root=tmp_path).search(
                _spec()
            )

        assert source.read_calls == []

    def test_symlink_blob_uses_link_text_bytes(self, tmp_path):
        link_text = b"needle"
        target = _write_shelf(tmp_path, files={})
        (target / "link.py").symlink_to(link_text.decode())
        from leitir.treehash import compute_materialized_tree_hash

        digest, scope = compute_materialized_tree_hash(target)
        manifest_path = target / "leitir-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.update(manifest_digest_fields(digest, scope=scope))
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        source = FakeTreeSource(
            blobs={
                "link.py": (
                    BlobEntry(
                        "link.py", _blob_sha(link_text), len(link_text), "120000"
                    ),
                    b"api bytes must not be read",
                )
            }
        )

        report = ScopedSearcher(
            source, (PythonAdapter(),), corpus_root=tmp_path
        ).search(
            _spec(must=(Predicate(PredicateKind.EXACT_TEXT, "needle"),))
        )

        assert report.matches
        assert source.read_calls == []

    def test_oversized_local_blob_uses_verified_stream(self, tmp_path):
        data = SAMPLE_PY.encode()
        source = FakeTreeSource(
            blobs={
                "parse.py": (
                    BlobEntry("Lib/urllib/parse.py", _blob_sha(data), len(data)),
                    data,
                )
            }
        )
        _write_shelf(tmp_path, files={"Lib/urllib/parse.py": data})

        report = ScopedSearcher(
            source, (PythonAdapter(),), max_blob_size=10, corpus_root=tmp_path
        ).search(_spec())

        assert report.matches
        assert source.read_calls == []

    def test_missing_shelf_uses_api_blob_path(self, tmp_path):
        source = _fake_source()

        report = ScopedSearcher(
            source, (PythonAdapter(),), corpus_root=tmp_path
        ).search(_spec())

        assert report.matches
        assert source.read_calls == [PY_BLOB_SHA]

    def test_invalid_shelf_uses_api_blob_path(self, tmp_path):
        data = SAMPLE_PY.encode()
        source = FakeTreeSource(
            blobs={
                "parse.py": (
                    BlobEntry("Lib/urllib/parse.py", _blob_sha(data), len(data)),
                    data,
                )
            }
        )
        target = _write_shelf(
            tmp_path, files={"Lib/urllib/parse.py": data}
        )
        (target / "Lib/urllib/parse.py").write_bytes(b"invalid shelf\n")

        report = ScopedSearcher(
            source, (PythonAdapter(),), corpus_root=tmp_path
        ).search(_spec())

        assert report.matches
        assert source.read_calls == [_blob_sha(data)]

    def test_local_shelf_report_is_deterministic(self, tmp_path, monkeypatch):
        data = SAMPLE_PY.encode()
        source = FakeTreeSource(
            blobs={
                "parse.py": (
                    BlobEntry("Lib/urllib/parse.py", _blob_sha(data), len(data)),
                    data,
                )
            }
        )
        _write_shelf(tmp_path, files={"Lib/urllib/parse.py": data})
        monkeypatch.setattr("leitir.engine._utc_now", lambda: "2026-08-14T00:00:00Z")
        searcher = ScopedSearcher(source, (PythonAdapter(),), corpus_root=tmp_path)

        first = searcher.search(_spec())
        second = searcher.search(_spec())

        assert first.to_dict() == second.to_dict()
        assert source.read_calls == []


def test_required_language_report_is_hash_seed_independent():
    script = textwrap.dedent(
        """
        import hashlib
        import json
        import leitir.engine
        from leitir.adapters import PythonAdapter, RustAdapter
        from leitir.engine import ScopedSearcher
        from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
        from leitir.tree import BlobEntry

        class Tree:
            def __init__(self):
                self.data = {"b.rs": b"fn target() {}\\n", "c.py": b"def target():\\n    return\\n", "a.py": b"def target():\\n    pass\\n"}
            def list_blobs(self, slug, commit_sha):
                return tuple(BlobEntry(path, self.sha(data), len(data)) for path, data in self.data.items())
            def list_blobs_ex(self, slug, commit_sha):
                return self.list_blobs(slug, commit_sha), False
            def read_blob(self, slug, blob_sha):
                return next(data for data in self.data.values() if self.sha(data) == blob_sha)
            @staticmethod
            def sha(data):
                return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\\x00" + data).hexdigest()

        leitir.engine._utc_now = lambda: "2026-08-10T00:00:00Z"
        spec = SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.IDENTIFIER, "target", "py"),),
            scopes=(RepoScope("owner/repo", "a" * 40),),
        )
        report = ScopedSearcher(Tree(), (RustAdapter(), PythonAdapter())).search(spec)
        print(json.dumps({"report": report.to_dict(), "coverage": report.coverage.to_dict()}, sort_keys=True))
        """
    )
    outputs = []
    for seed in ("0", "1", "42"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = "src"
        outputs.append(
            subprocess.check_output([sys.executable, "-c", script], env=env)
        )
    assert outputs[0] == outputs[1] == outputs[2]
    payload = json.loads(outputs[0])
    assert payload["coverage"]["files_eligible"] == 2
    assert [match["source"]["path"] for match in payload["report"]["matches"]] == [
        "a.py", "c.py"
    ]


def test_whole_file_report_is_hash_seed_independent():
    script = textwrap.dedent(
        """
        import hashlib
        import leitir.engine
        from leitir.adapters import PythonAdapter
        from leitir.engine import ScopedSearcher
        from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
        from leitir.tree import BlobEntry

        data = b"def build():\\n    pass\\nrun()\\nrun()\\n"
        blob_sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\\x00" + data).hexdigest()
        class Tree:
            def list_blobs(self, slug, commit_sha):
                return (BlobEntry("x.py", blob_sha, len(data)),)
            def list_blobs_ex(self, slug, commit_sha):
                return self.list_blobs(slug, commit_sha), False
            def read_blob(self, slug, requested_blob_sha):
                return data

        leitir.engine._utc_now = lambda: "2026-08-10T00:00:00Z"
        spec = SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.SYMBOL_DEFINITION, "build"), Predicate(PredicateKind.CALL, "run")),
            scopes=(RepoScope("owner/repo", "a" * 40),),
            whole_file_must=True,
        )
        print(ScopedSearcher(Tree(), (PythonAdapter(),)).search(spec).to_json(indent=None))
        """
    )
    outputs = []
    for seed in ("0", "1", "42"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = "src"
        outputs.append(subprocess.check_output([sys.executable, "-c", script], env=env))
    assert outputs[0] == outputs[1] == outputs[2]


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
        with pytest.raises(ValueError):
            SpanMatch(1, 1, (PredicateKind.IDENTIFIER,), 5, 4)


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
