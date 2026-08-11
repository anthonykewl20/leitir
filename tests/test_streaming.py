from __future__ import annotations

import gc
import hashlib
import json
import os
import subprocess
import sys
import textwrap
import tracemalloc
from collections.abc import Callable, Iterator
from typing import TypeVar

import pytest

from leitir.adapters import PythonAdapter
from leitir.adapters.python_ast import PythonAstAdapter
from leitir.engine import MAX_BLOB_SIZE, ScopedSearcher, score_content
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
    SourceMatch,
)
from leitir.streaming import (
    MAX_LINE_BYTES,
    StreamVerificationError,
    score_blob_stream,
)
from leitir.tree import STREAM_CHUNK_SIZE, BlobEntry, GitHubTreeSource

T = TypeVar("T")
COMMIT_SHA = "a" * 40


def _sha(data: bytes, *, size: int | None = None) -> str:
    declared = len(data) if size is None else size
    return hashlib.sha1(b"blob %d\0" % declared + data).hexdigest()


def _once(operation: Callable[[], T]) -> T:
    return operation()


def _spec(kind: PredicateKind = PredicateKind.IDENTIFIER, value: str = "target") -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(kind, value),),
        scopes=(RepoScope("owner/repo", COMMIT_SHA),),
    )


class FakeTreeSource:
    def __init__(
        self,
        data: bytes,
        *,
        declared_size: int | None = None,
        blob_sha: str | None = None,
        chunk_size: int = 64 * 1024,
    ) -> None:
        self.data = data
        self.declared_size = len(data) if declared_size is None else declared_size
        self.blob_sha = blob_sha or _sha(data)
        self.chunk_size = chunk_size
        self.stream_calls = 0

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return (
            (BlobEntry("large.py", self.blob_sha, self.declared_size),),
            False,
        )

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.list_blobs_ex(slug, commit_sha)[0]

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self.data

    def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
        self.stream_calls += 1
        for start in range(0, len(self.data), self.chunk_size):
            yield self.data[start : start + self.chunk_size]


def _stream_score(source: FakeTreeSource, spec: SearchSpec) -> list[SourceMatch]:
    blob = source.list_blobs("owner/repo", COMMIT_SHA)[0]
    matches, excluded, parser_unavailable = score_blob_stream(
        source,
        blob,
        slug="owner/repo",
        commit_sha=COMMIT_SHA,
        path=blob.path,
        adapter=PythonAdapter(),
        spec=spec,
        retry=_once,
    )
    assert excluded is False
    assert parser_unavailable is False
    return matches


def test_large_verified_stream_matches_whole_buffer_and_is_complete() -> None:
    filler = b"# filler\n" * (MAX_BLOB_SIZE // 9 + 1)
    data = filler[: MAX_BLOB_SIZE // 2] + b"\ntarget\n" + filler
    source = FakeTreeSource(data)
    spec = _spec()
    expected = score_content(
        data.decode(),
        PythonAdapter(),
        "owner/repo",
        COMMIT_SHA,
        "large.py",
        source.blob_sha,
        spec.must,
        (),
        (),
    )
    report = ScopedSearcher(source, (PythonAdapter(),)).search(spec)
    assert list(report.matches) == expected
    assert report.coverage.files_indexed == 1
    assert report.coverage.files_excluded == 0
    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
    assert report.coverage.incomplete_results is False


def test_streaming_peak_allocation_is_bounded_as_blob_size_grows() -> None:
    allocation_budget = 8 * (STREAM_CHUNK_SIZE + MAX_LINE_BYTES)
    peaks: list[int] = []
    line = b"x" * 4095 + b"\n"

    for size_mib in (1, 4, 16, 64):
        data = line * (size_mib * 1024 * 1024 // len(line))
        source = FakeTreeSource(data, chunk_size=STREAM_CHUNK_SIZE)
        gc.collect()
        tracemalloc.start()
        try:
            assert _stream_score(
                source, _spec(PredicateKind.EXACT_TEXT, "not-present")
            ) == []
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        peaks.append(peak)

    assert all(peak < allocation_budget for peak in peaks), peaks


def test_tampered_stream_discards_provisional_matches() -> None:
    original = b"target\n" + b"# filler\n" * (MAX_BLOB_SIZE // 9 + 1)
    tampered = b"target\n" + b"!" + original[8:]
    source = FakeTreeSource(tampered, blob_sha=_sha(original))
    blob = source.list_blobs("owner/repo", COMMIT_SHA)[0]
    with pytest.raises(StreamVerificationError, match="git blob sha mismatch"):
        score_blob_stream(
            source,
            blob,
            slug="owner/repo",
            commit_sha=COMMIT_SHA,
            path=blob.path,
            adapter=PythonAdapter(),
            spec=_spec(),
            retry=_once,
        )
    report = ScopedSearcher(source, (PythonAdapter(),)).search(_spec())
    assert report.matches == ()
    assert report.coverage.files_indexed == 0
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL


@pytest.mark.parametrize("declared_delta", [-1, 1])
def test_declared_size_mismatch_is_excluded(declared_delta: int) -> None:
    data = b"target\n" + b"# filler\n" * (MAX_BLOB_SIZE // 9 + 1)
    source = FakeTreeSource(
        data,
        declared_size=len(data) + declared_delta,
        blob_sha=_sha(data, size=len(data) + declared_delta),
    )
    report = ScopedSearcher(source, (PythonAdapter(),)).search(_spec())
    assert report.matches == ()
    assert report.coverage.files_indexed == 0
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL


def test_regex_large_blob_is_streamed() -> None:
    source = FakeTreeSource(
        b"target\n" + b"# filler\n" * (MAX_BLOB_SIZE // 9 + 1)
    )
    spec = _spec(PredicateKind.REGEX, "target.*")
    report = ScopedSearcher(source, (PythonAdapter(),)).search(spec)
    assert source.stream_calls == 1
    assert len(report.matches) == 1
    assert report.coverage.files_excluded == 0
    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE


def test_chunk_boundary_dedup_and_chunk_size_independence() -> None:
    data = b"prefix target suffix\n"
    outputs = [
        _stream_score(FakeTreeSource(data, chunk_size=size), _spec())
        for size in (7, 13, 16, 64 * 1024)
    ]
    assert all(output == outputs[0] for output in outputs)
    assert len(outputs[0]) == 1


def test_file_level_must_not_matches_whole_buffer_behavior() -> None:
    data = b"target\n" + b" " * 1024 + b"forbidden\n"
    spec = SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.IDENTIFIER, "target"),),
        must_not=(Predicate(PredicateKind.IDENTIFIER, "forbidden"),),
        scopes=(RepoScope("owner/repo", COMMIT_SHA),),
    )
    assert _stream_score(FakeTreeSource(data, chunk_size=31), spec) == []


def test_retry_restarts_digest_decoder_and_pending_matches() -> None:
    data = b"target\n"

    class InterruptedSource(FakeTreeSource):
        def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
            self.stream_calls += 1
            yield self.data[:4]
            if self.stream_calls == 1:
                raise OSError("interrupted")
            yield self.data[4:]

    def retry(
        operation: Callable[[], tuple[list[SourceMatch], bool]],
    ) -> tuple[list[SourceMatch], bool]:
        try:
            return operation()
        except OSError:
            return operation()

    source = InterruptedSource(data)
    blob = source.list_blobs("owner/repo", COMMIT_SHA)[0]
    matches, excluded, parser_unavailable = score_blob_stream(
        source,
        blob,
        slug="owner/repo",
        commit_sha=COMMIT_SHA,
        path=blob.path,
        adapter=PythonAdapter(),
        spec=_spec(),
        retry=retry,
    )
    assert excluded is False
    assert parser_unavailable is False
    assert source.stream_calls == 2
    assert len(matches) == 1


def test_split_utf8_and_invalid_bytes_use_incremental_replacement() -> None:
    split = FakeTreeSource("x\né\n".encode(), chunk_size=3)
    matches = _stream_score(split, _spec(PredicateKind.EXACT_TEXT, "é"))
    assert [match.source.start_line for match in matches] == [2]
    invalid = FakeTreeSource(b"x\n\xfftarget\n", chunk_size=3)
    invalid_matches = _stream_score(invalid, _spec())
    assert [match.source.start_line for match in invalid_matches] == [2]


def test_streaming_report_is_hash_seed_independent() -> None:
    script = textwrap.dedent(
        """
        import hashlib
        import leitir.engine
        from leitir.adapters import PythonAdapter
        from leitir.engine import MAX_BLOB_SIZE, ScopedSearcher
        from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
        from leitir.tree import BlobEntry

        data = b"target\\n" + b"# filler\\n" * (MAX_BLOB_SIZE // 9 + 1)
        sha = hashlib.sha1(b"blob %d\\0" % len(data) + data).hexdigest()
        class Tree:
            def list_blobs_ex(self, slug, commit_sha):
                return (BlobEntry("x.py", sha, len(data)),), False
            def read_blob_stream(self, slug, blob_sha):
                for start in range(0, len(data), 7919):
                    yield data[start:start + 7919]
        leitir.engine._utc_now = lambda: "2026-08-10T00:00:00Z"
        spec = SearchSpec(mode=SearchMode.SCOPED_EXHAUSTIVE, must=(Predicate(PredicateKind.IDENTIFIER, "target"),), scopes=(RepoScope("owner/repo", "a" * 40),))
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
    assert json.loads(outputs[0])["coverage"]["files_indexed"] == 1


def test_long_line_with_multiple_predicates_is_not_dropped() -> None:
    long_line = b"x" * 1000 + b" needle_one needle_two\n"
    data = long_line + b"# filler\n" * (MAX_BLOB_SIZE // 9 + 1)
    spec = SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(
            Predicate(PredicateKind.EXACT_TEXT, "needle_one"),
            Predicate(PredicateKind.EXACT_TEXT, "needle_two"),
        ),
        scopes=(RepoScope("owner/repo", COMMIT_SHA),),
    )
    report = ScopedSearcher(FakeTreeSource(data), (PythonAdapter(),)).search(spec)
    assert [match.source.start_line for match in report.matches] == [1]
    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE


def test_identifier_boundary_is_not_fabricated() -> None:
    data = b"x" * 1000 + b"target\n"
    for chunk_size in (1, 2, 3, 5, 7, 11, 64, 64 * 1024):
        assert _stream_score(FakeTreeSource(data, chunk_size=chunk_size), _spec()) == []


def test_overlong_line_is_excluded_and_partial() -> None:
    data = b"x" * (MAX_LINE_BYTES + 1)
    report = ScopedSearcher(
        FakeTreeSource(data), (PythonAdapter(),), max_blob_size=0
    ).search(_spec(PredicateKind.EXACT_TEXT, "x"))
    assert report.coverage.files_indexed == 0
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL


def test_whole_file_must_is_excluded_without_consuming_stream() -> None:
    source = FakeTreeSource(b"target\n")
    base = _spec()
    spec = SearchSpec(
        mode=base.mode,
        must=base.must,
        scopes=base.scopes,
        whole_file_must=True,
    )
    report = ScopedSearcher(source, (PythonAdapter(),), max_blob_size=0).search(spec)
    assert source.stream_calls == 0
    assert report.coverage.files_indexed == 0
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL


def test_streamed_parser_unavailable_is_excluded_and_partial() -> None:
    data = b"def broken(\n" + b"# filler\n" * (MAX_BLOB_SIZE // 9 + 1)
    report = ScopedSearcher(
        FakeTreeSource(data), (PythonAstAdapter(PythonAdapter()),)
    ).search(_spec(PredicateKind.SYMBOL_DEFINITION, "broken"))
    assert report.coverage.files_indexed == 1
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL


def test_streaming_matches_buffered_for_supported_specs() -> None:
    content = (
        "é" * 1000
        + " needle exact_target target token sequence\n"
        + "def target(value): return value\n"
        + "result = target(é)\n"
        + "import target_module\n"
        + "safe line"
    )
    data = content.encode()
    predicates = (
        Predicate(PredicateKind.IDENTIFIER, "target"),
        Predicate(PredicateKind.EXACT_TEXT, "exact_target"),
        Predicate(PredicateKind.TOKEN_SEQUENCE, "target token sequence"),
        Predicate(PredicateKind.SIGNATURE, r"target\(value\)"),
        Predicate(PredicateKind.REGEX, r"exact_target\s+target"),
        Predicate(PredicateKind.SYMBOL_DEFINITION, "target"),
        Predicate(PredicateKind.SYMBOL_REFERENCE, "target"),
        Predicate(PredicateKind.CALL, "target"),
        Predicate(PredicateKind.IMPORT, "target_module"),
    )
    specs = [
        SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(predicate,),
            scopes=(RepoScope("owner/repo", COMMIT_SHA),),
        )
        for predicate in predicates
    ]
    specs.extend(
        (
            SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=(Predicate(PredicateKind.EXACT_TEXT, "exact_target"),),
                should=(Predicate(PredicateKind.IDENTIFIER, "target"),),
                must_not=(Predicate(PredicateKind.IDENTIFIER, "absent"),),
                scopes=(RepoScope("owner/repo", COMMIT_SHA),),
            ),
            SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=(Predicate(PredicateKind.IDENTIFIER, "target"),),
                must_not=(Predicate(PredicateKind.EXACT_TEXT, "safe line"),),
                scopes=(RepoScope("owner/repo", COMMIT_SHA),),
            ),
        )
    )
    for spec in specs:
        buffered = ScopedSearcher(
            FakeTreeSource(data), (PythonAdapter(),), max_blob_size=len(data)
        ).search(spec)
        for chunk_size in (1, 2, 3, 5, 7, 11, 64, 64 * 1024):
            streamed = ScopedSearcher(
                FakeTreeSource(data, chunk_size=chunk_size),
                (PythonAdapter(),),
                max_blob_size=0,
            ).search(spec)
            assert streamed.matches == buffered.matches
            assert streamed.coverage == buffered.coverage


def test_github_stream_uses_raw_blob_api_and_gated_token(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            captured["size"] = size
            return b""

    def fake_urlopen(request: object, *, timeout: int) -> Response:
        captured["url"] = getattr(request, "full_url")
        captured["headers"] = dict(getattr(request, "headers"))
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    source = GitHubTreeSource(token="secret-token", timeout=17)
    assert list(source.read_blob_stream("owner/repo", "b" * 40)) == []
    headers = {str(key).lower(): value for key, value in dict(captured["headers"]).items()}
    assert captured["url"] == "https://api.github.com/repos/owner/repo/git/blobs/" + "b" * 40
    assert headers["accept"] == "application/vnd.github.raw"
    assert headers["authorization"] == "Bearer secret-token"
    assert captured["timeout"] == 17
    assert "raw.githubusercontent.com" not in str(captured["url"])
