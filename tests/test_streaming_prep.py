"""S9 #94 fixture goldens and red user-observable streaming intent tests."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from http.client import IncompleteRead
from pathlib import Path

import pytest
from streaming._reference import (
    bounded_overlap_matches,
    chunk_emitter,
    git_blob_sha,
)

from leitir.adapters import PythonAdapter
from leitir.engine import ScopedSearcher, score_content
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
)
from leitir.streaming import score_blob_stream
from leitir.tree import BlobEntry

FIXTURES = Path(__file__).parent / "fixtures" / "streaming"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
XFAIL = pytest.mark.xfail(
    strict=True,
    reason="S9 #94 streaming verifier not yet implemented; blocked by S5/S6 #92/#93 + S2a",
)
COMMIT = "a" * 40


def _source() -> bytes:
    return (FIXTURES / "source.bin").read_bytes()


def _apply_tamper(name: str, source: bytes) -> tuple[bytes, dict[str, object]]:
    item = MANIFEST["tamper_variants"][name]
    recipe = item["recipe"]
    if recipe == "flip":
        changed = bytearray(source)
        changed[item["offset"]] ^= 1
        return bytes(changed), item
    if recipe in {"prefix", "interrupt"}:
        return source[: item["length"]], item
    if recipe == "append":
        return source + bytes.fromhex(item["hex"]), item
    return source, item


class FixtureSource:
    def __init__(
        self,
        data: bytes,
        *,
        declared_size: int | None = None,
        declared_sha: str | None = None,
        boundaries: tuple[int, ...] = (),
        interrupt: bool = False,
    ) -> None:
        self.data = data
        self.entry = BlobEntry(
            "large.py",
            declared_sha or git_blob_sha((data,), len(data)),
            len(data) if declared_size is None else declared_size,
        )
        self.boundaries = boundaries
        self.interrupt = interrupt

    def list_blobs_ex(self, slug: str, commit_sha: str) -> tuple[tuple[BlobEntry, ...], bool]:
        return (self.entry,), False

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return (self.entry,)

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self.data

    def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
        yield from chunk_emitter(self.data, self.boundaries)
        if self.interrupt:
            raise IncompleteRead(self.data)


def _spec(kind: PredicateKind, value: str) -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(kind, value),),
        scopes=(RepoScope("fixture/streaming", COMMIT),),
    )


def _report(source: FixtureSource, kind: PredicateKind, value: str):
    return ScopedSearcher(source, (PythonAdapter(),)).search(_spec(kind, value))


def test_fixture_declared_git_identities_are_self_consistent() -> None:
    for name, identity in sorted(MANIFEST["blobs"].items()):
        data = (FIXTURES / name).read_bytes()
        assert len(data) == identity["size"]
        assert git_blob_sha((data,), identity["size"]) == identity["blob_sha"]


def test_tamper_recipes_record_actual_identity_and_declared_mismatch() -> None:
    for name, declared in sorted(MANIFEST["tamper_variants"].items()):
        data, _ = _apply_tamper(name, _source())
        assert len(data) == declared["actual_size"]
        assert git_blob_sha((data,), len(data)) == declared["actual_sha"]
        assert (declared["declared_size"], declared["declared_sha"]) != (
            declared["actual_size"], declared["actual_sha"]
        )


def test_empty_blob_has_canonical_git_sha() -> None:
    identity = MANIFEST["blobs"]["empty.bin"]
    assert identity["size"] == 0
    assert identity["blob_sha"] == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"


@pytest.mark.parametrize("name", sorted(MANIFEST["chunk_variants"]))
def test_chunk_variant_reassembles_source(name: str) -> None:
    boundaries = MANIFEST["chunk_variants"][name]
    assert b"".join(chunk_emitter(_source(), boundaries)) == _source()


def test_reference_utf8_decoder_handles_split_codepoint() -> None:
    data = (FIXTURES / "utf8.bin").read_bytes()
    boundaries = MANIFEST["utf8_split"]["boundaries"]
    spans = bounded_overlap_matches(
        chunk_emitter(data, boundaries), "€ STREAM_TARGET", overlap_chars=32
    )
    assert len(spans) == 1


@XFAIL
def test_large_stream_matches_whole_buffer_without_incomplete_coverage() -> None:
    data = _source()
    source = FixtureSource(data, boundaries=(65_536, 65_600, 131_072))
    pattern = "BOUNDARY_START[^\\n]*\\nSTREAM_TARGET_BOUNDARY_END"
    report = _report(source, PredicateKind.REGEX, pattern)
    whole = score_content(
        data.decode("utf-8", errors="replace"), PythonAdapter(), "fixture/streaming", COMMIT,
        "large.py", source.entry.blob_sha, (Predicate(PredicateKind.REGEX, pattern),), (), (),
    )
    # S5/S6 must first make this finite two-line pattern available to both
    # scoring paths; S9 then preserves that whole-buffer result while streaming.
    assert len(whole) == 1
    assert report.matches == tuple(whole)
    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
    assert report.coverage.incomplete_results is False


@pytest.mark.parametrize("name", sorted(MANIFEST["tamper_variants"]))
@XFAIL
def test_tamper_is_rejected_without_results_and_is_partial(name: str) -> None:
    data, declared = _apply_tamper(name, _source())
    source = FixtureSource(
        data,
        declared_size=declared["declared_size"],
        declared_sha=declared["declared_sha"],
        interrupt=name == "interrupted",
    )
    matches, excluded, _parser_unavailable = score_blob_stream(
        source, source.entry, slug="fixture/streaming", commit_sha=COMMIT,
        path="large.py", adapter=PythonAdapter(),
        spec=_spec(PredicateKind.EXACT_TEXT, "STREAM_TARGET"), retry=lambda operation: operation(),
    )
    assert matches == []
    assert excluded is True
    report = _report(source, PredicateKind.EXACT_TEXT, "STREAM_TARGET")
    assert report.matches == ()
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.coverage.incomplete_results is True


@XFAIL
def test_failed_attempt_spans_do_not_survive_retry() -> None:
    good = _source()

    class RetryingSource(FixtureSource):
        attempts = 0

        def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
            self.attempts += 1
            if self.attempts == 1:
                yield b"STREAM_TARGET_FROM_FAILED_ATTEMPT\n"
                raise IncompleteRead(b"truncated")
            yield from chunk_emitter(self.data, (65_536,))

    source = RetryingSource(good)

    def retry(operation: Callable[[], tuple[list[object], bool]]):
        try:
            return operation()
        except IncompleteRead:
            return operation()

    pattern = "BOUNDARY_START[^\\n]*\\nSTREAM_TARGET_BOUNDARY_END"
    matches, excluded, _ = score_blob_stream(
        source, source.entry, slug="fixture/streaming", commit_sha=COMMIT,
        path="large.py", adapter=PythonAdapter(), spec=_spec(PredicateKind.REGEX, pattern), retry=retry,
    )
    assert source.attempts == 2
    assert excluded is False
    assert len(matches) == 1
    assert all(match.source.start_line != 1 for match in matches)


@XFAIL
def test_overlap_boundary_match_is_deduplicated_before_ranking() -> None:
    item = MANIFEST["boundary_dedupe"]
    data = (FIXTURES / item["source"]).read_bytes()
    reference = bounded_overlap_matches(
        chunk_emitter(data, item["boundaries"]), item["pattern"], overlap_chars=item["overlap_chars"]
    )
    assert len(reference) == 1
    # The production scorer must expose one identity even when a finite match
    # crosses its matching-window boundary and is seen again via overlap.
    large = _source()
    pattern = "BOUNDARY_START[^\\n]*\\nSTREAM_TARGET_BOUNDARY_END"
    report = _report(FixtureSource(large, boundaries=(65_536,)), PredicateKind.REGEX, pattern)
    assert len(report.matches) == 1


@XFAIL
def test_unbounded_regex_is_excluded_and_never_false_complete() -> None:
    report = _report(FixtureSource(_source()), PredicateKind.REGEX, r"STREAM_TARGET.*END")
    assert report.matches == ()
    assert report.coverage.files_excluded == 1
    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.coverage.incomplete_results is True
