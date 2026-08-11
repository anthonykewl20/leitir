"""Fail-closed tests for malformed offline benchmark contracts."""

from __future__ import annotations

import sys
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from types import ModuleType
from typing import Any, cast

import pytest

from leitir.bench import (
    BenchmarkManifest,
    BenchmarkRun,
    BenchmarkRunner,
    BenchmarkTask,
    BenchmarkTaskRun,
    load_manifest,
    manifest_from_dict,
)
from leitir.corpus_bench import (
    CorpusBenchmarkManifest,
    CorpusBenchmarkRunner,
    CorpusBenchmarkTask,
    CorpusExpectedFile,
)
from leitir.corpus_bench import (
    manifest_from_dict as corpus_manifest_from_dict,
)
from leitir.ranking import RankedMatch
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    SearchMode,
    SearchSpec,
    SourceRef,
)


def _search_task() -> BenchmarkTask:
    manifest = load_manifest("search-v1")
    assert isinstance(manifest, BenchmarkManifest)
    return manifest.tasks[0]


def _task_run(*results: RankedMatch) -> BenchmarkTaskRun:
    return BenchmarkTaskRun(
        task_id="valid-task",
        language="python",
        spec_digest="a" * 64,
        coverage=Coverage(
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
            files_eligible=0,
            files_indexed=0,
            files_excluded=0,
        ),
        results=results,
    )


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        (lambda: replace(_search_task(), task_id="Not Valid"), ValueError, "lowercase kebab-case"),
        (lambda: replace(_search_task(), language="cobol"), ValueError, "language must be"),
        (
            lambda: replace(_search_task(), spec=cast(SearchSpec, object())),
            TypeError,
            "spec must be a SearchSpec",
        ),
        (
            lambda: replace(
                _search_task(),
                spec=replace(_search_task().spec, mode=SearchMode.GLOBAL_DISCOVERY),
            ),
            ValueError,
            "must use scoped_exhaustive",
        ),
        (
            lambda: replace(
                _search_task(),
                spec=replace(
                    _search_task().spec,
                    scopes=_search_task().spec.scopes * 2,
                ),
            ),
            ValueError,
            "exactly one scope",
        ),
        (
            lambda: replace(_search_task(), expected_results=cast(tuple[SourceRef, ...], [])),
            TypeError,
            "tuple of SourceRef",
        ),
        (lambda: replace(_search_task(), expected_results=()), ValueError, "expected-result pin"),
        (
            lambda: replace(
                _search_task(), expected_results=cast(tuple[SourceRef, ...], (object(),))
            ),
            TypeError,
            "only SourceRef",
        ),
        (
            lambda: replace(
                _search_task(),
                expected_results=(
                    _search_task().expected_results[0],
                    _search_task().expected_results[0],
                ),
            ),
            ValueError,
            "duplicate SourceRef",
        ),
        (
            lambda: replace(
                _search_task(),
                expected_results=(replace(_search_task().expected_results[0], slug="other/repo"),),
            ),
            ValueError,
            "belong to the task scope",
        ),
        (lambda: replace(_search_task(), pin_source="  "), ValueError, "non-empty text"),
    ],
)
def test_search_benchmark_task_rejects_malformed_contracts(
    factory: Callable[[], object], exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        factory()


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        (
            lambda: BenchmarkManifest("wrong", "search-v1", ()),
            ValueError,
            "schema_version",
        ),
        (
            lambda: BenchmarkManifest("leitir-benchmark-manifest-v1", "INVALID", ()),
            ValueError,
            "benchmark_id",
        ),
        (
            lambda: BenchmarkManifest(
                "leitir-benchmark-manifest-v1",
                "search-v1",
                cast(tuple[BenchmarkTask, ...], []),
            ),
            TypeError,
            "tuple of BenchmarkTask",
        ),
        (
            lambda: BenchmarkManifest(
                "leitir-benchmark-manifest-v1",
                "search-v1",
                cast(tuple[BenchmarkTask, ...], (object(),)),
            ),
            TypeError,
            "only BenchmarkTask",
        ),
        (
            lambda: BenchmarkRun("wrong", "search-v1", "a" * 64, ()),
            ValueError,
            "schema_version",
        ),
        (
            lambda: BenchmarkRun("leitir-benchmark-run-v1", "INVALID", "a" * 64, ()),
            ValueError,
            "benchmark_id",
        ),
        (
            lambda: BenchmarkRun("leitir-benchmark-run-v1", "search-v1", "bad", ()),
            ValueError,
            "manifest_sha256",
        ),
        (
            lambda: BenchmarkRun(
                "leitir-benchmark-run-v1",
                "search-v1",
                "a" * 64,
                cast(tuple[BenchmarkTaskRun, ...], []),
            ),
            TypeError,
            "tuple of BenchmarkTaskRun",
        ),
        (
            lambda: BenchmarkRun(
                "leitir-benchmark-run-v1",
                "search-v1",
                "a" * 64,
                cast(tuple[BenchmarkTaskRun, ...], (object(),)),
            ),
            TypeError,
            "only BenchmarkTaskRun",
        ),
        (
            lambda: BenchmarkRun(
                "leitir-benchmark-run-v1",
                "search-v1",
                "a" * 64,
                (_task_run(), _task_run()),
            ),
            ValueError,
            "task IDs must be unique",
        ),
    ],
)
def test_search_benchmark_containers_reject_malformed_contracts(
    factory: Callable[[], object], exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        factory()


@pytest.mark.parametrize(
    ("changes", "exception", "message"),
    [
        ({"task_id": "INVALID"}, ValueError, "task_id"),
        ({"language": "cobol"}, ValueError, "language"),
        ({"spec_digest": "bad"}, ValueError, "spec_digest"),
        ({"coverage": object()}, TypeError, "coverage must"),
        ({"results": []}, TypeError, "tuple of RankedMatch"),
        ({"results": (object(),)}, TypeError, "only RankedMatch"),
    ],
)
def test_search_benchmark_task_run_rejects_malformed_contracts(
    changes: dict[str, object], exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        replace(_task_run(), **changes)


def _ranked_match(*, rank: int, rank_score: int, path: str) -> RankedMatch:
    source = replace(_search_task().expected_results[0], path=path)
    return RankedMatch(
        source=source,
        score=1.0,
        normalized_score=1.0,
        rank=rank,
        rank_score=rank_score,
        matched_kinds=(PredicateKind.SYMBOL_DEFINITION,),
    )


def test_search_benchmark_task_run_rejects_invalid_ranking_invariants() -> None:
    first = _ranked_match(rank=1, rank_score=1, path="first.py")
    with pytest.raises(ValueError, match="contiguous ranks"):
        _task_run(replace(first, rank=2))

    second = _ranked_match(rank=2, rank_score=1, path="second.py")
    with pytest.raises(ValueError, match="unique rank_score"):
        _task_run(first, second)


def _mutated_search_manifest(case: str) -> object:
    raw: Any = deepcopy(load_manifest("search-v1").to_dict())
    task = raw["tasks"][0]
    if case == "manifest-not-object":
        return []
    if case == "tasks-not-list":
        raw["tasks"] = "bad"
    elif case == "task-not-object":
        raw["tasks"][0] = "bad"
    elif case == "scope-not-object":
        task["scope"] = "bad"
    elif case == "must-not-list":
        task["must"] = "bad"
    elif case == "predicate-not-object":
        task["must"] = ["bad"]
    elif case == "invalid-predicate-kind":
        task["must"] = [{"kind": "not-a-kind", "value": "x"}]
    elif case == "source-not-object":
        task["expected_results"] = ["bad"]
    elif case == "source-missing-field":
        del task["expected_results"][0]["blob_sha"]
    elif case == "task-missing-field":
        del task["id"]
    elif case == "manifest-missing-field":
        del raw["schema_version"]
    else:
        raise AssertionError(f"unknown test case: {case}")
    return raw


@pytest.mark.parametrize(
    ("case", "exception", "message"),
    [
        ("manifest-not-object", TypeError, "manifest must be an object"),
        ("tasks-not-list", TypeError, "manifest tasks must be a list"),
        ("task-not-object", TypeError, "task entries must be objects"),
        ("scope-not-object", TypeError, "scope must be an object"),
        ("must-not-list", TypeError, "field 'must' must be a list"),
        ("predicate-not-object", TypeError, "predicate entries must be objects"),
        ("invalid-predicate-kind", ValueError, "valid kind and value"),
        ("source-not-object", TypeError, "expected-result entries must be objects"),
        ("source-missing-field", ValueError, "missing 'blob_sha'"),
        ("task-missing-field", ValueError, "task is missing 'id'"),
        ("manifest-missing-field", ValueError, "manifest is missing 'schema_version'"),
    ],
)
def test_search_manifest_parser_rejects_malformed_nested_input(
    case: str, exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        manifest_from_dict(_mutated_search_manifest(case))


def _corpus_manifest() -> CorpusBenchmarkManifest:
    manifest = load_manifest("corpus-v1")
    assert isinstance(manifest, CorpusBenchmarkManifest)
    return manifest


@pytest.mark.parametrize(
    ("factory", "exception", "message"),
    [
        (lambda: CorpusExpectedFile(cast(str, 1), "line"), TypeError, "must be text"),
        (lambda: CorpusExpectedFile("../escape", "line"), ValueError, "safe path"),
        (lambda: CorpusExpectedFile("proof.txt", "two\nlines"), ValueError, "one non-empty"),
        (lambda: replace(_corpus_manifest().tasks[0], task_id="INVALID"), ValueError, "task id"),
        (lambda: replace(_corpus_manifest().tasks[0], spec=""), ValueError, "non-empty"),
        (lambda: replace(_corpus_manifest().tasks[0], expected_commit_sha="A" * 40), ValueError, "lowercase 40-character SHA"),
        (lambda: replace(_corpus_manifest().tasks[0], expected_files=()), ValueError, "expected file"),
        (lambda: replace(_corpus_manifest().tasks[0], pin_source=""), ValueError, "pin_source"),
        (lambda: replace(_corpus_manifest(), schema_version="wrong"), ValueError, "schema_version"),
        (lambda: replace(_corpus_manifest(), benchmark_id="other"), ValueError, "corpus benchmark id"),
        (
            lambda: replace(
                _corpus_manifest(), tasks=cast(tuple[CorpusBenchmarkTask, ...], [])
            ),
            TypeError,
            "tuple of tasks",
        ),
        (lambda: replace(_corpus_manifest(), tasks=()), ValueError, "four to six"),
        (
            lambda: replace(
                _corpus_manifest(),
                tasks=_corpus_manifest().tasks + (_corpus_manifest().tasks[0],),
            ),
            ValueError,
            "task IDs must be unique",
        ),
    ],
)
def test_corpus_benchmark_contracts_reject_malformed_values(
    factory: Callable[[], object], exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        factory()


def _mutated_corpus_manifest(case: str) -> object:
    raw: Any = deepcopy(_corpus_manifest().to_dict())
    if case == "manifest-not-object":
        return []
    if case == "tasks-not-list":
        raw["tasks"] = "bad"
    elif case == "task-not-object":
        raw["tasks"][0] = "bad"
    elif case == "files-not-list":
        raw["tasks"][0]["expected_files"] = "bad"
    elif case == "file-missing-field":
        del raw["tasks"][0]["expected_files"][0]["path"]
    elif case == "task-missing-field":
        del raw["tasks"][0]["expected_owner"]
    elif case == "manifest-missing-field":
        del raw["benchmark_id"]
    else:
        raise AssertionError(f"unknown test case: {case}")
    return raw


@pytest.mark.parametrize(
    ("case", "exception", "message"),
    [
        ("manifest-not-object", TypeError, "manifest must be an object"),
        ("tasks-not-list", TypeError, "tasks must be a list"),
        ("task-not-object", TypeError, "task must be an object"),
        ("files-not-list", TypeError, "expected_files must be a list"),
        ("file-missing-field", ValueError, "task is missing 'path'"),
        ("task-missing-field", ValueError, "task is missing 'expected_owner'"),
        ("manifest-missing-field", ValueError, "manifest is missing 'benchmark_id'"),
    ],
)
def test_corpus_manifest_parser_rejects_malformed_nested_input(
    case: str, exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        corpus_manifest_from_dict(_mutated_corpus_manifest(case))


def test_benchmark_runners_reject_invalid_collaborators_and_manifests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(TypeError, match="callable search"):
        BenchmarkRunner(object())

    class BadSearcher:
        def search(self, _spec: SearchSpec) -> object:
            return object()

    with pytest.raises(TypeError, match="searcher must return a SearchReport"):
        BenchmarkRunner(BadSearcher()).run(
            cast(BenchmarkManifest, load_manifest("search-v1"))
        )
    with pytest.raises(TypeError, match="manifest must be a BenchmarkManifest"):
        BenchmarkRunner(BadSearcher()).run(cast(BenchmarkManifest, object()))

    # Isolate this contract check from corpus materialization, which is imported
    # before the runner validates its argument.
    corpus_module = ModuleType("leitir.corpus")
    def unused_materializer(*_args: object, **_kwargs: object) -> None:
        return None

    corpus_module.materialize_source = unused_materializer  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "leitir.corpus", corpus_module)
    with pytest.raises(TypeError, match="CorpusBenchmarkManifest"):
        CorpusBenchmarkRunner(object(), object()).run(
            cast(CorpusBenchmarkManifest, object())
        )
