"""Pinned benchmark contracts and deterministic run-artifact production."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from leitir.ranking import RankedMatch, rank_matches, source_identity
from leitir.search import (
    Coverage,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchReport,
    SearchSpec,
    SourceRef,
)

_TASK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LANGUAGES = frozenset(
    {"python", "rust", "go", "javascript", "typescript", "java", "c", "cpp"}
)
_LANGUAGE_NAMES = ", ".join(sorted(_LANGUAGES))
_MANIFEST_SCHEMA = "leitir-benchmark-manifest-v1"
_RUN_SCHEMA = "leitir-benchmark-run-v1"


class _Searcher(Protocol):
    def search(self, spec: SearchSpec) -> SearchReport: ...


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    """One scoped query and its immutable expected-result pins."""

    task_id: str
    language: str
    spec: SearchSpec
    expected_results: tuple[SourceRef, ...]
    pin_source: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID.fullmatch(self.task_id):
            raise ValueError("task_id must be lowercase kebab-case")
        if self.language not in _LANGUAGES:
            raise ValueError(f"language must be one of: {_LANGUAGE_NAMES}")
        if not isinstance(self.spec, SearchSpec):
            raise TypeError("spec must be a SearchSpec")
        if self.spec.mode is not SearchMode.SCOPED_EXHAUSTIVE:
            raise ValueError("benchmark tasks must use scoped_exhaustive mode")
        if len(self.spec.scopes) != 1:
            raise ValueError("benchmark tasks must declare exactly one scope")
        if not isinstance(self.expected_results, tuple):
            raise TypeError("expected_results must be a tuple of SourceRef")
        if not self.expected_results:
            raise ValueError("a benchmark task requires an expected-result pin")
        if any(not isinstance(item, SourceRef) for item in self.expected_results):
            raise TypeError("expected_results must contain only SourceRef values")
        identities = [source_identity(item) for item in self.expected_results]
        if len(set(identities)) != len(identities):
            raise ValueError("expected_results contains duplicate SourceRef identities")
        scope = self.spec.scopes[0]
        if any(
            item.slug != scope.slug or item.commit_sha != scope.commit_sha
            for item in self.expected_results
        ):
            raise ValueError("expected-result pins must belong to the task scope")
        if not isinstance(self.pin_source, str) or not self.pin_source.strip():
            raise ValueError("pin_source must be non-empty text")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.task_id,
            "language": self.language,
            "scope": {
                "slug": self.spec.scopes[0].slug,
                "commit_sha": self.spec.scopes[0].commit_sha,
            },
            "must": [predicate.to_dict() for predicate in self.spec.must],
            "should": [predicate.to_dict() for predicate in self.spec.should],
            "must_not": [predicate.to_dict() for predicate in self.spec.must_not],
            "expected_results": [
                item.to_dict() for item in sorted(
                    self.expected_results,
                    key=source_identity,
                )
            ],
            "pin_source": self.pin_source,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkManifest:
    """The complete, versioned query set for one benchmark corpus."""

    schema_version: str
    benchmark_id: str
    tasks: tuple[BenchmarkTask, ...]

    def __post_init__(self) -> None:
        if self.schema_version != _MANIFEST_SCHEMA:
            raise ValueError(f"schema_version must be {_MANIFEST_SCHEMA!r}")
        if not isinstance(self.benchmark_id, str) or not _TASK_ID.fullmatch(
            self.benchmark_id
        ):
            raise ValueError("benchmark_id must be lowercase kebab-case")
        if not isinstance(self.tasks, tuple):
            raise TypeError("tasks must be a tuple of BenchmarkTask")
        if any(not isinstance(task, BenchmarkTask) for task in self.tasks):
            raise TypeError("tasks must contain only BenchmarkTask values")
        ids = [task.task_id for task in self.tasks]
        if len(set(ids)) != len(ids):
            raise ValueError("benchmark task IDs must be unique")
        language_counts = {
            language: sum(task.language == language for task in self.tasks)
            for language in _LANGUAGES
        }
        short = sorted(
            language for language, count in language_counts.items() if count < 4
        )
        if short:
            raise ValueError(
                "benchmark requires at least four tasks per language; short: "
                + ", ".join(f"{language}={language_counts[language]}" for language in short)
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark_id": self.benchmark_id,
            "tasks": [
                task.to_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)
            ],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class BenchmarkTaskRun:
    """Ranked search output for one manifest task."""

    task_id: str
    language: str
    spec_digest: str
    coverage: Coverage
    results: tuple[RankedMatch, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID.fullmatch(self.task_id):
            raise ValueError("task_id must be lowercase kebab-case")
        if self.language not in _LANGUAGES:
            raise ValueError(f"language must be one of: {_LANGUAGE_NAMES}")
        if not isinstance(self.spec_digest, str) or not _SHA256.fullmatch(
            self.spec_digest
        ):
            raise ValueError("spec_digest must be a 64-char sha256 hex string")
        if not isinstance(self.coverage, Coverage):
            raise TypeError("coverage must be a Coverage")
        if not isinstance(self.results, tuple):
            raise TypeError("results must be a tuple of RankedMatch")
        if any(not isinstance(item, RankedMatch) for item in self.results):
            raise TypeError("results must contain only RankedMatch values")
        expected_ranks = tuple(range(1, len(self.results) + 1))
        if tuple(item.rank for item in self.results) != expected_ranks:
            raise ValueError("results must have contiguous ranks starting at one")
        rank_scores = [item.rank_score for item in self.results]
        if len(set(rank_scores)) != len(rank_scores):
            raise ValueError("results must have unique rank_score values")

    def to_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "language": self.language,
            "spec_digest": self.spec_digest,
            "coverage": self.coverage.to_dict(),
            "results": [result.to_dict() for result in self.results],
        }


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    """Canonical ranked run artifact consumed by ADR-002 S4."""

    schema_version: str
    benchmark_id: str
    manifest_sha256: str
    tasks: tuple[BenchmarkTaskRun, ...]

    def __post_init__(self) -> None:
        if self.schema_version != _RUN_SCHEMA:
            raise ValueError(f"schema_version must be {_RUN_SCHEMA!r}")
        if not isinstance(self.benchmark_id, str) or not _TASK_ID.fullmatch(
            self.benchmark_id
        ):
            raise ValueError("benchmark_id must be lowercase kebab-case")
        if not isinstance(self.manifest_sha256, str) or not _SHA256.fullmatch(
            self.manifest_sha256
        ):
            raise ValueError("manifest_sha256 must be a 64-char sha256 hex string")
        if not isinstance(self.tasks, tuple):
            raise TypeError("tasks must be a tuple of BenchmarkTaskRun")
        if any(not isinstance(task, BenchmarkTaskRun) for task in self.tasks):
            raise TypeError("tasks must contain only BenchmarkTaskRun values")
        ids = [task.task_id for task in self.tasks]
        if len(set(ids)) != len(ids):
            raise ValueError("benchmark run task IDs must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark": {
                "id": self.benchmark_id,
                "manifest_sha256": self.manifest_sha256,
            },
            "tasks": [task.to_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


class BenchmarkRunner:
    """Execute every pinned task through one scoped searcher."""

    def __init__(self, searcher: object) -> None:
        if not callable(getattr(searcher, "search", None)):
            raise TypeError("searcher must provide a callable search method")
        self._searcher = cast(_Searcher, searcher)

    def run(self, manifest: BenchmarkManifest) -> BenchmarkRun:
        if not isinstance(manifest, BenchmarkManifest):
            raise TypeError("manifest must be a BenchmarkManifest")
        task_runs: list[BenchmarkTaskRun] = []
        for task in sorted(manifest.tasks, key=lambda item: item.task_id):
            report = self._searcher.search(task.spec)
            if not isinstance(report, SearchReport):
                raise TypeError("searcher must return a SearchReport")
            if report.spec_digest != task.spec.digest():
                raise ValueError(f"search report digest mismatch for {task.task_id}")
            task_runs.append(
                BenchmarkTaskRun(
                    task_id=task.task_id,
                    language=task.language,
                    spec_digest=report.spec_digest,
                    coverage=report.coverage,
                    results=rank_matches(report.matches),
                )
            )
        return BenchmarkRun(
            schema_version=_RUN_SCHEMA,
            benchmark_id=manifest.benchmark_id,
            manifest_sha256=manifest.digest(),
            tasks=tuple(task_runs),
        )


def _predicate(raw: object) -> Predicate:
    if not isinstance(raw, dict):
        raise TypeError("predicate entries must be objects")
    try:
        kind = PredicateKind(raw["kind"])
        value = raw["value"]
    except (KeyError, ValueError) as exc:
        raise ValueError("predicate requires a valid kind and value") from exc
    language = raw.get("language")
    return Predicate(kind=kind, value=value, language=language)


def _source_ref(raw: object) -> SourceRef:
    if not isinstance(raw, dict):
        raise TypeError("expected-result entries must be objects")
    required = (
        "slug",
        "commit_sha",
        "path",
        "blob_sha",
        "start_line",
        "end_line",
    )
    try:
        values = {name: raw[name] for name in required}
    except KeyError as exc:
        raise ValueError(f"expected-result pin is missing {exc.args[0]!r}") from exc
    return SourceRef(**values)


def _entry_list(raw: object, field: str) -> list:
    """Reject a non-list field before it reaches a generator expression.

    Iterating a malformed value directly raises a bare ``TypeError`` that the
    caller's ``except KeyError`` cannot convert, so the manifest-focused error
    contract would leak a message naming no field.
    """
    if isinstance(raw, (str, bytes)) or not isinstance(raw, list):
        raise TypeError(f"benchmark task field {field!r} must be a list")
    return raw


def _task(raw: object) -> BenchmarkTask:
    if not isinstance(raw, dict):
        raise TypeError("task entries must be objects")
    scope_raw = raw.get("scope")
    if not isinstance(scope_raw, dict):
        raise TypeError("task scope must be an object")
    try:
        scope = RepoScope(
            slug=scope_raw["slug"],
            commit_sha=scope_raw["commit_sha"],
        )
        must = tuple(_predicate(item) for item in _entry_list(raw["must"], "must"))
        should = tuple(
            _predicate(item) for item in _entry_list(raw.get("should", []), "should")
        )
        must_not = tuple(
            _predicate(item)
            for item in _entry_list(raw.get("must_not", []), "must_not")
        )
        expected = tuple(
            _source_ref(item)
            for item in _entry_list(raw["expected_results"], "expected_results")
        )
        return BenchmarkTask(
            task_id=raw["id"],
            language=raw["language"],
            spec=SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=must,
                should=should,
                must_not=must_not,
                scopes=(scope,),
            ),
            expected_results=expected,
            pin_source=raw["pin_source"],
        )
    except KeyError as exc:
        raise ValueError(f"benchmark task is missing {exc.args[0]!r}") from exc


def manifest_from_dict(raw: object) -> BenchmarkManifest:
    """Validate and construct a manifest from decoded JSON."""
    if not isinstance(raw, dict):
        raise TypeError("benchmark manifest must be an object")
    try:
        tasks_raw = raw["tasks"]
        if isinstance(tasks_raw, (str, bytes)) or not isinstance(tasks_raw, list):
            raise TypeError("manifest tasks must be a list")
        return BenchmarkManifest(
            schema_version=raw["schema_version"],
            benchmark_id=raw["benchmark_id"],
            tasks=tuple(_task(item) for item in tasks_raw),
        )
    except KeyError as exc:
        raise ValueError(f"benchmark manifest is missing {exc.args[0]!r}") from exc


def load_manifest(path: str | Path | None = None) -> object:
    """Load the default, a named packaged benchmark, or a local manifest."""
    if path is None:
        from importlib import resources

        manifest_path = resources.files("leitir").joinpath(
            "benchmarks", "search-v1", "manifest.json"
        )
        text = manifest_path.read_text(encoding="utf-8")
    else:
        if not isinstance(path, (str, Path)):
            raise TypeError("path must be text, Path, or None")
        candidate = Path(path)
        if isinstance(path, str) and not candidate.exists() and _TASK_ID.fullmatch(path):
            from importlib import resources

            manifest_path = resources.files("leitir").joinpath(
                "benchmarks", path, "manifest.json"
            )
            text = manifest_path.read_text(encoding="utf-8")
        else:
            text = candidate.read_text(encoding="utf-8")
    raw = json.loads(text)
    if isinstance(raw, dict) and raw.get("schema_version") == "leitir-corpus-benchmark-manifest-v1":
        from leitir.corpus_bench import manifest_from_dict as corpus_manifest_from_dict

        return corpus_manifest_from_dict(raw)
    return manifest_from_dict(raw)


__all__ = [
    "BenchmarkManifest",
    "BenchmarkRun",
    "BenchmarkRunner",
    "BenchmarkTask",
    "BenchmarkTaskRun",
    "load_manifest",
    "manifest_from_dict",
]
