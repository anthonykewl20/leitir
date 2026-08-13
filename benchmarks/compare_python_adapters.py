"""Produce the pinned Python AST-versus-regex comparison artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leitir.adapters import PythonAdapter, SpanMatch
from leitir.adapters.python_ast import PythonAstAdapter
from leitir.bench import BenchmarkManifest, BenchmarkTask, load_manifest
from leitir.search import PredicateKind

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = REPO_ROOT / "src" / "leitir" / "benchmarks"
ARTIFACT_ROOT = BENCHMARK_ROOT / "ast-vs-regex-v1"
DEFAULT_SOURCE = ARTIFACT_ROOT / "corpus" / "Lib" / "urllib" / "parse.py.txt"
DEFAULT_OUTPUT = ARTIFACT_ROOT / "comparison.json"
SCHEMA_VERSION = "leitir-python-adapter-comparison-v1"


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _span_key(span: SpanMatch) -> tuple[int, int]:
    return span.start_line, span.end_line


def _span_dict(span: tuple[int, int]) -> dict[str, int]:
    return {"end_line": span[1], "start_line": span[0]}


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 1.0


def _python_tasks(manifest: BenchmarkManifest) -> tuple[BenchmarkTask, ...]:
    return tuple(sorted((task for task in manifest.tasks if task.language == "python"), key=lambda task: task.task_id))


def build_artifact(source_path: Path = DEFAULT_SOURCE) -> dict[str, Any]:
    manifest = load_manifest()
    if not isinstance(manifest, BenchmarkManifest):
        raise TypeError("search-v1 must load as a BenchmarkManifest")
    tasks = _python_tasks(manifest)
    expected_sources = {
        (source.path, source.blob_sha)
        for task in tasks
        for source in task.expected_results
    }
    if len(expected_sources) != 1:
        raise ValueError("Python tasks must pin exactly one corpus blob")
    expected_path, expected_blob_sha = next(iter(expected_sources))
    data = source_path.read_bytes()
    actual_blob_sha = _git_blob_sha(data)
    if actual_blob_sha != expected_blob_sha:
        raise ValueError(f"corpus blob mismatch: expected {expected_blob_sha}, got {actual_blob_sha}")
    content = data.decode("utf-8")
    regex = PythonAdapter()
    ast_adapter = PythonAstAdapter(regex)
    task_results: list[dict[str, Any]] = []
    ast_total = 0
    regex_total = 0
    intersection_total = 0
    union_total = 0
    expected_total = 0
    ast_expected_total = 0
    regex_expected_total = 0
    for task in tasks:
        predicates = tuple(predicate for predicate in task.spec.must if predicate.kind is not PredicateKind.PATH)
        regex_spans = {_span_key(span) for span in regex.find_matches(content, predicates)}
        ast_spans = {_span_key(span) for span in ast_adapter.find_matches(content, predicates)}
        expected_spans = {(source.start_line, source.end_line) for source in task.expected_results}
        intersection = ast_spans & regex_spans
        union = ast_spans | regex_spans
        ast_expected = ast_spans & expected_spans
        regex_expected = regex_spans & expected_spans
        ast_total += len(ast_spans)
        regex_total += len(regex_spans)
        intersection_total += len(intersection)
        union_total += len(union)
        expected_total += len(expected_spans)
        ast_expected_total += len(ast_expected)
        regex_expected_total += len(regex_expected)
        task_results.append(
            {
                "agreement": _ratio(len(intersection), len(union)),
                "ast_only": [_span_dict(span) for span in sorted(ast_spans - regex_spans)],
                "ast_spans": [_span_dict(span) for span in sorted(ast_spans)],
                "expected_spans": [_span_dict(span) for span in sorted(expected_spans)],
                "id": task.task_id,
                "precision_ast_vs_regex": _ratio(len(intersection), len(ast_spans)),
                "recall_ast_vs_regex": _ratio(len(intersection), len(regex_spans)),
                "regex_only": [_span_dict(span) for span in sorted(regex_spans - ast_spans)],
                "regex_spans": [_span_dict(span) for span in sorted(regex_spans)],
            }
        )
    return {
        "aggregate": {
            "agreement": _ratio(intersection_total, union_total),
            "ast_span_count": ast_total,
            "expected_span_count": expected_total,
            "precision_ast_vs_pins": _ratio(ast_expected_total, ast_total),
            "precision_ast_vs_regex": _ratio(intersection_total, ast_total),
            "precision_regex_vs_pins": _ratio(regex_expected_total, regex_total),
            "recall_ast_vs_pins": _ratio(ast_expected_total, expected_total),
            "recall_ast_vs_regex": _ratio(intersection_total, regex_total),
            "recall_regex_vs_pins": _ratio(regex_expected_total, expected_total),
            "regex_span_count": regex_total,
        },
        "benchmark": {
            "id": manifest.benchmark_id,
            "manifest_sha256": manifest.digest(),
            "python_task_count": len(tasks),
        },
        "corpus": {
            "blob_sha": expected_blob_sha,
            "path": expected_path,
            "slug": tasks[0].spec.scopes[0].slug,
            "commit_sha": tasks[0].spec.scopes[0].commit_sha,
        },
        "schema_version": SCHEMA_VERSION,
        "tasks": task_results,
    }


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    produced = _canonical_bytes(build_artifact(args.source))
    if args.check:
        if not args.output.exists() or args.output.read_bytes() != produced:
            print(f"stale comparison artifact: {args.output}", file=sys.stderr)
            return 1
        return 0
    _write_atomic(args.output, produced)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
