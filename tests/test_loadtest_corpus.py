from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).parents[1] / "tools" / "loadtest_corpus.py"
    spec = importlib.util.spec_from_file_location("loadtest_corpus", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loadtest = _module()
SHA_A = "a" * 40
SHA_B = "b" * 40


def test_load_corpus_requires_closed_schema_sorted_unique_and_minimum(tmp_path: Path) -> None:
    entries = [
        {"note": "fixture", "source": f"github:example/repo-{index:03d}@{SHA_A}"}
        for index in range(110)
    ]
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"schema_version": loadtest.CORPUS_SCHEMA_VERSION, "entries": entries}), encoding="utf-8")

    assert loadtest.load_corpus(path) == tuple(entries)

    entries[1]["source"] = entries[0]["source"]
    path.write_text(json.dumps({"schema_version": loadtest.CORPUS_SCHEMA_VERSION, "entries": entries}), encoding="utf-8")
    with pytest.raises(loadtest.CorpusValidationError, match="unique"):
        loadtest.load_corpus(path)


def test_percentile_uses_nearest_rank_and_rejects_invalid_inputs() -> None:
    assert loadtest.percentile([1, 2, 3, 4, 5], 0.5) == 3
    assert loadtest.percentile([1, 2, 3, 4, 5], 0.95) == 5
    with pytest.raises(ValueError):
        loadtest.percentile([], 0.5)
    with pytest.raises(ValueError):
        loadtest.percentile([True], 0.5)


def test_aggregate_entries_reports_completed_phase_samples_and_failures() -> None:
    aggregate = loadtest.aggregate_entries(
        [
            {
                "status": "success",
                "bytes": 100,
                "files": 10,
                "materialize": {"status": "completed", "duration_ms": 10},
                "search": {"status": "completed", "duration_ms": 20},
                "index": {"status": "skipped_ineligible"},
                "integrity": {"status": "completed", "duration_ms": 1},
            },
            {
                "status": "success",
                "bytes": 200,
                "files": 20,
                "materialize": {"status": "completed", "duration_ms": 30},
                "search": {"status": "completed", "duration_ms": 40},
                "index": {"status": "completed", "duration_ms": 50},
                "integrity": {"status": "completed", "duration_ms": 3},
            },
            {"status": "failure", "failure": {"category": "timeout"}},
        ]
    )

    assert aggregate["entries_successful"] == 2
    assert aggregate["shelf_bytes"] == 300
    assert aggregate["shelf_size_bytes"] == {"count": 2, "max": 200, "p50": 100, "p95": 200, "total": 300}
    assert aggregate["shelf_files"] == {"count": 2, "max": 20, "p50": 10, "p95": 20, "total": 30}
    assert aggregate["failures_by_category"] == {"timeout": 1}
    assert aggregate["phases"]["materialize"] == {"completed": 2, "max_ms": 30, "p50_ms": 10, "p95_ms": 30, "total_ms": 40}
    assert aggregate["phases"]["index"]["completed"] == 1


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("HTTP 429 rate limit exceeded", "rate_limit"),
        ("request timed out", "timeout"),
        ("HTTP 404 Not Found", "not_found"),
        ("materialized shelf failed manifest validation", "integrity"),
        ("codeload download failed", "materialization"),
        ("unknown failure", "unexpected"),
    ],
)
def test_classify_failure(message: str, expected: str) -> None:
    assert loadtest.classify_failure(message) == expected
