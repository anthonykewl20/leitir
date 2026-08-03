from __future__ import annotations

import json
import io
from pathlib import Path

import pytest

from leitir.bench import load_manifest
from leitir.cli import ExitCode, main
from leitir.corpus_bench import (
    CorpusBenchmarkManifest,
    CorpusBenchmarkRun,
    CorpusBenchmarkTaskRun,
    CorpusBenchmarkRunner,
    manifest_from_dict,
)


def test_packaged_corpus_manifest_is_valid_and_pinned():
    manifest = load_manifest("corpus-v1")
    assert isinstance(manifest, CorpusBenchmarkManifest)
    assert len(manifest.tasks) == 4
    assert {task.spec.split(":", 1)[0] for task in manifest.tasks} >= {"npm", "pypi", "crates"}
    assert any(task.spec == "octocat/Hello-World" for task in manifest.tasks)
    for task in manifest.tasks:
        assert len(task.expected_commit_sha) == 40
        assert task.expected_files
        assert task.pin_source


def test_corpus_manifest_can_be_loaded_by_explicit_path():
    path = Path(__file__).parents[1] / "src/leitir/benchmarks/corpus-v1/manifest.json"
    assert load_manifest(path).digest() == load_manifest("corpus-v1").digest()


def test_corpus_manifest_rejects_missing_expected_files():
    raw = load_manifest("corpus-v1").to_dict()
    raw["tasks"][0]["expected_files"] = []
    with pytest.raises(ValueError, match="expected file"):
        manifest_from_dict(raw)


def test_corpus_manifest_round_trip_is_canonical():
    manifest = load_manifest("corpus-v1")
    assert json.loads(manifest.to_json()) == manifest.to_dict()


def test_cli_discovers_and_runs_packaged_corpus_manifest(monkeypatch):
    manifest = load_manifest("corpus-v1")

    def fake_run(self, received):
        assert received.digest() == manifest.digest()
        task = received.tasks[0]
        return CorpusBenchmarkRun(
            received.benchmark_id,
            received.digest(),
            (
                CorpusBenchmarkTaskRun(
                    task.task_id,
                    task.expected_owner,
                    task.expected_repo,
                    task.expected_commit_sha,
                    task.expected_files,
                ),
            ),
        )

    monkeypatch.setattr(CorpusBenchmarkRunner, "run", fake_run)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["bench", "--manifest", "corpus-v1"],
        resolver_factory=lambda _token: object(),
        code_search_factory=lambda _token: object(),
        tree_source_factory=lambda _token: pytest.fail("search runner was selected"),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out.getvalue())["benchmark"]["id"] == "corpus-v1"
    assert "benchmark=corpus-v1" in err.getvalue()
