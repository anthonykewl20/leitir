"""Pinned benchmark and canonical artifact tests for ADR-001 P6."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from leitir.bench import (
    BenchmarkManifest,
    BenchmarkRunner,
    load_manifest,
    manifest_from_dict,
)
from leitir.cli import ExitCode, main
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    Resolution,
    ResolutionStrategy,
    SearchReport,
    SearchSpec,
    SourceMatch,
    SourceRef,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"


class _FixtureSearcher:
    def __init__(self, manifest: BenchmarkManifest, *, reverse: bool = False) -> None:
        self._expected = {
            task.spec.digest(): task.expected_results[0] for task in manifest.tasks
        }
        self._reverse = reverse

    def search(self, spec: SearchSpec) -> SearchReport:
        expected = self._expected[spec.digest()]
        decoy = SourceRef(
            slug=expected.slug,
            commit_sha=expected.commit_sha,
            path=f"zz-decoy/{expected.path}",
            blob_sha="f" * 40,
            start_line=1,
            end_line=1,
        )
        matches = [
            SourceMatch(
                source=expected,
                score=2.0,
                matched_kinds=(PredicateKind.SYMBOL_DEFINITION,),
            ),
            SourceMatch(
                source=decoy,
                score=1.0,
                matched_kinds=(PredicateKind.SYMBOL_DEFINITION,),
            ),
        ]
        if self._reverse:
            matches.reverse()
        return SearchReport(
            spec_digest=spec.digest(),
            coverage=Coverage(
                status=CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
                files_eligible=1,
                files_indexed=1,
                files_excluded=0,
            ),
            matches=tuple(matches),
            resolution=Resolution(
                ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"
            ),
        )


def _run(*, reverse: bool = False):
    manifest = load_manifest()
    return BenchmarkRunner(_FixtureSearcher(manifest, reverse=reverse)).run(manifest)


def test_shipped_manifest_has_four_tasks_per_language():
    manifest = load_manifest()
    assert manifest.benchmark_id == "search-v1"
    assert len(manifest.tasks) == 12
    assert {
        language: sum(task.language == language for task in manifest.tasks)
        for language in ("python", "rust", "go")
    } == {"python": 4, "rust": 4, "go": 4}


def test_every_task_has_immutable_scope_and_expected_source_ref():
    manifest = load_manifest()
    for task in manifest.tasks:
        scope = task.spec.scopes[0]
        assert len(scope.commit_sha) == 40
        assert task.expected_results
        assert all(source.slug == scope.slug for source in task.expected_results)
        assert all(
            source.commit_sha == scope.commit_sha for source in task.expected_results
        )
        assert task.pin_source


def test_manifest_reuses_existing_fixture_commit_pins():
    manifest = load_manifest()
    pins = {(task.language, task.spec.scopes[0].slug, task.spec.scopes[0].commit_sha) for task in manifest.tasks}
    assert pins == {
        (
            "python",
            "python/cpython",
            "deaf509e8fc6e0363bd6f26d52ad42f976ec42f2",
        ),
        (
            "rust",
            "serde-rs/serde",
            "ccf9c6fc072378ea8c4f15df1024e258d35d6e61",
        ),
        (
            "go",
            "stretchr/testify",
            "b747d7c5f853d017ddbc5e623d026d7fc2770a58",
        ),
    }


def test_manifest_digest_is_canonical_under_task_permutation():
    manifest = load_manifest()
    permuted = BenchmarkManifest(
        schema_version=manifest.schema_version,
        benchmark_id=manifest.benchmark_id,
        tasks=tuple(reversed(manifest.tasks)),
    )
    assert permuted.to_json() == manifest.to_json()
    assert permuted.digest() == manifest.digest()


def test_manifest_rejects_duplicate_ids():
    manifest = load_manifest()
    with pytest.raises(ValueError, match="unique"):
        BenchmarkManifest(
            schema_version=manifest.schema_version,
            benchmark_id=manifest.benchmark_id,
            tasks=manifest.tasks + (manifest.tasks[0],),
        )


def test_manifest_requires_all_three_language_strata():
    raw = load_manifest().to_dict()
    raw["tasks"] = [task for task in raw["tasks"] if task["language"] != "go"]
    with pytest.raises(ValueError, match="four tasks per language"):
        manifest_from_dict(raw)


def test_runner_emits_exact_task_set_in_canonical_order():
    manifest = load_manifest()
    run = _run()
    assert [task.task_id for task in run.tasks] == sorted(
        task.task_id for task in manifest.tasks
    )
    assert run.manifest_sha256 == manifest.digest()


def test_run_results_expose_normalized_and_unique_rank_scores():
    run = _run()
    for task in run.tasks:
        assert [result.normalized_score for result in task.results] == [1.0, 0.0]
        assert [result.rank_score for result in task.results] == [2, 1]
        assert len({result.rank_score for result in task.results}) == len(task.results)


def test_artifact_is_byte_identical_across_repeats_and_match_permutations():
    first = _run().to_json().encode("utf-8")
    second = _run().to_json().encode("utf-8")
    permuted = _run(reverse=True).to_json().encode("utf-8")
    assert first == second == permuted
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(permuted).hexdigest()


def test_artifact_contains_no_qrels_metrics_or_baselines():
    artifact = _run().to_json().lower()
    for forbidden in ("qrels", "ndcg", "ir_measures", "pytrec", "baseline", "threshold"):
        assert forbidden not in artifact


def test_artifact_is_compact_canonical_json():
    run = _run()
    text = run.to_json()
    assert "\n" not in text
    assert " " not in text
    assert json.loads(text)["schema_version"] == "leitir-benchmark-run-v1"
    assert run.digest() == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_search_report_digest_mismatch_is_rejected():
    manifest = load_manifest()

    class BadSearcher:
        def search(self, spec):
            return SearchReport(
                spec_digest="0" * 64,
                coverage=Coverage(
                    status=CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
                    files_eligible=0,
                    files_indexed=0,
                    files_excluded=0,
                ),
                matches=(),
                resolution=Resolution(
                    ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"
                ),
            )

    with pytest.raises(ValueError, match="digest mismatch"):
        BenchmarkRunner(BadSearcher()).run(manifest)


def test_cli_help_lists_bench_and_bench_help_has_no_side_effects(capsys):
    assert main(["--help"]) == ExitCode.SUCCESS
    assert "bench" in capsys.readouterr().out
    assert main(["bench", "--help"]) == ExitCode.SUCCESS
    assert "search-v1" in capsys.readouterr().out


def test_cli_bench_emits_ranked_artifact_and_summary():
    manifest = load_manifest()
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        ["bench"],
        tree_source_factory=lambda _token: object(),
        searcher_factory=lambda _tree: _FixtureSearcher(manifest),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    payload = json.loads(out.getvalue())
    assert payload["benchmark"]["id"] == "search-v1"
    assert len(payload["tasks"]) == 12
    assert "artifact_sha256=" in err.getvalue()


def test_artifact_digest_is_identical_across_python_hash_seeds():
    script = textwrap.dedent(
        """
        from leitir.bench import BenchmarkRunner, load_manifest
        from leitir.search import Coverage, CoverageStatus, PredicateKind, Resolution, ResolutionStrategy, SearchReport, SourceMatch, SourceRef

        manifest = load_manifest()
        expected = {task.spec.digest(): task.expected_results[0] for task in manifest.tasks}

        class SeedSearcher:
            def search(self, spec):
                source = expected[spec.digest()]
                decoy = SourceRef(source.slug, source.commit_sha, "zz/" + source.path, "f" * 40, 1, 1)
                matches = tuple({
                    SourceMatch(source, 2.0, (PredicateKind.SYMBOL_DEFINITION,)),
                    SourceMatch(decoy, 1.0, (PredicateKind.SYMBOL_DEFINITION,)),
                })
                coverage = Coverage(CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE, 1, 1, 0)
                resolution = Resolution(ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z")
                return SearchReport(spec.digest(), coverage, matches, resolution)

        print(BenchmarkRunner(SeedSearcher()).run(manifest).digest())
        """
    )
    digests = []
    for seed in ("0", "12345"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(SRC)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=REPO_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        digests.append(completed.stdout.strip())
    assert digests[0] == digests[1]


def test_importing_new_modules_does_not_load_effect_modules(tmp_path):
    script = textwrap.dedent(
        f"""
        import json, sys
        sys.path.insert(0, {str(SRC)!r})
        import leitir.bench, leitir.ranking
        forbidden = ["urllib.request", "http.client", "subprocess"]
        print(json.dumps([name for name in forbidden if name in sys.modules]))
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == []
