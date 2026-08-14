"""Publication-target and anti-gaming tests for the BTS reference fixture."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from leitir.bts_bench import (
    AdaptationProbeObs,
    BTSEvalBenchmark,
    BTSEvalRun,
    BTSEvalTask,
    BTSTaskObservation,
    CandidateJudgment,
    MemberObs,
    load_manifest,
)
from tools.export_bts_eval import export, load_run

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_MANIFEST = ROOT / "benchmarks" / "bts-v1" / "tasks" / "reference-synthetic-v1.json"
# Regenerate with _reference_run().digest() after an intentional fixture change.
PINNED_RUN_DIGEST = "d6a6b4f29dd86fc277a9c7b9a9fb0725ad1fdca9882e704f09143173dc0bb196"


class GoldDerivedSyntheticRunner:
    """A deterministic observation whose expected evidence comes from the gold."""

    def run(self, task: BTSEvalTask) -> BTSTaskObservation:
        gold = task.gold
        qrels = tuple(sorted(gold.candidate_qrels, key=lambda item: item.identity.sort_key))
        seed = gold.seed_span.identity if gold.seed_span is not None else qrels[0].identity
        members = [MemberObs(seed.symbol, seed, "include")]
        for helper in sorted(gold.required_helpers):
            members.append(MemberObs(helper, replace(seed, symbol=helper), "include"))
        return BTSTaskObservation(
            task.task_id,
            task.digest(),
            tuple(item.identity for item in qrels[:1]),
            tuple(members),
            tuple(sorted(gold.required_tests)),
            tuple(sorted(gold.required_examples)),
            "complete",
            gold.expected_counts,
            gold.expected_outcome_vector,
            gold.expected_baseline_digest,
            False,
            gold.expected_license,
            tuple(AdaptationProbeObs(node, True) for node in sorted(gold.expected_adaptations)),
            tuple(sorted(gold.expected_probe_ids)),
            len(gold.expected_probe_ids),
            len(gold.expected_probe_ids),
        )


def _reference_run() -> BTSEvalRun:
    return BTSEvalBenchmark().execute(load_manifest(REFERENCE_MANIFEST), GoldDerivedSyntheticRunner())


def test_reference_synthetic_manifest_is_valid() -> None:
    manifest = load_manifest(REFERENCE_MANIFEST)
    assert manifest.benchmark_id == "bts-reference-synthetic-v1"
    assert tuple(task.task_id for task in manifest.tasks) == ("reference-synthetic-v1",)


def test_pinned_gold_binds_the_reference_run_and_metrics() -> None:
    manifest = load_manifest(REFERENCE_MANIFEST)
    run = BTSEvalBenchmark().execute(manifest, GoldDerivedSyntheticRunner())
    assert run.digest() == PINNED_RUN_DIGEST

    task = manifest.tasks[0]
    altered_qrels = tuple(
        CandidateJudgment(item.identity, 2 if item.grade == 1 else item.grade) for item in task.gold.candidate_qrels
    )
    altered_task = replace(task, gold=replace(task.gold, candidate_qrels=altered_qrels))
    altered_manifest = replace(manifest, tasks=(altered_task,))
    altered_run = BTSEvalBenchmark().execute(altered_manifest, GoldDerivedSyntheticRunner())

    assert altered_run.digest() != run.digest()
    assert any(
        (before.metric, before.score_bps) != (after.metric, after.score_bps)
        for before, after in zip(run.aggregate.metrics, altered_run.aggregate.metrics, strict=True)
    )


def test_pinned_gold_digest_is_pythonhashseed_independent() -> None:
    script = """
from tests.test_bts_bench_tasks import _reference_run
print(_reference_run().digest())
"""
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=os.pathsep.join(("src", ".")))
        outputs.append(subprocess.check_output((sys.executable, "-c", script), cwd=ROOT, env=environment, text=True))
    assert outputs == [f"{PINNED_RUN_DIGEST}\n"] * 3


def test_export_writes_canonical_run_and_pinned_metrics(tmp_path: Path) -> None:
    run = _reference_run()
    canonical = run.to_json().encode("utf-8")
    input_path = tmp_path / "input-run.json"
    input_path.write_bytes(canonical)

    destination = export(input_path, tmp_path / "published")

    assert (destination / "run.json").read_bytes() == canonical
    metrics = (destination / "METRICS.md").read_text(encoding="utf-8")
    assert metrics == """# BTS evaluation metrics

- Run digest: `d6a6b4f29dd86fc277a9c7b9a9fb0725ad1fdca9882e704f09143173dc0bb196`
- Manifest digest: `055c6e9a8c0fa42139d636c7b13dab2dc70e8b836c0f5d7fcd62e4e87a28788d`
- Task count: 1

| Metric | Value | Status |
| --- | --- | --- |
| adaptation_integrity | 10000 bps (1/1) | applicable |
| candidate_top1 | 0 bps (0/1) | applicable |
| candidate_top10 | 0 bps (0/1) | applicable |
| candidate_top3 | 0 bps (0/1) | applicable |
| donor_import_free | 10000 bps (1/1) | applicable |
| example_recall | 10000 bps (1/1) | applicable |
| hallucinated_dependency_rate | 0 bps (0/2) | applicable |
| helper_recall | 10000 bps (1/1) | applicable |
| integration_success | 10000 bps (1/1) | applicable |
| license_accuracy | 10000 bps (1/1) | applicable |
| missing_dependency_rate | 0 bps (0/1) | applicable |
| probe_success | 10000 bps (1/1) | applicable |
| seed_symbol_exact | 10000 bps (1/1) | applicable |
| seed_symbol_line_overlap | 10000 bps (3/3) | applicable |
| test_recall | 10000 bps (1/1) | applicable |
| time_saved | — | excluded: advisory_timing_in_envelope (1) |
"""
    assert "generated-at" not in metrics.lower()


def test_export_rejects_digest_tampered_run(tmp_path: Path) -> None:
    run = _reference_run()
    raw = json.loads(run.to_json())
    assert isinstance(raw, dict)
    timing = raw["timing"]
    assert isinstance(timing, dict)
    timing["run_digest"] = "0" * 64
    input_path = tmp_path / "tampered-run.json"
    input_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    result = subprocess.run(
        (sys.executable, "tools/export_bts_eval.py", str(input_path), "--output-dir", str(tmp_path / "published")),
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(("src", "."))),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "digest" in result.stderr.lower()


def test_export_rejects_input_larger_than_the_bounded_reader(tmp_path: Path, monkeypatch) -> None:
    input_path = tmp_path / "oversized.json"
    input_path.write_bytes(b"x" * 5)
    monkeypatch.setattr("tools.export_bts_eval.MAX_RUN_BYTES", 4)
    with pytest.raises(ValueError, match="maximum accepted size"):
        load_run(input_path)

    script = """
import sys
from pathlib import Path
import tools.export_bts_eval as exporter
exporter.MAX_RUN_BYTES = 4
sys.argv = ['export_bts_eval.py', sys.argv[1], '--output-dir', sys.argv[2]]
raise SystemExit(exporter.main())
"""
    result = subprocess.run(
        (sys.executable, "-c", script, str(input_path), str(tmp_path / "published")),
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(("src", "."))),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "maximum accepted size" in result.stderr
