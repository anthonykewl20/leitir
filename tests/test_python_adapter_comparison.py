"""Checks for the pinned Python adapter comparison artifact."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / "benchmarks" / "compare_python_adapters.py"
ARTIFACT = REPO_ROOT / "src" / "leitir" / "benchmarks" / "ast-vs-regex-v1" / "comparison.json"


def test_python_adapter_comparison_artifact_is_well_formed() -> None:
    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "leitir-python-adapter-comparison-v1"
    assert payload["benchmark"]["id"] == "search-v1"
    assert payload["benchmark"]["python_task_count"] == 4
    assert len(payload["benchmark"]["manifest_sha256"]) == 64
    assert len(payload["corpus"]["blob_sha"]) == 40
    assert [task["id"] for task in payload["tasks"]] == sorted(task["id"] for task in payload["tasks"])
    assert set(payload["aggregate"]) >= {
        "agreement",
        "precision_ast_vs_regex",
        "recall_ast_vs_regex",
        "precision_ast_vs_pins",
        "recall_ast_vs_pins",
    }


def test_python_adapter_comparison_is_byte_identical_across_hash_seeds(tmp_path: Path) -> None:
    outputs: list[bytes] = []
    for seed in ("0", "1", "42"):
        output = tmp_path / f"comparison-{seed}.json"
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        subprocess.run(
            [sys.executable, str(HARNESS), "--output", str(output)],
            cwd=REPO_ROOT,
            env=environment,
            check=True,
        )
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1] == outputs[2] == ARTIFACT.read_bytes()
