"""Export two native ASV 0.6.6 result files as scorecard evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ASV_COLUMNS = (
    "result",
    "params",
    "version",
    "started_at",
    "duration",
    "stats_ci_99_a",
    "stats_ci_99_b",
    "stats_q_25",
    "stats_q_75",
    "stats_number",
    "stats_repeat",
    "samples",
    "profile",
)
MIN_SAMPLES = 6


def _read_result(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 2:
        raise ValueError(f"{path} is not native ASV v2 JSON")
    if tuple(raw.get("result_columns", ())) != ASV_COLUMNS:
        raise ValueError(f"{path} has unexpected ASV result columns")
    results = raw.get("results")
    if not isinstance(results, dict) or not results:
        raise ValueError(f"{path} contains no benchmark results")
    sample_index = ASV_COLUMNS.index("samples")
    for name in sorted(results):
        row = results[name]
        if not isinstance(row, list) or len(row) <= sample_index:
            raise ValueError(f"{path}: {name} has no samples")
        samples = row[sample_index]
        if not isinstance(samples, list) or len(samples) != 1 or not isinstance(samples[0], list):
            raise ValueError(f"{path}: {name} samples are malformed")
        if len(samples[0]) < MIN_SAMPLES:
            raise ValueError(f"{path}: {name} has fewer than {MIN_SAMPLES} samples")
    raw["results"] = {name: results[name] for name in sorted(results)}
    # ASV includes uv's ephemeral executable path in existing-environment names.
    # The controlled identity is the measured Python version and declared env.
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if str(raw.get("env_name", "")).startswith("existing-py"):
        raw["env_name"] = f"existing-python{python_version}"
        raw["python"] = python_version
    if os.environ.get("PYTHONHASHSEED") != "0":
        raise ValueError("export requires PYTHONHASHSEED=0")
    raw["env_vars"] = {"PYTHONHASHSEED": "0"}
    params = raw.get("params")
    if not isinstance(params, dict):
        raise ValueError(f"{path} has malformed machine parameters")
    if "python" in params:
        params["python"] = python_version
    params.pop("environment_fingerprint", None)
    return raw


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _environment_fingerprint(baseline: dict[str, Any], candidate: dict[str, Any]) -> str:
    fields = ("params", "python", "requirements", "env_name", "env_vars")
    baseline_environment = {name: baseline[name] for name in fields}
    candidate_environment = {name: candidate[name] for name in fields}
    if baseline_environment != candidate_environment:
        raise ValueError("baseline and candidate ASV environments differ")
    return hashlib.sha256(_canonical(baseline_environment)).hexdigest()


def export(baseline_path: Path, candidate_path: Path, output_dir: Path) -> None:
    baseline = _read_result(baseline_path)
    candidate = _read_result(candidate_path)
    if set(baseline["results"]) != set(candidate["results"]):
        raise ValueError("baseline and candidate benchmark sets differ")
    fingerprint = _environment_fingerprint(baseline, candidate)
    baseline["params"]["environment_fingerprint"] = fingerprint
    candidate["params"]["environment_fingerprint"] = fingerprint
    runner = {
        "schema_version": "leitir-performance-runner-v1",
        "asv_version": "0.6.6",
        "controlled": True,
        "environment_fingerprint": fingerprint,
        "interleave_order": ["baseline", "candidate"],
        "harness_error": None,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "baseline-asv.json").write_bytes(_canonical(baseline))
    (output_dir / "candidate-asv.json").write_bytes(_canonical(candidate))
    (output_dir / "performance-runner.json").write_bytes(_canonical(runner))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path(".leitir-score/evidence"))
    args = parser.parse_args()
    export(args.baseline, args.candidate, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
