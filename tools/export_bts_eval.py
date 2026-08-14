"""Export a canonical BTS evaluation run as deterministic publication evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import cast

from leitir.bts_bench import (
    LEITIR_BTS_EVAL_RUN_V1,
    BTSAggregate,
    BTSEvalRun,
    BTSEvalTaskRun,
    BTSTimingEnvelope,
    CandidateIdentity,
    Exclusion,
    MetricRecord,
)

MAX_RUN_BYTES = 64 * 1024 * 1024


class RunInputTooLargeError(ValueError):
    """Raised when an untrusted evaluation run exceeds the bounded reader."""


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _exact(value: dict[str, object], fields: set[str], name: str) -> None:
    if set(value) != fields:
        raise ValueError(f"{name} has missing or unknown fields")


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be bool")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return value


def _identity_from_dict(raw: object) -> CandidateIdentity:
    value = _mapping(raw, "candidate identity")
    _exact(value, {"slug", "commit_sha", "path", "blob_sha", "symbol", "start_line", "end_line"}, "candidate identity")
    return CandidateIdentity(
        _string(value["slug"], "slug"),
        _string(value["commit_sha"], "commit_sha"),
        _string(value["path"], "path"),
        _string(value["blob_sha"], "blob_sha"),
        _string(value["symbol"], "symbol"),
        _integer(value["start_line"], "start_line"),
        _integer(value["end_line"], "end_line"),
    )


def _exclusion_from_dict(raw: object) -> Exclusion:
    value = _mapping(raw, "exclusion")
    _exact(value, {"reason", "count"}, "exclusion")
    return Exclusion(_string(value["reason"], "reason"), _integer(value["count"], "count"))


def _metric_from_dict(raw: object) -> MetricRecord:
    value = _mapping(raw, "metric")
    _exact(value, {"metric", "numerator", "denominator", "excluded", "exclusions", "score_bps", "diagnostic"}, "metric")
    score_raw = value["score_bps"]
    if score_raw is not None and (isinstance(score_raw, bool) or not isinstance(score_raw, int)):
        raise ValueError("score_bps must be an integer or null")
    return MetricRecord(
        _string(value["metric"], "metric"),
        _integer(value["numerator"], "numerator"),
        _integer(value["denominator"], "denominator"),
        _integer(value["excluded"], "excluded"),
        tuple(_exclusion_from_dict(item) for item in _list(value["exclusions"], "exclusions")),
        score_raw,
        _boolean(value["diagnostic"], "diagnostic"),
    )


def _task_run_from_dict(raw: object) -> BTSEvalTaskRun:
    value = _mapping(raw, "task run")
    _exact(value, {"task_id", "task_digest", "metrics"}, "task run")
    return BTSEvalTaskRun(
        _string(value["task_id"], "task_id"),
        _string(value["task_digest"], "task_digest"),
        tuple(_metric_from_dict(item) for item in _list(value["metrics"], "metrics")),
    )


def _timing_from_dict(raw: object) -> BTSTimingEnvelope:
    value = _mapping(raw, "timing")
    _exact(value, {"schema_version", "run_digest", "pipeline_samples_ns", "ordinary_search_samples_ns", "runner_fingerprint", "note"}, "timing")
    return BTSTimingEnvelope(
        _string(value["schema_version"], "timing.schema_version"),
        _string(value["run_digest"], "timing.run_digest"),
        tuple(_integer(item, "pipeline_samples_ns") for item in _list(value["pipeline_samples_ns"], "pipeline_samples_ns")),
        tuple(_integer(item, "ordinary_search_samples_ns") for item in _list(value["ordinary_search_samples_ns"], "ordinary_search_samples_ns")),
        _string(value["runner_fingerprint"], "runner_fingerprint"),
        _string(value["note"], "note"),
    )


def run_from_dict(raw: object) -> BTSEvalRun:
    """Strictly construct a run, rejecting schema drift and malformed evidence."""

    value = _mapping(raw, "BTS evaluation run")
    _exact(value, {"schema_version", "benchmark_id", "manifest_sha256", "tasks", "aggregate", "timing"}, "BTS evaluation run")
    aggregate_raw = _mapping(value["aggregate"], "aggregate")
    _exact(aggregate_raw, {"metrics"}, "aggregate")
    timing_raw = value["timing"]
    if timing_raw is not None and not isinstance(timing_raw, dict):
        raise ValueError("timing must be an object or null")
    return BTSEvalRun(
        _string(value["schema_version"], "schema_version"),
        _string(value["benchmark_id"], "benchmark_id"),
        _string(value["manifest_sha256"], "manifest_sha256"),
        tuple(_task_run_from_dict(item) for item in _list(value["tasks"], "tasks")),
        BTSAggregate(tuple(_metric_from_dict(item) for item in _list(aggregate_raw["metrics"], "aggregate.metrics"))),
        None if timing_raw is None else _timing_from_dict(timing_raw),
    )


def load_run(path: Path) -> tuple[BTSEvalRun, bytes]:
    """Load only canonical run bytes and verify the timing-bound graded digest."""

    with path.open("rb") as handle:
        raw_bytes = handle.read(MAX_RUN_BYTES + 1)
    if len(raw_bytes) > MAX_RUN_BYTES:
        raise RunInputTooLargeError(f"{path} exceeds the maximum accepted size")
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path} is not valid UTF-8 JSON") from error
    run = run_from_dict(raw)
    if run.schema_version != LEITIR_BTS_EVAL_RUN_V1:
        raise ValueError(f"{path} has an unsupported run schema")
    canonical = run.to_json().encode("utf-8")
    if raw_bytes != canonical:
        raise ValueError(f"{path} is not canonical BTS evaluation run JSON")
    # Harness-produced runs carry the graded digest in a timing envelope.
    # Without that binding, an exporter cannot verify a claimed self-digest.
    if run.timing is None:
        raise ValueError(f"{path} has no timing envelope bound to the graded run")
    # BTSEvalRun.digest hashes its graded canonical dictionary; construction
    # also performs this same check before the canonical-byte comparison.
    if run.timing.run_digest != run.digest():
        raise ValueError(f"{path} timing digest does not match the graded run")
    return run, raw_bytes


def metrics_markdown(run: BTSEvalRun) -> str:
    """Render the aggregate as timestamp-free, deterministic publication text."""

    lines = [
        "# BTS evaluation metrics",
        "",
        f"- Run digest: `{run.digest()}`",
        f"- Manifest digest: `{run.manifest_sha256}`",
        f"- Task count: {len(run.tasks)}",
        "",
        "| Metric | Value | Status |",
        "| --- | --- | --- |",
    ]
    for record in run.aggregate.metrics:
        if record.score_bps is None:
            reasons = "; ".join(f"{item.reason} ({item.count})" for item in record.exclusions)
            lines.append(f"| {record.metric} | — | excluded: {reasons} |")
        else:
            lines.append(f"| {record.metric} | {record.score_bps} bps ({record.numerator}/{record.denominator}) | applicable |")
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: bytes) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def export(input_path: Path, output_dir: Path) -> Path:
    """Validate and atomically publish one canonical run below its digest ID."""

    run, canonical_bytes = load_run(input_path)
    # BTSEvalRun has no separate run_id field. Its graded canonical digest is
    # therefore the immutable run identifier and prevents replacement of a
    # different result for the same benchmark under one directory name.
    target = output_dir / run.digest()
    target.mkdir(parents=True, exist_ok=True)
    _atomic_write(target / "run.json", canonical_bytes)
    _atomic_write(target / "METRICS.md", metrics_markdown(run).encode("utf-8"))
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="canonical BTSEvalRun JSON emitted by the harness")
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/bts-v1/runs"))
    args = parser.parse_args()
    try:
        export(args.run, args.output_dir)
    except (OSError, ValueError, TypeError) as error:
        print(f"BTS evaluation export failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
