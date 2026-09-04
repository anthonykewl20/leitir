"""Hot-path timing against a stored baseline, judged with robust (median/MAD) statistics."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

from ..ledger import Finding
from ..stats import mad, median, robust_regression
from . import ProbeContext, ProbeResult

BASELINE_RELATIVE = Path("calibration") / "perf-baseline.json"


def host_fingerprint() -> str:
    return f"{platform.machine()}|{os.cpu_count()}|{platform.python_implementation()}{sys.version_info.major}.{sys.version_info.minor}"


def _load_benchmarks(repo_root: Path) -> list[tuple[str, type, str]]:
    module_path = repo_root / "benchmarks" / "bench_hot_paths.py"
    spec = importlib.util.spec_from_file_location("leitir_bench_hot_paths", module_path)
    if spec is None or spec.loader is None:
        return []
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    benches: list[tuple[str, type, str]] = []
    for attr in sorted(dir(module)):
        cls = getattr(module, attr)
        if isinstance(cls, type) and attr.startswith("Time"):
            for method in sorted(dir(cls)):
                if method.startswith("time_"):
                    benches.append((f"{attr}.{method}", cls, method))
    return benches


def measure(repo_root: Path, repeat: int) -> dict[str, list[float]]:
    samples: dict[str, list[float]] = {}
    for name, cls, method in _load_benchmarks(repo_root):
        instance = cls()
        setup = getattr(instance, "setup", None)
        if callable(setup):
            setup()
        function = getattr(instance, method)
        function()  # warm-up
        timings = []
        for _ in range(repeat):
            started = time.perf_counter()
            function()
            timings.append(time.perf_counter() - started)
        teardown = getattr(instance, "teardown", None)
        if callable(teardown):
            teardown()
        samples[name] = timings
    return samples


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("perf", "ok")
    repeat = int(context.option("perf_repeat", 11))
    src = str(context.repo_root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    samples = measure(context.repo_root, repeat)
    if not samples:
        result.status = "skipped"
        result.notes.append("no benchmarks found in benchmarks/bench_hot_paths.py")
        return result
    baseline_path = context.repo_root / BASELINE_RELATIVE
    fingerprint = host_fingerprint()
    current: dict[str, dict[str, Any]] = {name: {"median": median(values), "mad": mad(values), "samples": [round(value, 6) for value in values]} for name, values in samples.items()}
    bench_metrics: dict[str, dict[str, Any]] = {name: {"median_ms": round(entry["median"] * 1000, 3), "mad_ms": round(entry["mad"] * 1000, 3)} for name, entry in current.items()}
    result.metrics = {"host": fingerprint, "benchmarks": bench_metrics}
    baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else None
    if baseline is None or context.option("update_perf_baseline"):
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps({"schema_version": "leitir-perf-baseline-v1", "host": fingerprint, "git_sha": context.option("git_sha", ""), "benchmarks": current}, indent=1, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result.notes.append("perf baseline written; regressions will be judged against it from the next run")
        return result
    if baseline.get("host") != fingerprint:
        result.notes.append(f"baseline host {baseline.get('host')!r} differs from {fingerprint!r}; timing comparison skipped (use --update-perf-baseline on this host)")
        return result
    regressions = 0
    for name, entry in current.items():
        reference = baseline.get("benchmarks", {}).get(name)
        if not reference:
            result.notes.append(f"{name}: no baseline entry")
            continue
        regressed, ratio = robust_regression([float(v) for v in reference["samples"]], [float(v) for v in entry["samples"]])
        bench_metrics[name]["ratio_vs_baseline"] = round(ratio, 3)
        if regressed:
            regressions += 1
            result.findings.append(
                Finding(
                    "perf",
                    "perf-regression",
                    "medium",
                    f"{name} is {ratio:.2f}x slower than baseline (median {float(entry['median']) * 1000:.2f} ms vs {float(reference['median']) * 1000:.2f} ms)",
                    name,
                    {"identity": name, "ratio": round(ratio, 3), "baseline_git_sha": baseline.get("git_sha", "")},
                    "python tools/calibrate.py run --probes perf",
                )
            )
    result.metrics["regressions"] = regressions
    return result
