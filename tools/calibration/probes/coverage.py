"""Branch coverage with per-test contexts: which fail-closed ``raise`` no test ever reaches?

The contexts file this probe writes is also what makes the mutation probe
precise (line -> covering tests), so the two probes compound.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

from ..ledger import Finding
from ..mutation import INTEGRITY_MODULES
from . import ProbeContext, ProbeResult


def _module_of(relative: str) -> str:
    parts = relative.removeprefix("src/").removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _raise_lines(path: Path) -> dict[int, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    lines: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            lines[node.lineno] = ast.unparse(node.exc)[:100]
    return lines


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("coverage", "ok")
    if importlib.util.find_spec("coverage") is None:
        result.status = "skipped"
        result.notes.append("coverage package not importable; run under uv with --with coverage==7.15.2 --with pytest-cov==7.1.0")
        return result
    rcfile = context.run_dir / "coveragerc.ini"
    data_file = context.run_dir / ".coverage"
    use_pytest_cov = importlib.util.find_spec("pytest_cov") is not None and importlib.util.find_spec("xdist") is not None
    # pytest-cov under xdist refuses dynamic_context in the rc file; it takes --cov-context instead.
    dynamic = "" if use_pytest_cov else "dynamic_context = test_function\n"
    rcfile.write_text(
        f"[run]\nbranch = True\nsource = leitir\n{dynamic}"
        f"data_file = {data_file}\nrelative_files = True\n[json]\nshow_contexts = True\n",
        encoding="utf-8",
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith("LEITIR_ENABLE_")}
    env["PYTHONPATH"] = str(context.repo_root / "src")
    env["COVERAGE_RCFILE"] = str(rcfile)
    env["PYTHONHASHSEED"] = "0"
    if use_pytest_cov:
        command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-n", "auto", "--cov=leitir", "--cov-branch", "--cov-context=test", "--cov-report="]
    else:
        command = [sys.executable, "-m", "coverage", "run", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        result.notes.append("pytest-cov/xdist unavailable; serial coverage run")
    completed = subprocess.run(command, cwd=context.repo_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    (context.run_dir / "coverage.log").write_text(completed.stdout.decode("utf-8", errors="replace"), encoding="utf-8")
    if not data_file.exists():
        result.status = "error"
        result.notes.append(f"coverage data file missing after pytest exit {completed.returncode}; see coverage.log")
        return result
    contexts_json = context.run_dir / "coverage-contexts.json"
    export = subprocess.run(
        [sys.executable, "-m", "coverage", "json", "--show-contexts", "-o", str(contexts_json)],
        cwd=context.repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if export.returncode != 0 or not contexts_json.exists():
        result.status = "error"
        result.notes.append("coverage json export failed: " + export.stdout.decode("utf-8", errors="replace")[-500:])
        return result
    raw = json.loads(contexts_json.read_text(encoding="utf-8"))
    # Persist for the mutation selector (precise mode) with the git sha it was measured on.
    persisted = context.state_dir / "coverage-contexts.json"
    persisted.write_bytes(contexts_json.read_bytes())
    (context.state_dir / "coverage-contexts.meta.json").write_text(json.dumps({"git_sha": context.option("git_sha", "")}), encoding="utf-8")

    totals = raw.get("totals", {})
    result.metrics["line_percent"] = round(float(totals.get("percent_covered", 0.0)), 2)
    result.metrics["missing_lines"] = int(totals.get("missing_lines", 0))
    result.metrics["missing_branches"] = int(totals.get("missing_branches", 0))

    baseline_path = context.repo_root / ".github" / "workflows" / "coverage-baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else {}
    module_floor = baseline.get("modules", {}) if isinstance(baseline, dict) else {}

    uncovered_integrity = 0
    uncovered_other = 0
    for file_name, entry in sorted(raw.get("files", {}).items()):
        relative = file_name.replace(os.sep, "/").removeprefix("./")
        if not relative.startswith("src/leitir/"):
            continue
        module = _module_of(relative)
        missing = set(entry.get("missing_lines", []))
        raises = _raise_lines(context.repo_root / relative)
        integrity = module in INTEGRITY_MODULES
        for line, text in sorted(raises.items()):
            if line not in missing:
                continue
            if integrity:
                uncovered_integrity += 1
                result.findings.append(
                    Finding(
                        "coverage",
                        "uncovered-raise",
                        "medium",
                        f"fail-closed path never executed by any test: raise {text}",
                        f"{relative}:{line}",
                        {"identity": f"{relative}:{line}:{text}", "module": module},
                        f"sed -n {max(1, line - 5)},{line + 2}p {relative}",
                    )
                )
            else:
                uncovered_other += 1
        floor = module_floor.get(relative)
        summary = entry.get("summary", {})
        percent = float(summary.get("percent_covered", 0.0))
        if isinstance(floor, (int, float)) and percent + 0.5 < float(floor):
            result.findings.append(
                Finding(
                    "coverage",
                    "coverage-regression",
                    "medium",
                    f"{relative} coverage {percent:.2f}% is below the recorded baseline {floor:.2f}%",
                    relative,
                    {"identity": relative, "measured": percent, "baseline": floor},
                    "python -m coverage report",
                )
            )
    result.metrics["uncovered_raise_integrity"] = uncovered_integrity
    result.metrics["uncovered_raise_other"] = uncovered_other
    return result
