"""Cheap static gates: lint, types, docs truth, and determinism-risk scans of the source."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys

from ..ledger import Finding
from . import ProbeContext, ProbeResult

_ALLOWED_CLOCK_MODULES = frozenset({"_http.py", "_update_check.py", "logging.py", "warm.py", "materialize.py", "resolver.py", "exec_sandbox.py", "doctor.py", "cli_diagnostics.py"})


def _run(context: ProbeContext, command: list[str]) -> tuple[int, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(context.repo_root / "src")
    completed = subprocess.run(command, cwd=context.repo_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")


def _ruff(context: ProbeContext, result: ProbeResult) -> None:
    if importlib.util.find_spec("ruff") is None:
        result.notes.append("ruff not importable in this interpreter; lint gate skipped (add --with ruff)")
        return
    code, output = _run(context, [sys.executable, "-m", "ruff", "check", ".", "--output-format", "json"])
    try:
        violations = json.loads(output) if output.strip().startswith("[") else []
    except json.JSONDecodeError:
        violations = []
    for item in violations:
        location = f"{item.get('filename', '?')}:{item.get('location', {}).get('row', 0)}"
        location = os.path.relpath(location, context.repo_root) if os.path.isabs(location) else location
        result.findings.append(
            Finding("static", "lint", "low", f"ruff {item.get('code')}: {item.get('message', '')[:120]}", location, {"identity": f"{location}:{item.get('code')}"}, "ruff check .")
        )
    result.metrics["ruff_violations"] = len(violations)
    result.metrics["ruff_exit"] = code


def _mypy(context: ProbeContext, result: ProbeResult) -> None:
    if importlib.util.find_spec("mypy") is None:
        result.notes.append("mypy not importable in this interpreter; type gate skipped (add --with mypy)")
        return
    code, output = _run(context, [sys.executable, "-m", "mypy", "src", "--no-error-summary", "--no-color-output"])
    errors = [line for line in output.splitlines() if ": error:" in line]
    for line in errors:
        location, _, message = line.partition(": error: ")
        result.findings.append(Finding("static", "type-error", "medium", f"mypy: {message[:140]}", location, {"identity": f"{location}:{message[:80]}"}, "mypy src"))
    result.metrics["mypy_errors"] = len(errors)
    result.metrics["mypy_exit"] = code


def _docs_truth(context: ProbeContext, result: ProbeResult) -> None:
    script = context.repo_root / "tools" / "check_docs_truth.py"
    if not script.exists():
        return
    code, output = _run(context, [sys.executable, str(script)])
    result.metrics["docs_truth_exit"] = code
    if code != 0:
        result.findings.append(
            Finding("static", "docs-truth", "high", "documentation claims something the CLI cannot do", "docs", {"identity": "docs-truth", "output": output[-1500:]}, "python tools/check_docs_truth.py")
        )


def _determinism_scan(context: ProbeContext, result: ProbeResult) -> None:
    """Flag json.dumps without sort_keys and wall-clock reads outside the modules that own time."""
    src = context.repo_root / "src" / "leitir"
    unsorted = 0
    clocks = 0
    for path in sorted(src.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(context.repo_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name in {"json.dumps", "json.dump"}:
                if not any(keyword.arg == "sort_keys" for keyword in node.keywords):
                    unsorted += 1
                    result.findings.append(
                        Finding(
                            "static",
                            "unsorted-json",
                            "low",
                            f"{name} without sort_keys (dict order becomes output order)",
                            f"{relative}:{node.lineno}",
                            {"identity": f"{relative}:{node.lineno}"},
                            f"sed -n {node.lineno}p {relative}",
                        )
                    )
            elif name in {"time.time", "datetime.now", "datetime.datetime.now", "datetime.utcnow", "datetime.datetime.utcnow", "date.today"} and path.name not in _ALLOWED_CLOCK_MODULES:
                clocks += 1
                result.findings.append(
                    Finding(
                        "static",
                        "wall-clock-read",
                        "info",
                        f"{name} read in a module not registered as owning time",
                        f"{relative}:{node.lineno}",
                        {"identity": f"{relative}:{node.lineno}"},
                        f"sed -n {node.lineno}p {relative}",
                    )
                )
    result.metrics["unsorted_json_calls"] = unsorted
    result.metrics["wall_clock_reads"] = clocks


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("static", "ok")
    _ruff(context, result)
    _mypy(context, result)
    _docs_truth(context, result)
    _determinism_scan(context, result)
    return result
