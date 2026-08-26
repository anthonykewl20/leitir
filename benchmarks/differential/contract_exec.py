"""Runs a candidate's code against its task's contract tests.

Does not reimplement pytest's collection/assertion logic: it places the
candidate at the import path the contract test expects, inside a private
temp workspace, then shells out to ``python -m pytest`` against the
*original* contract-test file path (never copied elsewhere) and parses the
JUnit XML pytest already knows how to emit (stdlib ``xml.etree`` only, no
extra pytest plugin).

Only pass/fail/error *counts* leave this module (as ``ContractRunOutcome``).
Nothing here returns pytest's stdout/stderr/assertion text to a caller that
could put it in a prompt -- ``harness.py`` only ever turns an outcome into a
``runner.RepairSignal``, which has no field for that text either.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .tasks import EvaluatorAssets

_TIMEOUT_SECONDS = 30.0


class ContractExecutionError(Exception):
    """Raised when the contract-test subprocess could not be run at all (infra failure)."""


@dataclass(frozen=True)
class ContractRunOutcome:
    passed: int
    failed: int
    errored: int
    skipped: int
    total: int

    @property
    def all_passed(self) -> bool:
        return self.total > 0 and self.failed == 0 and self.errored == 0

    def to_repair_signal_counts(self) -> tuple[int, int, int]:
        return (self.passed, self.failed, self.errored)


def _module_relative_path(seed_module: str, import_roots: tuple[str, ...]) -> Path:
    root = import_roots[0] if import_roots else "."
    module = seed_module
    prefix = f"{root}."
    if root != "." and module.startswith(prefix):
        module = module[len(prefix) :]
    return Path(*module.split("."))


def run_contract_tests(
    *,
    candidate_code: str,
    seed_module: str,
    import_roots: tuple[str, ...],
    evaluator: EvaluatorAssets,
) -> ContractRunOutcome:
    """Materialize ``candidate_code`` and run its task's contract tests against it.

    Raises :class:`ContractExecutionError` when the subprocess itself could
    not be run or produced no parseable result (an infrastructure failure,
    distinct from the candidate merely failing its tests).
    """

    with tempfile.TemporaryDirectory(prefix="leitir-differential-") as workspace_str:
        workspace = Path(workspace_str)
        module_path = workspace / _module_relative_path(seed_module, import_roots).with_suffix(".py")
        module_path.parent.mkdir(parents=True, exist_ok=True)
        module_path.write_text(candidate_code, encoding="utf-8")

        junit_path = workspace / "junit.xml"
        env = {
            "PATH": _minimal_path(),
            "PYTHONPATH": str(workspace),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
        }
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--tb=no",
            f"--junitxml={junit_path}",
            str(evaluator.contract_test_path),
        ]
        try:
            subprocess.run(
                cmd,
                cwd=str(workspace),
                env=env,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ContractExecutionError(f"could not run contract tests for {evaluator.case_id}: {exc}") from exc

        if not junit_path.exists():
            raise ContractExecutionError(
                f"contract-test run for {evaluator.case_id} produced no JUnit report "
                "(likely a pytest invocation failure)"
            )
        return _parse_junit(junit_path)


def _minimal_path() -> str:
    return os.environ.get("PATH", "/usr/bin:/bin")


def _parse_junit(path: Path) -> ContractRunOutcome:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ContractExecutionError(f"could not parse JUnit report {path}: {exc}") from exc
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise ContractExecutionError(f"JUnit report {path} has no <testsuite>")
    total = int(suite.get("tests", "0"))
    failed = int(suite.get("failures", "0"))
    errored = int(suite.get("errors", "0"))
    skipped = int(suite.get("skipped", "0"))
    passed = total - failed - errored - skipped
    if passed < 0:
        raise ContractExecutionError(f"JUnit report {path} has inconsistent counts")
    return ContractRunOutcome(passed=passed, failed=failed, errored=errored, skipped=skipped, total=total)


__all__ = ["ContractExecutionError", "ContractRunOutcome", "run_contract_tests"]
