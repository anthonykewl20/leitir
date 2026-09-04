"""Full offline test suite: the loop's first constraint gate (borrowed from GEPA-style gating)."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from xml.etree import ElementTree

from ..ledger import Finding
from . import ProbeContext, ProbeResult


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def probe(context: ProbeContext) -> ProbeResult:
    junit = context.run_dir / "junit.xml"
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short", f"--junitxml={junit}"]
    if _has_module("xdist"):
        command += ["-n", "auto"]
    env = {key: value for key, value in os.environ.items() if not key.startswith("LEITIR_ENABLE_")}
    env["PYTHONPATH"] = str(context.repo_root / "src")
    env["PYTHONHASHSEED"] = str(context.option("seed", 0))
    completed = subprocess.run(command, cwd=context.repo_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    output = completed.stdout.decode("utf-8", errors="replace")
    (context.run_dir / "suite.log").write_text(output, encoding="utf-8")
    result = ProbeResult("suite", "ok")
    if not junit.exists():
        result.status = "error"
        result.notes.append(f"pytest exited {completed.returncode} without a JUnit report; see suite.log")
        return result
    root = ElementTree.parse(junit).getroot()
    tests = failures = errors = skipped = 0
    duration = 0.0
    for suite in root.iter("testsuite"):
        tests += int(suite.get("tests", 0))
        failures += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
        duration += float(suite.get("time", 0.0))
    for case in root.iter("testcase"):
        for tag, category in (("failure", "test-failure"), ("error", "test-error")):
            node = case.find(tag)
            if node is None:
                continue
            classname = case.get("classname", "")
            file_part = classname.split(".")[0:2]
            test_file = "/".join(file_part) + ".py" if classname.startswith("tests.") else classname
            nodeid = f"{test_file}::{case.get('name', '')}"
            message = (node.get("message") or "")[:300]
            result.findings.append(
                Finding(
                    probe="suite",
                    category=category,
                    severity="critical",
                    title=f"{category}: {nodeid}",
                    location=nodeid,
                    evidence={"identity": nodeid, "message": message, "exit_code": completed.returncode},
                    reproducer=f"PYTHONPATH=src python -m pytest -q '{nodeid}'",
                )
            )
    result.metrics = {
        "tests": tests,
        "passed": tests - failures - errors - skipped,
        "failed": failures,
        "errors": errors,
        "skipped": skipped,
        "duration_seconds": round(duration, 1),
        "exit_code": completed.returncode,
    }
    if completed.returncode not in (0, 1):
        result.notes.append(f"pytest exit code {completed.returncode}")
    return result
