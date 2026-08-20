"""Authoritative live-marker inventory and env-gate consistency (#198).

The `live` marker (registered in tests/conftest.py) is the authoritative
inventory of live-gated tests: ``pytest -m live --collect-only -q`` lists
exactly the tests that are gated on ``LEITIR_ENABLE_LIVE_E2E``.  The two
tests here keep that statement mechanically true:

- the inventory command's file set must equal an independently derived
  env-gated set (AST over the test sources — the grep cross-check upgraded
  to a parse, since one file mentions the variable without gating on it);
- the marker must be registered so a typo'd marker name fails collection
  (unknown markers are errors via conftest's filterwarnings).
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_TESTS = _ROOT / "tests"
_ENV_GATE = "LEITIR_ENABLE_LIVE_E2E"


def _env_gated_files_by_source() -> set[str]:
    """Independently derive the files that gate tests on the live env var.

    A file gates when a ``skipif(...)`` call references the env var (module
    ``pytestmark`` or a decorator), or when it module-skips on the env var
    (``allow_module_level``).  Files that merely mention the variable in
    assertions (e.g. test_live_canary_workflow.py) are NOT gates.
    """
    gated: set[str] = set()
    for path in sorted(_TESTS.rglob("*.py")):
        if path.name == Path(__file__).name:
            # The auditor is not a subject: this file mentions the gate
            # constants in its own derivation logic and gates nothing.
            continue
        source = path.read_text(encoding="utf-8")
        if _ENV_GATE not in source:
            continue
        relative = path.relative_to(_ROOT).as_posix()
        if "allow_module_level=True" in source:
            gated.add(relative)
            continue
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "skipif"
                and _ENV_GATE in ast.unparse(node)
            ):
                gated.add(relative)
                break
    return gated


def _inventory_files() -> set[str]:
    """Run the documented inventory command and return its file set.

    Includes collection-level skips (a module that skips at import when the
    env var is unset is still live-gated — its tests appear once the gate is
    on), so the subprocess env deliberately leaves the gate unset.
    """
    env = dict(os.environ)
    env.pop("LEITIR_ENABLE_LIVE_E2E", None)
    env["PYTHONPATH"] = f"src{os.pathsep}."
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-m",
            "live",
            "--collect-only",
            "-q",
            "-rs",
        ),
        cwd=_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    files: set[str] = set()
    for line in result.stdout.splitlines():
        nodeid = re.match(r"^(tests[/\\][^\s:]+\.py)::", line)
        if nodeid:
            files.add(nodeid.group(1).replace("\\", "/"))
            continue
        skipped = re.match(r"^SKIPPED \[\d+\] (tests[/\\][^\s:]+\.py):\d+: (.*)$", line)
        if skipped and _ENV_GATE in skipped.group(2):
            # pytest emits os-native separators in skip-summary locations
            # on Windows; normalize to the forward-slash nodeid form.
            files.add(skipped.group(1).replace("\\", "/"))
    assert files, "live inventory came back empty — marker application drifted"
    return files


def test_live_marker_inventory_matches_env_gated_files() -> None:
    inventory = _inventory_files()
    gated = _env_gated_files_by_source()
    assert inventory == gated, (
        "live marker / env-gate drift: "
        f"marked-but-not-gated (SP-2, would run offline): {sorted(inventory - gated)}; "
        f"gated-but-not-marked (SP-1, invisible to inventory): {sorted(gated - inventory)}"
    )


def test_live_marker_is_registered() -> None:
    result = subprocess.run(
        (sys.executable, "-m", "pytest", "--markers"),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": f"src{os.pathsep}."},
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "@pytest.mark.live" in result.stdout, "live marker must be registered"
