"""Hallucinated-symbol measurement: shells out to ``leitir check``.

This module never reimplements ``leitir check``'s API-surface verification.
It invokes it exactly as a user would (``python -m leitir.cli check ...``)
as a subprocess and classifies the result.

``leitir check`` needs to materialize the pinned source it checks against,
which requires network access. In this offline harness that call will
typically fail to reach the network (or, when it does reach a fixture, may
find no usage of the checked-against package at all in a from-scratch
candidate) -- both are recorded as :class:`Unavailable`, never as a clean
"0 hallucinations" result. ``check`` exits 4 (``NOTHING_INDEXED``) when it
examined zero sites; per the harness contract this is always treated as
"not measured," never as "clean." See ``tests/test_differential_eval.py``
for an offline positive-path test against a local HTTP fixture (mirroring
``tests/test_check_cli_e2e.py``) that proves the classification logic
itself is correct without touching the network.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .metrics import Measured, Metric, Unavailable

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"

_EXIT_SUCCESS = 0
_EXIT_CORPUS_FAILURE = 1
_EXIT_MALFORMED_USAGE = 2
_EXIT_INFRASTRUCTURE_FAILURE = 3
_EXIT_NOTHING_INDEXED = 4

_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True)
class HallucinationMeasurement:
    hallucinated_symbol_count: Metric[int]
    check_status: Metric[str]


def run_leitir_check(
    *,
    candidate_path: Path,
    against_spec: str,
    corpus_root: Path,
    cwd: Path,
    extra_env: Mapping[str, str] | None = None,
) -> HallucinationMeasurement:
    """Shell out to ``leitir check`` and classify the outcome.

    Never returns a numeric hallucination count unless ``leitir check``
    actually examined at least one site and reported it in valid JSON.
    """

    # Preserve the Windows process environment (notably SYSTEMROOT, COMSPEC,
    # SystemDrive, TEMP, and TMP).  The CLI still receives the intentionally
    # controlled import path and PATH used by this bridge.
    env: dict[str, str] = dict(os.environ)
    env.update({"PATH": _path_env(), "PYTHONPATH": str(_SRC)})
    if extra_env:
        env.update(extra_env)

    cmd = [
        sys.executable,
        "-m",
        "leitir.cli",
        "check",
        str(candidate_path),
        "--against",
        against_spec,
        "--root",
        str(corpus_root),
        "--no-verify",
        "--json",
    ]
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _unavailable("leitir check timed out (no network in this offline harness run)")
    except OSError as exc:
        return _unavailable(f"could not invoke leitir check: {exc}")

    if completed.returncode == _EXIT_NOTHING_INDEXED:
        return _unavailable("leitir check examined zero sites (nothing_examined)")
    if completed.returncode in (_EXIT_SUCCESS, _EXIT_CORPUS_FAILURE):
        try:
            payload = json.loads(completed.stdout)
            counts = payload["counts"]
            violations = int(counts["sites_violation"])
            examined = int(counts["sites_examined"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return _unavailable(
                f"leitir check exited {completed.returncode} without a parseable JSON payload"
            )
        if examined == 0:
            return _unavailable("leitir check examined zero sites (nothing_examined)")
        status = "clean" if violations == 0 else "violations_found"
        return HallucinationMeasurement(
            hallucinated_symbol_count=Measured(violations), check_status=Measured(status)
        )
    if completed.returncode == _EXIT_MALFORMED_USAGE:
        return _unavailable(f"leitir check rejected the request: {_short(completed.stderr)}")
    return _unavailable(
        f"leitir check infrastructure failure (exit {completed.returncode}): {_short(completed.stderr)}"
    )


def _unavailable(reason: str) -> HallucinationMeasurement:
    return HallucinationMeasurement(
        hallucinated_symbol_count=Unavailable(reason), check_status=Unavailable(reason)
    )


def _short(text: str, limit: int = 200) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "..."


def _path_env() -> str:
    return os.environ.get("PATH", "/usr/bin:/bin")


__all__ = ["HallucinationMeasurement", "run_leitir_check"]
