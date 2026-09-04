"""Leitir self-calibration harness (stdlib-only, imports no ``leitir`` code at module level).

The harness hunts for the project's own blind spots -- surviving mutants,
fuzz crashes, nondeterminism, uncovered fail-closed paths, performance and
accuracy drift -- and keeps a convergence ledger across runs so each iteration
can be compared to the last.  See ``docs/calibration.md`` and ADR-0037.
"""

from __future__ import annotations

CALIBRATION_SCHEMA_VERSION = "leitir-calibration-v1"
LEDGER_SCHEMA_VERSION = "leitir-calibration-ledger-v1"
