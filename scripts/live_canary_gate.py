#!/usr/bin/env python3
"""Resolve Search v2 live-canary feature gates, failing closed on drift."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_GATES = (
    ("index_v2", "LEITIR_CANARY_INDEX_V2", "tests/test_index_recall_e2e_live.py"),
    ("stream_v2", "LEITIR_CANARY_STREAM_V2", "tests/test_streaming_e2e_live.py"),
    ("tree_v2", "LEITIR_CANARY_TREE_V2", "tests/test_tree_recovery_e2e_live.py"),
)
_TRUE = frozenset({"1", "on", "true", "yes"})
_FALSE = frozenset({"", "0", "false", "no", "off"})


def _parse_gate(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{name} must be an explicit boolean, got {raw!r}")


def _append_output(lines: list[str]) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if destination:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")


def evaluate(root: Path) -> tuple[tuple[str, bool], ...]:
    decisions: list[tuple[str, bool]] = []
    errors: list[str] = []
    for output_name, variable_name, test_path in _GATES:
        try:
            enabled = _parse_gate(variable_name)
        except ValueError as exc:
            enabled = False
            errors.append(str(exc))
        decisions.append((output_name, enabled))
        if enabled and not (root / test_path).is_file():
            errors.append(f"{variable_name}=true but required test is missing: {test_path}")
    if errors:
        raise ValueError("; ".join(errors))
    return tuple(decisions)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        decisions = evaluate(root)
    except ValueError as exc:
        # Emit deterministic false outputs for malformed configuration. For an
        # enabled-but-missing test, preserve the enabled output so the final
        # summary cannot mistake the surface for skipped coverage.
        fallback_decisions: list[tuple[str, bool]] = []
        for output_name, variable_name, _test_path in _GATES:
            try:
                enabled = _parse_gate(variable_name)
            except ValueError:
                enabled = False
            fallback_decisions.append((output_name, enabled))
        decisions = tuple(fallback_decisions)
        lines = [f"{name}={str(enabled).lower()}" for name, enabled in decisions]
        _append_output(lines)
        print("\n".join(lines))
        print(f"live canary gate configuration failure: {exc}", file=sys.stderr)
        return 1

    lines = [f"{name}={str(enabled).lower()}" for name, enabled in decisions]
    _append_output(lines)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
