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
_DISPATCH_BOOLEAN_NAMES = (
    "DISPATCH_ENABLE_INDEX_V2",
    "DISPATCH_ENABLE_STREAM_V2",
    "DISPATCH_ENABLE_TREE_V2",
)
_RUN_SURFACES = frozenset({"default", "all", "baseline-only"})
EXTRA_TEST_ALLOWLIST = (
    "tests/test_info.py::test_live_tinode_routes_study_only",
    "tests/test_diff_e2e.py::test_live_two_public_pypi_versions",
    "tests/test_diff_e2e.py::test_live_cli_tag_diff_identity_matches_manifest_pins",
    "tests/test_resolver_codeberg.py::test_live_pinned_commit_resolves",
    "tests/test_resolver_codeberg.py::test_live_symlink_reread_returns_digest_verified_target",
    "tests/test_discovery_coverage.py::test_provider_coverage_reported",
    "tests/test_resolver_gitlab.py::test_live_ref_resolves_to_pinned_commit",
    "tests/test_resolver_gitlab.py::test_live_subgroup_ref_resolves_to_pinned_commit",
    "tests/test_resolver_bitbucket.py::test_live_ref_resolves_to_pinned_commit",
)


def _parse_gate(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{name} must be an explicit boolean, got {raw!r}")


def _parse_dispatch_boolean(name: str) -> bool:
    raw = os.environ.get(name, "")
    if raw not in {"true", "false"}:
        raise ValueError(f"{name} must be the canonical boolean true or false, got {raw!r}")
    return raw == "true"


def _parse_extra_tests() -> str:
    raw = os.environ.get("DISPATCH_EXTRA_TESTS", "")
    if not raw.strip():
        return ""
    requested = [item.strip() for item in raw.split(",")]
    if any(not item for item in requested):
        raise ValueError("DISPATCH_EXTRA_TESTS contains an empty test node ID")
    configured_allowlist = os.environ.get("DISPATCH_EXTRA_TEST_ALLOWLIST")
    canonical_allowlist = " ".join(EXTRA_TEST_ALLOWLIST)
    if configured_allowlist is not None and configured_allowlist != canonical_allowlist:
        raise ValueError("DISPATCH_EXTRA_TEST_ALLOWLIST diverges from the script allowlist")
    unknown = sorted(set(requested).difference(EXTRA_TEST_ALLOWLIST))
    if unknown:
        raise ValueError(f"DISPATCH_EXTRA_TESTS contains unknown test node ID(s): {unknown}")
    if len(set(requested)) != len(requested):
        raise ValueError("DISPATCH_EXTRA_TESTS contains duplicate test node IDs")
    return " ".join(requested)


def _append_output(lines: list[str]) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if destination:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")


def _resolve_dispatch_surfaces() -> tuple[tuple[str, bool], ...]:
    run_surfaces = os.environ.get("DISPATCH_RUN_SURFACES", "default")
    if run_surfaces not in _RUN_SURFACES:
        raise ValueError(f"DISPATCH_RUN_SURFACES must be one of {sorted(_RUN_SURFACES)}, got {run_surfaces!r}")
    values = [_parse_dispatch_boolean(name) for name in _DISPATCH_BOOLEAN_NAMES]
    if run_surfaces == "baseline-only":
        return tuple((name, False) for name, _variable, _path in _GATES)
    if run_surfaces == "all":
        return tuple((name, True) for name, _variable, _path in _GATES)
    return tuple((gate[0], value) for gate, value in zip(_GATES, values, strict=True))


def evaluate(root: Path) -> tuple[tuple[str, bool], ...]:
    decisions: list[tuple[str, bool]] = []
    errors: list[str] = []
    dispatch = os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
    if dispatch:
        dispatch_decisions = dict(_resolve_dispatch_surfaces())
    for output_name, variable_name, test_path in _GATES:
        try:
            enabled = (
                dispatch_decisions[output_name]
                if dispatch
                else _parse_gate(variable_name)
            )
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
        extra_tests = _parse_extra_tests() if os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" else ""
    except ValueError as exc:
        # Emit deterministic false outputs for every malformed configuration.
        decisions = tuple((output_name, False) for output_name, _variable_name, _test_path in _GATES)
        lines = [f"{name}={str(enabled).lower()}" for name, enabled in decisions]
        lines.append("extra_tests=")
        lines.append("extra_tests_requested=false")
        _append_output(lines)
        print("\n".join(lines))
        print(f"live canary gate configuration failure: {exc}", file=sys.stderr)
        return 1

    lines = [f"{name}={str(enabled).lower()}" for name, enabled in decisions]
    lines.append(f"extra_tests={extra_tests}")
    lines.append(f"extra_tests_requested={str(bool(extra_tests)).lower()}")
    _append_output(lines)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
