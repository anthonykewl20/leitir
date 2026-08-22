"""Make the tests directory importable so e2e fixtures can be shared."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TESTS_DIR = str(Path(__file__).resolve().parent)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)


_MOCK_PRINCIPAL_TESTS = frozenset(
    {
        "test_corpus_bench.py::test_cli_discovers_and_runs_packaged_corpus_manifest",
        "test_corpus_cli.py::test_lock_emits_machine_json_and_progress_on_stderr",
        "test_corpus_cli.py::test_lock_best_effort_emits_failures_and_reports_each_one",
        "test_corpus_cli.py::test_lock_best_effort_returns_failure_when_nothing_materialized",
        "test_corpus_cli.py::test_sbom_emits_machine_json_and_progress_on_stderr",
        "test_corpus_cli.py::test_get_json_emits_materialization_metadata",
        "test_corpus_cli.py::test_api_materializes_extracts_and_prints_cache_path",
        "test_corpus_cli.py::test_examples_materializes_ensures_api_and_prints_cache_path",
        "test_diff.py::test_cli_json_shape_and_empty_diff_exits_zero",
    }
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "mock_principal: CLI/wiring test that replaces the principal domain operation",
    )
    config.addinivalue_line(
        "markers",
        "live: opt-in live-gated test (skips without LEITIR_ENABLE_LIVE_E2E=1; "
        "authoritative inventory: pytest -m live --collect-only -q — see docs/testing.md)",
    )
    # Strict-marker discipline (#198 SP-3): an unregistered (e.g. typo'd)
    # marker name is a collection error, not a silent no-op decoration.
    config.addinivalue_line(
        "filterwarnings", "error::pytest.PytestUnknownMarkWarning"
    )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        relative_nodeid = item.nodeid.removeprefix("tests/")
        if relative_nodeid in _MOCK_PRINCIPAL_TESTS:
            item.add_marker(pytest.mark.mock_principal)
