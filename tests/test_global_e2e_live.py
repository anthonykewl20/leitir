"""Opt-in live gate for global discovery (ADR-001 P5).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Drives ``leitir search --global``
against the live GitHub Code Search API and verifies honest coverage reporting.
"""

from __future__ import annotations

import io
import json
import os

import pytest

from leitir.cli import ExitCode, main

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)


def _invoke(argv):
    out = io.StringIO()
    err = io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class TestLiveGlobalDiscovery:
    def test_finds_python_symbol(self):
        code, out, err = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
            "--must", "path:urllib",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "indeterminate_global"
        assert len(payload["matches"]) > 0

    def test_coverage_is_honest(self):
        code, out, _ = _invoke([
            "search", "--global",
            "--must", "identifier:urlencode:python",
        ])
        payload = json.loads(out)
        cov = payload["coverage"]
        assert cov["status"] == "indeterminate_global"
        assert cov["files_indexed"] >= 0
        assert cov["files_eligible"] >= 0

    def test_provenance_has_commit_sha(self):
        code, out, _ = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
            "--must", "path:urllib",
        ])
        payload = json.loads(out)
        if payload["matches"]:
            sha = payload["matches"][0]["source"]["commit_sha"]
            assert len(sha) == 40


class TestLiveGlobalSadPaths:
    def test_no_results_for_absurd_query(self):
        code, out, _ = _invoke([
            "search", "--global",
            "--must", "identifier:zzz_nonexistent_symbol_xyz_999:python",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "indeterminate_global"
