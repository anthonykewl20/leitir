"""Opt-in live gate for the CLI shell (ADR-001 P4).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Drives ``leitir search`` through both
input modes against live GitHub and registry APIs, verifying the full
resolver -> engine -> report pipeline produces correct provenance.
"""

from __future__ import annotations

import io
import json
import os

import pytest

from leitir.cli import ExitCode, main

import fixtures_real as fx
import fixtures_resolver as rfx

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)


def _invoke(argv):
    out = io.StringIO()
    err = io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class TestLiveExplicitScope:
    def test_finds_urlencode_definition(self):
        code, out, err = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", f"path:{fx.PATH}",
            "--must", "symbol_definition:urlencode:python",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert len(payload["matches"]) > 0
        top = payload["matches"][0]
        assert top["source"]["slug"] == fx.REPO_SLUG
        assert top["source"]["commit_sha"] == fx.COMMIT_SHA
        assert top["source"]["path"] == fx.PATH
        assert top["source"]["blob_sha"] == fx.BLOB_SHA

    def test_permalink_is_immutable(self):
        code, out, _ = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", f"path:{fx.PATH}",
            "--must", "symbol_definition:urlencode:python",
        ])
        payload = json.loads(out)
        permalink = payload["matches"][0]["source"]["permalink"]
        assert f"/blob/{fx.COMMIT_SHA}/" in permalink
        assert "/blob/main/" not in permalink

    def test_coverage_is_honest(self):
        code, out, _ = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", f"path:{fx.PATH}",
            "--must", "symbol_definition:urlencode:python",
        ])
        payload = json.loads(out)
        cov = payload["coverage"]
        assert cov["files_eligible"] >= 1
        assert cov["files_indexed"] >= 1
        assert cov["files_indexed"] <= cov["files_eligible"]


class TestLivePackageResolution:
    def test_pypi_resolution_and_search(self):
        code, out, err = _invoke([
            "search",
            "--package", rfx.PYPI_NAME,
            "--version", rfx.PYPI_VERSION,
            "--ecosystem", "pypi",
            "--must", "identifier:Session",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["matches"][0]["source"]["slug"] == rfx.PYPI_SLUG
        assert payload["matches"][0]["source"]["commit_sha"] == rfx.PYPI_COMMIT_SHA


class TestLiveSadPaths:
    def test_corrupted_commit_yields_error(self):
        code, out, err = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", "0" * 40,
            "--must", "identifier:urlencode",
        ])
        assert code == ExitCode.INFRASTRUCTURE_FAILURE

    def test_unknown_package_is_infrastructure_failure(self):
        code, out, err = _invoke([
            "search",
            "--package", "nonexistent_pkg_xyz_999",
            "--version", "0.0.1",
            "--ecosystem", "pypi",
            "--must", "identifier:foo",
        ])
        assert code == ExitCode.INFRASTRUCTURE_FAILURE
