"""Opt-in full resolution, materialization, and verification of corpus-v1."""

import os

import pytest

from leitir.bench import load_manifest
from leitir.cli import _build_default_code_search, _build_default_resolver
from leitir.corpus_bench import CorpusBenchmarkRunner

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live corpus verification",
)


def test_corpus_v1_resolves_and_materializes_in_isolated_root():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    manifest = load_manifest("corpus-v1")
    run = CorpusBenchmarkRunner(
        _build_default_resolver(token), _build_default_code_search(token), token
    ).run(manifest)
    assert len(run.tasks) == len(manifest.tasks)
    assert all(task.results for task in run.tasks)
