"""Probe an actual published Python class closure through the CLI."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 for the real Packaging donor",
)


@pytest.mark.live
def test_packaging_parse_does_not_hide_constructor_dependencies(tmp_path: Path) -> None:
    pin = "pypa/packaging@85442b8032cb7bae72866dfd7782234a98dd2fb7"
    def invoke(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "leitir.cli", *args, "--root", str(tmp_path / "corpus"), "--json"],
            capture_output=True, text=True, timeout=180, check=False,
        )
    fetched = invoke("get", "github:" + pin)
    assert fetched.returncode == 0, fetched.stderr
    computed = invoke("bts-compute", pin, "--seed-module", "src.packaging.version",
                      "--seed-name", "src.packaging.version.parse", "--out", str(tmp_path / "bts"))
    # This real class contains unresolved receiver dispatch and stdlib calls
    # not authorized by the empty default policy. COMPLETE is unsound.
    assert computed.returncode != 0, computed.stdout
    assert json.loads(computed.stdout)["status"] == "REJECT"
    # Known blockers on the accepted seed dominate later nested-owner exhaustion.
    from leitir.bts import compute_bts
    from leitir.bts_cli import (
        _default_budget,
        _default_resolution_policy,
        load_donor_snapshot,
        python_graph_provider,
    )
    snapshot = load_donor_snapshot(tmp_path / "corpus", "pypa", "packaging", pin.split("@")[1])
    graph = python_graph_provider(snapshot)(snapshot.source_root)
    seed = next(node for node in graph.nodes if node.id.qualified_name == "noxfile.tests")
    known = tuple(item for item in graph.unresolved if item.source == seed.id)
    assert known
    for units in (2, 3):
        result = compute_bts(snapshot, seed.id, graph,
                             replace(_default_budget(), max_work_units=units), _default_resolution_policy())
        assert result.status.value == "reject"
        assert all(item in result.report.unresolved for item in known)
    # The actual source still must be authenticated before graph use.
    fetched_target = Path(json.loads(fetched.stdout)["results"][0]["path"])
    version = fetched_target / "src/packaging/version.py"
    version.write_bytes(version.read_bytes().replace(b"def parse(", b"def parsE(", 1))
    tampered = invoke("bts-compute", pin, "--list-seeds")
    assert tampered.returncode != 0
