"""Real Flask upgrade impact through the production CLI and pinned sources."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.live, pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="real Flask release sources require LEITIR_ENABLE_LIVE_E2E=1",
)]


def test_removed_flask_encoder_owner_is_not_hidden_by_inherited_attribute(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus"
    cases = (
        ("from flask.json import JSONEncoder\nprint(JSONEncoder.encode)\n", True),
        ("from flask.json import JSONEncoder as Encoder\nprint(Encoder.encode)\n", True),
        ("import flask.json\nprint(flask.json.JSONEncoder.encode)\n", True),
        ("from flask import Flask\nprint(Flask)\n", False),
    )
    for position, (code, affected) in enumerate(cases):
        consumer = tmp_path / f"consumer{position}.py"
        consumer.write_text(code)
        result = subprocess.run(
            [sys.executable, "-m", "leitir.cli", "diff", "pypi:flask@2.2.5",
             "pypi:flask@2.3.0", "--impact", str(consumer),
             "--root", str(root), "--json"],
            capture_output=True, text=True, timeout=240, check=False,
        )
        assert result.returncode == 0, result.stderr
        impact = json.loads(result.stdout)["impact"]
        assert impact["counts"]["sites_examined"] == 1
        assert impact["counts"]["sites_unresolved"] == 0
        if affected:
            assert impact["status"] == "impact_found", impact
            assert impact["counts"]["sites_impacted"] == 1
            assert [item["name"] for item in impact["impacted"]] == ["JSONEncoder"]
            assert "JSONEncoder" not in impact["not_impacted"]
        else:
            assert impact["status"] == "clean", impact
            assert impact["counts"]["sites_impacted"] == 0
            assert impact["counts"]["sites_other"] == 1

    # Source integrity still rejects a mutation of the actual downloaded donor.
    from leitir.materialize import read_valid_manifest

    entry = json.loads((root / "sources.json").read_text())[0]
    target = root / entry["path"]
    source = next(target.glob("src/flask/json/__init__.py"))
    source.write_bytes(source.read_bytes() + b"\n# altered actual release bytes\n")
    assert read_valid_manifest(
        target, entry["owner"], entry["repo"], entry["commit_sha"], host=entry["host"],
    ) is None
