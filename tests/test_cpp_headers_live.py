"""Explicit C++ header searches over the real immutable fmt source."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="actual fmt source requires LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_real_fmt_header_definitions_are_eligible_for_cpp(tmp_path: Path) -> None:
    manifest = json.loads((Path(__file__).parents[1] / "src/leitir/benchmarks/search-v1/manifest.json").read_text())
    tasks = [task for task in manifest["tasks"] if task["language"] == "cpp"]
    assert len(tasks) == 4
    for task in tasks:
        expected = task["expected_results"][0]
        with urlopen(f'https://raw.githubusercontent.com/{expected["slug"]}/{expected["commit_sha"]}/{expected["path"]}', timeout=60) as response:
            raw = response.read()
        assert hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest() == expected["blob_sha"]
        symbol = next(predicate["value"] for predicate in task["must"] if predicate["kind"] == "symbol_definition")
        assert symbol in raw.decode().splitlines()[expected["start_line"] - 1]
        result = subprocess.run([sys.executable, "-m", "leitir.cli", "search", "--repo", expected["slug"], "--commit", expected["commit_sha"], "--must", "path:" + expected["path"] + ":cpp", "--must", "symbol_definition:" + symbol + ":cpp", "--root", str(tmp_path), "--json"], capture_output=True, text=True, timeout=180, check=False)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["coverage"]["files_eligible"] == 1
        assert any(match["source"]["blob_sha"] == expected["blob_sha"] and match["source"]["start_line"] == expected["start_line"] for match in report["matches"]), report
