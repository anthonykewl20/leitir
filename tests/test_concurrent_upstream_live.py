"""Exercise real concurrent CLI clients against an immutable upstream package."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

pytestmark = [pytest.mark.live, pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="real concurrent upstream clients require LEITIR_ENABLE_LIVE_E2E=1",
)]


def test_concurrent_packaging_materialization_and_trust(tmp_path: Path) -> None:
    from leitir.materialize import read_valid_manifest

    sha = "85442b8032cb7bae72866dfd7782234a98dd2fb7"
    pin = "pypa/packaging@" + sha
    root = tmp_path / "corpus"

    def invoke(command: str) -> subprocess.CompletedProcess[str]:
        spec = "github:" + pin if command == "get" else pin
        return subprocess.run(
            [sys.executable, "-m", "leitir.cli", command, spec,
             "--root", str(root), "--json"],
            capture_output=True, text=True, timeout=180, check=False,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(invoke, ["get"] * 8))
    for result in results:
        assert result.returncode == 0, result.stderr
    paths = {json.loads(result.stdout)["results"][0]["path"] for result in results}
    assert len(paths) == 1
    target = Path(paths.pop())
    assert read_valid_manifest(target, "pypa", "packaging", sha) is not None
    with ThreadPoolExecutor(max_workers=8) as pool:
        trusted = list(pool.map(invoke, ["trust"] * 8))
    for result in trusted:
        assert result.returncode == 0, result.stderr
    assert read_valid_manifest(target, "pypa", "packaging", sha) is not None
    entries = json.loads((root / "sources.json").read_text())
    assert len(entries) == 1
    # Real published source must still be rejected after all writers complete.
    source = target / "src/packaging/version.py"
    source.write_bytes(source.read_bytes() + b"\n# live tamper probe\n")
    assert read_valid_manifest(target, "pypa", "packaging", sha) is None
