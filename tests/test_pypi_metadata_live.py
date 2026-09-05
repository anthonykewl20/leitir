"""Real PyPI metadata, downloads and fail-closed source tampering."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="real PyPI access requires LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_real_pypi_repository_and_artifact_only_sources(tmp_path: Path) -> None:
    def invoke(spec: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "leitir.cli", "info", spec, "--root", str(tmp_path), "--json"], capture_output=True, text=True, timeout=180, check=False)
    attrs = invoke("pypi:attrs@24.2.0")
    assert attrs.returncode == 0, attrs.stderr
    assert "python-attrs/attrs" in attrs.stdout
    assert "sponsors/hynek" not in json.dumps(json.loads(attrs.stdout)["provenance"])
    soup = invoke("pypi:beautifulsoup4@4.12.3")
    assert soup.returncode == 0, soup.stderr
    assert "registry/beautifulsoup4" in soup.stdout
    entries = json.loads((tmp_path / "sources.json").read_text())
    entry = next(row for row in entries if "beautifulsoup4" in row["repo"])
    target = tmp_path / entry["path"]
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["degraded_provenance"] == "no supported source repository declared"
    assert manifest["source"] == "registry-artifact"
    file = next(target.rglob("element.py"))
    file.write_bytes(file.read_bytes() + b"\n# altered actual downloaded source\n")
    from leitir.info import build_info

    with pytest.raises(ValueError, match="source has no valid manifest"):
        build_info("pypi:beautifulsoup4@4.12.3", corpus_root=tmp_path)
