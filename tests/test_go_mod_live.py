"""Published rsc/quote metadata checked against the installed Go toolchain."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from urllib.request import urlopen

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="real Go registry access requires LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_published_quoted_go_mod_and_actual_module_graph(tmp_path: Path) -> None:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain required for independent module-graph oracle")
    from leitir.lockfiles import dependency_closures, detect_installed_version

    pin = "c4d4236f92427c64bfbcf1cc3f8142ab18f30b22"
    with urlopen(f"https://raw.githubusercontent.com/rsc/quote/{pin}/go.mod", timeout=60) as response:
        raw = response.read()
    from leitir.bts_errors import BTSError
    from leitir.lockfiles import DependencyManifestPolicy, VerifiedManifestBytes, dependency_closures_from_manifest

    bound = VerifiedManifestBytes("go.mod", "dependency", len(raw), "sha256:" + hashlib.sha256(raw).hexdigest(), raw)
    policy = DependencyManifestPolicy(("go.mod",))
    verified = dependency_closures_from_manifest((bound,), policy)
    assert verified.sources[0].graph == "direct-only"
    with pytest.raises(BTSError):
        dependency_closures_from_manifest((replace(bound, content=raw + b"\n// altered upstream bytes\n"),), policy)
    (tmp_path / "go.mod").write_bytes(raw)
    parsed = subprocess.run([go, "mod", "edit", "-json"], cwd=tmp_path, capture_output=True, text=True, timeout=60, check=True)
    requirements = json.loads(parsed.stdout)["Require"]
    assert requirements
    closure = next(row for row in dependency_closures(tmp_path) if row.ecosystem == "go")
    assert [(edge.name, edge.version) for edge in closure.deps] == sorted((row["Path"], row["Version"]) for row in requirements)
    assert closure.graph == "direct-only"
    for row in requirements:
        assert detect_installed_version("go", row["Path"], tmp_path) == row["Version"]
    # Resolve the real graph independently; dependencies of sampler are absent
    # from quote's original go.mod, demonstrating why COMPLETE was false.
    graph = subprocess.run([go, "list", "-m", "-mod=mod", "all"], cwd=tmp_path, capture_output=True, text=True, timeout=180, check=True)
    assert "golang.org/x/text " in graph.stdout
    assert "golang.org/x/text" not in {edge.name for edge in closure.deps}
    # Exercise actual public materialization of the published quoted input.
    (tmp_path / "go.mod").write_bytes(raw)
    lock = subprocess.run([sys.executable, "-m", "leitir.cli", "lock", "--cwd", str(tmp_path), "--root", str(tmp_path / "corpus")], capture_output=True, text=True, timeout=240, check=False)
    assert lock.returncode == 0, lock.stderr
    entries = json.loads((tmp_path / "corpus/sources.json").read_text())
    assert entries
    for entry in entries:
        manifest = json.loads((tmp_path / "corpus" / entry["path"] / "leitir-manifest.json").read_text())
        assert manifest["graph"] == "direct-only"
