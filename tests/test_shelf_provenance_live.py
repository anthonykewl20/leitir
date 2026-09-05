"""Real Git symlinks, Go proxy eligibility and artifact/Git provenance."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="real shelves require LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_real_shelf_identity_indexing_and_tamper_rejection(tmp_path: Path) -> None:
    def invoke(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "leitir.cli", *args, "--root", str(root), *([] if args[0] == "index" else ["--json"])], capture_output=True, text=True, timeout=240, check=False)
    gitroot = tmp_path / "requests"
    pin = "0e322af87745eff34caffe4df68456ebc20d9068"
    fetched = invoke(gitroot, "get", "github:psf/requests@" + pin)
    assert fetched.returncode == 0, fetched.stderr
    indexed = invoke(gitroot, "index")
    assert indexed.returncode == 0, indexed.stderr
    found = invoke(gitroot, "search", "--repo", "psf/requests", "--commit", pin, "--must", "identifier:Session", "--require-index")
    assert found.returncode == 0, found.stderr
    assert json.loads(found.stdout)["matches"]
    goroot = tmp_path / "go"
    go = invoke(goroot, "get", "go:rsc.io/quote@v1.5.2")
    assert go.returncode == 0, go.stderr
    skipped = invoke(goroot, "index")
    assert skipped.returncode == 4, skipped.stderr
    assert "source" in skipped.stdout + skipped.stderr
    artifactroot = tmp_path / "zod"
    artifact = invoke(artifactroot, "info", "npm:zod@3.23.8")
    assert artifact.returncode == 0, artifact.stderr
    entry = json.loads((artifactroot / "sources.json").read_text())[0]
    searched = invoke(artifactroot, "search", "--repo", entry["owner"] + "/" + entry["repo"], "--commit", entry["commit_sha"], "--must", "identifier:ZodType")
    # Compiled artifact bytes cannot stand in for missing/different Git source.
    assert searched.returncode != 0, searched.stdout
    entry = json.loads((gitroot / "sources.json").read_text())[0]
    target = gitroot / entry["path"]
    link = next(path for path in target.rglob("*") if path.is_symlink())
    link.unlink()
    link.symlink_to("unrelated-target")
    rejected = invoke(gitroot, "index")
    assert rejected.returncode != 0


@pytest.mark.live
def test_actual_normalized_vitest_shelf_cannot_invent_git_blob_identity(tmp_path: Path) -> None:
    from leitir.tree import GitHubTreeSource

    pin = "c9e59a089d94642eea29a43f2ee1986a5afb99c6"
    slug = "vitest-dev/vitest"
    def invoke(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "leitir.cli", *args, "--root", str(tmp_path), "--json"], capture_output=True, text=True, timeout=300, check=False)
    fetched = invoke("get", "github:" + slug + "@" + pin)
    assert fetched.returncode == 0, fetched.stderr
    target = Path(json.loads(fetched.stdout)["results"][0]["path"])
    source = GitHubTreeSource(token=os.environ.get("GITHUB_TOKEN"))
    blobs = {item.path: item for item in source.list_blobs(slug, pin)}
    normalized = "test/reporters/fixtures/indicator-position.test.js"
    # GitHub's real archive has CRLF here; the pinned Git blob identity is
    # different. A full local tree hash authenticates the archive bytes only.
    assert GitHubTreeSource.git_blob_sha((target / normalized).read_bytes()) != blobs[normalized].blob_sha
    bad = invoke("search", "--repo", slug, "--commit", pin,
                 "--must", "path:" + normalized + ":js", "--must", "identifier:expect:js")
    assert bad.returncode != 0, bad.stdout
    # Exact bytes elsewhere in the same sampled shelf remain searchable
    # after checking them against the real upstream tree identities.
    path = "packages/vitest/src/node/core.ts"
    control = invoke("search", "--repo", slug, "--commit", pin,
                     "--must", "path:" + path + ":ts", "--must", "identifier:Vitest:ts")
    assert control.returncode == 0, control.stderr
    matches = json.loads(control.stdout)["matches"]
    assert matches and all(item["source"]["blob_sha"] == blobs[path].blob_sha for item in matches)
