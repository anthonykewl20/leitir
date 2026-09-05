"""Build and install the real release archives, then reject altered artifacts."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
                       reason="real release builds and upstream installs require live opt-in"),
]


def test_real_distributions_install_and_reject_version_tampering(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    public = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    normalized = ".".join(str(int(part)) for part in public.split("."))
    env = dict(os.environ, LEITIR_NO_UPDATE_CHECK="1")
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)

    def run(*args: str, cwd: Path = tmp_path, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        return result

    dist = tmp_path / "dist"
    run("uv", "run", "--no-project", "--with", "build", "python", "-m", "build",
        "--outdir", str(dist), cwd=root)
    verifier = str(root / "tools/verify_release.py")
    project = str(root / "pyproject.toml")

    def verify(directory: Path, *, tag: str = "v" + public, ok: bool = True) -> None:
        run(sys.executable, verifier, "--tag", tag, "--dist", str(directory), "--project", project, ok=ok)

    verify(dist)
    for number, archive in enumerate(sorted(dist.iterdir())):
        venv = tmp_path / f"venv-{number}"
        run("uv", "venv", "--python", sys.executable, str(venv))
        python = str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
        run("uv", "pip", "install", "--python", python, "--no-deps", str(archive))
        assert run(python, "-m", "leitir.cli", "--version").stdout.strip() == "leitir " + public
        assert run(python, "-c", "import importlib.metadata; print(importlib.metadata.version('leitir'))").stdout.strip() == normalized
        # This is the installed artifact resolving and materializing real upstream source.
        fetched = run(python, "-m", "leitir.cli", "get",
            "github:pypa/packaging@85442b8032cb7bae72866dfd7782234a98dd2fb7",
            "--root", str(tmp_path / f"corpus-{number}"), "--json")
        target = Path(json.loads(fetched.stdout)["results"][0]["path"])
        manifest = json.loads((target / "leitir-manifest.json").read_text())
        assert manifest["commit_sha"] == "85442b8032cb7bae72866dfd7782234a98dd2fb7"
        assert manifest["verified"] is True
        assert manifest["parity"] == "exact"
    verify(dist, tag="v" + ".".join(public.split(".")[:2]) + ".00", ok=False)
    verify(dist, tag="v999.999.999", ok=False)
    extra = tmp_path / "extra"
    shutil.copytree(dist, extra)
    (extra / "unexpected.txt").write_text("unexpected artifact")
    verify(extra, ok=False)
    for kind in ("wheel", "sdist"):
        altered = tmp_path / kind
        shutil.copytree(dist, altered)
        if kind == "wheel":
            archive = next(altered.glob("*.whl"))
            with zipfile.ZipFile(archive) as original:
                members = [(item, original.read(item)) for item in original.infolist()]
            with zipfile.ZipFile(archive, "w") as changed:
                for item, data in members:
                    if item.filename.endswith(".dist-info/METADATA"):
                        data = data.replace(f"Version: {normalized}\n".encode(), b"Version: 999.999.999\n")
                    changed.writestr(item, data)
        else:
            archive = next(altered.glob("*.tar.gz"))
            with tarfile.open(archive, "r:gz") as original:
                entries = []
                for item in original.getmembers():
                    stream = original.extractfile(item) if item.isfile() else None
                    data = stream.read() if stream is not None else None
                    if stream is not None:
                        stream.close()
                    entries.append((item, data))
            with tarfile.open(archive, "w:gz") as changed:
                for item, data in entries:
                    if item.name == f"leitir-{normalized}/PKG-INFO" and data is not None:
                        data = data.replace(f"Version: {normalized}\n".encode(), b"Version: 999.999.999\n")
                        item.size = len(data)
                    changed.addfile(item, io.BytesIO(data) if data is not None else None)
        verify(altered, ok=False)
