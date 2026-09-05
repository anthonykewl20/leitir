"""Build and install the real release archives, then reject altered artifacts."""
from __future__ import annotations

import io
import json
import os
import shutil
import struct
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
        checked = run(sys.executable, verifier, "--tag", tag, "--dist", str(directory), "--project", project, ok=ok)
        if not ok:
            assert checked.stderr.startswith("release verification rejected:")
            assert "Traceback" not in checked.stderr

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
    for kind in ("wheel", "sdist", "sdist-project-list", "sdist-project-string"):
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
                        if kind == "sdist":
                            data = data.replace(f"Version: {normalized}\n".encode(), b"Version: 999.999.999\n")
                        item.size = len(data)
                    if item.name == f"leitir-{normalized}/pyproject.toml" and kind.startswith("sdist-project-"):
                        data = b"project = []\n" if kind.endswith("list") else b'project = "invalid"\n'
                        item.size = len(data)
                    changed.addfile(item, io.BytesIO(data) if data is not None else None)
        verify(altered, ok=False)
    for kind in ("wheel-payload", "wheel-duplicate-payload", "sdist-gzip-trailer", "sdist-truncated"):
        altered = tmp_path / kind
        shutil.copytree(dist, altered)
        if kind.startswith("wheel-"):
            archive = next(altered.glob("*.whl"))
            with zipfile.ZipFile(archive) as wheel:
                member = wheel.getinfo("leitir/tree.py")
            data = bytearray(archive.read_bytes())
            name_size, extra_size = struct.unpack_from("<HH", data, member.header_offset + 26)
            payload_start = member.header_offset + 30 + name_size + extra_size
            data[payload_start + member.compress_size // 2] ^= 1
        else:
            archive = next(altered.glob("*.tar.gz"))
            data = bytearray(archive.read_bytes())
            if kind == "sdist-gzip-trailer":
                data[-8] ^= 1
            else:
                del data[-1:]
        archive.write_bytes(data)
        if kind == "wheel-duplicate-payload":
            with zipfile.ZipFile(next(dist.glob("*.whl"))) as original:
                unaltered = original.read("leitir/tree.py")
            with pytest.warns(UserWarning, match="Duplicate name"):
                with zipfile.ZipFile(archive, "a") as changed:
                    changed.writestr(member, unaltered)
        verify(altered, ok=False)
