"""Offline end-to-end coverage for corpus CLI materialization."""

from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile

from leitir.cli import ExitCode, main

from _http_server import routed_server, scripted_server, json_body

SHA = "b" * 40


def _tarball(*, package_subpath: str | None = None) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content in (("proof.txt", b"proof\n"), ("README.md", b"read me\n")):
            member = tarfile.TarInfo(f"demo-{SHA}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        docs = tarfile.TarInfo(f"demo-{SHA}/docs")
        docs.type = tarfile.DIRTYPE
        archive.addfile(docs)
        if package_subpath is not None:
            content = b'{"name":"@scope/demo"}\n'
            member = tarfile.TarInfo(
                f"demo-{SHA}/{package_subpath}/package.json"
            )
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_get_prints_usable_path_and_cache_hit(tmp_path, monkeypatch):
    with scripted_server([(200, {}, _tarball())]) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
        argv = ["get", f"acme/demo@{SHA}", "--no-verify"]
        code, out, err = _invoke(argv)
        assert code == ExitCode.SUCCESS
        path = out.strip()
        assert path.startswith("/")
        assert open(f"{path}/proof.txt", encoding="utf-8").read() == "proof\n"
        assert "materializing" in err

        manifest_path = Path(path) / "leitir-manifest.json"
        legacy = json.loads(manifest_path.read_text())
        legacy.pop("entry_points")
        legacy["docs_urls"] = ["https://legacy.example/docs"]
        manifest_path.write_text(json.dumps(legacy), encoding="utf-8")

        code, second_out, second_err = _invoke(argv)
        assert code == ExitCode.SUCCESS
        assert second_out.strip() == path
        assert "materializing" not in second_err
        assert server.state.served_count == 1

        backfilled = json.loads(manifest_path.read_text())
        assert backfilled["entry_points"] == ["docs/", "README.md"]
        assert backfilled["docs_urls"] == ["https://legacy.example/docs"]
        assert backfilled["verified"] is False
        assert backfilled["verified_at"] is None

        pointers = tmp_path / "POINTERS.md"
        text = pointers.read_text(encoding="utf-8")
        assert "Agents read this file first" in text
        assert "## acme/demo" in text
        assert f"- Commit SHA: `{SHA}`" in text
        assert "https://legacy.example/docs" in text
        assert "`README.md`" in text
        assert "`docs/`" in text
        assert "Practice entry points: none found" not in text

        backfilled["entry_points"] = []
        manifest_path.write_text(json.dumps(backfilled), encoding="utf-8")
        code, _, _ = _invoke(argv)
        assert code == ExitCode.SUCCESS
        assert json.loads(manifest_path.read_text())["entry_points"] == []
        assert "Practice entry points: none found" in pointers.read_text(encoding="utf-8")
        assert server.state.served_count == 1

        code, _, remove_err = _invoke(
            ["remove", f"acme/demo@{SHA}"]
        )
        assert code == ExitCode.SUCCESS, remove_err
        assert "## acme/demo" not in pointers.read_text(encoding="utf-8")

        code, _, clean_err = _invoke(["clean"])
        assert code == ExitCode.SUCCESS, clean_err
        assert not pointers.exists()


def test_local_creates_root_and_gitignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with scripted_server([(200, {}, _tarball())]) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        code, out, err = _invoke(["get", "--local", f"acme/demo@{SHA}", "--no-verify"])
    assert code == ExitCode.SUCCESS
    assert out.strip().startswith(str(tmp_path / ".leitir-refs"))
    assert (tmp_path / ".leitir-refs").is_dir()
    assert (tmp_path / ".gitignore").read_text() == ".leitir-refs/\n"
    assert ".gitignore" in err


def test_latest_package_uses_registry_tag_and_codeload(tmp_path, monkeypatch):
    routes = {
        "/pypi/demo/json": (200, {}, json_body({"info": {"version": "1.2"}})),
        "/pypi/demo/1.2/json": (
            200,
            {},
            json_body({"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}}),
        ),
        "/repos/acme/demo/git/ref/tags/v1.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": SHA}}),
        ),
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball()),
    }
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        code, out, err = _invoke(["get", "pypi:demo", "--root", str(tmp_path), "--no-verify"])
    assert code == ExitCode.SUCCESS
    manifest = json.loads((Path(out.strip()) / "leitir-manifest.json").read_text())
    assert manifest["version"] == "1.2"
    assert manifest["version_source"] == "latest"
    assert manifest["commit_sha"] == SHA
    assert "error" not in err


def test_lockfile_selects_registry_version_and_records_source(tmp_path, monkeypatch):
    project = tmp_path / "project"
    root = tmp_path / "corpus"
    project.mkdir()
    (project / "requirements.txt").write_text("demo==1.2\n", encoding="utf-8")
    routes = {
        "/pypi/demo/1.2/json": (
            200,
            {},
            json_body({"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}}),
        ),
        "/repos/acme/demo/git/ref/tags/v1.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": SHA}}),
        ),
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball()),
    }
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        code, out, err = _invoke(
            ["get", "pypi:demo", "--cwd", str(project), "--root", str(root), "--no-verify"]
        )
    assert code == ExitCode.SUCCESS, err
    manifest = json.loads((Path(out.strip()) / "leitir-manifest.json").read_text())
    assert manifest["version"] == "1.2"
    assert manifest["version_source"] == "lockfile"
    assert "demo: version 1.2 from requirements.txt" in err


def test_explicit_version_beats_lockfile(tmp_path, monkeypatch):
    project = tmp_path / "project"
    root = tmp_path / "corpus"
    project.mkdir()
    (project / "requirements.txt").write_text("demo==9.9\n", encoding="utf-8")
    routes = {
        "/pypi/demo/1.2/json": (
            200,
            {},
            json_body({"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}}),
        ),
        "/repos/acme/demo/git/ref/tags/v1.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": SHA}}),
        ),
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball()),
    }
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        code, out, err = _invoke(
            ["get", "pypi:demo@1.2", "--cwd", str(project), "--root", str(root), "--no-verify"]
        )
    assert code == ExitCode.SUCCESS, err
    manifest = json.loads((Path(out.strip()) / "leitir-manifest.json").read_text())
    assert manifest["version"] == "1.2"
    assert manifest["version_source"] == "explicit"
    assert "from requirements.txt" not in err


def test_scoped_npm_monorepo_get_prints_existing_subpath(tmp_path, monkeypatch):
    routes = {
        "/%40scope%2Fdemo": (
            200,
            {},
            json_body(
                {
                    "dist-tags": {"latest": "1.2"},
                    "versions": {
                        "1.2": {
                            "repository": {
                                "url": "git+ssh://git@github.com/acme/demo.git",
                                "directory": "packages/scoped-demo",
                            }
                        }
                    },
                }
            ),
        ),
        "/repos/acme/demo/git/ref/tags/%40scope%2Fdemo%401.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": SHA}}),
        ),
        f"/acme/demo/tar.gz/{SHA}": (
            200,
            {},
            _tarball(package_subpath="packages/scoped-demo"),
        ),
    }
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_NPM_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        code, out, err = _invoke(["get", "npm:@scope/demo", "--root", str(tmp_path), "--no-verify"])
    assert code == ExitCode.SUCCESS, err
    package_path = Path(out.strip())
    assert package_path.name == "scoped-demo"
    assert (package_path / "package.json").is_file()
    manifest = json.loads(
        (package_path.parents[1] / "leitir-manifest.json").read_text()
    )
    assert manifest["ecosystem"] == "npm"
    assert manifest["version"] == "1.2"
    assert manifest["subpath"] == "packages/scoped-demo"


def test_get_missing_recorded_subpath_prints_root_and_warns(tmp_path, monkeypatch):
    routes = {
        "/%40scope%2Fdemo": (
            200,
            {},
            json_body(
                {
                    "versions": {
                        "1.2": {
                            "repository": {
                                "url": "github:acme/demo",
                                "directory": "packages/missing",
                            }
                        }
                    }
                }
            ),
        ),
        "/repos/acme/demo/git/ref/tags/%40scope%2Fdemo%401.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": SHA}}),
        ),
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball()),
    }
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_NPM_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        code, out, err = _invoke(
            ["get", "npm:@scope/demo@1.2", "--root", str(tmp_path), "--no-verify"]
        )
    assert code == ExitCode.SUCCESS, err
    root = Path(out.strip())
    assert (root / "leitir-manifest.json").is_file()
    assert "warning: recorded subpath 'packages/missing' does not exist" in err
    assert "using repository root" in err


def test_failure_is_exit_one_clean_stderr_and_no_stdout(tmp_path):
    code, out, err = _invoke(["get", "https://github.com.attacker.example/o/r", "--root", str(tmp_path)])
    assert code == ExitCode.CORPUS_FAILURE
    assert out == ""
    assert err.startswith("leitir: resolving")
    assert "leitir: error:" in err
    assert "supported forms" in err
