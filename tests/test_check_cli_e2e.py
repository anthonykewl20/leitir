"""Offline end-to-end coverage for ``leitir check`` (issue #266 B3/E1).

User-level intent tests driving the public CLI (docs/testing.md): each test
observes exit code, JSON counts, and error messages -- never a private
function's return value.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

from _http_server import json_body, routed_server

from leitir.cli import ExitCode, main

SHA = "b" * 40
_REPO_ROOT = Path(__file__).parents[1]


def _tarball(files: dict[str, bytes]) -> bytes:
    # Issue #269 follow-up: tier 4 (a purely structural scan of the tree's
    # own directory layout) was retired as an authority -- it could still
    # bind a wrong root and produce a false violation (ADR-0032, "Tier 4
    # was retired as an authority"). This file's fixtures always model the
    # "demo" distribution with import root "demo", so every tarball built
    # here carries a real top_level.txt (tier 1, authoritative) declaring
    # it, unless the caller already supplied its own packaging metadata or
    # is deliberately testing an evidence-free tree (empty-index fixtures
    # with no demo/ package at all still resolve to an empty API index and
    # fail closed for that reason, independent of root determinability).
    complete_files = dict(files)
    if "demo/__init__.py" in complete_files and not any(
        name.endswith((".dist-info/top_level.txt", ".egg-info/top_level.txt"))
        for name in complete_files
    ):
        complete_files["demo.egg-info/top_level.txt"] = b"demo\n"
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content in complete_files.items():
            member = tarfile.TarInfo(f"demo-{SHA}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


_DEMO_SOURCE = (
    b"def Known(x):\n"
    b"    return x\n"
    b"\n"
    b"class Thing:\n"
    b"    def method(self):\n"
    b"        return None\n"
)


def _routes(*, package_bytes: bytes) -> dict[str, tuple[int, dict[str, str], bytes]]:
    return {
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
        f"/acme/demo/tar.gz/{SHA}": (200, {}, package_bytes),
    }


def _invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _run_check(tmp_path, monkeypatch, *, consumer_source: str, package_bytes: bytes):
    root = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    app = project / "app.py"
    app.write_text(consumer_source, encoding="utf-8")
    with routed_server(_routes(package_bytes=package_bytes)) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        return _invoke(
            [
                "check",
                str(app),
                "--against",
                "pypi:demo@1.2",
                "--root",
                str(root),
                "--no-verify",
                "--json",
            ]
        )


def test_symbol_that_genuinely_exists_passes(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source="import demo\n\ndemo.Known(1)\n",
        package_bytes=_tarball({"demo/__init__.py": _DEMO_SOURCE}),
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["counts"]["sites_violation"] == 0
    assert payload["counts"]["sites_ok"] == 1
    assert payload["ok"][0]["symbol"] == "Known"


def test_symbol_definitively_absent_fails_and_names_symbol(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source="import demo\n\ndemo.TotallyMadeUp(2)\n",
        package_bytes=_tarball({"demo/__init__.py": _DEMO_SOURCE}),
    )
    assert code == ExitCode.CORPUS_FAILURE, err
    payload = json.loads(out)
    assert payload["counts"]["sites_violation"] == 1
    violation = payload["violations"][0]
    assert violation["symbol"] == "TotallyMadeUp"
    assert "TotallyMadeUp" in violation["reason"]
    assert violation["file"] == "app.py"
    assert violation["line"] == 3


def test_symbol_present_via_from_import_alias_passes(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source="from demo import Known as K\n\nK(3)\n",
        package_bytes=_tarball({"demo/__init__.py": _DEMO_SOURCE}),
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["counts"]["sites_ok"] == 1
    assert payload["counts"]["sites_violation"] == 0


def test_dynamic_usage_is_unresolved_not_a_violation(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source=(
            "import importlib\n"
            "mod = importlib.import_module('demo')\n"
            "mod.Known(1)\n"
        ),
        package_bytes=_tarball({"demo/__init__.py": _DEMO_SOURCE}),
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["counts"]["sites_violation"] == 0
    assert payload["counts"]["sites_unresolved"] >= 1
    assert any(entry["reason"].endswith("dynamic-import") for entry in payload["unresolved"])


def test_conditionally_defined_symbol_is_unresolved_not_a_violation(tmp_path, monkeypatch):
    # The extractor only walks direct top-level statements (see check.py's
    # docstring): a symbol defined inside a top-level ``if`` is invisible to
    # the API index but is still real -- corroborated by the raw source
    # text scan, so it must never be reported as a violation.
    package_source = (
        b"if True:\n"
        b"    def Conditional(x):\n"
        b"        return x\n"
    )
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source="import demo\n\ndemo.Conditional(1)\n",
        package_bytes=_tarball({"demo/__init__.py": package_source}),
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["counts"]["sites_violation"] == 0
    assert payload["counts"]["sites_unresolved"] == 1
    assert payload["unresolved"][0]["symbol"] == "Conditional"


def test_dynamic_dispatch_only_usage_is_unresolved_not_ok(tmp_path, monkeypatch):
    # Adversarial-review regression (P1 rejection, defect 1): a file whose
    # *only* usage of the target distribution is dynamic dispatch --
    # getattr(mod, name)(), an import-alias called bare, and a module value
    # handed into a function and called there -- must never be reported as
    # "ok". None of these sites let the accessed symbol name be statically
    # recovered, so none of them were ever resolved; "ok" means resolved
    # *and* present, not merely "attributed to the right distribution".
    # Before the fix this reported sites_ok=3, sites_violation=0,
    # sites_unresolved=0, exit 0 -- a 100% "ok" reading for a file that
    # never demonstrated a single concretely-resolved symbol.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source=(
            "import demo\n"
            "import demo as d2\n"
            "\n"
            "def call_it(mod):\n"
            "    return mod()\n"
            "\n"
            "getattr(demo, 'Known')()\n"
            "d2()\n"
            "call_it(demo)\n"
        ),
        package_bytes=_tarball({"demo/__init__.py": _DEMO_SOURCE}),
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["counts"]["sites_examined"] == 3
    assert payload["counts"]["sites_ok"] == 0
    assert payload["counts"]["sites_violation"] == 0
    assert payload["counts"]["sites_unresolved"] == 3
    assert len(payload["ok"]) == 0
    for site in payload["unresolved"]:
        assert site["outcome"] == "unresolved"


def test_zero_examined_sites_is_loud_not_a_silent_pass(tmp_path, monkeypatch):
    # Adversarial-review regression (P1 rejection, defect 2): code that
    # imports the target distribution under a different top-level name than
    # the resolver was told to look for produces zero references -- the
    # resolver's import_roots dict is keyed on an exact top-level import
    # name (see guess_import_root's known pillow/bs4/yaml/dateutil/sklearn
    # mismatches), so the practical failure mode is silent zero-coverage.
    # Constructed directly here rather than via a real renamed distribution:
    # the consumer only ever imports "totallyunrelated", never "demo" (the
    # import root the resolver is actually configured to look for), so
    # nothing about this distribution is ever examined. Before the fix this
    # reported sites_examined=0, sites_ok=0, sites_violation=0,
    # sites_unresolved=0, exit 0 -- indistinguishable from a genuinely
    # clean, fully-checked file.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source="import totallyunrelated\n\ntotallyunrelated.whatever(1)\n",
        package_bytes=_tarball({"demo/__init__.py": _DEMO_SOURCE}),
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["counts"]["sites_examined"] == 0
    assert payload["status"] == "nothing_examined"
    # The human summary must name the import root it looked for, so a user
    # can see the mismatch, and must not read as a reassuring clean pass.
    assert "demo" in err
    assert "NOTHING" in err or "nothing" in err


def test_missing_or_empty_index_fails_closed(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        consumer_source="import demo\n\ndemo.Known(1)\n",
        package_bytes=_tarball({"README.md": b"no python here\n"}),
    )
    assert code == ExitCode.CORPUS_FAILURE, err
    assert out == ""
    assert "unverifiable" in err or "empty" in err
    assert "ok" not in err  # no false claim of success anywhere in the message


def test_nonpython_file_input_is_rejected_offline(tmp_path):
    target = tmp_path / "app.js"
    target.write_text("console.log('hi');\n", encoding="utf-8")
    code, out, err = _invoke(
        ["check", str(target), "--against", "pypi:demo@1.2", "--json"]
    )
    assert code == ExitCode.MALFORMED_USAGE
    assert out == ""
    assert "unsupported language" in err


def test_nonpython_directory_input_is_rejected_offline(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "notes.txt").write_text("hello\n", encoding="utf-8")
    code, out, err = _invoke(
        ["check", str(project), "--against", "pypi:demo@1.2", "--json"]
    )
    assert code == ExitCode.MALFORMED_USAGE
    assert "unsupported language" in err


def test_check_output_is_hash_seed_independent(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = project / "app.py"
    app.write_text(
        "import demo\n\ndemo.Known(1)\ndemo.Missing(2)\ndemo.Thing()\n",
        encoding="utf-8",
    )
    package_bytes = _tarball({"demo/__init__.py": _DEMO_SOURCE})
    outputs: dict[str, bytes] = {}
    with routed_server(_routes(package_bytes=package_bytes)) as server:
        for seed in ("0", "1", "42", "7"):
            root = tmp_path / f"corpus-{seed}"
            environment = os.environ.copy()
            environment.update(
                PYTHONHASHSEED=seed,
                PYTHONPATH=str(_REPO_ROOT / "src"),
                LEITIR_PYPI_BASE_URL=server.base_url + "/pypi",
                LEITIR_GITHUB_API_BASE_URL=server.base_url,
                LEITIR_CODELOAD_BASE_URL=server.base_url,
                LEITIR_HOME=str(root),
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from leitir.cli import main; sys.exit(main())",
                    "check",
                    str(app),
                    "--against",
                    "pypi:demo@1.2",
                    "--root",
                    str(root),
                    "--no-verify",
                    "--json",
                ],
                cwd=_REPO_ROOT,
                env=environment,
                capture_output=True,
                timeout=20,
                check=False,
            )
            assert completed.returncode == ExitCode.CORPUS_FAILURE, completed.stderr
            payload = json.loads(completed.stdout)
            assert payload["counts"] == {
                "sites_examined": 3,
                "sites_ok": 2,
                "sites_violation": 1,
                "sites_unresolved": 0,
            }
            outputs[seed] = completed.stdout

    baseline = outputs["0"]
    for seed, stdout in outputs.items():
        assert stdout == baseline, f"seed {seed} produced different output than seed 0"
