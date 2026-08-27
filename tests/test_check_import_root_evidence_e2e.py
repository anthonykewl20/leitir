"""Offline end-to-end coverage for issue #269: ``leitir check`` deriving a
distribution's import root(s) from the materialized source's own evidence
rather than guessing from its registry name.

Mirrors the existing ``tests/test_check_cli_e2e.py`` harness (an actual
local HTTP server standing in for the PyPI/GitHub registries, tarballs
served over that server, `leitir check` driven as a real subprocess-free
CLI invocation through ``leitir.cli.main``) but parameterizes the
distribution name and the tarball layout so the same flow can exercise a
renamed distribution (``pillow`` -> ``PIL``, ``pyyaml`` -> ``yaml``) and a
multi-root distribution, entirely offline and deterministically.
"""

from __future__ import annotations

import io
import json
import tarfile

from _http_server import json_body, routed_server

from leitir.cli import ExitCode, main

SHA = "c" * 40


def _tarball(files: dict[str, bytes], *, repo_slug: str) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(f"{repo_slug}-{SHA}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _routes(*, distribution: str, owner: str, repo: str, package_bytes: bytes) -> dict[str, tuple[int, dict[str, str], bytes]]:
    return {
        f"/pypi/{distribution}/1.0/json": (
            200,
            {},
            json_body({"info": {"project_urls": {"Source": f"https://github.com/{owner}/{repo}"}}}),
        ),
        f"/repos/{owner}/{repo}/git/ref/tags/v1.0": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": SHA}}),
        ),
        f"/{owner}/{repo}/tar.gz/{SHA}": (200, {}, package_bytes),
    }


def _invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _run_check(
    tmp_path,
    monkeypatch,
    *,
    distribution: str,
    owner: str,
    repo: str,
    consumer_source: str,
    package_files: dict[str, bytes],
):
    root = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    app = project / "app.py"
    app.write_text(consumer_source, encoding="utf-8")
    package_bytes = _tarball(package_files, repo_slug=repo)
    routes = _routes(distribution=distribution, owner=owner, repo=repo, package_bytes=package_bytes)
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        return _invoke(
            [
                "check",
                str(app),
                "--against",
                f"pypi:{distribution}@1.0",
                "--root",
                str(root),
                "--no-verify",
                "--json",
            ]
        )


_PIL_IMAGE_MODULE = (
    b"class Image:\n"
    b"    def open(self):\n"
    b"        return self\n"
    b"\n"
    b"def open(fp):\n"
    b"    return Image()\n"
)


def test_pillow_import_root_is_derived_from_top_level_txt_not_guessed_from_name(tmp_path, monkeypatch):
    # guess_import_root("pillow") == "pillow", which never matches "PIL" --
    # confirmed live in issue #269/#266. Tier 4 (a purely structural scan
    # of the src-layout tree) was retired as an authority (second
    # adversarial review round, reviewer-hy3): it could still bind a
    # *wrong* single root and produce a false violation against correct
    # code. A real top_level.txt (tier 1, authoritative) is required to
    # recover "PIL" now; see test_pillow_src_layout_alone_is_undeterminable
    # below for confirmation that the src-layout shape alone no longer
    # resolves anything.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="pillow",
        owner="python-pillow",
        repo="Pillow",
        consumer_source="from PIL import Image\n\nImage.open('x.png')\n",
        package_files={
            "src/PIL/__init__.py": b"",
            "src/PIL/Image.py": _PIL_IMAGE_MODULE,
            "Tests/test_image.py": b"",
            "Pillow-1.0.dist-info/top_level.txt": b"PIL\n",
        },
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["import_roots"] == ["PIL"]
    assert payload["import_roots_determinable"] is True
    assert payload["counts"]["sites_examined"] >= 1
    assert payload["counts"]["sites_violation"] == 0


def test_pillow_wrong_symbol_is_a_real_violation_now_that_root_is_derived(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="pillow",
        owner="python-pillow",
        repo="Pillow",
        consumer_source="import PIL\n\nPIL.TotallyMadeUp()\n",
        package_files={
            "src/PIL/__init__.py": b"",
            "src/PIL/Image.py": _PIL_IMAGE_MODULE,
            "Pillow-1.0.dist-info/top_level.txt": b"PIL\n",
        },
    )
    assert code == ExitCode.CORPUS_FAILURE, err
    payload = json.loads(out)
    assert payload["counts"]["sites_violation"] == 1
    assert payload["violations"][0]["symbol"] == "TotallyMadeUp"


def test_pillow_src_layout_alone_is_undeterminable(tmp_path, monkeypatch):
    # Tier 4 retirement, direct e2e confirmation: the exact same src/PIL
    # layout as above, but with NO top_level.txt/setup.cfg/pyproject.toml
    # anywhere -- the shape tier 4 used to recover before its retirement.
    # This must now fail safe rather than guess "PIL" from the layout.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="pillow",
        owner="python-pillow",
        repo="Pillow",
        consumer_source="from PIL import Image\n\nImage.open('x.png')\n",
        package_files={
            "src/PIL/__init__.py": b"",
            "src/PIL/Image.py": _PIL_IMAGE_MODULE,
            "Tests/test_image.py": b"",
        },
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["status"] == "nothing_examined"
    assert payload["import_roots_determinable"] is False
    assert payload["import_roots"] == []
    assert payload["counts"]["sites_violation"] == 0


_YAML_SOURCE = (
    b"def safe_load(stream):\n"
    b"    return {}\n"
    b"\n"
    b"def dump(data):\n"
    b"    return ''\n"
)


def test_pyyaml_import_root_is_derived_as_yaml_not_pyyaml(tmp_path, monkeypatch):
    # guess_import_root("pyyaml") == "pyyaml", which never matches "yaml".
    # A real top_level.txt (tier 1, authoritative) is required to resolve
    # this now that tier 4 (structural layout scan) is retired -- see
    # test_pyyaml_root_layout_alone_is_undeterminable below.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="pyyaml",
        owner="yaml",
        repo="pyyaml",
        consumer_source="import yaml\n\nyaml.safe_load('a: 1')\n",
        package_files={
            "yaml/__init__.py": _YAML_SOURCE,
            "tests/test_yaml.py": b"",
            "PyYAML-1.0.dist-info/top_level.txt": b"yaml\n",
        },
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["import_roots"] == ["yaml"]
    assert payload["counts"]["sites_ok"] == 1
    assert payload["counts"]["sites_violation"] == 0


def test_pyyaml_root_layout_alone_is_undeterminable(tmp_path, monkeypatch):
    # Tier 4 retirement, direct e2e confirmation: the exact same yaml/
    # layout as above, but with no top_level.txt anywhere -- the shape
    # tier 4 used to recover before its retirement. Must fail safe now.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="pyyaml",
        owner="yaml",
        repo="pyyaml",
        consumer_source="import yaml\n\nyaml.safe_load('a: 1')\n",
        package_files={
            "yaml/__init__.py": _YAML_SOURCE,
            "tests/test_yaml.py": b"",
        },
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["status"] == "nothing_examined"
    assert payload["import_roots_determinable"] is False


def test_multi_root_distribution_examines_usage_of_every_declared_root(tmp_path, monkeypatch):
    # A distribution that ships more than one top-level import root is a
    # legitimate, common shape (issue #269 acceptance criteria) -- not
    # ambiguous. Modeled on attrs, which ships both "attr" and "attrs".
    # A real top_level.txt (tier 1, authoritative) is required to resolve
    # this: there is no tree-layout tier any more (retired as an
    # authority, second adversarial review round) to guess that two
    # plausible top-level packages are both genuine roots -- see
    # tests/test_usage_import_evidence.py::test_multi_root_distribution_via_top_level_txt
    # and its undeterminable-without-top_level_txt counterpart next to it.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="attrs",
        owner="python-attrs",
        repo="attrs",
        consumer_source=(
            "import attr\n"
            "import attrs\n\n"
            "attr.Known(1)\n"
            "attrs.Known(2)\n"
        ),
        package_files={
            "attr/__init__.py": b"def Known(x):\n    return x\n",
            "attrs/__init__.py": b"def Known(x):\n    return x\n",
            "attrs.egg-info/top_level.txt": b"attr\nattrs\n",
            "tests/test_attr.py": b"",
        },
    )
    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    assert payload["import_roots"] == ["attr", "attrs"]
    assert payload["counts"]["sites_examined"] == 2
    assert payload["counts"]["sites_ok"] == 2
    assert payload["counts"]["sites_violation"] == 0


def test_multi_root_distribution_can_still_report_a_real_violation(tmp_path, monkeypatch):
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="attrs",
        owner="python-attrs",
        repo="attrs",
        consumer_source="import attr\n\nattr.NotReal()\n",
        package_files={
            "attr/__init__.py": b"def Known(x):\n    return x\n",
            "attrs/__init__.py": b"def Known(x):\n    return x\n",
            "attrs.egg-info/top_level.txt": b"attr\nattrs\n",
        },
    )
    assert code == ExitCode.CORPUS_FAILURE, err
    payload = json.loads(out)
    assert payload["counts"]["sites_violation"] == 1
    assert payload["violations"][0]["symbol"] == "NotReal"


def test_undeterminable_import_root_fails_safe_never_a_guessed_violation(tmp_path, monkeypatch):
    # A materialized source with real Python content but no recognizable
    # top-level package layout, no packaging metadata, and no top_level.txt
    # anywhere -- the import root genuinely cannot be determined. This must
    # still fail safe: nothing_examined, exit 4 -- never a guessed
    # violation, and never a silent "ok" (issue #269 acceptance criteria).
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="mystery",
        owner="acme",
        repo="mystery",
        consumer_source="import mystery\n\nmystery.whatever(1)\n",
        package_files={
            # Real Python content exists (so the API index is non-empty and
            # CheckIndexError is not raised), but it's not laid out as a
            # top-level package or module, and no docs/tests-only content
            # is mistaken for one either.
            "docs/conf.py": b"x = 1\n",
            "scripts/build.py": b"y = 2\n",
        },
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["status"] == "nothing_examined"
    assert payload["counts"]["sites_examined"] == 0
    assert payload["import_roots_determinable"] is False
    assert payload["import_roots"] == []
    # The undeterminable-root message must be legible without implying a
    # clean pass or a guessed match.
    assert "could not determine" in err
    assert "NOTHING" in err or "nothing" in err


def test_stray_top_level_module_never_produces_a_false_violation(tmp_path, monkeypatch):
    # P1 regression (adversarial review, reviewer-hy3): a donor ships a
    # real package ("widgetlib") plus an unrelated stray top-level helper
    # module ("constants.py"). Before the fix, the old tier 4 promoted BOTH
    # names to import roots bound to --against, so the consumer's own, wholly
    # unrelated "constants" module got misattributed to widgetlib the
    # moment it referenced a name that isn't in widgetlib's API index --
    # a false violation against code that is actually correct, exactly
    # the sad path issue #269 forbids. The undeterminable root must now
    # fail safe instead: nothing_examined, exit 4, never a violation.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="widgetlib",
        owner="acme",
        repo="widgetlib",
        consumer_source="import constants\n\nprint(constants.UNRELATED_LOCAL_THING)\n",
        package_files={
            "widgetlib/__init__.py": b"def real_api():\n    return 1\n",
            "constants.py": b"SOME_INTERNAL_CONSTANT = 1\n",
        },
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["status"] == "nothing_examined"
    assert payload["counts"]["sites_violation"] == 0
    assert payload["import_roots_determinable"] is False


def test_src_layout_vendored_helper_masking_real_root_never_produces_a_false_violation(tmp_path, monkeypatch):
    # P1 residual regression (second adversarial review round,
    # reviewer-hy3's exact reproduction): a src/-layout donor whose src/
    # directory contains ONLY a private/vendored helper package
    # ("src/buildutils/"), while the tree's REAL, public import root is a
    # module living OUTSIDE src/ ("reallib.py" at the repository root).
    #
    # The now-retired tier 4 preferred src/ unconditionally whenever it
    # was non-empty, so "reallib.py" was never even considered as a
    # candidate -- "buildutils" was tier 4's SOLE candidate, and under the
    # first P1 fix's "exactly one candidate, so resolve it" rule, it
    # bound to --against as if it were authoritative. The consumer's own,
    # unrelated local "buildutils.py" module then got misattributed to
    # the pinned "reallib" distribution the moment it referenced a name
    # not in reallib's API index -- a false violation against code that
    # is actually correct, exactly the sad path issue #269 forbids.
    #
    # With tier 4 retired entirely (not just narrowed further), this now
    # correctly fails safe: nothing_examined, exit 4, never a violation.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="reallib",
        owner="acme",
        repo="reallib",
        consumer_source="import buildutils\n\nprint(buildutils.UNRELATED_LOCAL_THING)\n",
        package_files={
            "src/buildutils/__init__.py": b"INTERNAL = 1\n",
            "reallib.py": b"def real_api():\n    return 1\n",
        },
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["status"] == "nothing_examined"
    assert payload["counts"]["sites_violation"] == 0
    assert payload["import_roots_determinable"] is False
    assert payload["import_roots"] == []


def test_vendored_subpackage_never_produces_a_false_violation(tmp_path, monkeypatch):
    # P1 regression (adversarial review, reviewer-hy3), second reproduced
    # shape: a donor uses a src/-layout with a real package plus a
    # vendored subpackage that itself has __init__.py ("src/vendor/"). The
    # consumer's own, unrelated top-level "vendor" module must never be
    # misattributed to the pinned distribution.
    code, out, err = _run_check(
        tmp_path,
        monkeypatch,
        distribution="reallib",
        owner="acme",
        repo="reallib",
        consumer_source="import vendor\n\nprint(vendor.UNRELATED_LOCAL_THING)\n",
        package_files={
            "src/reallib/__init__.py": b"def real_api():\n    return 1\n",
            "src/vendor/__init__.py": b"VENDORED = True\n",
        },
    )
    assert code == ExitCode.NOTHING_INDEXED, err
    payload = json.loads(out)
    assert payload["status"] == "nothing_examined"
    assert payload["counts"]["sites_violation"] == 0
    assert payload["import_roots_determinable"] is False


