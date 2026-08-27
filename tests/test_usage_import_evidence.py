"""Offline, deterministic coverage for import-root evidence derivation
(issue #269): deriving a distribution's actual import root(s) from its
materialized tree's own evidence, rather than guessing from its name.

These tests build small fixture directory trees directly on disk -- no
network, no registry lookups -- and exercise
:func:`leitir.usage.import_evidence.derive_distribution_records` and
:func:`leitir.usage.import_evidence.resolve_import_roots` against them.
"""

from __future__ import annotations

from pathlib import Path

from leitir.usage.import_evidence import derive_distribution_records, resolve_import_roots


def _write(root: Path, relpath: str, content: str = "") -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# --------------------------------------------------------------------------
# Tier 1: top_level.txt
# --------------------------------------------------------------------------


def test_top_level_txt_is_the_highest_precedence_evidence(tmp_path):
    # A tree that has BOTH a dist-info top_level.txt AND a src-layout that
    # would otherwise suggest a different root: top_level.txt must win.
    _write(tmp_path, "demo-1.0.dist-info/top_level.txt", "PIL\n")
    _write(tmp_path, "src/somethingelse/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pillow")
    assert roots == ("PIL",)


def test_top_level_txt_multi_line_is_multi_root(tmp_path):
    _write(tmp_path, "widget.egg-info/top_level.txt", "widget\nwidget_ext\n")
    roots = resolve_import_roots(tmp_path, "widget")
    assert roots == ("widget", "widget_ext")


def test_disagreeing_top_level_txt_files_are_undeterminable(tmp_path):
    _write(tmp_path, "a.dist-info/top_level.txt", "foo\n")
    _write(tmp_path, "b.egg-info/top_level.txt", "bar\n")
    roots = resolve_import_roots(tmp_path, "widget")
    assert roots is None


# --------------------------------------------------------------------------
# Tier 2: setup.cfg
# --------------------------------------------------------------------------


def test_setup_cfg_explicit_packages_list(tmp_path):
    _write(
        tmp_path,
        "setup.cfg",
        "[options]\npackages =\n    yaml\n    yaml.other\n",
    )
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)


def test_setup_cfg_find_directive_is_not_trusted(tmp_path):
    # "find:" requires actually running discovery -- must not be trusted
    # statically. Falls through to the tree-layout tier instead.
    _write(tmp_path, "setup.cfg", "[options]\npackages = find:\n")
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)


def test_setup_cfg_py_modules(tmp_path):
    _write(tmp_path, "setup.cfg", "[options]\npy_modules = six\n")
    roots = resolve_import_roots(tmp_path, "six")
    assert roots == ("six",)


# --------------------------------------------------------------------------
# Tier 3: pyproject.toml
# --------------------------------------------------------------------------


def test_pyproject_setuptools_packages(tmp_path):
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.setuptools]\npackages = ["bs4"]\n',
    )
    roots = resolve_import_roots(tmp_path, "beautifulsoup4")
    assert roots == ("bs4",)


def test_pyproject_poetry_packages_include(tmp_path):
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.poetry]\nname = "python-dateutil"\n\n'
        '[[tool.poetry.packages]]\ninclude = "dateutil"\n',
    )
    roots = resolve_import_roots(tmp_path, "python-dateutil")
    assert roots == ("dateutil",)


def test_malformed_pyproject_falls_through_to_tree_layout(tmp_path):
    _write(tmp_path, "pyproject.toml", "not [ valid toml")
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)


# --------------------------------------------------------------------------
# Tier 4: materialized-tree-layout (the pillow/PIL, pyyaml/yaml cases)
# --------------------------------------------------------------------------


def test_tree_layout_pillow_src_layout(tmp_path):
    # Pillow's real repo layout: src/PIL/*.py, Tests/, docs/, setup.py.
    _write(tmp_path, "src/PIL/__init__.py", "")
    _write(tmp_path, "src/PIL/Image.py", "def open(fp):\n    return fp\n")
    _write(tmp_path, "Tests/test_image.py", "")
    _write(tmp_path, "docs/index.rst", "")
    _write(tmp_path, "setup.py", "raise SystemExit('should never be executed')\n")
    roots = resolve_import_roots(tmp_path, "pillow")
    assert roots == ("PIL",)


def test_tree_layout_pyyaml_root_layout(tmp_path):
    _write(tmp_path, "yaml/__init__.py", "")
    _write(tmp_path, "yaml/loader.py", "")
    _write(tmp_path, "tests/test_yaml.py", "")
    _write(tmp_path, "setup.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)


def test_tree_layout_ambiguous_multi_candidate_is_undeterminable_not_multi_root(tmp_path):
    # P1 fix (adversarial review, reviewer-hy3): tier 4 has no
    # authoritative packaging evidence behind it, so it cannot tell a
    # genuine additional public import root apart from an unrelated
    # top-level module the donor tree just happens to ship. Two plausible
    # top-level packages found by structural scanning alone (with no
    # top_level.txt/setup.cfg/pyproject.toml corroborating either) must
    # resolve to undeterminable, never to a guessed multi-root mapping --
    # see test_multi_root_distribution_via_top_level_txt below for how a
    # *genuine* multi-root distribution is actually resolved.
    _write(tmp_path, "attr/__init__.py", "")
    _write(tmp_path, "attrs/__init__.py", "")
    _write(tmp_path, "tests/test_attr.py", "")
    roots = resolve_import_roots(tmp_path, "attrs")
    assert roots is None


def test_multi_root_distribution_via_top_level_txt(tmp_path):
    # A genuine multi-root distribution (attrs ships both "attr" and
    # "attrs") IS resolved -- but only when an authoritative evidence tier
    # (here, a real top_level.txt) actually declares both roots together,
    # not from tier 4's structural guess alone.
    _write(tmp_path, "attr/__init__.py", "")
    _write(tmp_path, "attrs/__init__.py", "")
    _write(tmp_path, "attrs-1.0.dist-info/top_level.txt", "attr\nattrs\n")
    roots = resolve_import_roots(tmp_path, "attrs")
    assert roots == ("attr", "attrs")


# --------------------------------------------------------------------------
# P1 regression (adversarial review, reviewer-hy3): a wrong, over-inclusive
# tier-4 root must never produce a false violation against code that is
# correct. Reproduced directly against resolve_import_roots below (the
# e2e shape -- a full leitir check run producing a false violation and
# then not producing one after the fix -- is covered in
# tests/test_check_import_root_evidence_e2e.py).
# --------------------------------------------------------------------------


def test_stray_top_level_module_does_not_get_promoted_to_a_root(tmp_path):
    # A donor ships a real package plus an unrelated stray top-level
    # helper module. Before the fix, both "widgetlib" and "constants"
    # became roots bound to the target -- a consumer's own, unrelated
    # "constants" import would then be misattributed to this distribution.
    _write(tmp_path, "widgetlib/__init__.py", "def real_api():\n    return 1\n")
    _write(tmp_path, "constants.py", "SOME_INTERNAL_CONSTANT = 1\n")
    roots = resolve_import_roots(tmp_path, "widgetlib")
    assert roots is None


def test_vendored_subpackage_does_not_get_promoted_to_a_root(tmp_path):
    # A donor uses a src/-layout with a real package plus a vendored
    # subpackage that itself has __init__.py -- also a real, ordinary
    # shape (a project vendoring a dependency under vendor/__init__.py).
    _write(tmp_path, "src/reallib/__init__.py", "def real_api():\n    return 1\n")
    _write(tmp_path, "src/vendor/__init__.py", "VENDORED = True\n")
    roots = resolve_import_roots(tmp_path, "reallib")
    assert roots is None


def test_tree_layout_single_top_level_module_file(tmp_path):
    _write(tmp_path, "six.py", "def u(x):\n    return x\n")
    _write(tmp_path, "test_six.py", "")
    roots = resolve_import_roots(tmp_path, "six")
    assert roots == ("six",)


def test_tree_layout_prefers_src_over_root(tmp_path):
    _write(tmp_path, "src/realpkg/__init__.py", "")
    _write(tmp_path, "notapackage_helper_dir_without_init/whatever.py", "")
    roots = resolve_import_roots(tmp_path, "realpkg")
    assert roots == ("realpkg",)


def test_tree_layout_excludes_generic_non_package_directories(tmp_path):
    _write(tmp_path, "yaml/__init__.py", "")
    _write(tmp_path, "tests/__init__.py", "")
    _write(tmp_path, "docs/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)


# --------------------------------------------------------------------------
# Undeterminable root: must fail safe, never guess.
# --------------------------------------------------------------------------


def test_no_evidence_at_all_is_undeterminable(tmp_path):
    _write(tmp_path, "README.md", "nothing here\n")
    roots = resolve_import_roots(tmp_path, "mystery")
    assert roots is None
    records = derive_distribution_records(tmp_path, "mystery")
    assert len(records) == 1
    assert records[0].declared_roots == ()


def test_no_recognizable_package_layout_is_undeterminable(tmp_path):
    # Only non-package top-level content (docs/tests dirs, no __init__.py
    # anywhere, no .py files at the top level at all).
    _write(tmp_path, "docs/index.rst", "")
    _write(tmp_path, "tests/test_thing.py", "")
    roots = resolve_import_roots(tmp_path, "mystery")
    assert roots is None


def test_undeterminable_root_never_produces_a_guessed_name_match(tmp_path):
    # Even though the distribution is literally named "mystery", nothing in
    # its tree declares "mystery" as an import root -- this must never fall
    # back to guessing the name.
    _write(tmp_path, "docs/index.rst", "")
    roots = resolve_import_roots(tmp_path, "mystery")
    assert roots is None


# --------------------------------------------------------------------------
# Cap enforcement (issue #269 must not introduce an unbounded resolution).
# --------------------------------------------------------------------------


def test_too_many_tree_layout_roots_is_undeterminable(tmp_path):
    from leitir.usage.contract import MAX_IMPORT_ROOTS_PER_MAPPING

    for index in range(MAX_IMPORT_ROOTS_PER_MAPPING + 1):
        _write(tmp_path, f"pkg{index}/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "toomany")
    assert roots is None


# --------------------------------------------------------------------------
# P2 regression (adversarial review, reviewer-hy3): malformed/adversarial
# evidence files (an attacker-influenceable materialized donor artifact)
# must fail closed at this module's own boundary -- never raise a raw,
# untyped exception -- rather than relying on an incidental blanket
# ``except Exception`` elsewhere (e.g. the CLI) to paper over it.
# --------------------------------------------------------------------------


def test_deeply_nested_pyproject_toml_recursion_error_fails_closed(tmp_path):
    # tomllib's recursive-descent parser raises RecursionError (not
    # tomllib.TOMLDecodeError) on a sufficiently deeply nested array --
    # this must not propagate out of resolve_import_roots/
    # derive_distribution_records; it must be treated the same as any
    # other unparsable pyproject.toml (this tier found nothing usable).
    depth = 3000
    nested = "x = " + "[" * depth + "]" * depth + "\n"
    _write(tmp_path, "pyproject.toml", nested)
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)  # falls through to the tree-layout tier
    records = derive_distribution_records(tmp_path, "pyyaml")
    assert records[0].source == "materialized-tree-layout"


def test_self_referencing_setup_cfg_interpolation_error_fails_closed(tmp_path):
    # A self-referencing "%(a)s" interpolation makes configparser raise
    # InterpolationDepthError (a subclass of configparser.Error) from
    # .get(), not from read_string -- this must not propagate uncaught
    # either; it must be treated the same as any other unparsable
    # setup.cfg (this tier found nothing usable).
    _write(
        tmp_path,
        "setup.cfg",
        "[options]\na = %(a)s\npackages = %(a)s\n",
    )
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots == ("yaml",)  # falls through to the tree-layout tier
    records = derive_distribution_records(tmp_path, "pyyaml")
    assert records[0].source == "materialized-tree-layout"
