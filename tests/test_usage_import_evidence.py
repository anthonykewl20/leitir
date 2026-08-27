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
    # statically. There is no tree-layout tier to fall through to any
    # more (retired, see module docstring), so this is undeterminable.
    _write(tmp_path, "setup.cfg", "[options]\npackages = find:\n")
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots is None


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


def test_malformed_pyproject_is_undeterminable_not_a_tree_layout_fallback(tmp_path):
    # There is no tree-layout tier to fall through to any more (retired,
    # see module docstring) -- a malformed pyproject.toml with no other
    # tier 1-3 evidence present is simply undeterminable.
    _write(tmp_path, "pyproject.toml", "not [ valid toml")
    _write(tmp_path, "yaml/__init__.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots is None


# --------------------------------------------------------------------------
# Tier 4 (materialized-tree-layout) was retired as an authority (issue
# #269 follow-up, second adversarial review round, reviewer-hy3): even
# restricted to "exactly one candidate" (the first P1 fix), it could still
# resolve the *wrong* single root and bind it to --against. Only tiers 1-3
# (the distribution's own packaging declarations) may originate a resolved
# root now; a materialized tree with no such declaration, no matter how
# unambiguous its directory layout looks to a human, is undeterminable.
# See docs/adr/0032-import-root-evidence-derivation.md, "Tier 4 was
# retired as an authority".
# --------------------------------------------------------------------------


def test_tree_layout_alone_never_resolves_a_root_pillow_shape(tmp_path):
    # Pillow's real repo layout: src/PIL/*.py, Tests/, docs/, setup.py --
    # no top_level.txt/setup.cfg/pyproject.toml declaring "PIL" anywhere.
    # Before tier 4's retirement this resolved to ("PIL",); now it must
    # not, since tier 4 no longer exists to guess it from the layout.
    _write(tmp_path, "src/PIL/__init__.py", "")
    _write(tmp_path, "src/PIL/Image.py", "def open(fp):\n    return fp\n")
    _write(tmp_path, "Tests/test_image.py", "")
    _write(tmp_path, "docs/index.rst", "")
    _write(tmp_path, "setup.py", "raise SystemExit('should never be executed')\n")
    roots = resolve_import_roots(tmp_path, "pillow")
    assert roots is None


def test_tree_layout_alone_never_resolves_a_root_pyyaml_shape(tmp_path):
    _write(tmp_path, "yaml/__init__.py", "")
    _write(tmp_path, "yaml/loader.py", "")
    _write(tmp_path, "tests/test_yaml.py", "")
    _write(tmp_path, "setup.py", "")
    roots = resolve_import_roots(tmp_path, "pyyaml")
    assert roots is None


def test_tree_layout_alone_never_resolves_a_root_even_with_one_candidate(tmp_path):
    # A single, seemingly unambiguous top-level package with an
    # __init__.py and no competing candidates anywhere -- exactly the
    # shape the first P1 fix's "exactly one candidate" heuristic used to
    # trust. Still undeterminable now that tier 4 is retired outright.
    _write(tmp_path, "six.py", "def u(x):\n    return x\n")
    _write(tmp_path, "test_six.py", "")
    roots = resolve_import_roots(tmp_path, "six")
    assert roots is None


def test_multi_root_distribution_via_top_level_txt(tmp_path):
    # A genuine multi-root distribution (attrs ships both "attr" and
    # "attrs") IS resolved -- but only when an authoritative evidence tier
    # (here, a real top_level.txt) actually declares both roots together.
    # Tree layout alone (attr/__init__.py + attrs/__init__.py, no
    # top_level.txt) is exercised right below and correctly resolves to
    # None -- there is no tier 4 any more to resolve it from structure.
    _write(tmp_path, "attr/__init__.py", "")
    _write(tmp_path, "attrs/__init__.py", "")
    _write(tmp_path, "attrs-1.0.dist-info/top_level.txt", "attr\nattrs\n")
    roots = resolve_import_roots(tmp_path, "attrs")
    assert roots == ("attr", "attrs")


def test_tree_layout_multi_candidate_without_top_level_txt_is_undeterminable(tmp_path):
    _write(tmp_path, "attr/__init__.py", "")
    _write(tmp_path, "attrs/__init__.py", "")
    _write(tmp_path, "tests/test_attr.py", "")
    roots = resolve_import_roots(tmp_path, "attrs")
    assert roots is None


# --------------------------------------------------------------------------
# P1 regression (adversarial review, reviewer-hy3): a wrong, over-inclusive
# guessed root must never produce a false violation against code that is
# correct. Reproduced directly against resolve_import_roots below (the
# e2e shape -- a full leitir check run producing a false violation and
# then not producing one after the fix -- is covered in
# tests/test_check_import_root_evidence_e2e.py).
# --------------------------------------------------------------------------


def test_stray_top_level_module_does_not_get_promoted_to_a_root(tmp_path):
    # A donor ships a real package plus an unrelated stray top-level
    # helper module. Before the original fix (and before tier 4's later
    # retirement), both "widgetlib" and "constants" became roots bound to
    # the target -- a consumer's own, unrelated "constants" import would
    # then be misattributed to this distribution.
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


def test_src_layout_donor_with_only_a_vendored_src_package_is_undeterminable(tmp_path):
    # P1 residual regression (second adversarial review round,
    # reviewer-hy3): a src/-layout donor whose src/ directory contains
    # ONLY a private/vendored helper package (src/buildutils/), while the
    # tree's real, public import root is a module living OUTSIDE src/
    # (reallib.py at the repository root). The old tier 4 preferred src/
    # unconditionally whenever it was non-empty, so reallib.py was never
    # even considered as a candidate -- "buildutils" was tier 4's SOLE
    # candidate and, under the first P1 fix's "exactly one candidate"
    # rule, resolved as if it were the real root. That is now impossible:
    # there is no tier 4 to resolve anything from directory shape at all.
    _write(tmp_path, "src/buildutils/__init__.py", "INTERNAL = 1\n")
    _write(tmp_path, "reallib.py", "def real_api():\n    return 1\n")
    roots = resolve_import_roots(tmp_path, "reallib")
    assert roots is None


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


def test_too_many_declared_roots_is_undeterminable(tmp_path):
    # There is no tree-layout tier any more (retired), so the cap is
    # exercised via an authoritative tier instead: a single top_level.txt
    # declaring more roots than MAX_IMPORT_ROOTS_PER_MAPPING allows.
    from leitir.usage.contract import MAX_IMPORT_ROOTS_PER_MAPPING

    names = "\n".join(f"pkg{index}" for index in range(MAX_IMPORT_ROOTS_PER_MAPPING + 1))
    _write(tmp_path, "toomany.egg-info/top_level.txt", names + "\n")
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
    # No tree-layout tier to fall through to any more (retired) -- with no
    # other tier 1-3 evidence, this is undeterminable, not a crash.
    assert roots is None
    records = derive_distribution_records(tmp_path, "pyyaml")
    assert records[0].source == "materialized-tree-layout"  # the "no evidence" sentinel
    assert records[0].declared_roots == ()


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
    # No tree-layout tier to fall through to any more (retired) -- with no
    # other tier 1-3 evidence, this is undeterminable, not a crash.
    assert roots is None
    records = derive_distribution_records(tmp_path, "pyyaml")
    assert records[0].source == "materialized-tree-layout"  # the "no evidence" sentinel
    assert records[0].declared_roots == ()
