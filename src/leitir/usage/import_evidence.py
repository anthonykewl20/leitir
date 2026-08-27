"""Derive distribution import-root evidence from a materialized source tree.

Issue #269: ``leitir check`` (ADR-0030) previously assumed a distribution's
import root equals its normalized registry name
(:func:`leitir.check.guess_import_root`) -- true for the common case
(``flask`` -> ``flask``, ``numpy`` -> ``numpy``), false for a large and
common slice of the ecosystem (``pillow`` -> ``PIL``, ``beautifulsoup4`` ->
``bs4``, ``pyyaml`` -> ``yaml``, ``python-dateutil`` -> ``dateutil``,
``scikit-learn`` -> ``sklearn``, ``opencv-python`` -> ``cv2``). When the
guess was wrong, the resolver simply found no reference under the wrong
name -- zero sites examined, ``nothing_examined``, exit 4. Safe, but a real
gap: for those packages, ``check`` never actually checked anything.

This module closes that gap the way ADR-0026 intended: it extends the
*existing* conservative-admission / import-catalog machinery
(:mod:`leitir.usage.import_catalog`, issue #256) rather than bolting a
lookup table onto ``check``. It builds
:class:`~leitir.usage.import_catalog.DistributionRecord` evidence directly
from the materialized distribution's own tree -- never from its name -- and
hands it to the existing :func:`~leitir.usage.import_catalog.build_import_catalog`,
which already has the typed-unresolved (ambiguous / unsupported) machinery
this needs. No new fallback table of per-distribution aliases is
introduced anywhere: every root this module reports is read out of some
artifact the distribution itself shipped or a structural convention of its
own tree, and a distribution this cannot determine anything for is always
reported as *no evidence*, never guessed.

## Evidence sources, in precedence order

The tiers are consulted in order; the first tier that finds *any* evidence
(one or more roots, or one or more distinct disagreeing candidate sets) is
used and lower tiers are never consulted -- so a lower-confidence
structural guess never overrides higher-confidence packaging metadata that
is actually present.

1. ``top-level-txt`` -- one or more real ``top_level.txt`` files found
   verbatim inside any ``*.dist-info/`` or ``*.egg-info/`` directory in the
   tree (the same evidence ``pip`` itself trusts for an installed
   distribution). One declared root per non-blank line.
2. ``setup-cfg-static`` -- a static (never executed) parse of a top-level
   ``setup.cfg``'s ``[options] packages`` (an explicit list only --
   ``find:``/``find_namespace:`` requires actually running discovery and is
   deliberately not attempted) and/or ``py_modules``.
3. ``pyproject-static`` -- a static (``tomllib``-only, never executed)
   parse of a top-level ``pyproject.toml``'s explicit
   ``[tool.setuptools] packages``/``py-modules``, or Poetry's
   ``[tool.poetry] packages`` (``include=`` entries).
4. ``materialized-tree-layout`` -- the lowest-confidence tier: a purely
   structural, algorithmic (never hand-maintained, always regenerable from
   the algorithm) scan of the tree itself for plausible top-level import
   roots -- a ``src/`` layout is preferred when present, matching the
   layout convention the packaging metadata tiers above would otherwise
   have described. This is the tier that recovers ``pillow`` -> ``PIL`` and
   ``pyyaml`` -> ``yaml`` when no packaging metadata for the distribution
   is present in this particular materialization. Because this tier has no
   authoritative evidence behind it, it can only ever resolve a *single*
   unambiguous root: a donor tree commonly ships more than one top-level
   directory/module that is not itself a public import root (a stray
   ``constants.py`` helper, a vendored ``vendor/__init__.py`` subpackage),
   and this tier has no way to tell those apart from a genuine additional
   public root. When it finds more than one candidate, it deliberately
   does not guess that all of them are real -- see "Multi-root" below.

If *no* tier finds any evidence at all, a single zero-root
:class:`~leitir.usage.import_catalog.DistributionRecord` is returned, which
``build_import_catalog`` types as
:attr:`~leitir.usage.UnresolvedState.UNSUPPORTED_SYNTAX` ("no local
evidence declares any import root") -- the same fail-safe outcome ADR-0026
already established for missing admission evidence. Two disagreeing
candidate root sets *within* one tier (e.g. two ``top_level.txt`` files
under different ``*.dist-info`` directories that disagree) are likewise
handled by ``build_import_catalog``'s existing ambiguity detection: both
records are passed through, and disagreement resolves to
:attr:`~leitir.usage.UnresolvedState.AMBIGUOUS_BINDING`, never a guess.

## Multi-root

A single coherent, *authoritative* piece of evidence (tier 1-3: a real
``top_level.txt``, or explicit ``setup.cfg``/``pyproject.toml`` packaging
metadata) declaring more than one root (e.g. a distribution that ships
both ``attr`` and ``attrs``) is a legitimate resolved mapping, not an
ambiguity -- this is exactly ``build_import_catalog``'s existing
multi-root contract (ADR-0026), reused unchanged here.

Tier 4 (the structural fallback) is the one tier this module never lets
resolve a multi-root mapping on its own: unlike tiers 1-3, it has no
packaging declaration to trust, only a heuristic scan of what happens to
be laid out at the top of the tree. If it finds exactly one candidate, it
resolves that one root normally. If it finds more than one, it emits one
single-root record *per* candidate instead of a single multi-root record,
so ``build_import_catalog``'s existing disagreement handling (unmodified)
types the whole distribution as ambiguous -- ``resolve_import_roots``
returns ``None`` and ``check`` fails safe. A distribution whose real
import surface genuinely spans multiple top-level roots must be evidenced
by tier 1-3 to be resolved as multi-root; tier 4 alone will never bind
more than one root to ``--against``, precisely because a false extra root
is not "harmless" -- it can misattribute an unrelated, same-named import
in the *consumer's own* code to the pinned distribution and produce a
false ``violation`` against code that is actually correct (the exact sad
path issue #269 forbids).

## Bounds

Every filesystem walk in this module is bounded (a directory-entry visit
cap for the ``*.dist-info``/``*.egg-info`` search, a byte cap per read file
via :func:`leitir.safeio.read_regular_file`) so a hostile or oversized
materialized tree cannot make evidence derivation unbounded. Hitting a
bound never raises and never fabricates a root: it simply means that tier
found nothing, and the search falls through to the next tier (or to the
zero-root fail-safe) -- the same safe, under-detecting-rather-than-guessing
direction the rest of ``leitir check`` already uses (ADR-0030's
corroboration-scan cap).
"""

from __future__ import annotations

import configparser
import os
import re
import tomllib
from pathlib import Path

from ..safeio import read_regular_file
from .contract import MAX_IMPORT_ROOTS_PER_MAPPING
from .import_catalog import (
    DISTRIBUTION_RECORD_SCHEMA_VERSION,
    DistributionRecord,
    build_import_catalog,
)

# Bounds. Declared near their consumers, per AGENTS.md.
MAX_EVIDENCE_FILE_BYTES = 1_048_576
MAX_WALK_DIR_ENTRIES = 20_000

_SPLIT_ON_COMMA_OR_NEWLINE = re.compile(r"[,\n]")

# Generic, cross-ecosystem structural conventions for "this top-level
# directory/file is not a package", not a per-distribution alias table:
# every Python source distribution uses some subset of these same names for
# its own tests/docs/tooling regardless of what it is named or imports as.
_TREE_LAYOUT_EXCLUDE_DIR_NAMES = frozenset(
    {
        "test",
        "tests",
        "testing",
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "benchmark",
        "benchmarks",
        "script",
        "scripts",
        "tool",
        "tools",
        "build",
        "dist",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".git",
        ".github",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
    }
)
_TREE_LAYOUT_EXCLUDE_FILE_STEMS = frozenset({"setup", "conftest", "noxfile", "_version", "versioneer"})


def _distribution_record(distribution: str, roots: tuple[str, ...], source: str) -> DistributionRecord:
    return DistributionRecord(
        schema_version=DISTRIBUTION_RECORD_SCHEMA_VERSION,
        distribution=distribution,
        declared_roots=roots,
        source=source,
    )


def _read_text(path: Path) -> str | None:
    try:
        data = read_regular_file(path, maximum_bytes=MAX_EVIDENCE_FILE_BYTES, no_follow=False)
        return data.decode("utf-8")
    except (OSError, ValueError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------
# Tier 1: top_level.txt (dist-info / egg-info).
# --------------------------------------------------------------------------


def _find_info_dirs(root: Path) -> tuple[Path, ...]:
    """Bounded, deterministic search for ``*.dist-info``/``*.egg-info`` dirs.

    Hitting the entry-visit cap before the walk completes simply stops the
    walk (returning whatever was already found) rather than raising --
    under-detection is the safe direction here, matching the rest of this
    module's caps.
    """

    found: list[Path] = []
    visited = 0
    try:
        for dirpath, dirnames, _filenames in os.walk(root):
            dirnames.sort()
            for name in list(dirnames):
                visited += 1
                if name.endswith((".dist-info", ".egg-info")):
                    found.append(Path(dirpath) / name)
                if visited >= MAX_WALK_DIR_ENTRIES:
                    dirnames.clear()
                    break
            if visited >= MAX_WALK_DIR_ENTRIES:
                break
    except OSError:
        pass
    return tuple(sorted(set(found), key=lambda p: p.relative_to(root).as_posix()))


def _top_level_txt_records(root: Path, distribution: str) -> tuple[DistributionRecord, ...]:
    records: list[DistributionRecord] = []
    for info_dir in _find_info_dirs(root):
        txt = info_dir / "top_level.txt"
        if not txt.is_file():
            continue
        text = _read_text(txt)
        if text is None:
            continue
        roots = tuple(sorted({line.strip() for line in text.splitlines() if line.strip()}))
        if roots:
            records.append(_distribution_record(distribution, roots, "top-level-txt"))
    return tuple(records)


# --------------------------------------------------------------------------
# Tier 2: setup.cfg (static, never executed).
# --------------------------------------------------------------------------


def _setup_cfg_records(root: Path, distribution: str) -> tuple[DistributionRecord, ...]:
    path = root / "setup.cfg"
    if not path.is_file():
        return ()
    text = _read_text(path)
    if text is None:
        return ()
    parser = configparser.ConfigParser()
    try:
        parser.read_string(text)
        if not parser.has_section("options"):
            return ()
        roots: set[str] = set()
        packages_raw = parser.get("options", "packages", fallback="").strip()
        if packages_raw and not packages_raw.lower().startswith("find"):
            for entry in _SPLIT_ON_COMMA_OR_NEWLINE.split(packages_raw):
                name = entry.strip()
                if name:
                    roots.add(name.split(".")[0])
        modules_raw = parser.get("options", "py_modules", fallback="").strip()
        for entry in _SPLIT_ON_COMMA_OR_NEWLINE.split(modules_raw):
            name = entry.strip()
            if name:
                roots.add(name)
    except configparser.Error:
        # P2 fix (adversarial review, reviewer-hy3): configparser.Error is
        # the base of every interpolation error configparser can raise
        # (InterpolationDepthError, InterpolationMissingOptionError,
        # InterpolationSyntaxError), not only parse errors -- a
        # self-referencing "%(x)s" value in setup.cfg (an attacker-
        # influenceable, materialized donor artifact) previously escaped
        # this handler because only ``read_string`` was wrapped, not the
        # subsequent ``.get()`` calls that actually perform interpolation.
        # Any failure here means this tier found nothing usable -- fail
        # closed the same way a parse failure already does, never raise.
        return ()
    if not roots:
        return ()
    return (_distribution_record(distribution, tuple(sorted(roots)), "setup-cfg-static"),)


# --------------------------------------------------------------------------
# Tier 3: pyproject.toml (static, tomllib only, never executed).
# --------------------------------------------------------------------------


def _pyproject_records(root: Path, distribution: str) -> tuple[DistributionRecord, ...]:
    path = root / "pyproject.toml"
    if not path.is_file():
        return ()
    text = _read_text(path)
    if text is None:
        return ()
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        # P2 fix (adversarial review, reviewer-hy3): a deeply nested TOML
        # structure (an attacker-influenceable, materialized donor
        # artifact) can make tomllib's recursive-descent parser raise
        # RecursionError rather than TOMLDecodeError. Either way, this
        # tier simply found nothing usable -- fail closed, never let a
        # raw exception escape this module's boundary.
        return ()
    roots: set[str] = set()
    tool = doc.get("tool")
    tool_table = tool if isinstance(tool, dict) else {}

    setuptools_cfg = tool_table.get("setuptools")
    if isinstance(setuptools_cfg, dict):
        packages = setuptools_cfg.get("packages")
        if isinstance(packages, list):
            for name in packages:
                if isinstance(name, str) and name:
                    roots.add(name.split(".")[0])
        py_modules = setuptools_cfg.get("py-modules")
        if isinstance(py_modules, list):
            for name in py_modules:
                if isinstance(name, str) and name:
                    roots.add(name)

    poetry_cfg = tool_table.get("poetry")
    if isinstance(poetry_cfg, dict):
        packages = poetry_cfg.get("packages")
        if isinstance(packages, list):
            for entry in packages:
                if isinstance(entry, dict):
                    include = entry.get("include")
                    if isinstance(include, str) and include:
                        roots.add(include.split("/")[0].split(".")[0])

    if not roots:
        return ()
    return (_distribution_record(distribution, tuple(sorted(roots)), "pyproject-static"),)


# --------------------------------------------------------------------------
# Tier 4: materialized-tree-layout (structural fallback).
# --------------------------------------------------------------------------


def _package_candidates(base: Path) -> tuple[str, ...]:
    names: set[str] = set()
    try:
        entries = sorted(base.iterdir(), key=lambda p: p.name)
    except OSError:
        return ()
    for entry in entries:
        name = entry.name
        if name.startswith("."):
            continue
        try:
            is_dir = entry.is_dir()
            is_file = entry.is_file()
        except OSError:
            continue
        if is_dir:
            if name.lower() in _TREE_LAYOUT_EXCLUDE_DIR_NAMES:
                continue
            if name.endswith((".dist-info", ".egg-info")):
                continue
            if not name.isidentifier():
                continue
            if (entry / "__init__.py").is_file():
                names.add(name)
        elif is_file and entry.suffix == ".py":
            stem = entry.stem
            if stem == "__init__" or stem.lower() in _TREE_LAYOUT_EXCLUDE_FILE_STEMS:
                continue
            if stem.startswith("test_") or stem.endswith("_test"):
                continue
            if not stem.isidentifier():
                continue
            names.add(stem)
    return tuple(sorted(names))


def _tree_layout_records(root: Path, distribution: str) -> tuple[DistributionRecord, ...]:
    candidates: tuple[str, ...] = ()
    src = root / "src"
    if src.is_dir():
        candidates = _package_candidates(src)
    if not candidates:
        candidates = _package_candidates(root)
    if not candidates:
        return ()
    if len(candidates) == 1:
        return (_distribution_record(distribution, candidates, "materialized-tree-layout"),)
    # P1 fix (adversarial review, reviewer-hy3): tier 4 is a purely
    # structural heuristic with no authoritative packaging evidence behind
    # it -- unlike tiers 1-3, it has no way to distinguish a genuine
    # additional public import root (a real multi-root distribution) from
    # an unrelated top-level helper module or vendored subpackage the
    # donor repository simply happens to ship (a stray "constants.py", a
    # "vendor/__init__.py"). Binding every such candidate to --against
    # used to let a same-named, wholly unrelated import in the consumer's
    # own code get misattributed to the pinned distribution -- exactly
    # the false-violation-against-correct-code shape issue #269 forbids
    # ("a wrong import root must never produce a violation against code
    # that is actually correct"). When more than one candidate is found,
    # this tier can no longer positively resolve a single root, so it
    # must not guess by binding all of them either: it emits one
    # single-root record per candidate (never one multi-root record), and
    # build_import_catalog's existing, unmodified disagreement handling
    # (distinct declared_roots sets across records for the same
    # distribution) then correctly types the whole distribution as
    # UnresolvedState.AMBIGUOUS_BINDING -- resolve_import_roots returns
    # None, and check.py fails safe (nothing_examined, exit 4) rather than
    # ever guessing. A genuine multi-root distribution must be evidenced
    # by an authoritative packaging source (tier 1-3) instead; tier 4
    # alone can only ever resolve a single, unambiguous top-level root.
    return tuple(
        _distribution_record(distribution, (candidate,), "materialized-tree-layout")
        for candidate in candidates
    )


# --------------------------------------------------------------------------
# Public entry points.
# --------------------------------------------------------------------------

_EVIDENCE_TIERS = (
    _top_level_txt_records,
    _setup_cfg_records,
    _pyproject_records,
    _tree_layout_records,
)


def derive_distribution_records(materialized_root: Path, distribution: str) -> tuple[DistributionRecord, ...]:
    """Derive import-root evidence for one distribution from its materialized tree.

    Consults each evidence tier in precedence order and returns the first
    tier's records that found anything at all. If no tier finds any
    evidence, returns a single zero-root record (source
    ``"materialized-tree-layout"``) so :func:`~leitir.usage.import_catalog.build_import_catalog`
    types the outcome as unresolved, matching ADR-0026's contract for
    missing evidence.
    """

    for tier in _EVIDENCE_TIERS:
        records = tier(materialized_root, distribution)
        if records:
            return records
    return (_distribution_record(distribution, (), "materialized-tree-layout"),)


def resolve_import_roots(materialized_root: Path, distribution: str) -> tuple[str, ...] | None:
    """Return the resolved, deterministically sorted import roots for
    ``distribution``, derived from ``materialized_root``'s own evidence, or
    ``None`` if the import root genuinely could not be determined
    (ambiguous evidence, or no evidence at all) -- never a guess.

    The cap on the number of distinct roots a single mapping may carry is
    the existing :data:`~leitir.usage.MAX_IMPORT_ROOTS_PER_MAPPING`
    (ADR-0026); exceeding it is treated the same as any other
    unsupported-shape rejection by ``build_import_catalog``.
    """

    records = derive_distribution_records(materialized_root, distribution)
    catalog = build_import_catalog(records)
    if not catalog.mappings:
        return None
    (mapping,) = catalog.mappings
    if len(mapping.import_roots) > MAX_IMPORT_ROOTS_PER_MAPPING:
        return None
    return mapping.import_roots


__all__ = [
    "MAX_EVIDENCE_FILE_BYTES",
    "MAX_WALK_DIR_ENTRIES",
    "derive_distribution_records",
    "resolve_import_roots",
]
