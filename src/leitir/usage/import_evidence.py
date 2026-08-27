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

## Tier 4 (``materialized-tree-layout``) was retired as an authority

An earlier version of this module also consulted a fourth,
lowest-confidence tier: a purely structural scan of the tree's own
top-level layout (``src/`` preferred when present) for directories with
``__init__.py`` or top-level ``.py`` files. It was retired (issue #269
follow-up, adversarial review, reviewer-hy3) because it could still
originate a *wrong* binding even after being restricted to "exactly one
candidate": a ``src/``-layout donor whose ``src/`` directory contains only
a private/vendored helper package, while the tree's real, public import
root is a module living outside ``src/`` (e.g. a top-level ``reallib.py``
next to a ``src/buildutils/`` internal helper), resolves tier 4 to the
*wrong* single "unambiguous" candidate (``buildutils``), because the
``src/``-preference rule means the real root outside ``src/`` is never
even considered. That wrong root then binds to ``--against``, and a
consumer's own, unrelated same-named local import (its own
``buildutils.py``) gets misattributed to the pinned distribution -- a
false ``violation`` against code that is actually correct, exactly the
sad path issue #269 forbids ("a wrong import root must never produce a
violation against code that is actually correct"). Restricting tier 4 to
"exactly one candidate" (the earlier P1 fix) closes the *multi-candidate*
collision shape but not this *single-candidate, wrong-candidate* shape --
there is no purely structural rule that reliably tells "the one candidate
tier 4 found" apart from "the one candidate tier 4 found, which happens to
be wrong" without either executing untrusted build logic (out of scope,
by design) or hardcoding distribution-specific knowledge (forbidden by
issue #269). A guess is a guess regardless of how few candidates it had to
choose from; tiers 1-3 are the distribution's own declarations about
itself, tier 4 was never more than a guess from directory shape, and a
guess must not bind a gate whose defining property is "never flag correct
code". See "Negative Consequences" in ADR-0032 for the resulting,
accepted coverage limitation: a distribution with no `top_level.txt`/
``setup.cfg``/``pyproject.toml`` evidence in a given materialization (a
GitHub-sourced source tree, most commonly) is now reported undeterminable
rather than resolved from tree shape, even in cases (``pillow`` -> ``PIL``,
``pyyaml`` -> ``yaml``) tier 4 used to recover.

If no tier (1-3) finds any evidence at all, a single zero-root
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

A distribution whose real import surface genuinely spans multiple
top-level roots (e.g. ``attrs`` shipping both ``attr`` and ``attrs``) must
therefore be evidenced by tier 1-3 to be resolved as multi-root at all --
there is no tier 4 to fall back on any more (see "Tier 4 ... was retired
as an authority" above).

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
# Public entry points.
# --------------------------------------------------------------------------

# Tier 4 ("materialized-tree-layout", a purely structural scan of the
# tree's own top-level layout) was retired as an authority -- see the
# module docstring's "Tier 4 ... was retired as an authority" section and
# ADR-0032's "Negative Consequences" for why: even restricted to "exactly
# one candidate", it could still resolve the *wrong* single root (a
# src/-layout donor whose src/ holds only a vendored helper while the real
# public root lives outside src/) and bind that wrong root to --against,
# producing a false violation against a consumer's own, unrelated,
# same-named local import -- the exact sad path issue #269 forbids. Only
# tiers 1-3 (the distribution's own packaging declarations about itself)
# may originate a resolved root; when they are all silent, the outcome is
# the zero-root fail-safe below, never a guess from directory shape.
_EVIDENCE_TIERS = (
    _top_level_txt_records,
    _setup_cfg_records,
    _pyproject_records,
)


def derive_distribution_records(materialized_root: Path, distribution: str) -> tuple[DistributionRecord, ...]:
    """Derive import-root evidence for one distribution from its materialized tree.

    Consults each evidence tier (1-3: ``top_level.txt``, static
    ``setup.cfg``, static ``pyproject.toml``, in that precedence order) and
    returns the first tier's records that found anything at all. If no
    tier finds any evidence, returns a single zero-root record (source
    ``"materialized-tree-layout"``, the fixed sentinel tag for "no
    evidence") so :func:`~leitir.usage.import_catalog.build_import_catalog`
    types the outcome as unresolved, matching ADR-0026's contract for
    missing evidence. There is no structural-tree-layout tier any more
    (see the module docstring) -- a distribution whose import root is not
    declared by any of tiers 1-3 in this materialization is always
    reported undeterminable, never guessed from directory shape.
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
