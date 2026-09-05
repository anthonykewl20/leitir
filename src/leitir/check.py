"""``leitir check``: validate written Python code against a materialized
source's API surface (issue #266, tasks B3/E1).

Every other leitir verb is retrieval or provenance: it tells an agent what a
pinned source actually contains. None of them look at code the agent just
*wrote* and check it against that truth. This module closes that gap for
Python consumer code checked against one pinned registry/repository source.

## Premise, verified before design

Two existing modules were read before anything here was written:

- :mod:`leitir.apisurface` -- the Python extractor (``_python_extractor``)
  walks only *direct* top-level statements (``for node in tree.body``) plus
  one level of methods on a top-level class. It never recurses into
  ``if``/``try`` blocks (so a conditionally defined symbol is invisible to
  it), never indexes plain module-level assignments/constants, and
  deliberately excludes any name starting with ``_``. Its ``signature``
  field is a formatted string (parameter names, defaults, annotations) --
  useful for a human diff, not a structured arity model a machine can
  safely check a call site against (defaults, ``*args``/``**kwargs``, and
  decorator-rewritten signatures all make "arity" ill-defined from a string
  alone). **Conclusion: the index supports symbol-existence checking. It
  does not support reliable arity/signature checking.** This first version
  therefore checks existence only; see the ADR for the full reasoning.
- :mod:`leitir.usage.resolver` (``resolve_consumer``, ADR-0027) -- resolves,
  per source line, *which distribution* a name is bound to, using a real
  scope-aware binding table. It does **not** extract the attribute/symbol
  name actually accessed at a usage site (a ``CodeReference`` carries only
  ``distribution``, ``span``, and a code digest) -- that is dependency-level
  evidence, not symbol-level evidence. This module reuses ``resolve_consumer``
  for what it already gives for free -- correct, conservative distribution
  attribution and the closed :class:`~leitir.usage.UnresolvedState` outcomes
  for anything statically unknowable -- and adds a small, local, top-level
  import-table pass (see ``_ImportTable``) only to recover *which* symbol a
  resolved reference names. That recovery is intentionally best-effort and
  conservative: whenever it cannot pin down a candidate symbol with
  confidence it falls back to treating the site as ``unresolved`` (never a
  guessed ``ok``, and never a guessed ``violation``).

## Three-way outcome (mirrors ADR-0002: unknown is neither zero nor pass)

- ``ok`` -- the symbol was *statically recovered* and is present in the
  pinned surface. "Recovered" is load-bearing: a site whose accessed
  symbol name could not be pinned down (dynamic dispatch via ``getattr``,
  an alias handed to a function, a module value passed around and called
  elsewhere) was never resolved, so it can never be ``ok`` even though
  ``resolve_consumer`` correctly attributed the site to this distribution.
- ``violation`` -- provably absent: not in the extracted API index *and*
  not present anywhere in the pinned source's own text (a corroborating
  raw scan that catches conditionally defined, aliased, or constant
  symbols the index's def/class-only extractor cannot see). Only this
  outcome fails the gate.
- ``unresolved`` -- statically undecidable: dynamic dispatch, star import,
  ambiguous binding, re-export, a private/underscore name the index never
  indexes by policy, a corroboration scan that hit its byte budget before
  finishing, *or* a resolved reference whose accessed symbol name itself
  could not be statically recovered (a bare module reference used
  dynamically). Always counted, never silently dropped, never treated as
  a violation, and never counted as ``ok``.

A ``CheckReport`` additionally exposes ``status`` (``"nothing_examined"``
/ ``"violations_found"`` / ``"clean"``) precisely because zero examined
sites and zero violating sites both make ``sites_violation == 0`` true --
without a separate indicator a run that checked nothing looks identical to
a run that checked everything and found it clean. This still happens
whenever the pinned distribution's import root(s) cannot be determined at
all from its own evidence (see :mod:`leitir.usage.import_evidence`,
issue #269, ADR-0032) -- an undeterminable root must fail safe the same
way a wrong guess used to.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .apisurface import ApiIndex, extract_api_surface
from .materialize import VerificationError
from .safeio import read_regular_file
from .usage.contract import CodeReference, UnresolvedState
from .usage.import_evidence import resolve_import_roots
from .usage.resolver import (
    MAX_RESOLVER_FILE_BYTES,
    MAX_RESOLVER_FILES,
    resolve_consumer,
)

CHECK_SCHEMA_VERSION = "leitir-check-report-v1"

# Caps for reading the *target* (materialized, pinned) source tree for the
# violation-corroboration scan. Declared near their consumer, per AGENTS.md.
# Distinct from the resolver's own caps (those bound the untrusted consumer
# tree); this budget bounds the trusted, already-verified materialized tree.
MAX_TARGET_FILES = 500
MAX_TARGET_FILE_BYTES = 1_048_576
MAX_TARGET_TOTAL_BYTES = 16_777_216


class UnsupportedLanguageError(ValueError):
    """Raised when the path to check is not Python source.

    The static usage resolver this module builds on (ADR-0027) is
    Python-only. Anything else must reject clearly rather than silently
    reporting ``ok``.
    """


class CheckIndexError(VerificationError):
    """The pinned source's API surface could not be verified as checkable.

    Raised instead of proceeding with an empty or otherwise unusable index
    -- fail closed, never pass code against a truth surface that was not
    actually established (matches the existing ``VerificationError``
    taxonomy so callers can handle it the same way as any other
    materialization/verification failure).
    """


@dataclass(frozen=True, slots=True)
class CheckSite:
    """One examined site: an attribute/call usage, or a whole-file record."""

    file: str
    line: int
    col: int
    symbol: str
    outcome: str  # "ok" | "violation" | "unresolved"
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "symbol": self.symbol,
            "outcome": self.outcome,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class CheckReport:
    """The full, deterministic result of one ``leitir check`` run."""

    schema_version: str
    against: str
    language: str
    sites_examined: int
    sites_ok: int
    sites_violation: int
    sites_unresolved: int
    violations: tuple[CheckSite, ...]
    unresolved: tuple[CheckSite, ...]
    ok_sites: tuple[CheckSite, ...]
    files_examined: tuple[str, ...]
    files_excluded: tuple[str, ...]
    target_corroboration_capped: bool
    import_roots: tuple[str, ...]
    import_roots_determinable: bool

    def __post_init__(self) -> None:
        if self.sites_examined != self.sites_ok + self.sites_violation + self.sites_unresolved:
            raise ValueError("sites_examined must equal ok + violation + unresolved")
        if len(self.violations) != self.sites_violation:
            raise ValueError("violations count mismatch")
        if len(self.unresolved) != self.sites_unresolved:
            raise ValueError("unresolved count mismatch")
        if len(self.ok_sites) != self.sites_ok:
            raise ValueError("ok_sites count mismatch")
        # Strengthened invariant (P1 fix, defect 1): "ok" must mean resolved
        # *and* present -- a site whose symbol could not be statically
        # recovered is never genuinely resolved, so it can never carry one
        # of the placeholder symbol names used for statically-undecidable
        # sites. Every ok site must name a real, concrete symbol.
        for site in self.ok_sites:
            if site.symbol in ("<module>", "<file>") or not site.symbol:
                raise ValueError(
                    f"ok_sites must only contain resolved, concrete symbols; got {site.symbol!r}"
                )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "against": self.against,
            "language": self.language,
            "status": self.status,
            "counts": {
                "sites_examined": self.sites_examined,
                "sites_ok": self.sites_ok,
                "sites_violation": self.sites_violation,
                "sites_unresolved": self.sites_unresolved,
            },
            "violations": [site.to_dict() for site in self.violations],
            "unresolved": [site.to_dict() for site in self.unresolved],
            "ok": [site.to_dict() for site in self.ok_sites],
            "files_examined": list(self.files_examined),
            "files_excluded": list(self.files_excluded),
            "target_corroboration_capped": self.target_corroboration_capped,
            "import_roots": list(self.import_roots),
            "import_roots_determinable": self.import_roots_determinable,
        }

    @property
    def passed(self) -> bool:
        return self.sites_violation == 0

    @property
    def status(self) -> str:
        """An unambiguous top-level indicator, distinct from ``passed``.

        ``passed`` alone conflates "verified clean" with "verified nothing"
        -- a zero-site run has ``sites_violation == 0`` and reads exactly
        like a clean pass unless a consumer separately checks
        ``sites_examined``. ``status`` makes the three cases explicit:

        - ``"nothing_examined"`` -- zero sites were examined; nothing was
          verified at all (see defect 2: a wrong ``guess_import_root``
          guess produces exactly this, silently).
        - ``"violations_found"`` -- at least one genuine violation.
        - ``"clean"`` -- at least one site was examined and none violated.
        """

        if self.sites_examined == 0:
            return "nothing_examined"
        if self.sites_violation > 0:
            return "violations_found"
        return "clean"


# --------------------------------------------------------------------------
# Path discovery / language gate.
# --------------------------------------------------------------------------


def discover_python_files(path: Path) -> tuple[Path, tuple[str, ...]]:
    """Return ``(consumer_root, relative .py files)`` for a file or directory.

    Rejects (``UnsupportedLanguageError``) for a non-Python file, or a
    directory containing no Python source at all, rather than silently
    reporting an empty, vacuously-passing check.
    """

    if not path.exists():
        raise FileNotFoundError(f"no such file or directory: {path}")
    if path.is_file():
        if path.suffix != ".py":
            raise UnsupportedLanguageError(
                f"unsupported language: {path} is not a .py file; "
                "leitir check supports Python source only (ADR-0027)"
            )
        return path.parent, (path.name,)
    if path.is_dir():
        files = tuple(
            sorted(
                candidate.relative_to(path).as_posix()
                for candidate in path.rglob("*.py")
                if candidate.is_file()
            )
        )
        if not files:
            raise UnsupportedLanguageError(
                f"unsupported language: no .py files found under {path}; "
                "leitir check supports Python source only (ADR-0027)"
            )
        return path, files
    raise FileNotFoundError(f"not a regular file or directory: {path}")


# --------------------------------------------------------------------------
# Target (pinned source) API index + corroboration text.
# --------------------------------------------------------------------------


def extract_check_index(materialized_root: Path) -> ApiIndex:
    """Extract the Python API surface, always Python-only regardless of the
    materialized source's declared ecosystem -- the consumer side this
    module checks is Python-only, so only the target's Python surface is
    relevant, including inside an otherwise polyglot repository."""

    return extract_api_surface(materialized_root, "python")


def _require_checkable_index(index: ApiIndex, *, against: str) -> None:
    modules = index.get("modules")
    if not isinstance(modules, list) or not modules:
        raise CheckIndexError(
            f"API surface for {against} is empty or unverifiable (no Python "
            "modules were extracted from the materialized source); refusing "
            "to check code against an unestablished truth surface"
        )


def _index_symbol_names(index: ApiIndex) -> frozenset[str]:
    symbols = index.get("symbols")
    names: set[str] = set()
    if isinstance(symbols, list):
        for symbol in symbols:
            if isinstance(symbol, dict):
                name = symbol.get("name")
                if isinstance(name, str) and name:
                    names.add(name)
    return frozenset(names)


@dataclass(frozen=True, slots=True)
class _TargetText:
    texts: tuple[str, ...]
    capped: bool


def _read_target_text(materialized_root: Path) -> _TargetText:
    """Bounded, deterministic read of the pinned source's own .py bytes.

    Used only to corroborate a violation: a symbol the index's def/class-only
    extractor could not see (a conditional definition, an alias, a module
    constant) but that genuinely exists in the source text must never be
    reported as a violation. If the budget is exhausted before every file is
    read, ``capped`` is ``True`` and no violation may be declared from this
    scan (an absence found under a capped scan is not proven absence).
    """

    try:
        candidates = sorted(
            p for p in materialized_root.rglob("*.py") if p.is_file()
        )
    except OSError:
        return _TargetText(texts=(), capped=True)
    capped = len(candidates) > MAX_TARGET_FILES
    candidates = candidates[:MAX_TARGET_FILES]
    texts: list[str] = []
    total = 0
    for candidate in candidates:
        if total >= MAX_TARGET_TOTAL_BYTES:
            capped = True
            break
        try:
            data = read_regular_file(
                candidate, maximum_bytes=MAX_TARGET_FILE_BYTES, no_follow=False
            )
        except (OSError, ValueError):
            capped = True
            continue
        if len(data) >= MAX_TARGET_FILE_BYTES:
            # Read hit the byte cap: the file may have been truncated by the
            # bounded reader, so its absence of a match is not trustworthy.
            capped = True
        total += len(data)
        try:
            texts.append(data.decode("utf-8"))
        except UnicodeDecodeError:
            capped = True
    return _TargetText(texts=tuple(texts), capped=capped)


def _appears_in_text(name: str, texts: tuple[str, ...]) -> bool:
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    return any(pattern.search(text) for text in texts)


# --------------------------------------------------------------------------
# Consumer-side symbol candidate recovery.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ImportTable:
    """Best-effort, module-top-level-only recovery of what a bound name
    actually names, for one consumer file.

    ``resolve_consumer`` already conservatively guarantees *that* a name at
    a given position is certainly bound to the target distribution; this
    table only recovers, on a best-effort basis, *which* provider symbol
    that binding names, by re-reading the file's own top-level
    import/from-import statements. Anything not resolvable at the top level
    (a deeper-scope import, a re-bound alias) falls back at lookup time to
    the attribute-access heuristic in ``_candidate_for_reference``, which is
    always safe: it either recovers a concrete attribute name or reports a
    bare module reference, never a guess.
    """

    # local name -> original provider symbol name, or None if this local
    # name is the *module* itself (so an attribute access off of it is what
    # names a symbol).
    module_names: dict[str, str]
    symbol_aliases: dict[str, str]


def _build_import_table(tree: ast.Module, import_roots: frozenset[str]) -> _ImportTable:
    module_names: dict[str, str] = {}
    symbol_aliases: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.name.split(".")[0] in import_roots:
                    module_names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.level == 0 and stmt.module and stmt.module.split(".")[0] in import_roots:
                for alias in stmt.names:
                    if alias.name == "*":
                        continue
                    symbol_aliases[alias.asname or alias.name] = stmt.module + "." + alias.name
    return _ImportTable(module_names=module_names, symbol_aliases=symbol_aliases)


def _find_name_node(tree: ast.Module, *, line: int, col: int) -> ast.Name | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.lineno == line and node.col_offset == col:
            return node
    return None


def _find_enclosing_attribute(tree: ast.Module, name_node: ast.Name) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.value is name_node:
            return node.attr
    return None


@dataclass(frozen=True, slots=True)
class _Candidate:
    symbol: str | None
    reason: str
    qualified: str | None = None


def _candidate_for_reference(
    tree: ast.Module, table: _ImportTable, reference: CodeReference
) -> _Candidate:
    span = reference.span
    name_node = _find_name_node(tree, line=span.start_line, col=span.start_col)
    if name_node is None:
        return _Candidate(symbol=None, reason="module reference (symbol site not statically located)")
    local_name = name_node.id
    qualified = table.symbol_aliases.get(local_name) or table.module_names.get(local_name)
    if qualified is None:
        return _Candidate(symbol=None, reason="provider binding is not statically recovered")
    current: ast.expr = name_node
    attributes: list[str] = []
    while True:
        parent = next((item for item in ast.walk(tree) if isinstance(item, ast.Attribute) and item.value is current), None)
        if parent is None:
            break
        attributes.append(parent.attr)
        current = parent
    if attributes:
        qualified += "." + ".".join(attributes)
    elif local_name not in table.symbol_aliases:
        return _Candidate(symbol=None, reason="module reference (no attribute access)")
    return _Candidate(symbol=qualified.rsplit(".", 1)[-1], reason="qualified import binding", qualified=qualified)


def _qualified_api_evidence(index: ApiIndex, root: Path, import_roots: tuple[str, ...]) -> tuple[frozenset[str], dict[str, str]]:
    """Recover source-backed names and explicit module-level reexports.

    Ambiguous module layouts, conditional/star exports and dynamic mutations
    remain unknown. A matching bare name in another module is never proof.
    """
    module_records = index.get("modules", [])
    normalized: dict[str, str] = {}
    paths: dict[str, str] = {}
    ambiguous: set[str] = set()
    for record in module_records if isinstance(module_records, list) else []:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str) or not isinstance(record.get("path"), str):
            continue
        name, path = record["name"], record["path"]
        pieces = name.split(".")
        candidates = [".".join(pieces[position:]) for position, part in enumerate(pieces) if part in import_roots]
        if len(candidates) != 1:
            continue
        public = candidates[0]
        if public in paths and paths[public] != path:
            ambiguous.add(public)
        normalized[name] = public
        paths[public] = path
    known: set[str] = set()
    symbols = index.get("symbols", [])
    for symbol in symbols if isinstance(symbols, list) else []:
        if not isinstance(symbol, dict):
            continue
        module, qualified = symbol.get("module"), symbol.get("qualified_name")
        if isinstance(module, str) and isinstance(qualified, str) and module in normalized:
            public = normalized[module]
            if public not in ambiguous and qualified.startswith(module + "."):
                known.add(public + qualified[len(module):])
    aliases: dict[str, str] = {}
    total = 0
    for module, relative in sorted(paths.items())[:MAX_TARGET_FILES]:
        if module in ambiguous:
            continue
        try:
            path = root / relative
            if not path.resolve().is_relative_to(root.resolve()):
                continue
            raw = read_regular_file(path, maximum_bytes=MAX_TARGET_FILE_BYTES, no_follow=True)
            total += len(raw)
            if total > MAX_TARGET_TOTAL_BYTES:
                break
            tree = ast.parse(raw)
        except (OSError, ValueError, SyntaxError):
            continue
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom):
                if statement.level:
                    parts = package.split(".")
                    if statement.level > len(parts):
                        continue
                    prefix = ".".join(parts[:len(parts) - statement.level + 1])
                    target = prefix + ("." + statement.module if statement.module else "")
                else:
                    target = statement.module or ""
                for alias in statement.names:
                    if alias.name != "*" and target:
                        aliases[module + "." + (alias.asname or alias.name)] = target + "." + alias.name
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    aliases[module + "." + (alias.asname or alias.name.split(".")[0])] = alias.name if alias.asname else alias.name.split(".")[0]
    return frozenset(known), aliases


def _has_qualified_api(qualified: str | None, known: frozenset[str], aliases: dict[str, str]) -> bool:
    visited: set[str] = set()
    while qualified and qualified not in visited and len(visited) < 32:
        if qualified in known:
            return True
        visited.add(qualified)
        parts = qualified.split(".")
        for count in range(len(parts), 0, -1):
            prefix = ".".join(parts[:count])
            if prefix in aliases:
                qualified = aliases[prefix] + ("." + ".".join(parts[count:]) if count < len(parts) else "")
                break
        else:
            return False
    return False



# --------------------------------------------------------------------------
# Public entry point.
# --------------------------------------------------------------------------


def guess_import_root(package_name: str) -> str:
    """Best-effort normalization of a registry distribution name.

    HISTORICAL NOTE (superseded by issue #269): this was previously the
    *only* source ``run_check`` used to decide which import root to look
    for, which is wrong for any renamed distribution (``beautifulsoup4`` ->
    ``bs4``, ``PyYAML`` -> ``yaml``, ``pillow`` -> ``PIL``, ...). As of
    issue #269, ``run_check`` derives the actual import root(s) from the
    materialized distribution's own evidence via
    :func:`leitir.usage.import_evidence.resolve_import_roots` (see
    ADR-0032), which extends ADR-0026's import-catalog machinery instead of
    guessing from the name. This function is kept only as a display/
    diagnostic helper (e.g. the CLI's "nothing examined" message can still
    show what a name-based guess *would* have been) and is no longer
    consulted to decide what the resolver looks for.
    """

    normalized = re.sub(r"[^0-9a-zA-Z_]", "_", package_name).lower()
    return normalized.strip("_") or normalized


def run_check(
    *,
    consumer_path: Path,
    against: str,
    package_name: str,
    materialized_root: Path,
) -> CheckReport:
    """Check Python source at ``consumer_path`` against ``against``'s pinned
    API surface, materialized already at ``materialized_root``.

    Fails closed (raises :class:`CheckIndexError`) if the pinned source's
    API surface cannot be established as a usable truth surface. Never
    raises for ordinary unresolved/violation findings -- those are reported
    in the returned :class:`CheckReport`.
    """

    consumer_root, files = discover_python_files(consumer_path)
    index = extract_check_index(materialized_root)
    _require_checkable_index(index, against=against)
    target_text = _read_target_text(materialized_root)

    # Issue #269: derive the import root(s) from the materialized
    # distribution's own evidence (leitir.usage.import_evidence, extending
    # ADR-0026's import-catalog machinery) rather than guessing it from the
    # registry name. ``None`` means the evidence was absent or ambiguous --
    # this must fail safe (zero import roots => the resolver finds no
    # reference to check => sites_examined stays 0 => status
    # "nothing_examined", never a guessed violation and never a silent
    # "ok"). A resolved mapping may legitimately name more than one root
    # (a multi-root distribution); every resolved root maps to the same
    # ``against`` target.
    resolved_roots = resolve_import_roots(materialized_root, package_name)
    import_roots_determinable = resolved_roots is not None
    import_roots = tuple(sorted(resolved_roots)) if resolved_roots else ()
    qualified_names, aliases = _qualified_api_evidence(index, materialized_root, import_roots)
    result = resolve_consumer(
        consumer_root=consumer_root,
        import_roots={root: against for root in import_roots},
        files=files,
        max_files=MAX_RESOLVER_FILES,
        max_file_bytes=MAX_RESOLVER_FILE_BYTES,
    )

    tree_cache: dict[str, ast.Module | None] = {}
    table_cache: dict[str, _ImportTable] = {}

    def _tree_for(relpath: str) -> ast.Module | None:
        if relpath in tree_cache:
            return tree_cache[relpath]
        try:
            data = read_regular_file(
                consumer_root / relpath,
                maximum_bytes=MAX_RESOLVER_FILE_BYTES,
                no_follow=False,
            )
            tree = ast.parse(data.decode("utf-8"), filename=relpath)
        except (OSError, ValueError, UnicodeDecodeError, SyntaxError):
            tree = None
        tree_cache[relpath] = tree
        return tree

    ok_sites: list[CheckSite] = []
    violation_sites: list[CheckSite] = []
    unresolved_sites: list[CheckSite] = []

    for reference in result.references:
        relpath = reference.span.file
        tree = _tree_for(relpath)
        if tree is None:
            unresolved_sites.append(
                CheckSite(
                    file=relpath,
                    line=reference.span.start_line,
                    col=reference.span.start_col,
                    symbol="<file>",
                    outcome="unresolved",
                    reason="consumer file could not be re-parsed for symbol recovery",
                )
            )
            continue
        table = table_cache.setdefault(relpath, _build_import_table(tree, frozenset(import_roots)))
        candidate = _candidate_for_reference(tree, table, reference)
        line = reference.span.start_line
        col = reference.span.start_col
        if candidate.symbol is None:
            # P1 fix (defect 1): a site whose accessed symbol name could not
            # be statically recovered was never resolved, so it cannot be
            # "ok" -- "ok" means resolved *and* present. Every reachable
            # ``_candidate_for_reference`` no-symbol reason corresponds to a
            # real usage site (the resolver only emits a CodeReference at an
            # actual Name-load use -- an unused ``import x`` never reaches
            # here at all), so there is no genuinely-fine "bare import, no
            # usage" case being reclassified here: both reasons ("symbol
            # site not statically located" and "no attribute access", e.g.
            # dynamic dispatch via getattr, an alias handed to a function,
            # or a module value passed around and called elsewhere) are
            # statically undecidable and must be ``unresolved``, never a
            # guessed ``violation`` either.
            unresolved_sites.append(
                CheckSite(file=relpath, line=line, col=col, symbol="<module>", outcome="unresolved", reason=candidate.reason)
            )
            continue
        symbol = candidate.symbol
        if symbol.startswith("_"):
            unresolved_sites.append(
                CheckSite(
                    file=relpath,
                    line=line,
                    col=col,
                    symbol=symbol,
                    outcome="unresolved",
                    reason="underscore-prefixed symbol is never indexed by policy; cannot verify",
                )
            )
            continue
        if _has_qualified_api(candidate.qualified, qualified_names, aliases):
            ok_sites.append(
                CheckSite(file=relpath, line=line, col=col, symbol=symbol, outcome="ok", reason="qualified binding is present in the source-backed API index")
            )
            continue
        if target_text.capped:
            unresolved_sites.append(
                CheckSite(
                    file=relpath,
                    line=line,
                    col=col,
                    symbol=symbol,
                    outcome="unresolved",
                    reason="not in the API index, and the corroborating source scan was capped before completion",
                )
            )
            continue
        if _appears_in_text(symbol, target_text.texts):
            unresolved_sites.append(
                CheckSite(
                    file=relpath,
                    line=line,
                    col=col,
                    symbol=symbol,
                    outcome="unresolved",
                    reason="qualified binding is not established, but the bare name is present in pinned source text "
                    "(likely a conditional definition, alias, or module constant the "
                    "def/class-only extractor cannot see)",
                )
            )
            continue
        violation_sites.append(
            CheckSite(
                file=relpath,
                line=line,
                col=col,
                symbol=symbol,
                outcome="violation",
                reason=f"symbol {symbol!r} was not found anywhere in {against}'s materialized API index or source text",
            )
        )

    for record in result.coverage.records:
        if record.state is UnresolvedState.RESOLVED:
            continue
        unresolved_sites.append(
            CheckSite(
                file=record.file,
                line=0,
                col=0,
                symbol="<file>",
                outcome="unresolved",
                reason=f"file could not be fully resolved: {record.state.value}",
            )
        )
    for excluded in result.coverage.exclusions:
        unresolved_sites.append(
            CheckSite(
                file=excluded,
                line=0,
                col=0,
                symbol="<file>",
                outcome="unresolved",
                reason="file excluded from resolution (oversized or beyond the file-count cap)",
            )
        )

    ok_sites.sort(key=lambda site: (site.file, site.line, site.col, site.symbol))
    violation_sites.sort(key=lambda site: (site.file, site.line, site.col, site.symbol))
    unresolved_sites.sort(key=lambda site: (site.file, site.line, site.col, site.symbol))

    files_examined = tuple(sorted({record.file for record in result.coverage.records}))
    files_excluded = tuple(sorted(result.coverage.exclusions))

    total = len(ok_sites) + len(violation_sites) + len(unresolved_sites)
    return CheckReport(
        schema_version=CHECK_SCHEMA_VERSION,
        against=against,
        language="python",
        sites_examined=total,
        sites_ok=len(ok_sites),
        sites_violation=len(violation_sites),
        sites_unresolved=len(unresolved_sites),
        violations=tuple(violation_sites),
        unresolved=tuple(unresolved_sites),
        ok_sites=tuple(ok_sites),
        files_examined=files_examined,
        files_excluded=files_excluded,
        target_corroboration_capped=target_text.capped,
        import_roots=import_roots,
        import_roots_determinable=import_roots_determinable,
    )


__all__ = [
    "CHECK_SCHEMA_VERSION",
    "CheckIndexError",
    "CheckReport",
    "CheckSite",
    "UnsupportedLanguageError",
    "discover_python_files",
    "extract_check_index",
    "guess_import_root",
    "run_check",
]
