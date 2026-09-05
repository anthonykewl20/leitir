"""Deterministic file and public-API differences between corpus versions."""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from leitir import _http
from leitir.apisurface import ApiDiff, diff_api_indexes, extract_api_surface
from leitir.materialize import MANIFEST_NAME
from leitir.spec import CorpusSpec, parse_corpus_spec

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FileDiff:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    modified: tuple[str, ...]

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "modified": list(self.modified),
        }


@dataclass(frozen=True, slots=True)
class VersionIdentity:
    spec: str
    name: str
    version: str | None
    repository: str
    commit_sha: str

    def as_dict(self) -> dict[str, object]:
        return {
            "spec": self.spec,
            "name": self.name,
            "version": self.version,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
        }


@dataclass(frozen=True, slots=True)
class ReleaseNote:
    version: str | None
    tag: str
    url: str
    body: str

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "tag": self.tag,
            "url": self.url,
            "body": self.body,
        }


@dataclass(frozen=True, slots=True)
class ImpactSite:
    """One consumer usage site examined during ``--impact`` analysis."""

    file: str
    line: int
    col: int
    symbol: str

    def as_dict(self) -> dict[str, object]:
        return {"file": self.file, "line": self.line, "col": self.col, "symbol": self.symbol}


@dataclass(frozen=True, slots=True)
class ImpactedSymbol:
    """A removed symbol the consumer provably calls, with its call sites."""

    name: str
    qualified_name: str
    sites: tuple[ImpactSite, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "sites": [site.as_dict() for site in self.sites],
        }


@dataclass(frozen=True, slots=True)
class ImpactReport:
    """Intersection of the before/after removed-symbol delta with actual
    consumer usage, reusing :mod:`leitir.check`'s usage-resolution machinery
    (ADR-0027 resolver + its best-effort symbol-candidate recovery).

    Mirrors ``check``'s three-way honesty model at the granularity that
    actually matters for "does this upgrade touch my code":

    - ``impacted`` -- a removed symbol with at least one statically
      recovered call site. Never a guess.
    - ``not_impacted`` -- a removed symbol with zero recovered call sites,
      reported *only* when at least one site was examined at all (see
      ``status``); otherwise reporting "not impacted" would falsely read as
      evidence of absence when no evidence was gathered.
    - ``unresolved_sites`` -- usage sites the resolver attributed to this
      package but whose accessed symbol name (or whose file) could not be
      statically pinned down. These can never be ruled out as touching a
      removed symbol, so they are always counted and surfaced, never folded
      into "not impacted" and never silently dropped.
    """

    against: str
    package_name: str
    removed_total: int
    status: str  # "no_sites_examined" | "impact_found" | "clean"
    sites_examined: int
    sites_impacted: int
    sites_unresolved: int
    sites_other: int
    impacted: tuple[ImpactedSymbol, ...]
    not_impacted: tuple[str, ...]
    unresolved_sites: tuple[ImpactSite, ...]

    def __post_init__(self) -> None:
        if self.sites_impacted != sum(len(symbol.sites) for symbol in self.impacted):
            raise ValueError("sites_impacted must equal the sum of impacted call sites")
        if self.sites_unresolved != len(self.unresolved_sites):
            raise ValueError("sites_unresolved count mismatch")
        if self.sites_examined != self.sites_impacted + self.sites_unresolved + self.sites_other:
            raise ValueError("sites_examined must equal impacted + unresolved + other")
        if self.status == "no_sites_examined" and self.not_impacted and self.removed_total:
            # Zero examined sites is loud: we may never claim a removed
            # symbol is safe ("not impacted") when no evidence was gathered
            # for it at all.
            raise ValueError("no_sites_examined must not carry a not_impacted claim")

    def as_dict(self) -> dict[str, object]:
        return {
            "against": self.against,
            "package_name": self.package_name,
            "status": self.status,
            "counts": {
                "removed_total": self.removed_total,
                "sites_examined": self.sites_examined,
                "sites_impacted": self.sites_impacted,
                "sites_unresolved": self.sites_unresolved,
                "sites_other": self.sites_other,
            },
            "impacted": [symbol.as_dict() for symbol in self.impacted],
            "not_impacted": list(self.not_impacted),
            "unresolved_sites": [site.as_dict() for site in self.unresolved_sites],
        }


@dataclass(frozen=True, slots=True)
class DiffReport:
    before: VersionIdentity
    after: VersionIdentity
    files: FileDiff
    api: ApiDiff
    release_notes: tuple[ReleaseNote, ...] = ()
    impact: ImpactReport | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "before": self.before.as_dict(),
            "after": self.after.as_dict(),
            "files": self.files.as_dict(),
            "api": self.api.as_dict(),
        }
        if self.release_notes:
            payload["release_notes"] = [note.as_dict() for note in self.release_notes]
        if self.impact is not None:
            payload["impact"] = self.impact.as_dict()
        return payload

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


def _regular_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            relative = path.relative_to(root).as_posix()
            if relative != MANIFEST_NAME:
                files[relative] = path
    return dict(sorted(files.items()))


def diff_file_trees(tree_a: str | os.PathLike[str], tree_b: str | os.PathLike[str]) -> FileDiff:
    """Compare regular files by relative path and exact bytes."""
    files_a = _regular_files(Path(tree_a))
    files_b = _regular_files(Path(tree_b))
    names_a = set(files_a)
    names_b = set(files_b)
    modified = tuple(
        name
        for name in sorted(names_a & names_b)
        if files_a[name].read_bytes() != files_b[name].read_bytes()
    )
    return FileDiff(
        added=tuple(sorted(names_b - names_a)),
        removed=tuple(sorted(names_a - names_b)),
        modified=modified,
    )


class GitHubReleaseNotes:
    def __init__(
        self,
        token: str | None = None,
        timeout: int = 30,
        *,
        base_url: str = "https://api.github.com",
        max_attempts: int = 4,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._token = token
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=1.0,
            max_delay=60.0,
            max_rate_limit_delay=300.0,
            sleeper=sleeper,
        )

    def fetch(self, repository: str, tag: str, version: str | None) -> ReleaseNote | None:
        from urllib.parse import quote, urlsplit
        from urllib.request import Request

        if self._token is not None:
            from leitir.credentials import validate_secret

            validate_secret(self._token, kind="token")

        endpoint = urlsplit(self._base_url)
        if endpoint.scheme != "https":
            return None
        url = f"{self._base_url}/repos/{repository}/releases/tags/{quote(tag, safe='')}"
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "leitir"}
        if self._token and endpoint.hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {self._token}"

        def request() -> object:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as response:
                return json.load(response)

        try:
            payload = self._retry(request)
            if not isinstance(payload, dict):
                return None
            body = payload.get("body")
            html_url = payload.get("html_url")
            if not isinstance(body, str) or not body.strip():
                return None
            if not isinstance(html_url, str) or not html_url.startswith("https://"):
                return None
            return ReleaseNote(version=version, tag=tag, url=html_url, body=body)
        except Exception:
            return None


class ReleaseNotesFetcher(Protocol):
    def fetch(
        self, repository: str, tag: str, version: str | None
    ) -> ReleaseNote | None: ...


@dataclass(frozen=True, slots=True)
class _PreparedSource:
    identity: VersionIdentity
    tree: Path
    api: dict[str, object]
    tag: str | None


def _matching_entry(root: Path, target: Path) -> dict[str, Any] | None:
    """Return the catalog entry for an already-materialized ``target``, if any.

    issue #268: deliberately non-strict. ``target`` was already materialized
    by this same ``diff`` invocation, so a corrupt catalog only means the
    optional catalog-recorded pin is unavailable; :func:`_shelf_pin` falls
    back to the scope that fed the materializer for the exact bytes diffed
    (see its docstring). ``diff`` never claims to summarize the whole
    corpus, only the two trees it actually read, so there is no false
    "complete corpus" claim for a corrupt catalog to falsify here.
    """
    from leitir.corpus import load_sources

    for entry in load_sources(root):
        if (root / str(entry["path"])).absolute() == target.absolute():
            return entry
    return None


def _manifest(target: Path) -> dict[str, object]:
    try:
        payload = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


_SHA1_HEX = re.compile(r"[0-9a-f]{40}")


def _usable_pin(value: object) -> str | None:
    """Return ``value`` only when it is an exact lowercase 40-hex commit SHA."""
    if isinstance(value, str) and _SHA1_HEX.fullmatch(value) is not None:
        return value
    return None


def _shelf_pin(
    entry: Mapping[str, Any] | None, manifest: Mapping[str, object], fallback: str
) -> str:
    """Return the commit SHA bound to the bytes materialized for this shelf.

    The corpus index entry and the shelf manifest are written by the same
    materializer call that produced the shelf bytes, so they record the pin
    the diffed tree was materialized at even when the spec re-resolved to a
    moved SHA afterwards. When the shelf carries no usable pin (embedding
    path, shelf without a readable manifest, malformed pin fields) the scope
    that fed the materializer in the same ``_prepare`` call is the honest
    identity for the bytes actually diffed; a non-conforming recorded value
    is never normalized or guessed into a pin.
    """
    if entry is not None:
        pinned = _usable_pin(entry.get("commit_sha"))
        if pinned is not None:
            return pinned
    pinned = _usable_pin(manifest.get("commit_sha"))
    if pinned is not None:
        return pinned
    return fallback


def _prepare(
    raw: str,
    *,
    root: Path,
    resolver: object,
    heads: object,
    cwd: Path,
    materializer: Callable[..., Path],
    fetch_options: Mapping[str, object],
    on_resolve: Callable[[str], None] | None,
    on_materialize: Callable[[str], None] | None,
) -> _PreparedSource:
    from leitir.corpus import read_api_index, write_api_index
    from leitir.resolver import ResolvedPackage, resolve_corpus_spec

    if on_resolve is not None:
        on_resolve(raw)
    parsed: CorpusSpec = parse_corpus_spec(raw)
    resolved, tag, version_source, _ = resolve_corpus_spec(
        parsed, cast(Any, resolver), cast(Any, heads), cwd
    )
    target = materializer(
        raw,
        resolved,
        root=root,
        name=parsed.name,
        tag=tag,
        version_source=version_source,
        host=(parsed.host or "github.com") if parsed.ecosystem is None else "github.com",
        repository_resolver=(
            getattr(resolver, "_repository_resolvers", {}).get(parsed.host)
            if parsed.ecosystem is None and parsed.host not in (None, "github.com")
            else None
        ),
        on_fetch=(lambda: on_materialize(raw)) if on_materialize is not None else None,
        **fetch_options,
    )
    manifest = _manifest(target)
    recorded_subpath = manifest.get("subpath")
    tree = target / recorded_subpath if isinstance(recorded_subpath, str) else target
    entry = _matching_entry(root, target)
    index = read_api_index(root, entry, manifest) if entry is not None and manifest else None
    if index is None:
        hint = manifest.get("ecosystem")
        index = extract_api_surface(tree, str(hint) if hint in {"pypi", "npm"} else None)
        if entry is not None and manifest:
            write_api_index(root, entry, manifest, index)
    if isinstance(resolved, ResolvedPackage):
        scope = resolved.scope
    else:
        scope = resolved
    resolved_version = getattr(getattr(resolved, "ref", None), "version", None)
    identity = VersionIdentity(
        spec=raw,
        name=parsed.name,
        version=resolved_version,
        repository=scope.slug,
        # Report the pin bound to the materialized bytes, not this call's
        # independent re-resolution (which may have moved mid-run).
        commit_sha=_shelf_pin(entry, manifest, scope.commit_sha),
    )
    return _PreparedSource(identity, tree, index, getattr(resolved, "tag", None) or tag)


def compute_impact(
    *,
    before: _PreparedSource,
    after: _PreparedSource,
    consumer_path: str | os.PathLike[str],
) -> ImpactReport:
    """Intersect the Python symbol removals between ``before`` and ``after``
    with actual usage in the consumer code at ``consumer_path``.

    Reuses ``leitir.check``'s usage-resolution machinery end to end: the same
    ADR-0027 ``resolve_consumer`` static resolver, the same best-effort
    top-level import-table symbol recovery, and the same fail-closed
    "unverifiable API index" gate (``CheckIndexError``). This module adds no
    new usage-resolution logic of its own -- see the module docstring premise
    check.

    The removed-symbol set used here is a *Python-only* extraction of
    ``before``/``after`` (via ``check.extract_check_index``), independent of
    the general multi-language ``diff`` symbol delta: the consumer this
    analyzes is always Python (ADR-0027's resolver is Python-only), so
    intersecting against a same-named symbol from a non-Python file in the
    same repository would be a false attribution.
    """

    from leitir.check import (
        _build_import_table,
        _candidate_for_reference,
        _find_name_node,
        _require_checkable_index,
        discover_python_files,
        extract_check_index,
        guess_import_root,
    )
    from leitir.safeio import read_regular_file
    from leitir.usage.contract import UnresolvedState
    from leitir.usage.resolver import (
        MAX_RESOLVER_FILE_BYTES,
        MAX_RESOLVER_FILES,
        resolve_consumer,
    )

    against = before.identity.spec
    package_name = before.identity.name

    before_index = extract_check_index(before.tree)
    _require_checkable_index(before_index, against=against)
    after_index = extract_check_index(after.tree)
    _require_checkable_index(after_index, against=after.identity.spec)

    removed_symbols = diff_api_indexes(before_index, after_index).removed
    removed_by_name: dict[str, dict[str, object]] = {}
    for symbol in removed_symbols:
        name = symbol.get("name")
        if isinstance(name, str) and name and name not in removed_by_name:
            removed_by_name[name] = symbol

    consumer_root, files = discover_python_files(Path(consumer_path))

    impacted_sites: dict[str, list[ImpactSite]] = {}
    unresolved_sites: list[ImpactSite] = []
    other_resolved = 0

    if removed_by_name:
        import ast

        import_root = guess_import_root(package_name)
        result = resolve_consumer(
            consumer_root=consumer_root,
            import_roots={import_root: against},
            files=files,
            max_files=MAX_RESOLVER_FILES,
            max_file_bytes=MAX_RESOLVER_FILE_BYTES,
        )

        tree_cache: dict[str, ast.Module | None] = {}
        table_cache: dict[str, Any] = {}

        def _tree_for(relpath: str) -> ast.Module | None:
            if relpath in tree_cache:
                return tree_cache[relpath]
            try:
                data = read_regular_file(
                    consumer_root / relpath,
                    maximum_bytes=MAX_RESOLVER_FILE_BYTES,
                    no_follow=False,
                )
                tree: ast.Module | None = ast.parse(data.decode("utf-8"), filename=relpath)
            except (OSError, ValueError, UnicodeDecodeError, SyntaxError):
                tree = None
            tree_cache[relpath] = tree
            return tree

        for reference in result.references:
            relpath = reference.span.file
            line = reference.span.start_line
            col = reference.span.start_col
            tree = _tree_for(relpath)
            if tree is None:
                unresolved_sites.append(ImpactSite(file=relpath, line=line, col=col, symbol="<file>"))
                continue
            table = table_cache.get(relpath)
            if table is None:
                table = _build_import_table(tree, frozenset({import_root}))
                table_cache[relpath] = table
            candidate = _candidate_for_reference(tree, table, reference)
            if candidate.symbol is None:
                unresolved_sites.append(ImpactSite(file=relpath, line=line, col=col, symbol="<module>"))
                continue
            symbol_name = candidate.symbol
            # An attribute access also depends on its imported owner. A
            # removed JSONEncoder breaks JSONEncoder.encode even though the
            # inherited `encode` method was never in the donor's API index.
            name_node = _find_name_node(tree, line=line, col=col)
            imported = table.symbol_aliases.get(name_node.id) if name_node else None
            imported_name = imported.rsplit(".", 1)[-1] if imported else None
            if imported_name is not None and imported_name in removed_by_name:
                symbol_name = imported_name
            elif candidate.qualified is not None:
                parts = candidate.qualified.split(".")
                for length in range(2, len(parts)):
                    ancestor = ".".join(parts[:length])
                    if any(
                        isinstance(qualified := item.get("qualified_name"), str)
                        and (qualified == ancestor or qualified.endswith("." + ancestor))
                        for item in removed_symbols
                    ):
                        symbol_name = parts[length - 1]
                        break
            if symbol_name in removed_by_name:
                impacted_sites.setdefault(symbol_name, []).append(
                    ImpactSite(file=relpath, line=line, col=col, symbol=symbol_name)
                )
            else:
                # A resolved usage of a symbol that was not removed is
                # neither impacted nor unresolved, but it was genuinely
                # examined -- counted in ``sites_other`` so ``sites_examined``
                # stays an honest total and a package with real, fully
                # resolved usage that simply avoids the removed symbols is
                # never mistaken for "nothing was examined".
                other_resolved += 1

        for record in result.coverage.records:
            if record.state is UnresolvedState.RESOLVED:
                continue
            unresolved_sites.append(
                ImpactSite(file=record.file, line=0, col=0, symbol="<file>")
            )
        for excluded in result.coverage.exclusions:
            unresolved_sites.append(
                ImpactSite(file=excluded, line=0, col=0, symbol="<file>")
            )

    impacted = tuple(
        ImpactedSymbol(
            name=name,
            qualified_name=str(removed_by_name[name].get("qualified_name") or name),
            sites=tuple(
                sorted(impacted_sites[name], key=lambda site: (site.file, site.line, site.col))
            ),
        )
        for name in sorted(impacted_sites)
    )
    sites_impacted = sum(len(symbol.sites) for symbol in impacted)
    unresolved_sites_sorted = tuple(
        sorted(unresolved_sites, key=lambda site: (site.file, site.line, site.col, site.symbol))
    )
    # Honest total: every call site the resolver could attribute to this
    # package, whether it named a removed symbol, a still-present symbol
    # (irrelevant to this delta but genuinely examined), or could not be
    # pinned down at all.
    sites_examined = sites_impacted + len(unresolved_sites_sorted) + other_resolved

    if not removed_by_name:
        status = "clean"
        not_impacted: tuple[str, ...] = ()
    elif sites_examined == 0:
        status = "no_sites_examined"
        not_impacted = ()
    else:
        not_impacted = tuple(sorted(name for name in removed_by_name if name not in impacted_sites))
        status = "impact_found" if impacted else "clean"

    return ImpactReport(
        against=against,
        package_name=package_name,
        removed_total=len(removed_by_name),
        status=status,
        sites_examined=sites_examined,
        sites_impacted=sites_impacted,
        sites_unresolved=len(unresolved_sites_sorted),
        sites_other=other_resolved,
        impacted=impacted,
        not_impacted=not_impacted,
        unresolved_sites=unresolved_sites_sorted,
    )


def diff_packages(
    spec_a: str,
    spec_b: str,
    *,
    corpus_root: str | os.PathLike[str],
    resolver: object,
    heads: object,
    cwd: str | os.PathLike[str] | None = None,
    materializer: Callable[..., Path] | None = None,
    release_notes: ReleaseNotesFetcher | None = None,
    fetch_options: Mapping[str, object] | None = None,
    on_resolve: Callable[[str], None] | None = None,
    on_materialize: Callable[[str], None] | None = None,
    impact_path: str | os.PathLike[str] | None = None,
) -> DiffReport:
    """Resolve, materialize, and compare two source specifications."""
    logger.debug("diff packages before=%s after=%s", spec_a, spec_b)
    if materializer is None:
        from leitir.corpus import materialize_source

        materializer = materialize_source
    root = Path(corpus_root).expanduser().absolute()
    directory = Path(cwd or Path.cwd()).expanduser().absolute()
    options = dict(fetch_options or {})
    before = _prepare(
        spec_a, root=root, resolver=resolver, heads=heads, cwd=directory,
        materializer=materializer, fetch_options=options, on_resolve=on_resolve,
        on_materialize=on_materialize,
    )
    after = _prepare(
        spec_b, root=root, resolver=resolver, heads=heads, cwd=directory,
        materializer=materializer, fetch_options=options, on_resolve=on_resolve,
        on_materialize=on_materialize,
    )
    notes: list[ReleaseNote] = []
    if release_notes is not None:
        for source in (before, after):
            if source.tag is not None:
                try:
                    note = release_notes.fetch(
                        source.identity.repository, source.tag, source.identity.version
                    )
                except Exception:
                    note = None
                if note is not None:
                    notes.append(note)
    impact = (
        compute_impact(before=before, after=after, consumer_path=impact_path)
        if impact_path is not None
        else None
    )
    return DiffReport(
        before=before.identity,
        after=after.identity,
        files=diff_file_trees(before.tree, after.tree),
        api=diff_api_indexes(before.api, after.api),
        release_notes=tuple(notes),
        impact=impact,
    )


__all__ = [
    "DiffReport",
    "FileDiff",
    "GitHubReleaseNotes",
    "ImpactReport",
    "ImpactSite",
    "ImpactedSymbol",
    "ReleaseNote",
    "ReleaseNotesFetcher",
    "VersionIdentity",
    "compute_impact",
    "diff_file_trees",
    "diff_packages",
]
