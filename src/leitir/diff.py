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
class DiffReport:
    before: VersionIdentity
    after: VersionIdentity
    files: FileDiff
    api: ApiDiff
    release_notes: tuple[ReleaseNote, ...] = ()

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
    return DiffReport(
        before=before.identity,
        after=after.identity,
        files=diff_file_trees(before.tree, after.tree),
        api=diff_api_indexes(before.api, after.api),
        release_notes=tuple(notes),
    )


__all__ = [
    "DiffReport",
    "FileDiff",
    "GitHubReleaseNotes",
    "ReleaseNote",
    "ReleaseNotesFetcher",
    "VersionIdentity",
    "diff_file_trees",
    "diff_packages",
]
