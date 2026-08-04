"""Corpus roots, the atomic source index, and source removal."""

from __future__ import annotations

from collections.abc import Callable
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from leitir.materialize import (
    materialize_repo,
    merge_parity_result,
    read_valid_manifest,
    target_path,
    update_manifest,
)
from leitir.resolver import ResolvedPackage
from leitir.search import RepoScope

INDEX_NAME = "sources.json"
_INDEX_FIELDS = {
    "name": str,
    "host": str,
    "owner": str,
    "repo": str,
    "commit_sha": str,
    "path": str,
    "fetched_at": str,
}


def resolve_root(root: str | os.PathLike[str] | None = None) -> Path:
    """Resolve explicit root, then ``LEITIR_HOME``, then ``~/.leitir``."""
    selected = root
    if selected is None:
        selected = os.environ.get("LEITIR_HOME") or "~/.leitir"
    return Path(selected).expanduser().absolute()


def load_sources(root: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    """Load the index, backing up corruption and treating it as empty."""
    corpus_root = resolve_root(root)
    index = corpus_root / INDEX_NAME
    try:
        payload = json.loads(index.read_text(encoding="utf-8"))
        valid_entries = isinstance(payload, list) and all(
            isinstance(item, dict)
            and all(
                isinstance(item.get(field), expected)
                for field, expected in _INDEX_FIELDS.items()
            )
            for item in payload
        )
        if not valid_entries:
            raise ValueError("sources index must be a list of objects")
        return payload
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        corpus_root.mkdir(parents=True, exist_ok=True)
        if index.exists():
            os.replace(index, corpus_root / f"{INDEX_NAME}.bak")
        return []


def write_sources(
    root: str | os.PathLike[str] | None, entries: list[dict[str, Any]]
) -> None:
    """Atomically replace the corpus source index."""
    corpus_root = resolve_root(root)
    corpus_root.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{INDEX_NAME}.tmp-", dir=corpus_root)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, corpus_root / INDEX_NAME)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _key(entry: dict[str, Any]) -> tuple[object, object, object, object]:
    return (entry.get("host"), entry.get("owner"), entry.get("repo"), entry.get("commit_sha"))


def _upsert(root: Path, entry: dict[str, Any]) -> None:
    entries = load_sources(root)
    wanted = _key(entry)
    result: list[dict[str, Any]] = []
    found = False
    for existing in entries:
        if _key(existing) == wanted:
            if not found:
                result.append(entry)
                found = True
        else:
            result.append(existing)
    if not found:
        result.append(entry)
    result.sort(key=lambda item: tuple(str(part) for part in _key(item)))
    write_sources(root, result)
    from leitir.docpointers import regenerate_pointers

    regenerate_pointers(root, result)


def materialize_source(
    spec: str,
    resolved: RepoScope | ResolvedPackage,
    *,
    root: str | os.PathLike[str] | None = None,
    name: str | None = None,
    tag: str | None = None,
    version_source: str | None = None,
    host: str = "github.com",
    repository_resolver: object | None = None,
    on_fetch: Callable[[], None] | None = None,
    parity_fetcher: object | None = None,
    **fetch_options: object,
) -> Path:
    """Ensure a resolved source is materialized and indexed exactly once."""
    corpus_root = resolve_root(root)
    manifest_fields: dict[str, object] = {
        "docs_urls": [],
        "parity": "unknown",
        "files_compared": 0,
        "only_in_git": 0,
        "only_in_artifact": 0,
    }
    if isinstance(resolved, ResolvedPackage):
        scope = resolved.scope
        source_name = name or resolved.ref.name
        source_tag = tag if tag is not None else resolved.tag
        manifest_fields.update(
            ecosystem=resolved.ref.ecosystem.value,
            version=resolved.ref.version,
            version_source=version_source or "explicit",
            registry_url=resolved.registry_url,
            docs_urls=list(resolved.docs_urls),
        )
        subpath = resolved.subpath
    elif isinstance(resolved, RepoScope):
        scope = resolved
        source_name = name or spec
        source_tag = tag
        subpath = None
    else:
        raise TypeError("resolved must be a RepoScope or ResolvedPackage")

    owner, repo = scope.slug.split("/", 1)
    target = materialize_repo(
        corpus_root,
        spec,
        scope,
        host=host,
        resolver=repository_resolver,
        tag=source_tag,
        subpath=subpath,
        manifest_fields=manifest_fields,
        on_fetch=on_fetch,
        **fetch_options,  # type: ignore[arg-type]
    )
    manifest = read_valid_manifest(
        target, owner, repo, scope.commit_sha, host=host
    )
    if manifest is None:
        raise RuntimeError("materializer returned a source without a valid manifest")
    if isinstance(resolved, ResolvedPackage) and resolved.ref.ecosystem.value in {
        "npm",
        "pypi",
        "crates",
    }:
        from leitir.parity import (
            UNKNOWN_PARITY,
            ArtifactInfo,
            RegistryArtifactFetcher,
            package_parity,
        )

        artifact = resolved.artifact if isinstance(resolved.artifact, ArtifactInfo) else None
        if manifest.get("parity") not in {"exact", "drift"}:
            parity = package_parity(
                resolved.ref.ecosystem.value,
                resolved.ref.name,
                resolved.ref.version,
                target / subpath if subpath else target,
                artifact=artifact,
                fetcher=(
                    parity_fetcher
                    if isinstance(parity_fetcher, RegistryArtifactFetcher)
                    else None
                ),
            ) if artifact is not None else UNKNOWN_PARITY
            manifest = merge_parity_result(target, parity)
    if "entry_points" not in manifest:
        from leitir.docpointers import discover_entry_points

        manifest = update_manifest(
            target,
            {
                "entry_points": discover_entry_points(
                    target,
                    manifest.get("subpath")
                    if isinstance(manifest.get("subpath"), str)
                    else None,
                )
            },
        )

    entry = {
        "name": source_name,
        "host": host,
        "owner": owner,
        "repo": repo,
        "commit_sha": scope.commit_sha,
        "path": target.relative_to(corpus_root).as_posix(),
        "fetched_at": manifest["fetched_at"],
        "verified": manifest.get("verified", False),
    }
    _upsert(corpus_root, entry)
    return target


def _prune_empty(path: Path, stop: Path) -> None:
    while path != stop and path.is_dir():
        try:
            path.rmdir()
        except OSError:
            break
        path = path.parent


def remove_source(
    root: str | os.PathLike[str] | None,
    owner: str,
    repo: str,
    commit_sha: str | None = None,
    *,
    host: str = "github.com",
) -> bool:
    """Remove one commit or a repository, update the index, and prune parents."""
    corpus_root = resolve_root(root)
    probe_sha = commit_sha or ("0" * 40)
    repo_path = target_path(
        corpus_root, owner, repo, probe_sha, host=host
    ).parent
    removal_path = repo_path / commit_sha if commit_sha else repo_path
    existed = removal_path.exists()
    if existed:
        shutil.rmtree(removal_path)

    entries = load_sources(corpus_root)
    kept = [
        entry
        for entry in entries
        if not (
            entry.get("host") == host
            and entry.get("owner") == owner
            and entry.get("repo") == repo
            and (commit_sha is None or entry.get("commit_sha") == commit_sha)
        )
    ]
    if kept != entries or (corpus_root / INDEX_NAME).exists():
        write_sources(corpus_root, kept)
    from leitir.docpointers import regenerate_pointers

    regenerate_pointers(corpus_root, kept)
    prune_from = repo_path if repo_path.exists() else repo_path.parent
    _prune_empty(prune_from, corpus_root)
    return existed or kept != entries
