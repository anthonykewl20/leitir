"""Corpus roots, the atomic source index, and source removal."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from leitir.materialize import (
    MANIFEST_NAME,
    ArtifactRetrievalError,
    MaterializationError,
    VerificationError,
    _assert_target_confinement,
    _file_lock,
    _fsync_directory,
    _target_lock,
    materialize_artifact,
    materialize_go_module_zip,
    materialize_repo,
    read_valid_manifest,
    target_path,
    update_manifest,
)
from leitir.resolver import ResolvedPackage
from leitir.safeio import atomic_text_writer
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
# Optional per-entry marker for registry-only (degraded) shelves: the
# commit_sha is a deterministic registry digest, not a git commit
# (ADR-0023; reviewer-qwen 2026-08-23).
_INDEX_OPTIONAL_FIELDS = {"degraded_provenance": str}


def resolve_root(root: str | os.PathLike[str] | None = None) -> Path:
    """Resolve explicit root, then ``LEITIR_HOME``, then ``~/.leitir``."""
    selected = root
    if selected is None:
        selected = os.environ.get("LEITIR_HOME") or "~/.leitir"
    return Path(selected).expanduser().absolute()


def load_sources(
    root: str | os.PathLike[str] | None = None, *, strict: bool = False
) -> list[dict[str, Any]]:
    """Load the index, backing up corruption and treating it as empty.

    A missing catalog (``FileNotFoundError``) is always a genuinely empty
    corpus -- nothing has ever been materialized -- and is reported as an
    empty list regardless of ``strict``.

    By default (``strict=False``, unchanged for every existing caller --
    list/export/sbom/snapshot/gc/etc.), a *corrupt or unreadable* catalog is
    silently recovered: the bad file is backed up to ``sources.json.bak``
    and an empty list is returned, exactly as before.

    ``strict=True`` is for callers where "the declared universe could not be
    established" must never be indistinguishable from "the declared universe
    is empty" (issue #266 P1: corpus-wide search fail-closed). In that mode
    a corrupt or unreadable catalog raises ``VerificationError`` instead of
    being silently swallowed -- the ``.bak`` rename is no longer the only
    record that something went wrong.
    """
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
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        if strict:
            raise VerificationError(
                f"corpus catalog is corrupt or unreadable, the declared universe "
                f"cannot be established: {index}"
            ) from exc
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
    with atomic_text_writer(corpus_root / INDEX_NAME, encoding="utf-8", newline=None) as handle:
        json.dump(entries, handle, indent=2, sort_keys=True)
        handle.write("\n")


def enumerate_shelved_sources(
    root: str | os.PathLike[str] | None = None,
) -> list[tuple[dict[str, Any], dict[str, object], Path]]:
    """Return indexed sources with their validated manifests and paths."""
    corpus_root = resolve_root(root)
    result: list[tuple[dict[str, Any], dict[str, object], Path]] = []
    for entry in load_sources(corpus_root):
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid shelved source path: {entry['path']!r}")
        target = corpus_root / relative
        _assert_target_confinement(corpus_root, target)
        manifest = read_valid_manifest(
            target,
            entry["owner"],
            entry["repo"],
            entry["commit_sha"],
            host=entry["host"],
        )
        if manifest is None:
            raise ValueError(
                "source has no valid manifest (run 'leitir upgrade-cache' to "
                f"migrate legacy shelves): {entry['path']}"
            )
        result.append((dict(entry), manifest, target))
    result.sort(key=lambda item: tuple(str(part) for part in _key(item[0])))
    return result


def find_materialized_sources(
    spec: str, root: str | os.PathLike[str] | None = None
) -> list[tuple[dict[str, Any], dict[str, object], Path]]:
    """Return all shelved sources matching a parsed, resolved identity."""
    from leitir.spec import parse_corpus_spec

    parsed = parse_corpus_spec(spec)
    is_bare_name = (
        parsed.ecosystem == "npm"
        and parsed.version is None
        and parsed.host is None
        and parsed.name == spec
    )

    def matches_identity(item: tuple[dict[str, Any], dict[str, object], Path]) -> bool:
        entry, manifest, _target = item
        if is_bare_name:
            return entry.get("name") == parsed.name
        if parsed.ecosystem is not None:
            ecosystem = manifest.get("ecosystem") or (
                entry.get("host")
                if entry.get("host") in {"npm", "pypi", "crates", "go"}
                else None
            )
            if ecosystem != parsed.ecosystem or entry.get("name") != parsed.name:
                return False
            return parsed.version is None or parsed.version in {
                manifest.get("version"),
                manifest.get("tag"),
                manifest.get("commit_sha"),
            }

        slug = f"{entry.get('owner')}/{entry.get('repo')}"
        if entry.get("host") != parsed.host or slug != parsed.name:
            return False
        if parsed.ref is None:
            return True
        if parsed.ref_kind == "sha":
            return entry.get("commit_sha") == parsed.ref
        return parsed.ref in {
            manifest.get("tag"),
            manifest.get("branch"),
            manifest.get("commit_sha"),
        }

    return [item for item in enumerate_shelved_sources(root) if matches_identity(item)]


def record_trust(
    spec: str, root: str | os.PathLike[str] | None = None
) -> tuple[dict[str, Any], object, Path]:
    """Compute and persist trust for one uniquely matching shelved source."""
    from leitir.trust import compute_trust

    matches = find_materialized_sources(spec, root)
    if not matches:
        raise ValueError(f"source is not materialized: {spec}")
    if len(matches) != 1:
        raise ValueError(f"source spec is ambiguous: {spec}")
    entry, _manifest, target = matches[0]
    corpus_root = resolve_root(root)
    with _target_lock(corpus_root, target, str(entry["commit_sha"])):
        manifest = read_valid_manifest(
            target,
            str(entry["owner"]),
            str(entry["repo"]),
            str(entry["commit_sha"]),
            host=str(entry["host"]),
        )
        if manifest is None:
            raise ValueError(f"source changed during trust verification: {spec}")
        from leitir.sbom import license_manifest_fields

        license_fields = license_manifest_fields(manifest, target)
        manifest.update(license_fields)
        result = compute_trust(manifest, target)
        update_manifest(target, {**license_fields, **result.as_dict()})
    return entry, result, target


def api_index_path(
    root: str | os.PathLike[str] | None,
    entry: dict[str, Any],
    manifest: dict[str, object],
) -> Path:
    """Return the deterministic API cache path for one source identity."""
    registry = str(manifest.get("ecosystem") or entry["host"])
    name = str(entry["name"])
    version = str(manifest.get("version") or entry["commit_sha"])
    for label, value, allow_parts in (
        ("registry", registry, False),
        ("name", name, True),
        ("version", version, False),
    ):
        candidate = Path(value)
        if (
            not value
            or candidate.is_absolute()
            or ".." in candidate.parts
            or (not allow_parts and len(candidate.parts) != 1)
        ):
            raise ValueError(f"invalid API cache {label}: {value!r}")
    return resolve_root(root) / "api" / registry / name / version / "index.json"


def write_api_index(
    root: str | os.PathLike[str] | None,
    entry: dict[str, Any],
    manifest: dict[str, object],
    index: dict[str, object],
) -> Path:
    """Atomically cache an API index and return its absolute path."""
    path = api_index_path(root, entry, manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    with atomic_text_writer(path, encoding="utf-8", newline="\n") as handle:
        json.dump(index, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path.absolute()


def read_api_index(
    root: str | os.PathLike[str] | None,
    entry: dict[str, Any],
    manifest: dict[str, object],
) -> dict[str, object] | None:
    """Read a valid cached API index, or return ``None``."""
    try:
        payload = json.loads(
            api_index_path(root, entry, manifest).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def examples_index_path(
    root: str | os.PathLike[str] | None,
    entry: dict[str, Any],
    manifest: dict[str, object],
) -> Path:
    """Return the deterministic examples cache path for one source identity."""
    registry = str(manifest.get("ecosystem") or entry["host"])
    name = str(entry["name"])
    version = str(manifest.get("version") or entry["commit_sha"])
    for label, value, allow_parts in (
        ("registry", registry, False),
        ("name", name, True),
        ("version", version, False),
    ):
        candidate = Path(value)
        if (
            not value
            or candidate.is_absolute()
            or ".." in candidate.parts
            or (not allow_parts and len(candidate.parts) != 1)
        ):
            raise ValueError(f"invalid examples cache {label}: {value!r}")
    return resolve_root(root) / "examples" / registry / name / version / "index.json"


def write_examples_index(
    root: str | os.PathLike[str] | None,
    entry: dict[str, Any],
    manifest: dict[str, object],
    index: dict[str, object],
) -> Path:
    """Atomically cache an examples index and return its absolute path."""
    path = examples_index_path(root, entry, manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    with atomic_text_writer(path, encoding="utf-8", newline="\n") as handle:
        json.dump(index, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path.absolute()


def read_examples_index(
    root: str | os.PathLike[str] | None,
    entry: dict[str, Any],
    manifest: dict[str, object],
) -> dict[str, object] | None:
    """Read a valid cached examples index, or return ``None``."""
    try:
        payload = json.loads(
            examples_index_path(root, entry, manifest).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def shelve_imported_sources(
    staging: Path,
    root: str | os.PathLike[str] | None,
    entries: list[dict[str, Any]],
    *,
    pointers_name: str,
) -> None:
    """Install a fully verified staged snapshot into an empty corpus."""
    corpus_root = resolve_root(root)
    parent = corpus_root.parent
    parent.mkdir(parents=True, exist_ok=True)
    lock_path = parent / f".{corpus_root.name}.snapshot-import.lock"
    with _file_lock(lock_path):
        if corpus_root.is_symlink() or (
            corpus_root.exists() and not corpus_root.is_dir()
        ):
            raise FileExistsError(
                f"destination corpus is not an ordinary directory: {corpus_root}"
            )
        if corpus_root.exists() and any(corpus_root.iterdir()):
            raise FileExistsError(f"destination corpus is not empty: {corpus_root}")
        prefix = f".{corpus_root.name}.snapshot-import-"
        for abandoned in sorted(parent.glob(f"{prefix}*")):
            if abandoned.is_dir() and not abandoned.is_symlink():
                shutil.rmtree(abandoned, ignore_errors=True)
            else:
                abandoned.unlink(missing_ok=True)
        install = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
        try:
            for entry in sorted(entries, key=lambda item: str(item["path"])):
                relative = Path(entry["path"])
                source = staging / relative
                destination = install / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(source, destination, symlinks=True)
            source_pointers = staging / pointers_name
            if not source_pointers.is_file() or source_pointers.is_symlink():
                raise ValueError(f"snapshot is missing {pointers_name}")
            shutil.copyfile(source_pointers, install / pointers_name)
            write_sources(install, entries)
            if os.name != "nt":
                for path in sorted(
                    install.rglob("*"), key=lambda item: item.as_posix()
                ):
                    if path.is_file() and not path.is_symlink():
                        fd = os.open(path, os.O_RDONLY)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                directories = [
                    install,
                    *(path for path in install.rglob("*") if path.is_dir()),
                ]
                for directory in sorted(
                    directories, key=lambda item: len(item.parts), reverse=True
                ):
                    _fsync_directory(directory)
            if corpus_root.is_symlink() or (
                corpus_root.exists() and not corpus_root.is_dir()
            ):
                raise FileExistsError(
                    f"destination corpus is not an ordinary directory: {corpus_root}"
                )
            if corpus_root.exists() and any(corpus_root.iterdir()):
                raise FileExistsError(f"destination corpus is not empty: {corpus_root}")
            os.replace(install, corpus_root)
            _fsync_directory(parent)
        except Exception:
            shutil.rmtree(install, ignore_errors=True)
            raise


def _key(entry: dict[str, Any]) -> tuple[object, object, object, object]:
    return (
        entry.get("host"),
        entry.get("owner"),
        entry.get("repo"),
        entry.get("commit_sha"),
    )


def _upsert(root: Path, entry: dict[str, Any]) -> None:
    with _file_lock(root / ".sources.lock"):
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
    published_at: str | None = None,
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
    source_tag: str | None
    if isinstance(resolved, ResolvedPackage):
        scope = resolved.scope
        host = resolved.host
        # Audit 2026-08-23 P1(b): a registry-only (degraded) resolution has no
        # git commit to bind a hosted-repository shelf to; only the artifact
        # channel (which materializes straight from the checksum-verified
        # registry artifact) may proceed, and it records the degraded
        # provenance in the manifest.
        artifact_only = resolved.degraded_provenance is not None
        if repository_resolver is None and host in {"gitlab.com", "bitbucket.org"}:
            from leitir.resolver import BitbucketResolver, GitLabResolver

            repository_resolver = (
                GitLabResolver() if host == "gitlab.com" else BitbucketResolver()
            )
        source_name = name or resolved.ref.name
        source_tag = tag if tag is not None else resolved.tag
        manifest_fields.update(
            ecosystem=resolved.ref.ecosystem.value,
            version=resolved.ref.version,
            version_source=version_source or "explicit",
            registry_url=resolved.registry_url,
            docs_urls=list(resolved.docs_urls),
        )
        if resolved.published_at is not None:
            manifest_fields["published_at"] = resolved.published_at
        subpath = resolved.subpath
    elif isinstance(resolved, RepoScope):
        scope = resolved
        source_name = name or spec
        source_tag = tag
        subpath = None
    else:
        raise TypeError("resolved must be a RepoScope or ResolvedPackage")
    if published_at is not None:
        manifest_fields["published_at"] = published_at

    owner, repo = scope.slug.split("/", 1)
    artifact = None
    if isinstance(resolved, ResolvedPackage):
        from leitir.parity import ArtifactInfo

        artifact = (
            resolved.artifact if isinstance(resolved.artifact, ArtifactInfo) else None
        )
        if artifact_only and artifact is None:
            # Degraded resolution requires a checksum-verified artifact; the
            # resolvers guarantee one, so reaching here means an inconsistency
            # between the resolver contract and this orchestration.
            raise MaterializationError(
                f"registry-only resolution of {spec} has no checksum-verified artifact"
            )
        if artifact_only:
            manifest_fields["degraded_provenance"] = resolved.degraded_provenance
    if isinstance(resolved, ResolvedPackage) and resolved.go_module_zip:
        if resolved.go_proxy_url is None:
            raise RuntimeError("Go module zip resolution has no proxy URL")
        requested_sumdb_url = fetch_options.get("sumdb_url", "https://sum.golang.org")
        requested_timeout = fetch_options.get("timeout", 30)
        if not isinstance(requested_sumdb_url, str) or not isinstance(requested_timeout, int):
            raise TypeError("Go module zip fetch options have invalid types")
        target = materialize_go_module_zip(
            corpus_root,
            spec,
            scope,
            resolved.ref.name,
            resolved.ref.version,
            resolved.go_proxy_url,
            sumdb_url=requested_sumdb_url,
            timeout=requested_timeout,
            manifest_fields=manifest_fields,
            on_fetch=on_fetch,
        )
    elif artifact is not None:
        try:
            target = materialize_artifact(
                corpus_root,
                spec,
                scope,
                artifact,
                tag=source_tag,
                subpath=None,
                manifest_fields=manifest_fields,
                fetcher=parity_fetcher,
                on_fetch=on_fetch,
            )
        except ArtifactRetrievalError:
            if artifact_only:
                # No hosted-repository fallback exists for a degraded
                # resolution: its scope is not a git commit, so the repo
                # channel cannot be bound (audit 2026-08-23 P1(b)).
                raise
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
                **fetch_options,
            )
    else:
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
            **fetch_options,
        )
    # Reacquire the writer lock before reading or updating the published
    # generation. A writer that won the release/reacquire race is therefore
    # observed and updated rather than swallowing these metadata writes.
    with _target_lock(corpus_root, target, scope.commit_sha):
        manifest_owner = (
            f"~{owner}" if host == "git.sr.ht" and not owner.startswith("~") else owner
        )
        manifest = read_valid_manifest(
            target, manifest_owner, repo, scope.commit_sha, host=host
        )
        if manifest is None:
            raise RuntimeError(
                "materializer returned a source without a valid manifest"
            )
        owner = str(manifest["owner"])
        repo = str(manifest["repo"])
        if isinstance(resolved, ResolvedPackage) and resolved.ref.ecosystem.value in {
            "npm",
            "pypi",
            "crates",
        }:
            from leitir.materialize import has_top_level_tests
            from leitir.parity import (
                UNKNOWN_PARITY,
                RegistryArtifactFetcher,
                compare_trees,
                package_parity,
            )

            if manifest.get("parity") not in {"exact", "drift"}:
                has_tests: bool | None = None
                if artifact_only:
                    # The hosted-repository parity comparison is unavailable
                    # for a degraded scope: there is no git commit to
                    # materialize. The artifact checksum was already verified
                    # during materialization, so record the parity verdict as
                    # unknown with the degraded provenance retained above.
                    parity = UNKNOWN_PARITY
                elif manifest.get("source") == "registry-artifact":
                    temporary_root = Path(tempfile.mkdtemp(prefix="leitir-git-parity-"))
                    try:
                        git_target = materialize_repo(
                            temporary_root,
                            spec,
                            scope,
                            host=host,
                            resolver=repository_resolver,
                            tag=source_tag,
                            subpath=subpath,
                            verify=fetch_options.get("verify", True),
                            **{
                                key: value
                                for key, value in fetch_options.items()
                                if key != "verify"
                            },
                        )
                        git_tree = git_target / subpath if subpath else git_target
                        has_tests = has_top_level_tests(git_target, subpath)
                        parity = compare_trees(git_tree, target)
                    except Exception:
                        parity = UNKNOWN_PARITY
                    finally:
                        shutil.rmtree(temporary_root, ignore_errors=True)
                else:
                    parity = (
                        package_parity(
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
                        )
                        if artifact is not None
                        else UNKNOWN_PARITY
                    )
                fields = parity.manifest_fields()
                if manifest.get("source") == "registry-artifact":
                    fields["has_tests"] = (
                        has_tests
                        if has_tests is not None
                        else manifest.get("has_tests")
                    )
                manifest = update_manifest(target, fields)
        if "entry_points" not in manifest:
            from leitir.docpointers import discover_entry_points

            manifest_subpath = manifest.get("subpath")
            manifest = update_manifest(
                target,
                {
                    "entry_points": discover_entry_points(
                        target,
                        manifest_subpath
                        if isinstance(manifest_subpath, str)
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
        # Propagate the degraded marker into the corpus index so
        # consumers (list/sbom/export) never present the fabricated
        # 40-hex registry digest as an ordinary commit pin
        # (reviewer-qwen 2026-08-23).
        degraded_reason = manifest.get("degraded_provenance")
        if isinstance(degraded_reason, str) and degraded_reason:
            entry["degraded_provenance"] = degraded_reason
    # Pointer regeneration may lock every indexed target. Do it only after
    # releasing this target's writer lock to preserve the global lock order.
    _upsert(corpus_root, entry)
    return target


def lock_project(
    directory: str | os.PathLike[str],
    resolver: object,
    *,
    root: str | os.PathLike[str] | None = None,
    on_resolve: Callable[[str], None] | None = None,
    on_fetch: Callable[[str], None] | None = None,
    on_failure: Callable[[str, str], None] | None = None,
    best_effort: bool = False,
    failures: list[dict[str, str]] | None = None,
    materializer: Callable[..., Path] = materialize_source,
    **fetch_options: object,
) -> list[dict[str, object]]:
    """Resolve and materialize every dependency represented by project lockfiles."""
    from leitir.lockfiles import dependency_closures
    from leitir.resolver import Ecosystem, PackageRef

    corpus_root = resolve_root(root)
    results: list[dict[str, object]] = []
    for closure in dependency_closures(Path(directory)):
        deps = [edge.as_dict() for edge in closure.deps]
        for edge in closure.deps:
            try:
                if on_resolve is not None:
                    on_resolve(edge.spec)
                resolved = cast(Any, resolver).resolve(
                    PackageRef(Ecosystem(closure.ecosystem), edge.name, edge.version)
                )
                target = materializer(
                    edge.spec,
                    resolved,
                    root=corpus_root,
                    name=edge.name,
                    version_source="lockfile",
                    on_fetch=(
                        (lambda spec=edge.spec: on_fetch(spec))
                        if on_fetch is not None
                        else None
                    ),
                    **fetch_options,
                )
                scope = resolved.scope if hasattr(resolved, "scope") else resolved
                with _target_lock(corpus_root, target, scope.commit_sha):
                    # Enforce the producer contract for injected materializers
                    # as well as the built-in one before any manifest update.
                    manifest_path = target / MANIFEST_NAME
                    produced = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if not isinstance(produced, dict):
                        raise ValueError("source manifest must be an object")
                    if produced.get("materialized_tree_hash") is None:
                        from leitir.materialize import _write_manifest
                        from leitir.treehash import (
                            compute_materialized_tree_hash,
                            manifest_digest_fields,
                        )

                        digest, digest_scope = compute_materialized_tree_hash(target)
                        produced.update(
                            manifest_digest_fields(digest, scope=digest_scope)
                        )
                        _write_manifest(manifest_path, produced)
                    update_manifest(target, {"graph": closure.graph, "deps": deps})
                results.append(
                    {
                        "spec": edge.spec,
                        "path": str(target.absolute()),
                        "graph": closure.graph,
                    }
                )
            except Exception as exc:
                if not best_effort:
                    raise
                failure = {"spec": edge.spec, "error": str(exc)}
                if failures is not None:
                    failures.append(failure)
                if on_failure is not None:
                    on_failure(edge.spec, str(exc))
    if failures is not None:
        failures.sort(key=lambda item: (item["spec"], item["error"]))
    return results


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
    if host == "go-module-zip":
        repo_path = corpus_root / "repos" / host / owner
        removal_path = repo_path / repo
    else:
        probe_sha = commit_sha or ("0" * 40)
        repo_path = target_path(corpus_root, owner, repo, probe_sha, host=host).parent
        removal_path = repo_path / commit_sha if commit_sha else repo_path
    if host == "gitlab.com":
        parts = f"{owner}/{repo}".split("/")
        owner, repo = "/".join(parts[:-1]), parts[-1]
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
