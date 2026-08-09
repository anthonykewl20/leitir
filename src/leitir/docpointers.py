"""Documentation metadata, practice entry points, and corpus pointers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlsplit

POINTERS_NAME = "POINTERS.md"
PRIMARY_REFERENCE = "The source itself is the primary reference."
_README_NAMES = {"readme", "readme.md", "readme.rst", "readme.txt"}
_PRACTICE_DIRS = {"docs", "example", "examples", "test", "tests"}
_PYPI_LABELS = ("documentation", "docs", "wiki", "website", "homepage", "home")


def _http_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return candidate


def extract_docs_urls(
    ecosystem: object,
    metadata: Mapping[str, Any] | None = None,
    *,
    name: str | None = None,
    version: str | None = None,
) -> list[str]:
    """Extract the preferred official docs URL from already-fetched metadata."""
    kind = getattr(ecosystem, "value", ecosystem)
    payload: Mapping[str, Any] = metadata or {}

    if kind == "go":
        if name and version:
            return [f"https://pkg.go.dev/{name}@{version}"]
        return []

    candidates: list[object] = []
    if kind == "pypi":
        info = payload.get("info")
        info = info if isinstance(info, Mapping) else {}
        project_urls = info.get("project_urls")
        project_urls = project_urls if isinstance(project_urls, Mapping) else {}
        by_label = {
            str(label).casefold(): value for label, value in project_urls.items()
        }
        candidates.extend(by_label.get(label) for label in _PYPI_LABELS)
        candidates.append(info.get("home_page"))
    elif kind == "crates":
        crate = payload.get("version")
        crate = crate if isinstance(crate, Mapping) else {}
        candidates.extend((crate.get("documentation"), crate.get("homepage")))
    elif kind == "npm":
        version_data: Mapping[str, Any] = {}
        versions = payload.get("versions")
        if version and isinstance(versions, Mapping):
            selected = versions.get(version)
            if isinstance(selected, Mapping):
                version_data = selected
        candidates.extend((version_data.get("homepage"), payload.get("homepage")))
    else:
        return []

    for candidate in candidates:
        url = _http_url(candidate)
        if url is not None:
            return [url]
    return []


def discover_entry_points(
    source: str | os.PathLike[str], subpath: str | None = None
) -> list[str]:
    """Find conventional entry points near the repository and package roots."""
    root = Path(source)
    if not root.is_dir():
        return []

    found: set[str] = set()

    def inspect(parent: Path) -> None:
        try:
            children = list(parent.iterdir())
        except OSError:
            return
        for child in children:
            relative = child.relative_to(root).as_posix()
            folded = child.name.casefold()
            if child.is_file() and folded in _README_NAMES:
                found.add(relative)
            elif child.is_dir() and folded in _PRACTICE_DIRS:
                found.add(relative + "/")

    scan_roots = [root]
    if subpath:
        package_root = root / subpath
        if package_root.is_dir() and package_root != root:
            scan_roots.append(package_root)
    for scan_root in scan_roots:
        inspect(scan_root)
        try:
            first_level = [
                path
                for path in scan_root.iterdir()
                if path.is_dir() and not path.is_symlink()
            ]
        except OSError:
            first_level = []
        for directory in first_level:
            inspect(directory)
    return sorted(found, key=lambda item: (item.casefold(), item))


def _source_sort_key(entry: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(entry.get(field, ""))
        for field in ("name", "host", "owner", "repo", "commit_sha", "path")
    )


def _render_source(root: Path, entry: Mapping[str, Any]) -> list[str]:
    from leitir.corpus import api_index_path, examples_index_path
    from leitir.materialize import MANIFEST_NAME, _target_lock, update_manifest

    relative = str(entry.get("path", ""))
    target = root / relative
    manifest: Mapping[str, Any] = {}
    commit_sha = entry.get("commit_sha")
    if isinstance(commit_sha, str):
        with _target_lock(root, target, commit_sha):
            try:
                loaded = json.loads(
                    (target / MANIFEST_NAME).read_text(encoding="utf-8")
                )
                if isinstance(loaded, Mapping):
                    manifest = loaded
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
            if manifest and "entry_points" not in manifest:
                subpath = manifest.get("subpath")
                manifest = update_manifest(
                    target,
                    {
                        "entry_points": discover_entry_points(
                            target, subpath if isinstance(subpath, str) else None
                        )
                    },
                )

    name = str(entry.get("name", ""))
    lines = [f"## {name}", ""]
    version = manifest.get("version")
    if version is not None:
        lines.append(f"- Version: `{version}`")
    lines.extend(
        (
            f"- Commit SHA: `{entry.get('commit_sha', '')}`",
            f"- Local path: `{relative}`",
        )
    )
    docs = manifest.get("docs_urls")
    valid_docs = [url for url in docs if _http_url(url)] if isinstance(docs, list) else []
    if valid_docs:
        lines.append("- Documentation:")
        lines.extend(f"  - {url}" for url in valid_docs)
    else:
        lines.append(f"- Documentation: {PRIMARY_REFERENCE}")
    points = manifest.get("entry_points")
    valid_points = [point for point in points if isinstance(point, str)] if isinstance(points, list) else []
    if valid_points:
        lines.append("- Practice entry points:")
        lines.extend(f"  - `{point}`" for point in valid_points)
    else:
        lines.append("- Practice entry points: none found")
    if manifest:
        cache_entry = dict(entry)
        cache_manifest = dict(manifest)
        indexes = []
        try:
            api_path = api_index_path(root, cache_entry, cache_manifest)
            examples_path = examples_index_path(root, cache_entry, cache_manifest)
            if api_path.is_file():
                indexes.append(("API index", api_path.relative_to(root).as_posix()))
            if examples_path.is_file():
                indexes.append(("Examples index", examples_path.relative_to(root).as_posix()))
        except (KeyError, OSError, ValueError):
            indexes = []
        if indexes:
            lines.append("- API surface:")
            lines.extend(
                f"  - {label}: [`{path}`]({path})" for label, path in indexes
            )
    lines.append("")
    return lines


def regenerate_pointers(
    root: str | os.PathLike[str],
    entries: Sequence[Mapping[str, Any]] | None = None,
) -> Path:
    """Atomically regenerate ``POINTERS.md`` from the corpus index and manifests."""
    corpus_root = Path(root)
    corpus_root.mkdir(parents=True, exist_ok=True)
    if entries is None:
        from leitir.corpus import load_sources

        entries = load_sources(corpus_root)
    lines = [
        "# Leitir Corpus Pointers",
        "",
        "Agents read this file first to find official documentation and local practice entry points for each materialized source.",
        "",
    ]
    for entry in sorted(entries, key=_source_sort_key):
        lines.extend(_render_source(corpus_root, entry))
    content = "\n".join(lines)

    fd, temporary_name = tempfile.mkstemp(prefix=f".{POINTERS_NAME}.tmp-", dir=corpus_root)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, corpus_root / POINTERS_NAME)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return corpus_root / POINTERS_NAME


__all__ = [
    "POINTERS_NAME",
    "PRIMARY_REFERENCE",
    "discover_entry_points",
    "extract_docs_urls",
    "regenerate_pointers",
]
