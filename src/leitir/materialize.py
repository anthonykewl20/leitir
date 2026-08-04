"""Safely materialize and verify an immutable hosted source tree.

Verification hashes every extracted regular file when both the file count and
aggregate byte size are within :data:`VERIFY_MAX_FILES` and
:data:`VERIFY_MAX_BYTES`.  Above either cap, files are ordered by SHA-256 of
``<commit SHA>\0<path>``; in that order, files are selected greedily while both
caps permit (at least one file when the tree is non-empty). Sampled trees are
recorded distinctly so partial verification is never represented as complete.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping

from leitir import _http
from leitir.search import RepoScope

_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_CODELOAD = "https://codeload.github.com"
_HOST_METADATA = {
    "github.com": ("codeload-tarball", "https://github.com"),
    "gitlab.com": ("gitlab-archive", "https://gitlab.com"),
    "bitbucket.org": ("bitbucket-archive", "https://bitbucket.org"),
}
MANIFEST_NAME = "leitir-manifest.json"
VERIFY_MAX_FILES = 1_000
VERIFY_MAX_BYTES = 64 * 1024 * 1024


class MaterializationError(Exception):
    """A pinned source tree could not be downloaded or safely extracted."""


class UnsafeArchiveError(Exception):
    """A tar archive contains a member that is unsafe to materialize."""


class VerificationError(Exception):
    """An extracted tree does not match its pinned Git tree listing."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _failure_detail(exc: BaseException) -> str:
    current: BaseException | None = exc
    while current is not None:
        detail = _http.describe_failure(current)
        if detail.startswith("HTTP "):
            if current is exc:
                return detail
            return f"{type(exc).__name__}: {detail}"
        current = current.__cause__
    return _http.describe_failure(exc)


def _write_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    """Write a manifest atomically, including upgrades of cached manifests."""
    fd, name = tempfile.mkstemp(prefix=f".{MANIFEST_NAME}.tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def update_manifest(target: str | os.PathLike[str], fields: Mapping[str, object]) -> dict[str, object]:
    """Atomically merge derived fields into an existing valid manifest."""
    path = Path(target) / MANIFEST_NAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("source manifest must be an object")
    payload.update(fields)
    _write_manifest(path, payload)
    return payload


def _validate_identity(owner: str, repo: str, commit_sha: str) -> None:
    if not _NAME.fullmatch(owner):
        raise ValueError("owner must be a repository owner")
    if not _NAME.fullmatch(repo):
        raise ValueError("repo must be a repository name")
    if not _SHA1.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a 40-char lowercase hex SHA")


def target_path(
    root: str | os.PathLike[str],
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str = "github.com",
) -> Path:
    """Return the canonical target path for one pinned hosted repository."""
    _validate_identity(owner, repo, commit_sha)
    if host not in _HOST_METADATA:
        raise ValueError(f"unsupported repository host {host!r}")
    return Path(root) / "repos" / host / owner / repo / commit_sha


def read_valid_manifest(
    target: str | os.PathLike[str],
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str = "github.com",
) -> dict[str, object] | None:
    """Read a manifest only when it identifies exactly the requested source."""
    metadata = _HOST_METADATA.get(host)
    if metadata is None:
        return None
    fetch_method, canonical_base = metadata
    try:
        payload = json.loads((Path(target) / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    expected = {
        "host": host,
        "owner": owner,
        "repo": repo,
        "commit_sha": commit_sha,
        "fetch_method": fetch_method,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        return None
    if not isinstance(payload.get("spec"), str) or not payload["spec"]:
        return None
    if payload.get("repo_url") != f"{canonical_base}/{owner}/{repo}":
        return None
    if not isinstance(payload.get("fetched_at"), str) or not payload["fetched_at"]:
        return None
    if payload.get("tag") is not None and not isinstance(payload.get("tag"), str):
        return None
    verified = payload.get("verified")
    if "verified" in payload and not (
        verified is True or verified is False or verified == "sampled"
    ):
        return None
    if verified in (True, "sampled") and (
        not isinstance(payload.get("verified_at"), str) or not payload["verified_at"]
    ):
        return None
    if verified is False and payload.get("verified_at") is not None:
        return None
    return payload


def _archive_path(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise UnsafeArchiveError("invalid archive member path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise UnsafeArchiveError("archive member escapes its target")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        raise UnsafeArchiveError("invalid archive member path")
    return PurePosixPath(*parts)


def _stripped_member_path(member: tarfile.TarInfo, expected_root: str) -> PurePosixPath | None:
    path = _archive_path(member.name)
    if path.parts[0] != expected_root:
        raise UnsafeArchiveError("archive does not have the expected single top-level directory")
    if len(path.parts) == 1:
        return None
    return PurePosixPath(*path.parts[1:])


def _symlink_destination(path: PurePosixPath, linkname: str) -> None:
    if not linkname or "\\" in linkname:
        raise UnsafeArchiveError("invalid symbolic-link target")
    target = PurePosixPath(linkname)
    if target.is_absolute():
        raise UnsafeArchiveError("symbolic link escapes its target")
    depth = 0
    for part in path.parent.parts + target.parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise UnsafeArchiveError("symbolic link escapes its target")
        else:
            depth += 1


def _hardlink_path(linkname: str, expected_root: str) -> PurePosixPath:
    path = _archive_path(linkname)
    if path.parts[0] != expected_root or len(path.parts) == 1:
        raise UnsafeArchiveError("hard link escapes its target")
    return PurePosixPath(*path.parts[1:])


def _extract_tarball(
    data: bytes,
    destination: Path,
    repo: str,
    commit_sha: str,
    *,
    archive_root: str | None = None,
) -> None:
    expected_root = archive_root
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise UnsafeArchiveError("archive is empty")
        if expected_root is None:
            expected_root = _archive_path(members[0].name).parts[0]

        planned: list[tuple[tarfile.TarInfo, PurePosixPath | None]] = []
        seen: set[PurePosixPath] = set()
        for member in members:
            path = _stripped_member_path(member, expected_root)
            if path is None and not member.isdir():
                raise UnsafeArchiveError("archive top-level member is not a directory")
            if path is not None:
                if path == PurePosixPath(MANIFEST_NAME):
                    raise UnsafeArchiveError("archive contains Leitir's reserved manifest path")
                if path in seen:
                    raise UnsafeArchiveError("archive contains duplicate member paths")
                seen.add(path)
            if not (member.isdir() or member.isreg() or member.issym() or member.islnk()):
                raise UnsafeArchiveError("archive contains a device or other special file")
            if member.issym() and path is not None:
                _symlink_destination(path, member.linkname)
            if member.islnk():
                _hardlink_path(member.linkname, expected_root)
            planned.append((member, path))

        destination.mkdir(parents=True, exist_ok=True)
        regular_paths: set[PurePosixPath] = set()
        for member, path in planned:
            if path is None or not (member.isdir() or member.isreg()):
                continue
            output = destination.joinpath(*path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(member.mode & 0o777)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise UnsafeArchiveError("regular archive member has no data")
            with source, output.open("xb") as handle:
                shutil.copyfileobj(source, handle)
            output.chmod(member.mode & 0o777)
            regular_paths.add(path)

        for member, path in planned:
            if path is None or not member.islnk():
                continue
            linked = _hardlink_path(member.linkname, expected_root)
            if linked not in regular_paths:
                raise UnsafeArchiveError("hard link does not target a regular archive member")
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            os.link(destination.joinpath(*linked.parts), output)

        for member, path in planned:
            if path is None or not member.issym():
                continue
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.symlink_to(member.linkname)


def _verify_extracted_tree(
    staging: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    tree_source: object,
    *,
    max_files: int,
    max_bytes: int,
) -> tuple[bool | str, int]:
    """Return verification status and the number of EOL-normalized files."""
    import hashlib

    from leitir.tree import GitHubTreeSource

    if max_files < 1:
        raise ValueError("verification_max_files must be >= 1")
    if max_bytes < 1:
        raise ValueError("verification_max_bytes must be >= 1")

    extracted_paths = [
        path
        for path in staging.rglob("*")
        if not path.is_symlink() and path.is_file()
    ]
    extracted = {
        path.relative_to(staging).as_posix(): path
        for path in extracted_paths
    }

    entries = tree_source.list_blobs(f"{owner}/{repo}", commit_sha)  # type: ignore[attr-defined]
    expected: dict[str, object] = {}
    for entry in entries:
        if entry.path in expected:
            raise VerificationError(f"duplicate blob path in Git tree: {entry.path}")
        expected[entry.path] = entry

    # GitHub's mode distinguishes regular blobs from symlinks (whose blob is
    # the link target). Injected legacy TreeSources may omit mode; in that case
    # retain compatibility by verifying the extracted regular-file universe.
    modes_available = all(getattr(entry, "mode", None) is not None for entry in entries)
    if modes_available:
        candidates = {
            path: entry
            for path, entry in expected.items()
            if getattr(entry, "mode", "").startswith("100")
        }
        sizes = {path: entry.size for path, entry in candidates.items()}  # type: ignore[attr-defined]
    else:
        candidates = {path: expected.get(path) for path in extracted}
        sizes = {path: file.stat().st_size for path, file in extracted.items()}

    total_bytes = sum(sizes.values())
    sampled = len(candidates) > max_files or total_bytes > max_bytes
    selected = sorted(candidates)
    if not sampled and modes_available and set(extracted) != set(candidates):
        missing = sorted(set(candidates) - set(extracted))
        extra = sorted(set(extracted) - set(candidates))
        detail = missing[0] if missing else extra[0]
        kind = "missing" if missing else "unexpected"
        raise VerificationError(f"{kind} extracted regular file: {detail}")
    if sampled:
        selected = sorted(
            candidates,
            key=lambda path: hashlib.sha256(
                commit_sha.encode("ascii")
                + b"\0"
                + path.encode("utf-8")
            ).digest(),
        )
        bounded: list[str] = []
        selected_bytes = 0
        for path in selected:
            size = sizes[path]
            if len(bounded) >= max_files:
                break
            if selected_bytes + size <= max_bytes:
                bounded.append(path)
                selected_bytes += size
        if not bounded and selected:
            bounded.append(selected[0])
        selected = bounded

    text_normalized = 0
    for relative in selected:
        path = extracted.get(relative)
        entry = expected.get(relative)
        if path is None:
            raise VerificationError(f"missing extracted regular file: {relative}")
        if entry is None:
            raise VerificationError(f"extracted file is absent from Git tree: {relative}")
        extracted_bytes = path.read_bytes()
        actual = GitHubTreeSource.git_blob_sha(extracted_bytes)
        if actual != entry.blob_sha:  # type: ignore[attr-defined]
            read_at_commit = getattr(tree_source, "read_blob_at_commit", None)
            if read_at_commit is not None:
                blob_bytes = read_at_commit(f"{owner}/{repo}", commit_sha, relative)
            else:
                # Compatibility for injected TreeSource implementations. The
                # blob SHA came from the pinned commit's tree listing.
                blob_bytes = tree_source.read_blob(  # type: ignore[attr-defined]
                    f"{owner}/{repo}", entry.blob_sha  # type: ignore[attr-defined]
                )
            if extracted_bytes not in (blob_bytes, blob_bytes.replace(b"\n", b"\r\n")):
                raise VerificationError(f"Git blob digest mismatch: {relative}")
            text_normalized += 1
    return ("sampled" if sampled else True), text_normalized


def materialize_github_repo(
    root: str | os.PathLike[str],
    spec: str,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    token: str | None = None,
    timeout: int = 60,
    base_url: str = _CODELOAD,
    max_attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    max_rate_limit_delay: float = 300.0,
    sleeper: Callable[[float], None] | None = None,
    verify: bool = True,
    tree_source: object | None = None,
    tree_base_url: str = "https://api.github.com",
    verification_max_files: int = VERIFY_MAX_FILES,
    verification_max_bytes: int = VERIFY_MAX_BYTES,
    on_fetch: Callable[[], None] | None = None,
) -> Path:
    """Download and safely extract an exact GitHub commit into the corpus."""
    from urllib.parse import urlsplit
    from urllib.request import Request, urlopen

    retry = _http.make_retry(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        max_rate_limit_delay=max_rate_limit_delay,
        sleeper=sleeper,
    )
    url = f"{base_url.rstrip('/')}/{owner}/{repo}/tar.gz/{commit_sha}"
    headers = {"Accept": "application/gzip", "User-Agent": "leitir"}
    github_token = token if token is not None else os.environ.get("GITHUB_TOKEN")
    endpoint = urlsplit(url)
    if (
        github_token
        and endpoint.scheme == "https"
        and endpoint.hostname == "codeload.github.com"
    ):
        headers["Authorization"] = f"Bearer {github_token}"

    def _fetch() -> bytes:
        with urlopen(Request(url, headers=headers), timeout=timeout) as response:
            return response.read()

    if tree_source is None and verify:
        from leitir.tree import GitHubTreeSource

        tree_source = GitHubTreeSource(
            token=github_token,
            timeout=timeout,
            base_url=tree_base_url,
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )
    return _materialize_hosted_repo(
        root,
        spec,
        owner,
        repo,
        commit_sha,
        host="github.com",
        fetch_archive=lambda: retry(_fetch),
        tree_source=tree_source,
        tag=tag,
        subpath=subpath,
        manifest_fields=manifest_fields,
        verify=verify,
        verification_max_files=verification_max_files,
        verification_max_bytes=verification_max_bytes,
        on_fetch=on_fetch,
        archive_root=f"{repo}-{commit_sha}",
    )


def _materialize_hosted_repo(
    root: str | os.PathLike[str],
    spec: str,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str,
    fetch_archive: Callable[[], bytes],
    tree_source: object | None,
    tag: str | None = None,
    subpath: str | None = None,
    manifest_fields: Mapping[str, object] | None = None,
    verify: bool = True,
    verification_max_files: int = VERIFY_MAX_FILES,
    verification_max_bytes: int = VERIFY_MAX_BYTES,
    on_fetch: Callable[[], None] | None = None,
    archive_root: str | None = None,
) -> Path:
    _validate_identity(owner, repo, commit_sha)
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("spec must be non-empty")
    metadata = _HOST_METADATA.get(host)
    if metadata is None:
        raise ValueError(f"unsupported repository host {host!r}")
    fetch_method, canonical_base = metadata
    target = target_path(root, owner, repo, commit_sha, host=host)
    existing = (
        read_valid_manifest(target, owner, repo, commit_sha, host=host)
        if target.is_dir()
        else None
    )
    if existing is not None:
        if not verify:
            if "verified" not in existing:
                existing.update(verified=False, verified_at=None)
                _write_manifest(target / MANIFEST_NAME, existing)
            return target
        if existing.get("verified") in (True, "sampled"):
            return target
    if verify and tree_source is None:
        raise ValueError("tree_source is required when verification is enabled")
    if on_fetch is not None:
        on_fetch()
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{commit_sha}.tmp-", dir=target.parent))
    try:
        data = fetch_archive()
        _extract_tarball(
            data,
            staging,
            repo,
            commit_sha,
            archive_root=archive_root,
        )
        if verify:
            verified, text_normalized = _verify_extracted_tree(
                staging,
                owner,
                repo,
                commit_sha,
                tree_source,
                max_files=verification_max_files,
                max_bytes=verification_max_bytes,
            )
            verified_at: str | None = _utc_now()
        else:
            verified = False
            verified_at = None
            text_normalized = 0
        verification_notes = (
            [f"text-normalized: {text_normalized} file(s)"]
            if text_normalized
            else []
        )
        fetched_at = _utc_now()
        manifest: dict[str, object] = dict(manifest_fields or {})
        manifest.update(
            {
                "spec": spec,
                "host": host,
                "owner": owner,
                "repo": repo,
                "commit_sha": commit_sha,
                "tag": tag,
                "repo_url": f"{canonical_base}/{owner}/{repo}",
                "fetched_at": fetched_at,
                "fetch_method": fetch_method,
                "subpath": subpath,
                "verified": verified,
                "verified_at": verified_at,
                "verification_notes": verification_notes,
            }
        )
        _write_manifest(staging / MANIFEST_NAME, manifest)
        if target.exists():
            shutil.rmtree(target)
        os.replace(staging, target)
        return target
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if target.exists() and read_valid_manifest(
            target, owner, repo, commit_sha, host=host
        ) is None:
            shutil.rmtree(target, ignore_errors=True)
        if isinstance(exc, MaterializationError):
            raise
        raise MaterializationError(
            f"materialization failed for {owner}/{repo}@{commit_sha}: "
            f"{_failure_detail(exc)}"
        ) from exc


def materialize_repo(
    root: str | os.PathLike[str],
    spec: str,
    scope: RepoScope,
    *,
    host: str = "github.com",
    resolver: object | None = None,
    **kwargs: object,
) -> Path:
    """Materialize a :class:`RepoScope` through its host-native resolver."""
    owner, repo = scope.slug.split("/", 1)
    if host == "github.com":
        return materialize_github_repo(
            root, spec, owner, repo, scope.commit_sha, **kwargs  # type: ignore[arg-type]
        )
    if host not in ("gitlab.com", "bitbucket.org"):
        raise ValueError(f"unsupported repository host {host!r}")
    if resolver is None:
        raise ValueError(f"a repository resolver is required for {host}")
    archive_url = resolver.archive_url(scope.slug, scope.commit_sha)  # type: ignore[attr-defined]
    hosted_options = {
        key: kwargs.pop(key)
        for key in tuple(kwargs)
        if key
        in {
            "tag",
            "subpath",
            "manifest_fields",
            "verify",
            "verification_max_files",
            "verification_max_bytes",
            "on_fetch",
        }
    }
    for github_only in (
        "token",
        "timeout",
        "base_url",
        "max_attempts",
        "base_delay",
        "max_delay",
        "max_rate_limit_delay",
        "sleeper",
        "tree_source",
        "tree_base_url",
    ):
        kwargs.pop(github_only, None)
    if kwargs:
        unexpected = next(iter(kwargs))
        raise TypeError(f"unexpected materialization option {unexpected!r}")
    return _materialize_hosted_repo(
        root,
        spec,
        owner,
        repo,
        scope.commit_sha,
        host=host,
        fetch_archive=lambda: resolver._get_bytes(archive_url),  # type: ignore[attr-defined]
        tree_source=resolver,
        **hosted_options,  # type: ignore[arg-type]
    )
