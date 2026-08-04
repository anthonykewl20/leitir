"""Strict package resolution: map a pinned package version to a RepoScope.

ADR-001 P4: given an ecosystem, package name, and exact version, resolve the
canonical GitHub repository slug and the immutable commit SHA that the version
tag points to.  Resolution is deterministic: same input always yields the same
RepoScope, and the result is verifiable against the registry and GitHub.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol, runtime_checkable

from leitir import _http
from leitir.search import RepoScope

if TYPE_CHECKING:
    from leitir.parity import ArtifactInfo


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    CRATES = "crates"
    GO = "go"


@dataclass(frozen=True, slots=True)
class PackageRef:
    """A fully pinned package reference."""

    ecosystem: Ecosystem
    name: str
    version: str

    def __post_init__(self) -> None:
        if not isinstance(self.ecosystem, Ecosystem):
            raise TypeError("ecosystem must be an Ecosystem")
        if not self.name or not self.name.strip():
            raise ValueError("name must be non-empty")
        if not self.version or not self.version.strip():
            raise ValueError("version must be non-empty")
        if self.ecosystem is Ecosystem.GO and "/" not in self.name:
            raise ValueError("go package name must be a module path")
        if self.ecosystem is Ecosystem.NPM:
            scoped = re.fullmatch(r"@[^/@\s]+/[^/@\s]+", self.name)
            unscoped = re.fullmatch(r"[^/@\s]+", self.name)
            if scoped is None and unscoped is None:
                raise ValueError("npm package name must be unscoped or @scope/name")


@dataclass(frozen=True, slots=True)
class ResolvedPackage:
    """The deterministic result of resolving a PackageRef."""

    ref: PackageRef
    scope: RepoScope
    tag: str
    registry_url: str
    subpath: str | None = None
    docs_urls: tuple[str, ...] = ()
    artifact: ArtifactInfo | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ref, PackageRef):
            raise TypeError("ref must be a PackageRef")
        if not isinstance(self.scope, RepoScope):
            raise TypeError("scope must be a RepoScope")
        if not self.tag or not self.tag.strip():
            raise ValueError("tag must be non-empty")
        if not self.registry_url.startswith("https://"):
            raise ValueError("registry_url must be https")
        if self.subpath is not None and (
            not self.subpath.strip()
            or self.subpath.startswith("/")
            or ".." in self.subpath.split("/")
        ):
            raise ValueError("subpath must be a safe non-empty relative path")
        if not isinstance(self.docs_urls, tuple) or not all(
            isinstance(url, str) and url.startswith(("http://", "https://"))
            for url in self.docs_urls
        ):
            raise ValueError("docs_urls must be a tuple of HTTP(S) URLs")


@runtime_checkable
class PackageResolver(Protocol):
    """Port: resolve a pinned package to an immutable RepoScope."""

    def resolve(self, ref: PackageRef) -> ResolvedPackage: ...


class ResolutionError(Exception):
    """The package could not be resolved deterministically."""


def resolve_corpus_spec(
    parsed: object, resolver: object, heads: object, cwd: Path
) -> tuple[object, str | None, str | None, str | None]:
    """Resolve a parsed corpus spec using lockfile/latest and repository rules."""
    from leitir.lockfiles import detect_installed_version_with_source
    from leitir.spec import CorpusSpec

    if not isinstance(parsed, CorpusSpec):
        raise TypeError("parsed must be a CorpusSpec")
    if parsed.ecosystem is not None:
        ecosystem = Ecosystem(parsed.ecosystem)
        version = parsed.version
        version_source = "explicit"
        detection_source = None
        if version is None:
            detected = detect_installed_version_with_source(parsed.ecosystem, parsed.name, cwd)
            if detected is not None:
                version = detected.version
                version_source = "lockfile"
                detection_source = detected.source
            else:
                version = resolver.latest_version(ecosystem, parsed.name)
                version_source = "latest"
        return (
            resolver.resolve(PackageRef(ecosystem, parsed.name, version)),
            None,
            version_source,
            detection_source,
        )
    if parsed.ref_kind == "sha":
        return RepoScope(parsed.name, parsed.ref), None, None, None
    if parsed.ref_kind == "tag":
        sha = resolver.resolve_tag_to_sha(parsed.name, parsed.ref, host=parsed.host) if parsed.host not in (None, "github.com") else resolver.resolve_tag_to_sha(parsed.name, parsed.ref)
        return RepoScope(parsed.name, sha), parsed.ref, None, None
    if parsed.host not in (None, "github.com"):
        sha = resolver.resolve_tag_to_sha(parsed.name, parsed.ref or "HEAD", host=parsed.host)
        return RepoScope(parsed.name, sha), None, None, None
    sha = heads.resolve_head_sha(parsed.name, parsed.ref) if parsed.ref_kind == "branch" else heads.resolve_head_sha(parsed.name)
    return RepoScope(parsed.name, sha), None, None, None


class GitHubTagResolver:
    """Resolves a git tag to a commit SHA via the GitHub API."""

    _API = "https://api.github.com"

    def __init__(
        self,
        token: str | None = None,
        timeout: int = 30,
        *,
        base_url: str = _API,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._token = token
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _headers(self) -> dict[str, str]:
        from urllib.parse import urlsplit

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "leitir",
        }
        endpoint = urlsplit(self._base_url)
        if (
            self._token
            and endpoint.scheme == "https"
            and endpoint.hostname == "api.github.com"
        ):
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        from urllib.parse import quote
        from urllib.request import Request, urlopen

        url = f"{self._base_url}/repos/{slug}/git/ref/tags/{quote(tag, safe='')}"
        headers = self._headers()

        def _fetch() -> dict:
            with urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"tag {tag!r} not found in {slug}: {_http.describe_failure(exc)}"
            ) from exc

        obj = payload["object"]
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] == "tag":
            return self._dereference_annotated_tag(slug, obj["sha"])
        raise ResolutionError(f"unexpected object type {obj['type']!r}")

    def resolve_commit_to_sha(self, slug: str, ref: str) -> str:
        """Expand a Git commit reference, including Go pseudo-version revisions."""
        from urllib.parse import quote
        from urllib.request import Request, urlopen

        url = f"{self._base_url}/repos/{slug}/commits/{quote(ref, safe='')}"
        headers = self._headers()

        def _fetch() -> dict:
            with urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"commit {ref!r} not found in {slug}: {_http.describe_failure(exc)}"
            ) from exc
        sha = payload.get("sha") if isinstance(payload, dict) else None
        if not isinstance(sha, str) or re.fullmatch(r"[0-9a-fA-F]{40}", sha) is None:
            raise ResolutionError(f"GitHub returned malformed commit metadata for {slug}")
        return sha.lower()

    def _dereference_annotated_tag(self, slug: str, tag_sha: str) -> str:
        from urllib.request import Request, urlopen

        url = f"{self._base_url}/repos/{slug}/git/tags/{tag_sha}"
        headers = self._headers()

        def _fetch() -> dict:
            with urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"cannot dereference annotated tag {tag_sha} in {slug}: "
                f"{_http.describe_failure(exc)}"
            ) from exc
        obj = payload["object"]
        if obj["type"] != "commit":
            raise ResolutionError(
                f"annotated tag does not point to a commit: {obj['type']!r}"
            )
        return obj["sha"]


class _HostedRepoResolver:
    _HOST = ""
    _TOKEN_ENV = ""
    _AUTH_HEADER = ""

    def __init__(
        self,
        token: str | None = None,
        timeout: int = 30,
        *,
        base_url: str,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        import os

        self._token = token if token is not None else os.environ.get(self._TOKEN_ENV)
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _headers(self, url: str, accept: str = "application/json") -> dict[str, str]:
        from urllib.parse import urlsplit

        headers = {"Accept": accept, "User-Agent": "leitir"}
        endpoint = urlsplit(url)
        if self._token and endpoint.scheme == "https" and endpoint.hostname == self._HOST:
            headers[self._AUTH_HEADER] = (
                f"Bearer {self._token}"
                if self._AUTH_HEADER == "Authorization"
                else self._token
            )
        return headers

    def _get_json(self, url: str) -> object:
        from urllib.request import Request, urlopen

        def _fetch() -> object:
            with urlopen(
                Request(url, headers=self._headers(url)), timeout=self._timeout
            ) as response:
                return json.load(response)

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"{self._HOST} API call failed: {_http.describe_failure(exc)}"
            ) from exc
        except (ValueError, TypeError) as exc:
            raise ResolutionError(f"{self._HOST} returned malformed metadata") from exc

    def _get_bytes(self, url: str) -> bytes:
        from urllib.request import Request, urlopen

        def _fetch() -> bytes:
            with urlopen(
                Request(url, headers=self._headers(url, "application/octet-stream")),
                timeout=self._timeout,
            ) as response:
                return response.read()

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"{self._HOST} content call failed: {_http.describe_failure(exc)}"
            ) from exc

    @staticmethod
    def _sha(payload: object, field: str, host: str) -> str:
        value = payload.get(field) if isinstance(payload, dict) else None
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
            raise ResolutionError(f"{host} returned malformed commit metadata")
        return value.lower()


class GitLabResolver(_HostedRepoResolver):
    """Resolve and inspect immutable GitLab repository commits."""

    _HOST = "gitlab.com"
    _TOKEN_ENV = "GITLAB_TOKEN"
    _AUTH_HEADER = "PRIVATE-TOKEN"
    _API = "https://gitlab.com/api/v4"

    def __init__(
        self,
        token: str | None = None,
        timeout: int = 30,
        *,
        base_url: str = _API,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            token,
            timeout,
            base_url=base_url,
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    @staticmethod
    def _project(slug: str) -> str:
        from urllib.parse import quote

        if re.fullmatch(
            r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", slug
        ) is None or any(part in {".", ".."} for part in slug.split("/")):
            raise ResolutionError(f"invalid GitLab repository slug {slug!r}")
        return quote(slug, safe="")

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        from urllib.parse import quote

        if not tag or any(char.isspace() for char in tag):
            raise ResolutionError("GitLab ref must be non-empty and contain no whitespace")
        url = f"{self._base_url}/projects/{self._project(slug)}/repository/commits/{quote(tag, safe='')}"
        return self._sha(self._get_json(url), "id", self._HOST)

    resolve_ref_to_sha = resolve_tag_to_sha

    def archive_url(self, slug: str, commit_sha: str) -> str:
        from urllib.parse import urlencode

        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        return (
            f"{self._base_url}/projects/{self._project(slug)}/repository/archive.tar.gz?"
            f"{urlencode({'sha': sha})}"
        )

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[object, ...]:
        from urllib.parse import urlencode

        from leitir.tree import BlobEntry

        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        entries: list[BlobEntry] = []
        page = 1
        while True:
            query = urlencode(
                {"ref": sha, "recursive": "true", "per_page": 100, "page": page}
            )
            payload = self._get_json(
                f"{self._base_url}/projects/{self._project(slug)}/repository/tree?{query}"
            )
            if not isinstance(payload, list):
                raise ResolutionError("gitlab.com returned malformed tree metadata")
            for item in payload:
                if not isinstance(item, dict):
                    raise ResolutionError("gitlab.com returned malformed tree metadata")
                if item.get("type") != "blob":
                    continue
                try:
                    metadata = self._get_json(
                        f"{self._base_url}/projects/{self._project(slug)}/repository/blobs/"
                        f"{self._sha(item, 'id', self._HOST)}"
                    )
                    size = metadata.get("size") if isinstance(metadata, dict) else None
                    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                        raise ValueError
                    entries.append(
                        BlobEntry(
                            path=item["path"],
                            blob_sha=item["id"],
                            size=size,
                            mode=item.get("mode"),
                        )
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ResolutionError("gitlab.com returned malformed tree metadata") from exc
            if len(payload) < 100:
                break
            page += 1
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        sha = self._sha({"sha": blob_sha}, "sha", self._HOST)
        return self._get_bytes(
            f"{self._base_url}/projects/{self._project(slug)}/repository/blobs/{sha}/raw"
        )

    def read_blob_at_commit(self, slug: str, commit_sha: str, path: str) -> bytes:
        from urllib.parse import quote, urlencode

        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        return self._get_bytes(
            f"{self._base_url}/projects/{self._project(slug)}/repository/files/"
            f"{quote(path, safe='')}/raw?{urlencode({'ref': sha})}"
        )


class BitbucketResolver(_HostedRepoResolver):
    """Resolve and inspect immutable Bitbucket repository commits."""

    _HOST = "api.bitbucket.org"
    _TOKEN_ENV = "BITBUCKET_TOKEN"
    _AUTH_HEADER = "Authorization"
    _API = "https://api.bitbucket.org/2.0"

    def __init__(
        self,
        token: str | None = None,
        timeout: int = 30,
        *,
        base_url: str = _API,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            token,
            timeout,
            base_url=base_url,
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    @staticmethod
    def _slug(slug: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug) is None:
            raise ResolutionError(f"invalid Bitbucket repository slug {slug!r}")
        return slug

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        from urllib.parse import quote

        if not tag or any(char.isspace() for char in tag):
            raise ResolutionError("Bitbucket ref must be non-empty and contain no whitespace")
        url = f"{self._base_url}/repositories/{self._slug(slug)}/commit/{quote(tag, safe='')}"
        return self._sha(self._get_json(url), "hash", "bitbucket.org")

    resolve_ref_to_sha = resolve_tag_to_sha

    def archive_url(self, slug: str, commit_sha: str) -> str:
        sha = self._sha({"sha": commit_sha}, "sha", "bitbucket.org")
        return f"https://bitbucket.org/{self._slug(slug)}/get/{sha}.tar.gz"

    def read_blob_at_commit(self, slug: str, commit_sha: str, path: str) -> bytes:
        from urllib.parse import quote

        sha = self._sha({"sha": commit_sha}, "sha", "bitbucket.org")
        return self._get_bytes(
            f"{self._base_url}/repositories/{self._slug(slug)}/src/{sha}/"
            f"{quote(path, safe='/')}"
        )

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[object, ...]:
        from urllib.parse import quote

        from leitir.tree import BlobEntry, GitHubTreeSource

        sha = self._sha({"sha": commit_sha}, "sha", "bitbucket.org")
        pending = [""]
        entries: list[BlobEntry] = []
        while pending:
            directory = pending.pop(0)
            suffix = f"/{quote(directory, safe='/')}" if directory else ""
            url = (
                f"{self._base_url}/repositories/{self._slug(slug)}/src/{sha}"
                f"{suffix}/?pagelen=100"
            )
            while url:
                payload = self._get_json(url)
                values = payload.get("values") if isinstance(payload, dict) else None
                if not isinstance(values, list):
                    raise ResolutionError("bitbucket.org returned malformed tree metadata")
                for item in values:
                    if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                        raise ResolutionError("bitbucket.org returned malformed tree metadata")
                    if item.get("type") == "commit_directory":
                        pending.append(item["path"])
                    elif item.get("type") == "commit_file":
                        content = self.read_blob_at_commit(slug, sha, item["path"])
                        attributes = item.get("attributes", [])
                        mode = "120000" if isinstance(attributes, list) and "link" in attributes else "100644"
                        entries.append(
                            BlobEntry(
                                path=item["path"],
                                blob_sha=GitHubTreeSource.git_blob_sha(content),
                                size=len(content),
                                mode=mode,
                            )
                        )
                next_url = payload.get("next")
                if next_url is None:
                    url = ""
                elif isinstance(next_url, str) and next_url.startswith(self._base_url + "/"):
                    url = next_url
                else:
                    raise ResolutionError("bitbucket.org returned an unsafe tree page URL")
            pending.sort()
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        raise ResolutionError("Bitbucket blobs must be read by path at a pinned commit")


_GITHUB_URL_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
)


class PyPIResolver:
    """Resolves a PyPI package + version to a GitHub RepoScope."""

    _REGISTRY = "https://pypi.org/pypi"

    def __init__(
        self,
        tag_resolver: GitHubTagResolver,
        timeout: int = 30,
        *,
        base_url: str = _REGISTRY,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        from urllib.request import Request, urlopen

        if ref.ecosystem is not Ecosystem.PYPI:
            raise ResolutionError("PyPIResolver only handles pypi packages")

        url = f"{self._base_url}/{ref.name}/{ref.version}/json"

        def _fetch() -> dict:
            with urlopen(
                Request(url, headers={"User-Agent": "leitir", "Accept": "application/json"}),
                timeout=self._timeout,
            ) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"PyPI lookup failed for {ref.name}=={ref.version}: "
                f"{_http.describe_failure(exc)}"
            ) from exc

        slug = self._extract_github_slug(payload)
        if slug is None:
            raise ResolutionError(
                f"no GitHub repository found for {ref.name}=={ref.version}"
            )

        tag, commit_sha = self._resolve_first_tag(slug, ref.version)
        scope = RepoScope(slug=slug, commit_sha=commit_sha)
        from leitir.docpointers import extract_docs_urls

        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://pypi.org/project/{ref.name}/{ref.version}/",
            docs_urls=tuple(extract_docs_urls(ref.ecosystem, payload)),
            artifact=self._artifact(ref, payload),
        )

    def latest_version(self, name: str) -> str:
        """Return the registry's current version for ``name``."""
        from urllib.request import Request, urlopen

        url = f"{self._base_url}/{name}/json"

        def _fetch() -> dict:
            with urlopen(
                Request(url, headers={"User-Agent": "leitir", "Accept": "application/json"}),
                timeout=self._timeout,
            ) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"PyPI latest-version lookup failed for {name}: "
                f"{_http.describe_failure(exc)}"
            ) from exc
        version = payload.get("info", {}).get("version")
        if not isinstance(version, str) or not version.strip():
            raise ResolutionError(f"PyPI returned no latest version for {name}")
        return version

    @staticmethod
    def _artifact(ref: PackageRef, payload: object) -> ArtifactInfo | None:
        from leitir.parity import artifact_from_metadata

        return artifact_from_metadata(ref.ecosystem.value, ref.name, ref.version, payload)

    def _extract_github_slug(self, payload: dict) -> str | None:
        info = payload.get("info", {})
        urls_to_check = []
        if info.get("project_url"):
            urls_to_check.append(info["project_url"])
        for url_entry in info.get("project_urls", {}).values():
            if url_entry:
                urls_to_check.append(url_entry)
        if info.get("home_page"):
            urls_to_check.append(info["home_page"])

        for candidate in urls_to_check:
            m = _GITHUB_URL_RE.search(candidate)
            if m:
                slug = m.group(1).rstrip("/")
                if slug.endswith(".git"):
                    slug = slug[:-4]
                return slug
        return None

    def _candidate_tags(self, version: str) -> tuple[str, ...]:
        return (f"v{version}", version)

    def _resolve_first_tag(self, slug: str, version: str) -> tuple[str, str]:
        last_err: ResolutionError | None = None
        for tag in self._candidate_tags(version):
            try:
                sha = self._tag_resolver.resolve_tag_to_sha(slug, tag)
                return tag, sha
            except ResolutionError as exc:
                last_err = exc
        raise last_err or ResolutionError(f"no tag found for {version}")


class CratesResolver:
    """Resolves a crates.io package + version to a GitHub RepoScope."""

    _REGISTRY = "https://crates.io/api/v1/crates"

    def __init__(
        self,
        tag_resolver: GitHubTagResolver,
        timeout: int = 30,
        *,
        base_url: str = _REGISTRY,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        from urllib.request import Request, urlopen

        if ref.ecosystem is not Ecosystem.CRATES:
            raise ResolutionError("CratesResolver only handles crates packages")

        url = f"{self._base_url}/{ref.name}/{ref.version}"

        def _fetch() -> dict:
            with urlopen(
                Request(url, headers={"User-Agent": "leitir (package resolver)"}),
                timeout=self._timeout,
            ) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"crates.io lookup failed for {ref.name}=={ref.version}: "
                f"{_http.describe_failure(exc)}"
            ) from exc

        version_info = payload.get("version", {})
        repo_url = version_info.get("repository") or ""
        m = _GITHUB_URL_RE.search(repo_url)
        if not m:
            raise ResolutionError(
                f"no GitHub repository for {ref.name}=={ref.version}"
            )
        slug = m.group(1).rstrip("/")
        if slug.endswith(".git"):
            slug = slug[:-4]

        tag, commit_sha = self._resolve_first_tag(slug, ref.name, ref.version)
        scope = RepoScope(slug=slug, commit_sha=commit_sha)
        from leitir.docpointers import extract_docs_urls

        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://crates.io/crates/{ref.name}/{ref.version}",
            docs_urls=tuple(extract_docs_urls(ref.ecosystem, payload)),
            artifact=self._artifact(ref, payload),
        )

    def latest_version(self, name: str) -> str:
        """Return the registry's current version for ``name``."""
        from urllib.request import Request, urlopen

        url = f"{self._base_url}/{name}"

        def _fetch() -> dict:
            with urlopen(
                Request(url, headers={"User-Agent": "leitir (package resolver)"}),
                timeout=self._timeout,
            ) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"crates.io latest-version lookup failed for {name}: "
                f"{_http.describe_failure(exc)}"
            ) from exc
        version = payload.get("crate", {}).get("max_version")
        if not isinstance(version, str) or not version.strip():
            raise ResolutionError(f"crates.io returned no latest version for {name}")
        return version

    @staticmethod
    def _artifact(ref: PackageRef, payload: object) -> ArtifactInfo | None:
        from leitir.parity import artifact_from_metadata

        return artifact_from_metadata(ref.ecosystem.value, ref.name, ref.version, payload)

    def _resolve_first_tag(
        self, slug: str, name: str, version: str
    ) -> tuple[str, str]:
        candidates = (f"{name}-{version}", f"v{version}", version)
        last_err: ResolutionError | None = None
        for tag in candidates:
            try:
                sha = self._tag_resolver.resolve_tag_to_sha(slug, tag)
                return tag, sha
            except ResolutionError as exc:
                last_err = exc
        raise last_err or ResolutionError(f"no tag found for {name} {version}")


class GoResolver:
    """Resolves a Go module + version to a GitHub RepoScope."""

    _PROXY = "https://proxy.golang.org"
    _PSEUDO_VERSION = re.compile(
        r"^v\d+\.\d+\.\d+.*(?:-|\.)\d{14}-([0-9a-f]{12})(?:\+incompatible)?$"
    )

    def __init__(
        self,
        tag_resolver: GitHubTagResolver,
        timeout: int = 30,
        *,
        base_url: str = _PROXY,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        from urllib.request import Request, urlopen

        if ref.ecosystem is not Ecosystem.GO:
            raise ResolutionError("GoResolver only handles go packages")

        module = ref.name
        if not module.startswith("github.com/"):
            raise ResolutionError(
                f"only github.com Go modules are supported, got {module!r}"
            )

        parts = module.split("/")
        slug = f"{parts[1]}/{parts[2]}"

        escaped = self._escape_module(module)
        version = ref.version
        info_url = f"{self._base_url}/{escaped}/@v/{version}.info"

        def _fetch() -> dict:
            with urlopen(
                Request(info_url, headers={"User-Agent": "leitir"}),
                timeout=self._timeout,
            ) as resp:
                return json.load(resp)

        try:
            self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"Go proxy lookup failed for {module}@{version}: "
                f"{_http.describe_failure(exc)}"
            ) from exc

        tag = version
        pseudo = self._PSEUDO_VERSION.fullmatch(version)
        if pseudo is None:
            commit_sha = self._tag_resolver.resolve_tag_to_sha(slug, tag)
        else:
            expand = getattr(self._tag_resolver, "resolve_commit_to_sha", None)
            if expand is None:
                raise ResolutionError("Go pseudo-version resolution requires commit expansion")
            commit_sha = expand(slug, pseudo.group(1))
        scope = RepoScope(slug=slug, commit_sha=commit_sha)
        from leitir.docpointers import extract_docs_urls

        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://pkg.go.dev/{module}@{version}",
            docs_urls=tuple(
                extract_docs_urls(ref.ecosystem, name=module, version=version)
            ),
        )

    def latest_version(self, name: str) -> str:
        """Return the Go proxy's current version for ``name``."""
        from urllib.request import Request, urlopen

        escaped = self._escape_module(name)
        url = f"{self._base_url}/{escaped}/@latest"

        def _fetch() -> dict:
            with urlopen(
                Request(url, headers={"User-Agent": "leitir"}),
                timeout=self._timeout,
            ) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"Go proxy latest-version lookup failed for {name}: "
                f"{_http.describe_failure(exc)}"
            ) from exc
        version = payload.get("Version")
        if not isinstance(version, str) or not version.strip():
            raise ResolutionError(f"Go proxy returned no latest version for {name}")
        return version

    @staticmethod
    def _escape_module(module: str) -> str:
        return re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), module)


class NpmResolver:
    """Resolve an npm package version through registry metadata and GitHub tags."""

    _REGISTRY = "https://registry.npmjs.org"

    def __init__(
        self,
        tag_resolver: GitHubTagResolver,
        timeout: int = 30,
        *,
        base_url: str = _REGISTRY,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _metadata(self, name: str) -> tuple[dict, str]:
        from urllib.parse import quote
        from urllib.request import Request, urlopen

        encoded = quote(name, safe="")
        url = f"{self._base_url}/{encoded}"

        def _fetch() -> dict:
            with urlopen(
                Request(url, headers={"Accept": "application/json", "User-Agent": "leitir"}),
                timeout=self._timeout,
            ) as response:
                return json.load(response)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"npm registry lookup failed for {name}: {_http.describe_failure(exc)}"
            ) from exc
        if not isinstance(payload, dict):
            raise ResolutionError(f"npm registry returned malformed metadata for {name}")
        return payload, encoded

    def latest_version(self, name: str) -> str:
        payload, _ = self._metadata(name)
        dist_tags = payload.get("dist-tags")
        version = dist_tags.get("latest") if isinstance(dist_tags, dict) else None
        if not isinstance(version, str) or not version.strip():
            raise ResolutionError(f"npm returned no latest version for {name}")
        return version

    @staticmethod
    def _repository(metadata: object) -> tuple[str, str | None] | None:
        if isinstance(metadata, str):
            return metadata, None
        if not isinstance(metadata, dict):
            return None
        url = metadata.get("url")
        directory = metadata.get("directory")
        if not isinstance(url, str) or not url.strip():
            return None
        if directory is not None and not isinstance(directory, str):
            raise ResolutionError("npm repository.directory must be a string")
        return url, directory

    @staticmethod
    def _github_slug(raw: str) -> str:
        from urllib.parse import urlsplit

        value = raw.strip()
        if value.startswith("github:"):
            value = "https://github.com/" + value[len("github:"):]
        elif value.startswith("git@github.com:"):
            value = "https://github.com/" + value[len("git@github.com:"):]
        else:
            for prefix in ("git+https://", "git+ssh://git@", "ssh://git@", "git://"):
                if value.startswith(prefix):
                    value = "https://" + value[len(prefix):]
                    break
        value = value.rstrip("/")
        if value.endswith(".git"):
            value = value[:-4]
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ResolutionError(f"invalid npm repository URL {raw!r}") from exc
        if parsed.scheme.lower() != "https" or parsed.hostname is None:
            raise ResolutionError(f"npm repository URL must be HTTPS, got {raw!r}")
        if parsed.hostname.lower() != "github.com":
            raise ResolutionError(
                f"only github.com npm repositories are materializable, got {parsed.hostname!r}"
            )
        if parsed.username is not None or parsed.password is not None:
            raise ResolutionError("npm GitHub repository URL must not contain credentials")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ResolutionError(f"invalid npm repository URL {raw!r}") from exc
        if port not in (None, 443) or parsed.query or parsed.fragment:
            raise ResolutionError(f"invalid GitHub repository URL for npm package: {raw!r}")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2:
            raise ResolutionError(f"invalid GitHub repository URL for npm package: {raw!r}")
        owner, repo = parts
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+", repo
        ):
            raise ResolutionError(f"invalid GitHub repository URL for npm package: {raw!r}")
        return f"{owner}/{repo}"

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.NPM:
            raise ResolutionError("NpmResolver only handles npm packages")
        payload, encoded = self._metadata(ref.name)
        versions = payload.get("versions")
        if not isinstance(versions, dict):
            raise ResolutionError(f"npm returned no versions for {ref.name}")
        if ref.version not in versions:
            recent = sorted(str(item) for item in versions)[-5:]
            suffix = ", ".join(recent) if recent else "none"
            raise ResolutionError(
                f"version {ref.version!r} not found for {ref.name!r}; recent versions: {suffix}"
            )
        version_data = versions[ref.version]
        version_repo = version_data.get("repository") if isinstance(version_data, dict) else None
        selected = self._repository(version_repo)
        if selected is None:
            selected = self._repository(payload.get("repository"))
        if selected is None:
            raise ResolutionError(f"no repository URL found for {ref.name}@{ref.version}")
        repo_url, directory = selected
        if directory is not None and (
            not directory.strip()
            or directory.startswith("/")
            or "\\" in directory
            or ".." in directory.split("/")
        ):
            raise ResolutionError("npm repository.directory must be a safe relative path")
        slug = self._github_slug(repo_url)

        from leitir.docpointers import extract_docs_urls

        docs_urls = tuple(
            extract_docs_urls(ref.ecosystem, payload, version=ref.version)
        )

        candidates = (f"{ref.name}@{ref.version}", f"v{ref.version}", ref.version)
        for tag in candidates:
            try:
                sha = self._tag_resolver.resolve_tag_to_sha(slug, tag)
                return ResolvedPackage(
                    ref=ref,
                    scope=RepoScope(slug, sha),
                    tag=tag,
                    registry_url=f"https://www.npmjs.com/package/{encoded}/v/{ref.version}",
                    subpath=directory,
                    docs_urls=docs_urls,
                    artifact=self._artifact(ref, payload),
                )
            except ResolutionError:
                pass
        tried = ", ".join(repr(tag) for tag in candidates)
        raise ResolutionError(
            f"none of the npm tag candidates [{tried}] exists in {slug}; "
            "npm resolution has no default-branch fallback"
        )

    @staticmethod
    def _artifact(ref: PackageRef, payload: object) -> ArtifactInfo | None:
        from leitir.parity import artifact_from_metadata

        return artifact_from_metadata(ref.ecosystem.value, ref.name, ref.version, payload)


class MultiResolver:
    """Dispatches to the correct ecosystem resolver."""

    def __init__(
        self,
        pypi: PyPIResolver,
        crates: CratesResolver,
        go: GoResolver,
        npm: NpmResolver | None = None,
        gitlab: GitLabResolver | None = None,
        bitbucket: BitbucketResolver | None = None,
    ) -> None:
        self._tag_resolver = pypi._tag_resolver
        self._resolvers = {
            Ecosystem.PYPI: pypi,
            Ecosystem.CRATES: crates,
            Ecosystem.GO: go,
            Ecosystem.NPM: npm or NpmResolver(self._tag_resolver),
        }
        self._repository_resolvers = {
            "github.com": self._tag_resolver,
            "gitlab.com": gitlab or GitLabResolver(),
            "bitbucket.org": bitbucket or BitbucketResolver(),
        }

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        resolver = self._resolvers.get(ref.ecosystem)
        if resolver is None:
            raise ResolutionError(f"no resolver for {ref.ecosystem}")
        return resolver.resolve(ref)

    def latest_version(self, ecosystem: Ecosystem, name: str) -> str:
        """Dispatch an unpinned package's latest-version lookup."""
        resolver = self._resolvers.get(ecosystem)
        if resolver is None:
            raise ResolutionError(f"no resolver for {ecosystem}")
        return resolver.latest_version(name)

    def resolve_tag_to_sha(
        self, slug: str, tag: str, host: str = "github.com"
    ) -> str:
        """Resolve a repository ref using the resolver registered for its host."""
        resolver = self._repository_resolvers.get(host)
        if resolver is None:
            raise ResolutionError(f"no repository resolver for {host}")
        return resolver.resolve_tag_to_sha(slug, tag)
