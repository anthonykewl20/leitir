"""Strict package resolution: map a pinned package version to a RepoScope.

ADR-001 P4: given an ecosystem, package name, and exact version, resolve the
canonical GitHub repository slug and the immutable commit SHA that the version
tag points to.  Resolution is deterministic: same input always yields the same
RepoScope, and the result is verifiable against the registry and GitHub.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from leitir.search import RepoScope


class Ecosystem(str, Enum):
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


@dataclass(frozen=True, slots=True)
class ResolvedPackage:
    """The deterministic result of resolving a PackageRef."""

    ref: PackageRef
    scope: RepoScope
    tag: str
    registry_url: str

    def __post_init__(self) -> None:
        if not isinstance(self.ref, PackageRef):
            raise TypeError("ref must be a PackageRef")
        if not isinstance(self.scope, RepoScope):
            raise TypeError("scope must be a RepoScope")
        if not self.tag or not self.tag.strip():
            raise ValueError("tag must be non-empty")
        if not self.registry_url.startswith("https://"):
            raise ValueError("registry_url must be https")


@runtime_checkable
class PackageResolver(Protocol):
    """Port: resolve a pinned package to an immutable RepoScope."""

    def resolve(self, ref: PackageRef) -> ResolvedPackage: ...


class ResolutionError(Exception):
    """The package could not be resolved deterministically."""


class GitHubTagResolver:
    """Resolves a git tag to a commit SHA via the GitHub API."""

    _API = "https://api.github.com"

    def __init__(self, token: str | None = None, timeout: int = 30) -> None:
        self._token = token
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "leitir",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        url = f"{self._API}/repos/{slug}/git/ref/tags/{tag}"
        request = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            raise ResolutionError(
                f"tag {tag!r} not found in {slug}: HTTP {exc.code}"
            ) from exc

        obj = payload["object"]
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] == "tag":
            return self._dereference_annotated_tag(slug, obj["sha"])
        raise ResolutionError(f"unexpected object type {obj['type']!r}")

    def _dereference_annotated_tag(self, slug: str, tag_sha: str) -> str:
        url = f"{self._API}/repos/{slug}/git/tags/{tag_sha}"
        request = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(request, timeout=self._timeout) as resp:
            payload = json.load(resp)
        obj = payload["object"]
        if obj["type"] != "commit":
            raise ResolutionError(
                f"annotated tag does not point to a commit: {obj['type']!r}"
            )
        return obj["sha"]


_GITHUB_URL_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
)


class PyPIResolver:
    """Resolves a PyPI package + version to a GitHub RepoScope."""

    _REGISTRY = "https://pypi.org/pypi"

    def __init__(
        self, tag_resolver: GitHubTagResolver, timeout: int = 30
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.PYPI:
            raise ResolutionError("PyPIResolver only handles pypi packages")

        url = f"{self._REGISTRY}/{ref.name}/{ref.version}/json"
        request = urllib.request.Request(
            url, headers={"User-Agent": "leitir", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            raise ResolutionError(
                f"PyPI lookup failed for {ref.name}=={ref.version}: HTTP {exc.code}"
            ) from exc

        slug = self._extract_github_slug(payload)
        if slug is None:
            raise ResolutionError(
                f"no GitHub repository found for {ref.name}=={ref.version}"
            )

        tag, commit_sha = self._resolve_first_tag(slug, ref.version)
        scope = RepoScope(slug=slug, commit_sha=commit_sha)
        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://pypi.org/project/{ref.name}/{ref.version}/",
        )

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
        self, tag_resolver: GitHubTagResolver, timeout: int = 30
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.CRATES:
            raise ResolutionError("CratesResolver only handles crates packages")

        url = f"{self._REGISTRY}/{ref.name}/{ref.version}"
        request = urllib.request.Request(
            url, headers={"User-Agent": "leitir (package resolver)"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            raise ResolutionError(
                f"crates.io lookup failed for {ref.name}=={ref.version}: HTTP {exc.code}"
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
        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://crates.io/crates/{ref.name}/{ref.version}",
        )

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

    def __init__(
        self, tag_resolver: GitHubTagResolver, timeout: int = 30
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
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
        info_url = f"{self._PROXY}/{escaped}/@v/{version}.info"
        request = urllib.request.Request(
            info_url, headers={"User-Agent": "leitir"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                json.load(resp)
        except urllib.error.HTTPError as exc:
            raise ResolutionError(
                f"Go proxy lookup failed for {module}@{version}: HTTP {exc.code}"
            ) from exc

        tag = version
        commit_sha = self._tag_resolver.resolve_tag_to_sha(slug, tag)
        scope = RepoScope(slug=slug, commit_sha=commit_sha)
        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://pkg.go.dev/{module}@{version}",
        )

    @staticmethod
    def _escape_module(module: str) -> str:
        return re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), module)


class MultiResolver:
    """Dispatches to the correct ecosystem resolver."""

    def __init__(
        self,
        pypi: PyPIResolver,
        crates: CratesResolver,
        go: GoResolver,
    ) -> None:
        self._resolvers = {
            Ecosystem.PYPI: pypi,
            Ecosystem.CRATES: crates,
            Ecosystem.GO: go,
        }

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        resolver = self._resolvers.get(ref.ecosystem)
        if resolver is None:
            raise ResolutionError(f"no resolver for {ref.ecosystem}")
        return resolver.resolve(ref)
