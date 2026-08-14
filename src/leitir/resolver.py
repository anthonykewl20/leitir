"""Strict package resolution: map a pinned package version to a RepoScope.

ADR-001 P4: given an ecosystem, package name, and exact version, resolve the
canonical GitHub repository slug and the immutable commit SHA that the version
tag points to.  Resolution is deterministic: same input always yields the same
RepoScope, and the result is verifiable against the registry and GitHub.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from leitir import _http
from leitir.credentials import Credentials
from leitir.search import RepoScope

if TYPE_CHECKING:
    from leitir.parity import ArtifactInfo

logger = logging.getLogger(__name__)


def escape_go_module_path(module: str) -> str:
    """Return the Go wire form of a module path.

    Go proxies and the checksum database address uppercase path bytes as
    ``!`` followed by their lowercase form.  The unescaped path remains the
    module's canonical identity.
    """
    return re.sub(r"[A-Z]", lambda match: "!" + match.group().lower(), module)


class Ecosystem(StrEnum):
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
    host: str = "github.com"
    published_at: str | None = None
    go_module_zip: bool = False
    go_proxy_url: str | None = None

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
        if self.host not in {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht", "go-module-zip"}:
            raise ValueError(f"unsupported repository host {self.host!r}")
        if self.go_module_zip != (self.host == "go-module-zip"):
            raise ValueError("go module zip provenance must use go-module-zip host")
        if self.go_module_zip and (
            not isinstance(self.go_proxy_url, str)
            or not self.go_proxy_url.startswith(("https://", "http://127.0.0.1", "http://localhost"))
        ):
            raise ValueError("go module zip provenance requires an HTTPS or local proxy URL")
        if not self.go_module_zip and self.go_proxy_url is not None:
            raise ValueError("repository source must not have a Go proxy URL")
        if self.published_at is not None and not _valid_published_at(
            self.published_at
        ):
            raise ValueError("published_at must be a timezone-aware ISO-8601 timestamp")


def _valid_published_at(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _first_valid_timestamp(*values: object) -> str | None:
    return next(
        (
            value
            for value in values
            if isinstance(value, str) and _valid_published_at(value)
        ),
        None,
    )


@runtime_checkable
class PackageResolver(Protocol):
    """Port: resolve a pinned package to an immutable RepoScope."""

    def resolve(self, ref: PackageRef) -> ResolvedPackage: ...


class _CorpusResolver(Protocol):
    def resolve(self, ref: PackageRef) -> ResolvedPackage: ...

    def latest_version(self, ecosystem: Ecosystem, name: str) -> str: ...

    def resolve_tag_to_sha(
        self, slug: str, tag: str, host: str = "github.com"
    ) -> str: ...


class _HeadResolver(Protocol):
    def resolve_head_sha(self, slug: str, branch: str | None = None) -> str: ...


class _RepositoryResolver(Protocol):
    def resolve_tag_to_sha(self, slug: str, tag: str) -> str: ...


class _EcosystemResolver(Protocol):
    def resolve(self, ref: PackageRef) -> ResolvedPackage: ...

    def latest_version(self, name: str) -> str: ...


class ResolutionError(Exception):
    """The package could not be resolved deterministically."""


class TagAbsentError(ResolutionError):
    """A requested repository tag definitively does not exist."""


class ArchiveOnlyVerification(Exception):
    """The host can authenticate an archive but cannot enumerate its Git tree."""


class _InfoRefsPermissionError(ResolutionError):
    """Sourcehut denied access to a repository's smart-HTTP advertisement."""


def _validate_network_base_url(
    base_url: str,
    *,
    credentialled: bool,
    allow_insecure_http_for_tests: bool = False,
) -> str:
    """Validate and normalize a resolver endpoint before requests are built."""
    from urllib.parse import urlsplit

    try:
        endpoint = urlsplit(base_url)
        _port = endpoint.port
    except (TypeError, ValueError) as exc:
        raise ValueError("network base URL is malformed") from exc
    scheme = endpoint.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("network base URL must use HTTP or HTTPS")
    if scheme == "http" and credentialled and not allow_insecure_http_for_tests:
        raise ValueError("network base URL must use HTTPS when credentials are configured")
    if endpoint.hostname is None:
        raise ValueError("network base URL must include a host")
    if endpoint.username is not None or endpoint.password is not None:
        raise ValueError("network base URL must not contain userinfo")
    if endpoint.fragment:
        raise ValueError("network base URL must not contain a fragment")
    return base_url.rstrip("/")


def _base_url_is_credentialled(
    credentials: Credentials,
    base_url: str,
    *,
    provider: str,
    token: str | None = None,
) -> bool:
    """Return whether explicit or host-scoped credentials apply to an endpoint."""
    from urllib.parse import urlsplit, urlunsplit

    if token:
        return True
    try:
        endpoint = urlsplit(base_url)
    except (TypeError, ValueError):
        return False
    if endpoint.hostname is None:
        return False
    hostname = endpoint.hostname
    if ":" in hostname:
        hostname = f"[{hostname}]"
    credential_probe = urlunsplit(("https", hostname, "/", "", ""))
    return credentials.auth_for_url(credential_probe, provider=provider) is not None


def resolve_corpus_spec(
    parsed: object, resolver: object, heads: object, cwd: Path
) -> tuple[ResolvedPackage | RepoScope, str | None, str | None, str | None]:
    """Resolve a parsed corpus spec using lockfile/latest and repository rules."""
    from leitir.lockfiles import detect_installed_version_with_source
    from leitir.spec import CorpusSpec

    if not isinstance(parsed, CorpusSpec):
        raise TypeError("parsed must be a CorpusSpec")
    corpus_resolver = cast(_CorpusResolver, resolver)
    head_resolver = cast(_HeadResolver, heads)
    logger.debug("resolving corpus spec name=%s ecosystem=%s ref=%s", parsed.name, parsed.ecosystem, parsed.ref)
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
                version = corpus_resolver.latest_version(ecosystem, parsed.name)
                version_source = "latest"
        return (
            corpus_resolver.resolve(PackageRef(ecosystem, parsed.name, version)),
            None,
            version_source,
            detection_source,
        )
    scope_name = parsed.name[1:] if parsed.host == "git.sr.ht" else parsed.name
    if parsed.ref is not None and re.fullmatch(r"[0-9a-fA-F]{40}", parsed.ref):
        return RepoScope(scope_name, parsed.ref.lower()), None, None, None
    if parsed.ref_kind == "tag":
        tag = cast(str, parsed.ref)
        sha = corpus_resolver.resolve_tag_to_sha(parsed.name, tag, host=parsed.host) if parsed.host not in (None, "github.com") else corpus_resolver.resolve_tag_to_sha(parsed.name, tag)
        return RepoScope(scope_name, sha), tag, None, None
    if parsed.host not in (None, "github.com"):
        sha = corpus_resolver.resolve_tag_to_sha(parsed.name, parsed.ref or "HEAD", host=parsed.host)
        return RepoScope(scope_name, sha), None, None, None
    sha = head_resolver.resolve_head_sha(parsed.name, parsed.ref) if parsed.ref_kind == "branch" else head_resolver.resolve_head_sha(parsed.name)
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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        self._token = token
        self._credentials = Credentials()
        self._timeout = timeout
        self._base_url = _validate_network_base_url(
            base_url,
            credentialled=_base_url_is_credentialled(
                self._credentials, base_url, provider="github", token=token
            ),
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "leitir",
        }
        return self._credentials.headers(
            self._base_url, headers, provider="github", token=self._token
        )

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        from urllib.error import HTTPError
        from urllib.parse import quote
        from urllib.request import Request

        url = f"{self._base_url}/repos/{slug}/git/ref/tags/{quote(tag, safe='')}"
        logger.debug("resolve tag slug=%s tag=%s url=%s", slug, tag, url)
        headers = self._headers()

        def _fetch() -> dict:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except HTTPError as exc:
            if exc.code == 404:
                raise TagAbsentError(
                    f"tag {tag!r} not found in {slug}: "
                    f"{_http.describe_failure(exc)}"
                ) from exc
            raise ResolutionError(
                f"tag {tag!r} not found in {slug}: {_http.describe_failure(exc)}"
            ) from exc
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"tag {tag!r} not found in {slug}: {_http.describe_failure(exc)}"
            ) from exc

        obj = payload["object"]
        if obj["type"] == "commit":
            logger.debug("resolved tag slug=%s tag=%s sha=%s", slug, tag, obj["sha"][:12])
            return obj["sha"]
        if obj["type"] == "tag":
            return self._dereference_annotated_tag(slug, obj["sha"])
        raise ResolutionError(f"unexpected object type {obj['type']!r}")

    def resolve_commit_to_sha(self, slug: str, ref: str) -> str:
        """Expand a Git commit reference, including Go pseudo-version revisions."""
        from urllib.parse import quote
        from urllib.request import Request

        url = f"{self._base_url}/repos/{slug}/commits/{quote(ref, safe='')}"
        headers = self._headers()

        def _fetch() -> dict:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
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

    def published_at_for_commit(self, slug: str, commit_sha: str) -> str:
        """Return GitHub's timezone-aware committer timestamp for a commit."""
        from urllib.parse import quote
        from urllib.request import Request

        url = f"{self._base_url}/repos/{slug}/commits/{quote(commit_sha, safe='')}"

        def _fetch() -> dict:
            with _http.safe_urlopen(
                Request(url, headers=self._headers()), timeout=self._timeout
            ) as response:
                return json.load(response)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"commit metadata for {commit_sha!r} not found in {slug}: "
                f"{_http.describe_failure(exc)}"
            ) from exc
        commit = payload.get("commit") if isinstance(payload, dict) else None
        committer = commit.get("committer") if isinstance(commit, dict) else None
        published_at = committer.get("date") if isinstance(committer, dict) else None
        if not isinstance(published_at, str) or not _valid_published_at(published_at):
            raise ResolutionError(f"GitHub returned malformed commit timestamp for {slug}")
        return published_at

    def _dereference_annotated_tag(self, slug: str, tag_sha: str) -> str:
        from urllib.error import HTTPError
        from urllib.request import Request

        url = f"{self._base_url}/repos/{slug}/git/tags/{tag_sha}"
        headers = self._headers()

        def _fetch() -> dict:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except HTTPError as exc:
            raise ResolutionError(
                f"cannot dereference annotated tag {tag_sha} in {slug}: "
                f"{_http.describe_failure(exc)}"
            ) from exc
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
    _CREDENTIAL_PROVIDER = ""

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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        self._token = token
        self._credentials = Credentials()
        self._timeout = timeout
        self._base_url = _validate_network_base_url(
            base_url,
            credentialled=_base_url_is_credentialled(
                self._credentials,
                base_url,
                provider=self._CREDENTIAL_PROVIDER,
                token=token,
            ),
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _headers(self, url: str, accept: str = "application/json") -> dict[str, str]:
        headers = {"Accept": accept, "User-Agent": "leitir"}
        return self._credentials.headers(
            url, headers, provider=self._CREDENTIAL_PROVIDER, token=self._token
        )

    def _get_json(self, url: str, *, absent_message: str | None = None) -> object:
        from urllib.error import HTTPError
        from urllib.request import Request

        logger.debug("resolver querying host=%s url=%s", self._HOST, url)

        def _fetch() -> object:
            with _http.safe_urlopen(
                Request(url, headers=self._headers(url)), timeout=self._timeout
            ) as response:
                return json.load(response)

        try:
            return self._retry(_fetch)
        except HTTPError as exc:
            detail = f"{self._HOST} API call failed: {_http.describe_failure(exc)}"
            if exc.code == 404 and absent_message is not None:
                raise TagAbsentError(f"{absent_message}: {_http.describe_failure(exc)}") from exc
            raise ResolutionError(detail) from exc
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"{self._HOST} API call failed: {_http.describe_failure(exc)}"
            ) from exc
        except (ValueError, TypeError) as exc:
            raise ResolutionError(f"{self._HOST} returned malformed metadata") from exc

    def _get_bytes_limited(self, url: str, max_bytes: int | None) -> bytes:
        from urllib.request import Request

        def _fetch() -> bytes:
            with _http.safe_urlopen(
                Request(url, headers=self._headers(url, "application/octet-stream")),
                timeout=self._timeout,
            ) as response:
                if max_bytes is None:
                    return response.read()
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise ResolutionError("archive download exceeds compressed size limit")
                return data

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"{self._HOST} content call failed: {_http.describe_failure(exc)}"
            ) from exc

    def _get_bytes(self, url: str) -> bytes:
        return self._get_bytes_limited(url, None)

    def _get_archive_bytes(self, url: str, max_bytes: int) -> bytes:
        return self._get_bytes_limited(url, max_bytes)

    @staticmethod
    def _sha(payload: object, field: str, host: str) -> str:
        value = payload.get(field) if isinstance(payload, dict) else None
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
            raise ResolutionError(f"{host} returned malformed commit metadata")
        return value.lower()


class GitLabResolver(_HostedRepoResolver):
    """Resolve and inspect immutable GitLab repository commits."""

    _HOST = "gitlab.com"
    _CREDENTIAL_PROVIDER = "gitlab"
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
        allow_insecure_http_for_tests: bool = False,
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
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
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
        return self._sha(
            self._get_json(url, absent_message=f"tag {tag!r} not found in {slug}"),
            "id",
            self._HOST,
        )

    resolve_ref_to_sha = resolve_tag_to_sha
    resolve_commit_to_sha = resolve_tag_to_sha

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
    _CREDENTIAL_PROVIDER = "bitbucket"
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
        allow_insecure_http_for_tests: bool = False,
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
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
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
        return self._sha(
            self._get_json(url, absent_message=f"tag {tag!r} not found in {slug}"),
            "hash",
            "bitbucket.org",
        )

    resolve_ref_to_sha = resolve_tag_to_sha
    resolve_commit_to_sha = resolve_tag_to_sha

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
                if not isinstance(payload, dict):
                    raise ResolutionError("bitbucket.org returned malformed tree metadata")
                values = payload.get("values")
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


class CodebergResolver(_HostedRepoResolver):
    """Resolve and inspect immutable Codeberg repository commits."""

    _HOST = "codeberg.org"
    _CREDENTIAL_PROVIDER = "codeberg"
    _API = "https://codeberg.org/api/v1"

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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        super().__init__(
            token, timeout, base_url=base_url, max_attempts=max_attempts,
            base_delay=base_delay, max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay, sleeper=sleeper,
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )

    @staticmethod
    def _slug(slug: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug) is None:
            raise ResolutionError(f"invalid Codeberg repository slug {slug!r}")
        return slug

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        from urllib.parse import urlencode

        if not tag or any(char.isspace() for char in tag):
            raise ResolutionError("Codeberg ref must be non-empty and contain no whitespace")
        payload = self._get_json(
            f"{self._base_url}/repos/{self._slug(slug)}/commits?"
            f"{urlencode({'sha': tag, 'limit': 1})}",
            absent_message=f"tag {tag!r} not found in {slug}",
        )
        if not isinstance(payload, list) or len(payload) != 1:
            raise ResolutionError("codeberg.org returned malformed commit metadata")
        return self._sha(payload[0], "sha", self._HOST)

    resolve_ref_to_sha = resolve_tag_to_sha
    resolve_commit_to_sha = resolve_tag_to_sha

    def archive_url(self, slug: str, commit_sha: str) -> str:
        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        return f"https://codeberg.org/{self._slug(slug)}/archive/{sha}.tar.gz"

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[object, ...]:
        from urllib.parse import urlencode

        from leitir.tree import BlobEntry

        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        payload = self._get_json(
            f"{self._base_url}/repos/{self._slug(slug)}/git/trees/{sha}?"
            f"{urlencode({'recursive': 'true'})}"
        )
        if not isinstance(payload, dict):
            raise ResolutionError("codeberg.org returned incomplete tree metadata")
        tree = payload.get("tree")
        if not isinstance(tree, list) or payload.get("truncated") is True:
            raise ResolutionError("codeberg.org returned incomplete tree metadata")
        entries: list[BlobEntry] = []
        for item in tree:
            if not isinstance(item, dict):
                raise ResolutionError("codeberg.org returned malformed tree metadata")
            if item.get("type") != "blob":
                continue
            path, size, mode = item.get("path"), item.get("size"), item.get("mode")
            if not isinstance(path, str) or not isinstance(size, int) or isinstance(size, bool):
                raise ResolutionError("codeberg.org returned malformed tree metadata")
            entries.append(BlobEntry(path, self._sha(item, "sha", self._HOST), size, mode))
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        import base64

        sha = self._sha({"sha": blob_sha}, "sha", self._HOST)
        payload = self._get_json(
            f"{self._base_url}/repos/{self._slug(slug)}/git/blobs/{sha}"
        )
        if not isinstance(payload, dict):
            raise ResolutionError("codeberg.org returned malformed blob metadata")
        content = payload.get("content")
        if not isinstance(content, str) or payload.get("encoding") not in (None, "base64"):
            raise ResolutionError("codeberg.org returned malformed blob metadata")
        try:
            return base64.b64decode(content, validate=True)
        except ValueError as exc:
            raise ResolutionError("codeberg.org returned malformed blob metadata") from exc

    def read_blob_at_commit(self, slug: str, commit_sha: str, path: str) -> bytes:
        import base64
        from urllib.parse import quote, urlencode

        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        payload = self._get_json(
            f"{self._base_url}/repos/{self._slug(slug)}/contents/{quote(path, safe='/')}?"
            f"{urlencode({'ref': sha})}"
        )
        if not isinstance(payload, dict):
            raise ResolutionError("codeberg.org returned malformed content metadata")
        content = payload.get("content")
        if not isinstance(content, str) or payload.get("encoding") != "base64":
            raise ResolutionError("codeberg.org returned malformed content metadata")
        try:
            return base64.b64decode(content, validate=True)
        except ValueError as exc:
            raise ResolutionError("codeberg.org returned malformed content metadata") from exc


class SourcehutResolver(_HostedRepoResolver):
    """Resolve and inspect immutable Sourcehut repository commits."""

    _HOST = "git.sr.ht"
    _CREDENTIAL_PROVIDER = "sourcehut"
    _API = "https://git.sr.ht/query"

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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        super().__init__(
            token, timeout, base_url=base_url, max_attempts=max_attempts,
            base_delay=base_delay, max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay, sleeper=sleeper,
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._blob_urls: dict[tuple[str, str], str] = {}
        self._path_urls: dict[tuple[str, str, str], str] = {}

    @staticmethod
    def _slug(slug: str) -> str:
        if re.fullmatch(r"~[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug) is None:
            raise ResolutionError(f"invalid Sourcehut repository slug {slug!r}")
        return slug

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        if not tag or any(char.isspace() for char in tag):
            raise ResolutionError("Sourcehut ref must be non-empty and contain no whitespace")
        try:
            refs = self._info_refs(slug)
        except _InfoRefsPermissionError:
            if self._has_token():
                return self._resolve_ref_graphql(slug, tag)
            raise
        candidates = (tag, f"refs/tags/{tag}", f"refs/heads/{tag}")
        for candidate in candidates:
            sha = refs.get(f"{candidate}^{{}}", refs.get(candidate))
            if sha is not None:
                return sha
        raise TagAbsentError(f"tag {tag!r} not found in {slug}")

    def _resolve_ref_graphql(self, slug: str, tag: str) -> str:
        """Resolve a ref through authenticated GraphQL for private repositories."""
        owner, repo = self._slug(slug).split("/", 1)
        payload = self._graphql(
            "query($user:String!,$repo:String!,$ref:String!){"
            "user(username:$user){repository(name:$repo){"
            "revparse_single(revspec:$ref){id}}}}",
            {"user": owner[1:], "repo": repo, "ref": tag},
            absent_message=f"tag {tag!r} not found in {slug}",
        )
        try:
            repository = payload["user"]["repository"]
            commit = repository["revparse_single"]
        except (KeyError, TypeError) as exc:
            raise ResolutionError("git.sr.ht returned malformed commit metadata") from exc
        if commit is None:
            cause = ResolutionError("git.sr.ht returned a null ref result")
            raise TagAbsentError(f"tag {tag!r} not found in {slug}") from cause
        return self._sha(commit, "id", self._HOST)

    resolve_ref_to_sha = resolve_tag_to_sha
    resolve_commit_to_sha = resolve_tag_to_sha

    def archive_url(self, slug: str, commit_sha: str) -> str:
        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        return f"https://git.sr.ht/{self._slug(slug)}/archive/{sha}.tar.gz"

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[object, ...]:
        from leitir.tree import BlobEntry

        owner, repo = self._slug(slug).split("/", 1)
        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        if not self._has_token():
            raise ArchiveOnlyVerification(
                "anonymous Sourcehut archives cannot be cross-checked against the GraphQL tree API"
            )
        root = self._graphql(
            "query($user:String!,$repo:String!,$ref:String!){"
            "user(username:$user){repository(name:$repo){"
            "revparse_single(revspec:$ref){tree{id}}}}}",
            {"user": owner[1:], "repo": repo, "ref": sha},
        )
        try:
            tree_id = root["user"]["repository"]["revparse_single"]["tree"]["id"]
        except (KeyError, TypeError) as exc:
            raise ResolutionError("git.sr.ht returned malformed tree metadata") from exc
        if not isinstance(tree_id, str):
            raise ResolutionError("git.sr.ht returned malformed tree metadata")
        pending = [("", tree_id)]
        entries: list[BlobEntry] = []
        while pending:
            prefix, current = pending.pop(0)
            cursor: object = None
            while True:
                payload = self._graphql(
                    "query($user:String!,$repo:String!,$id:String!,$cursor:Cursor){"
                    "user(username:$user){repository(name:$repo){object(id:$id){"
                    "... on Tree{entries(cursor:$cursor){results{id name mode object{"
                    "type id ... on TextBlob{size content} ... on BinaryBlob{size content}"
                    "}} cursor}}}}}}",
                    {"user": owner[1:], "repo": repo, "id": current, "cursor": cursor},
                )
                try:
                    page = payload["user"]["repository"]["object"]["entries"]
                    results, cursor = page["results"], page["cursor"]
                except (KeyError, TypeError) as exc:
                    raise ResolutionError("git.sr.ht returned malformed tree metadata") from exc
                if not isinstance(results, list):
                    raise ResolutionError("git.sr.ht returned malformed tree metadata")
                for item in results:
                    try:
                        name, mode, obj = item["name"], item["mode"], item["object"]
                        object_type, object_id = obj["type"], obj["id"]
                    except (KeyError, TypeError) as exc:
                        raise ResolutionError("git.sr.ht returned malformed tree metadata") from exc
                    if not isinstance(name, str) or "/" in name or name in {"", ".", ".."}:
                        raise ResolutionError("git.sr.ht returned unsafe tree metadata")
                    path = f"{prefix}/{name}" if prefix else name
                    if object_type == "TREE" and isinstance(object_id, str):
                        pending.append((path, object_id))
                    elif object_type == "BLOB":
                        size, content = obj.get("size"), obj.get("content")
                        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                            raise ResolutionError("git.sr.ht returned malformed tree metadata")
                        url = self._safe_content_url(content)
                        blob_sha = self._sha({"id": object_id}, "id", self._HOST)
                        git_mode = self._git_mode(mode)
                        entries.append(BlobEntry(path, blob_sha, size, git_mode))
                        self._blob_urls[(slug, blob_sha)] = url
                        self._path_urls[(slug, sha, path)] = url
                    else:
                        raise ResolutionError("git.sr.ht returned unsupported tree object")
                if cursor is None:
                    break
                if not isinstance(cursor, str):
                    raise ResolutionError("git.sr.ht returned malformed tree cursor")
            pending.sort()
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def _has_token(self) -> bool:
        return self._credentials.auth_for_url(
            "https://git.sr.ht", provider=self._CREDENTIAL_PROVIDER, token=self._token
        ) is not None

    def full_tree_verification_available(self) -> bool:
        """Return whether Sourcehut's authenticated tree API can be used."""
        return self._has_token()

    def _info_refs(self, slug: str) -> dict[str, str]:
        """Return refs advertised by Sourcehut's anonymous git smart-HTTP endpoint."""
        from urllib.error import HTTPError
        from urllib.parse import urlsplit, urlunsplit
        from urllib.request import Request

        slug = self._slug(slug)
        endpoint = urlsplit(self._base_url)
        path = endpoint.path
        if path == "/query" or path.endswith("/query"):
            path = path[:-len("/query")]
        repository_base = urlunsplit(
            (endpoint.scheme, endpoint.netloc, path.rstrip("/"), "", "")
        )
        url = f"{repository_base}/{slug}/info/refs?service=git-upload-pack"

        def _fetch() -> bytes:
            with _http.safe_urlopen(
                Request(url, headers=self._headers(url, "application/x-git-upload-pack-advertisement")),
                timeout=self._timeout,
            ) as response:
                data = response.read(16 * 1024 * 1024 + 1)
                if len(data) > 16 * 1024 * 1024:
                    raise ResolutionError("git.sr.ht info/refs response exceeds size limit")
                return data

        try:
            data = self._retry(_fetch)
        except HTTPError as exc:
            message = (
                f"cannot access Sourcehut refs for {slug}: "
                f"{_http.describe_failure(exc)}"
            )
            if exc.code in (401, 403):
                raise _InfoRefsPermissionError(message) from exc
            raise ResolutionError(message) from exc
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"cannot access Sourcehut refs for {slug}: {_http.describe_failure(exc)}"
            ) from exc

        refs: dict[str, str] = {}
        offset = 0
        try:
            while offset < len(data):
                if len(data) - offset < 4:
                    raise ValueError("truncated pkt-line length")
                prefix = data[offset:offset + 4]
                length = int(prefix, 16)
                offset += 4
                if length in (0, 1, 2):
                    continue
                if length < 4 or offset + length - 4 > len(data):
                    raise ValueError("invalid pkt-line length")
                payload = data[offset:offset + length - 4]
                offset += length - 4
                payload = payload.split(b"\0", 1)[0].rstrip(b"\r\n")
                if payload.startswith(b"# service=") or not payload:
                    continue
                sha_bytes, separator, ref_bytes = payload.partition(b" ")
                sha = sha_bytes.decode("ascii")
                ref = ref_bytes.decode("utf-8")
                if (
                    not separator
                    or re.fullmatch(r"[0-9a-fA-F]{40}", sha) is None
                    or not ref
                    or any(char.isspace() for char in ref)
                    or (ref != "HEAD" and not ref.startswith("refs/"))
                ):
                    raise ValueError("malformed advertised ref")
                refs[ref] = sha.lower()
        except (UnicodeError, ValueError) as exc:
            raise ResolutionError("git.sr.ht returned malformed info/refs data") from exc
        if not refs:
            raise ResolutionError("git.sr.ht returned no advertised refs")
        return refs

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        sha = self._sha({"sha": blob_sha}, "sha", self._HOST)
        url = self._blob_urls.get((self._slug(slug), sha))
        if url is None:
            raise ResolutionError("Sourcehut blob URL is unavailable before tree enumeration")
        return self._get_bytes(url)

    def read_blob_at_commit(self, slug: str, commit_sha: str, path: str) -> bytes:
        slug = self._slug(slug)
        sha = self._sha({"sha": commit_sha}, "sha", self._HOST)
        url = self._path_urls.get((slug, sha, path))
        if url is None:
            raise ResolutionError("Sourcehut path URL is unavailable before tree enumeration")
        return self._get_bytes(url)

    def _graphql(
        self,
        query: str,
        variables: dict[str, object],
        *,
        absent_message: str | None = None,
    ) -> dict:
        from urllib.error import HTTPError
        from urllib.parse import urlencode
        from urllib.request import Request

        url = f"{self._base_url}?{urlencode({'query': query, 'variables': json.dumps(variables, separators=(',', ':'))})}"

        def _fetch() -> object:
            with _http.safe_urlopen(Request(url, headers=self._headers(self._base_url)), timeout=self._timeout) as response:
                return json.load(response)

        try:
            payload = self._retry(_fetch)
        except HTTPError as exc:
            if exc.code == 404 and absent_message is not None:
                raise TagAbsentError(f"{absent_message}: {_http.describe_failure(exc)}") from exc
            raise ResolutionError(
                f"git.sr.ht API call failed: {_http.describe_failure(exc)}"
            ) from exc
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise ResolutionError(
                f"git.sr.ht API call failed: {_http.describe_failure(exc)}"
            ) from exc
        except (ValueError, TypeError) as exc:
            raise ResolutionError("git.sr.ht returned malformed metadata") from exc
        if not isinstance(payload, dict):
            raise ResolutionError("git.sr.ht returned malformed metadata")
        errors = payload.get("errors")
        if errors:
            if absent_message is not None and self._ref_absent_errors(errors):
                cause = ResolutionError("git.sr.ht reported an absent ref")
                raise TagAbsentError(absent_message) from cause
            raise ResolutionError("git.sr.ht returned malformed metadata")
        if not isinstance(payload.get("data"), dict):
            raise ResolutionError("git.sr.ht returned malformed metadata")
        return payload["data"]

    @staticmethod
    def _ref_absent_errors(errors: object) -> bool:
        if not isinstance(errors, list) or not errors:
            return False
        absent = re.compile(
            r"(?:\b(?:ref(?:erence)?|revision|revspec|commit)\b.*"
            r"\b(?:not found|does not exist|unknown|missing|cannot be resolved)\b|"
            r"\b(?:not found|does not exist|unknown|missing|no such|"
            r"could not resolve|cannot resolve|unable to resolve)\b.*"
            r"\b(?:ref(?:erence)?|revision|revspec|commit)\b)",
            re.IGNORECASE,
        )
        messages = [
            item.get("message") if isinstance(item, dict) else None
            for item in errors
        ]
        return all(isinstance(message, str) and absent.search(message) for message in messages)

    @staticmethod
    def _git_mode(mode: object) -> str:
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0:
            raise ResolutionError("git.sr.ht returned malformed tree metadata")
        octal = format(mode, "o")
        return octal if len(octal) == 6 else "100" + octal.zfill(3)

    @staticmethod
    def _safe_content_url(value: object) -> str:
        from urllib.parse import urlsplit

        if not isinstance(value, str):
            raise ResolutionError("git.sr.ht returned malformed blob metadata")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ResolutionError("git.sr.ht returned unsafe blob URL") from exc
        if parsed.scheme != "https" or parsed.hostname != "git.sr.ht" or port not in (None, 443) or parsed.username is not None:
            raise ResolutionError("git.sr.ht returned unsafe blob URL")
        return value


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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._credentials = Credentials()
        self._base_url = _validate_network_base_url(
            base_url,
            credentialled=_base_url_is_credentialled(
                self._credentials, base_url, provider="pypi"
            ),
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        from urllib.request import Request

        if ref.ecosystem is not Ecosystem.PYPI:
            raise ResolutionError("PyPIResolver only handles pypi packages")

        url = f"{self._base_url}/{ref.name}/{ref.version}/json"

        def _fetch() -> dict:
            with _http.safe_urlopen(
                Request(url, headers=self._credentials.headers(
                    url,
                    {"User-Agent": "leitir", "Accept": "application/json"},
                    provider="pypi",
                )),
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
            published_at=self._published_at(payload),
        )

    def latest_version(self, name: str) -> str:
        """Return the registry's current version for ``name``."""
        from urllib.request import Request

        url = f"{self._base_url}/{name}/json"

        def _fetch() -> dict:
            with _http.safe_urlopen(
                Request(url, headers=self._credentials.headers(
                    url,
                    {"User-Agent": "leitir", "Accept": "application/json"},
                    provider="pypi",
                )),
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

    @staticmethod
    def _published_at(payload: object) -> str | None:
        urls = payload.get("urls") if isinstance(payload, dict) else None
        timestamps = sorted(
            item["upload_time_iso_8601"]
            for item in urls
            if isinstance(item, dict)
            and _valid_published_at(item.get("upload_time_iso_8601"))
        ) if isinstance(urls, list) else []
        return timestamps[0] if timestamps else None

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
                slug = slug.removesuffix(".git")
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
            except TagAbsentError as exc:
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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._credentials = Credentials()
        self._base_url = _validate_network_base_url(
            base_url,
            credentialled=_base_url_is_credentialled(
                self._credentials, base_url, provider="crates"
            ),
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        from urllib.request import Request

        if ref.ecosystem is not Ecosystem.CRATES:
            raise ResolutionError("CratesResolver only handles crates packages")

        url = f"{self._base_url}/{ref.name}/{ref.version}"

        def _fetch() -> dict:
            with _http.safe_urlopen(
                Request(url, headers=self._credentials.headers(
                    url, {"User-Agent": "leitir (package resolver)"}, provider="crates"
                )),
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
        slug = slug.removesuffix(".git")

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
            published_at=self._published_at(payload, ref.version),
        )

    def latest_version(self, name: str) -> str:
        """Return the registry's current version for ``name``."""
        from urllib.request import Request

        url = f"{self._base_url}/{name}"

        def _fetch() -> dict:
            with _http.safe_urlopen(
                Request(url, headers=self._credentials.headers(
                    url, {"User-Agent": "leitir (package resolver)"}, provider="crates"
                )),
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

    @staticmethod
    def _published_at(payload: object, version: str) -> str | None:
        if not isinstance(payload, dict):
            return None
        selected = payload.get("version")
        if not isinstance(selected, dict):
            versions = payload.get("versions")
            selected = next(
                (
                    item
                    for item in versions
                    if isinstance(item, dict) and item.get("num") == version
                ),
                None,
            ) if isinstance(versions, list) else None
        if not isinstance(selected, dict):
            return None
        return _first_valid_timestamp(
            selected.get("created_at"), selected.get("updated_at")
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
            except TagAbsentError as exc:
                last_err = exc
        raise last_err or ResolutionError(f"no tag found for {name} {version}")


class GoResolver:
    """Resolves a Go module + version to its supported repository host."""

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
        repository_resolvers: dict[str, _RepositoryResolver] | None = None,
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._repository_resolvers: dict[str, _RepositoryResolver] = {
            "github.com": tag_resolver,
            "gitlab.com": GitLabResolver(),
            "bitbucket.org": BitbucketResolver(),
        }
        if repository_resolvers is not None:
            self._repository_resolvers.update(repository_resolvers)
        self._timeout = timeout
        self._base_url = _validate_network_base_url(
            base_url,
            credentialled=False,
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        from urllib.request import Request

        if ref.ecosystem is not Ecosystem.GO:
            raise ResolutionError("GoResolver only handles go packages")

        module = ref.name
        host, candidates = self._repository_candidates(module)

        escaped = self._escape_module(module)
        version = ref.version
        info_url = f"{self._base_url}/{escaped}/@v/{version}.info"

        def _fetch() -> dict:
            with _http.safe_urlopen(
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

        if host == "go-module-zip":
            source_id = hashlib.sha1(f"{module}@{version}".encode()).hexdigest()
            scope = RepoScope(f"module/{source_id}", source_id)
            from leitir.docpointers import extract_docs_urls

            return ResolvedPackage(
                ref=ref,
                scope=scope,
                tag=version,
                registry_url=f"https://pkg.go.dev/{module}@{version}",
                docs_urls=tuple(
                    extract_docs_urls(ref.ecosystem, name=module, version=version)
                ),
                host=host,
                go_module_zip=True,
                go_proxy_url=self._base_url,
            )
        resolver = self._repository_resolvers[host]

        tag = version
        pseudo = self._PSEUDO_VERSION.fullmatch(version)
        slug = ""
        subpath = None
        last_error: ResolutionError | None = None
        for candidate_slug, candidate_subpath in candidates:
            try:
                if pseudo is None:
                    tags = (
                        (f"{candidate_subpath}/{version}", version)
                        if candidate_subpath is not None
                        else (version,)
                    )
                    for candidate_tag in tags:
                        try:
                            commit_sha = resolver.resolve_tag_to_sha(
                                candidate_slug, candidate_tag
                            )
                            tag = candidate_tag
                            break
                        except TagAbsentError as exc:
                            last_error = exc
                    else:
                        continue
                else:
                    expand = getattr(resolver, "resolve_commit_to_sha", None)
                    if expand is None:
                        raise ResolutionError(
                            f"Go pseudo-version resolution for {host} requires commit expansion"
                        )
                    commit_sha = expand(candidate_slug, pseudo.group(1))
                slug = candidate_slug
                subpath = candidate_subpath
                break
            except TagAbsentError as exc:
                last_error = exc
        else:
            raise last_error or ResolutionError(
                f"repository for Go module {module!r} could not be resolved"
            )
        scope = RepoScope(slug=slug, commit_sha=commit_sha)
        from leitir.docpointers import extract_docs_urls

        return ResolvedPackage(
            ref=ref,
            scope=scope,
            tag=tag,
            registry_url=f"https://pkg.go.dev/{module}@{version}",
            subpath=subpath,
            docs_urls=tuple(
                extract_docs_urls(ref.ecosystem, name=module, version=version)
            ),
            host=host,
        )

    @staticmethod
    def _repository_candidates(module: str) -> tuple[str, tuple[tuple[str, str | None], ...]]:
        parts = module.split("/")
        if any(
            part in {"", ".", ".."}
            or re.fullmatch(r"[A-Za-z0-9_.~+-]+", part) is None
            for part in parts
        ):
            raise ResolutionError(f"invalid Go module path {module!r}")
        module_host = parts[0].lower()
        if module_host == "golang.org":
            if len(parts) < 3 or parts[1] != "x":
                raise ResolutionError(f"unsupported Go module host {parts[0]!r}")
            remainder = parts[3:]
            if len(remainder) == 1 and re.fullmatch(r"v[2-9][0-9]*", remainder[0]):
                remainder = []
            subpath = "/".join(remainder) or None
            return "github.com", ((f"golang/{parts[2]}", subpath),)
        if module_host not in {"github.com", "gitlab.com", "bitbucket.org"}:
            return "go-module-zip", ()
        if len(parts) < 3:
            raise ResolutionError(f"invalid Go module path {module!r}")
        if module_host == "gitlab.com":
            return module_host, tuple(
                ("/".join(parts[1:end]), "/".join(parts[end:]) or None)
                for end in range(len(parts), 2, -1)
            )
        slug = f"{parts[1]}/{parts[2]}"
        remainder = parts[3:]
        if len(remainder) == 1 and re.fullmatch(r"v[2-9][0-9]*", remainder[0]):
            remainder = []
        subpath = "/".join(remainder) or None
        return module_host, ((slug, subpath),)

    def latest_version(self, name: str) -> str:
        """Return the Go proxy's current version for ``name``."""
        from urllib.request import Request

        escaped = self._escape_module(name)
        url = f"{self._base_url}/{escaped}/@latest"

        def _fetch() -> dict:
            with _http.safe_urlopen(
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
        return escape_go_module_path(module)


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
        allow_insecure_http_for_tests: bool = False,
    ) -> None:
        self._tag_resolver = tag_resolver
        self._timeout = timeout
        self._credentials = Credentials()
        self._base_url = _validate_network_base_url(
            base_url,
            credentialled=_base_url_is_credentialled(
                self._credentials, base_url, provider="npm"
            ),
            allow_insecure_http_for_tests=allow_insecure_http_for_tests,
        )
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _metadata(self, name: str) -> tuple[dict, str]:
        from urllib.parse import quote
        from urllib.request import Request

        encoded = quote(name, safe="")
        url = f"{self._base_url}/{encoded}"
        logger.debug("resolver querying ecosystem=npm package=%s url=%s", name, url)

        def _fetch() -> dict:
            with _http.safe_urlopen(
                Request(url, headers=self._credentials.headers(
                    url,
                    {"Accept": "application/json", "User-Agent": "leitir"},
                    provider="npm",
                )),
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
        value = value.removesuffix(".git")
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
        logger.debug("resolving ecosystem=%s package=%s version=%s", ref.ecosystem.value, ref.name, ref.version)
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
                logger.debug("resolved package=%s@%s slug=%s tag=%s sha=%s artifact=%s", ref.name, ref.version, slug, tag, sha[:12], "registry-artifact" if self._artifact(ref, payload) is not None else "git-commit")
                return ResolvedPackage(
                    ref=ref,
                    scope=RepoScope(slug, sha),
                    tag=tag,
                    registry_url=f"https://www.npmjs.com/package/{encoded}/v/{ref.version}",
                    subpath=directory,
                    docs_urls=docs_urls,
                    artifact=self._artifact(ref, payload),
                    published_at=self._published_at(payload, ref.version),
                )
            except TagAbsentError:
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

    @staticmethod
    def _published_at(payload: object, version: str) -> str | None:
        if not isinstance(payload, dict):
            return None
        times = payload.get("time")
        if not isinstance(times, dict):
            return None
        return _first_valid_timestamp(times.get(version), times.get("created"))


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
        codeberg: CodebergResolver | None = None,
        sourcehut: SourcehutResolver | None = None,
    ) -> None:
        self._tag_resolver = pypi._tag_resolver
        self._resolvers: dict[Ecosystem, _EcosystemResolver] = {
            Ecosystem.PYPI: pypi,
            Ecosystem.CRATES: crates,
            Ecosystem.GO: go,
            Ecosystem.NPM: npm or NpmResolver(self._tag_resolver),
        }
        self._repository_resolvers: dict[str, _RepositoryResolver] = {
            "github.com": self._tag_resolver,
            "gitlab.com": gitlab or GitLabResolver(),
            "bitbucket.org": bitbucket or BitbucketResolver(),
            "codeberg.org": codeberg or CodebergResolver(),
            "git.sr.ht": sourcehut or SourcehutResolver(),
        }
        go._repository_resolvers.update(self._repository_resolvers)

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        resolver = self._resolvers.get(ref.ecosystem)
        if resolver is None:
            raise ResolutionError(f"no resolver for {ref.ecosystem}")
        result = resolver.resolve(ref)
        logger.debug("resolution result ecosystem=%s package=%s version=%s scope=%s@%s", ref.ecosystem.value, ref.name, ref.version, result.scope.slug, result.scope.commit_sha[:12])
        return result

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

    def published_at_for_commit(self, slug: str, commit_sha: str) -> str:
        """Return GitHub commit publication metadata for direct GitHub specs."""
        return self._tag_resolver.published_at_for_commit(slug, commit_sha)
