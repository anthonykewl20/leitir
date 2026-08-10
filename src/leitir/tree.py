"""Tree enumeration over a strictly pinned commit.

ADR-001 P2: the scoped-exhaustive searcher needs to enumerate every blob in a
declared repository at an immutable commit SHA.  ``TreeSource`` is the port;
``GitHubTreeSource`` is the production adapter that talks to the GitHub REST API.
"""

from __future__ import annotations

import hashlib
import json
import logging
import string
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from leitir import _http

logger = logging.getLogger(__name__)

MAX_TREE_DEPTH = 64
MAX_TREE_REQUESTS = 256
MAX_TREE_ENTRIES = 600_000


@dataclass(frozen=True, slots=True)
class BlobEntry:
    """One blob discovered in a git tree."""

    path: str
    blob_sha: str
    size: int
    mode: str | None = None

    def __post_init__(self) -> None:
        if not self.path or not self.path.strip():
            raise ValueError("path must be non-empty")
        if not self.blob_sha or len(self.blob_sha) != 40:
            raise ValueError("blob_sha must be a 40-char hex string")
        if self.size < 0:
            raise ValueError("size must be non-negative")
        if self.mode is not None and not isinstance(self.mode, str):
            raise ValueError("mode must be a string when provided")


@runtime_checkable
class TreeSource(Protocol):
    """Port: enumerate blobs and read their content at a pinned commit."""

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        ...

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        """Return every blob reachable from *commit_sha*."""
        ...

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        """Return the raw bytes of one blob."""
        ...


class GitHubTreeSource:
    """TreeSource backed by the GitHub REST API (anonymous or tokened)."""

    _API = "https://api.github.com"
    _RAW = "https://raw.githubusercontent.com"

    def __init__(
        self,
        token: str | None = None,
        timeout: int = 60,
        *,
        base_url: str = _API,
        raw_base_url: str = _RAW,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_rate_limit_delay: float = 300.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._token = token
        if token:
            from leitir.logging import register_secret

            register_secret(token)
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._raw_base_url = raw_base_url.rstrip("/")
        self._retry = _http.make_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=sleeper,
        )

    def _headers(self) -> dict[str, str]:
        from urllib.parse import urlsplit

        from leitir.credentials import validate_secret

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "leitir",
        }
        if self._token is not None:
            validate_secret(self._token, kind="token")
        endpoint = urlsplit(self._base_url)
        if (
            self._token
            and endpoint.scheme.lower() == "https"
            and endpoint.hostname == "api.github.com"
            and endpoint.port in (None, 443)
        ):
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get_json(self, url: str, headers: dict[str, str]) -> dict:
        from urllib.request import Request

        def _fetch() -> dict:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(f"GitHub API call failed: {_http.describe_failure(exc)}") from exc

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        url = f"{self._base_url}/repos/{slug}/git/trees/{commit_sha}?recursive=1"
        logger.debug("tree API url=%s", url)
        payload = self._get_json(url, self._headers())
        if not payload.get("truncated"):
            blobs = _recursive_blobs(payload)
            logger.debug("tree fetched blobs=%d slug=%s sha=%s", len(blobs), slug, commit_sha[:12])
            return blobs, False

        stack = [(commit_sha, "")]
        visited: set[tuple[str, str]] = set()
        cache: dict[str, tuple[dict[str, object], ...]] = {}
        blobs_by_path: dict[str, BlobEntry] = {}
        requests = 0
        entry_count = 0

        def partial_blobs() -> tuple[BlobEntry, ...]:
            return tuple(blobs_by_path[path] for path in sorted(blobs_by_path))

        while stack:
            tree_sha, prefix = stack.pop()
            key = (tree_sha, prefix)
            if key in visited:
                continue
            if _path_depth(prefix) > MAX_TREE_DEPTH:
                raise TreeWalkBudgetError(
                    "tree walk depth budget exhausted", partial_blobs=partial_blobs()
                )
            visited.add(key)
            if tree_sha not in cache:
                if requests >= MAX_TREE_REQUESTS:
                    raise TreeWalkBudgetError(
                        "tree walk request budget exhausted", partial_blobs=partial_blobs()
                    )
                subtree_url = f"{self._base_url}/repos/{slug}/git/trees/{tree_sha}"
                subtree = self._get_json(subtree_url, self._headers())
                requests += 1
                if subtree.get("truncated"):
                    raise TreeTruncatedError(
                        slug, commit_sha, partial_blobs=partial_blobs()
                    )
                try:
                    cache[tree_sha] = tuple(
                        sorted(
                            _require_tree_array(subtree),
                            key=lambda item: (
                                str(item.get("path", "")),
                                str(item.get("sha", "")),
                            ),
                        )
                    )
                except TreeEnumerationError as exc:
                    exc.partial_blobs = partial_blobs()
                    raise
            for item in cache[tree_sha]:
                entry_count += 1
                if entry_count > MAX_TREE_ENTRIES:
                    raise TreeWalkBudgetError(
                        "tree walk entry budget exhausted", partial_blobs=partial_blobs()
                    )
                try:
                    path, kind, sha = _validated_item(prefix, item)
                    full_path = f"{prefix}/{path}" if prefix else path
                    if kind == "blob":
                        if full_path in blobs_by_path:
                            raise TreeEnumerationError("duplicate path in tree walk")
                        blobs_by_path[full_path] = _blob_entry(full_path, sha, item)
                    elif kind == "tree":
                        stack.append((sha, full_path))
                except TreeEnumerationError as exc:
                    exc.partial_blobs = partial_blobs()
                    raise
        return partial_blobs(), True

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        url = f"{self._base_url}/repos/{slug}/git/trees/{commit_sha}?recursive=1"
        logger.debug("tree API url=%s", url)
        payload = self._get_json(url, self._headers())
        if payload.get("truncated"):
            raise TreeTruncatedError(slug, commit_sha, partial_blobs=())
        return _recursive_blobs(payload)

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        import base64
        from urllib.request import Request

        url = f"{self._base_url}/repos/{slug}/git/blobs/{blob_sha}"
        headers = self._headers()

        def _fetch() -> bytes:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                payload = json.load(resp)
            return base64.b64decode(payload["content"])

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(
                f"cannot read blob {slug}/{blob_sha}: {_http.describe_failure(exc)}"
            ) from exc

    def read_blob_at_commit(self, slug: str, commit_sha: str, path: str) -> bytes:
        """Read a path's exact bytes through the contents API at a commit."""
        from urllib.parse import quote, urlencode
        from urllib.request import Request

        encoded_path = quote(path, safe="/")
        url = (
            f"{self._base_url}/repos/{slug}/contents/{encoded_path}"
            f"?{urlencode({'ref': commit_sha})}"
        )
        headers = self._headers()
        headers["Accept"] = "application/vnd.github.raw+json"

        def _fetch() -> bytes:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return resp.read()

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(
                f"cannot read blob {slug}/{commit_sha}/{path}: "
                f"{_http.describe_failure(exc)}"
            ) from exc

    def read_blob_by_path(
        self, slug: str, commit_sha: str, path: str
    ) -> bytes:
        from urllib.parse import quote
        from urllib.request import Request

        safe_slug = quote(slug, safe="/")
        safe_path = quote(path, safe="/")
        url = f"{self._raw_base_url}/{safe_slug}/{commit_sha}/{safe_path}"

        def _fetch() -> bytes:
            with _http.safe_urlopen(
                Request(url, headers={"User-Agent": "leitir"}), timeout=self._timeout
            ) as resp:
                return resp.read()

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(
                f"cannot read blob {slug}/{commit_sha}/{path}: "
                f"{_http.describe_failure(exc)}"
            ) from exc

    @staticmethod
    def git_blob_sha(data: bytes) -> str:
        return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def _require_tree_array(
    payload: dict[str, object],
) -> tuple[dict[str, object], ...]:
    tree = payload.get("tree")
    if not isinstance(tree, list) or not all(isinstance(item, dict) for item in tree):
        raise TreeEnumerationError("malformed tree response")
    return tuple(tree)


def _validated_item(
    prefix: str, item: dict[str, object]
) -> tuple[str, str, str]:
    kind = item.get("type")
    path = item.get("path")
    sha = item.get("sha")
    if (
        kind not in ("blob", "tree", "commit")
        or not isinstance(path, str)
        or not path
        or not isinstance(sha, str)
        or len(sha) != 40
        or any(char not in string.hexdigits for char in sha)
    ):
        raise TreeEnumerationError("malformed tree item")
    return path, kind, sha


def _recursive_blobs(payload: dict[str, object]) -> tuple[BlobEntry, ...]:
    entries: list[BlobEntry] = []
    for item in _require_tree_array(payload):
        path, kind, sha = _validated_item("", item)
        if kind != "blob":
            continue
        entries.append(_blob_entry(path, sha, item))
    return tuple(sorted(entries, key=lambda entry: entry.path))


def _path_depth(prefix: str) -> int:
    return prefix.count("/")


def _blob_entry(
    path: str, sha: str, item: dict[str, object]
) -> BlobEntry:
    size = item.get("size", 0)
    mode = item.get("mode")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise TreeEnumerationError("malformed tree item")
    if mode is not None and not isinstance(mode, str):
        raise TreeEnumerationError("malformed tree item")
    return BlobEntry(path=path, blob_sha=sha, size=size, mode=mode)


class TreeEnumerationError(Exception):
    def __init__(
        self, message: str, *, partial_blobs: tuple[BlobEntry, ...] = ()
    ) -> None:
        super().__init__(message)
        self.partial_blobs = partial_blobs


class TreeTruncatedError(TreeEnumerationError):
    """The GitHub tree API returned a truncated response."""

    def __init__(
        self,
        slug: str,
        commit_sha: str,
        *,
        partial_blobs: tuple[BlobEntry, ...] = (),
    ) -> None:
        super().__init__(
            f"tree for {slug}@{commit_sha} was truncated by the API",
            partial_blobs=partial_blobs,
        )
        self.slug = slug
        self.commit_sha = commit_sha


class TreeWalkBudgetError(TreeEnumerationError):
    pass


class TreeReadError(Exception):
    """A GitHub tree/blob HTTP call failed after categorized retry."""
