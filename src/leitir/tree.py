"""Tree enumeration over a strictly pinned commit.

ADR-001 P2: the scoped-exhaustive searcher needs to enumerate every blob in a
declared repository at an immutable commit SHA.  ``TreeSource`` is the port;
``GitHubTreeSource`` is the production adapter that talks to the GitHub REST API.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from leitir import _http


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
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "leitir",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get_json(self, url: str, headers: dict[str, str]) -> dict:
        from urllib.request import Request, urlopen

        def _fetch() -> dict:
            with urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(f"GitHub API call failed: {_http.describe_failure(exc)}") from exc

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        url = f"{self._base_url}/repos/{slug}/git/trees/{commit_sha}?recursive=1"
        payload = self._get_json(url, self._headers())
        if payload.get("truncated"):
            raise TreeTruncatedError(slug, commit_sha)
        entries: list[BlobEntry] = []
        for item in payload.get("tree", []):
            if item.get("type") != "blob":
                continue
            entries.append(
                BlobEntry(
                    path=item["path"],
                    blob_sha=item["sha"],
                    size=item.get("size", 0),
                    mode=item.get("mode"),
                )
            )
        return tuple(entries)

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        import base64
        from urllib.request import Request, urlopen

        url = f"{self._base_url}/repos/{slug}/git/blobs/{blob_sha}"
        headers = self._headers()

        def _fetch() -> bytes:
            with urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                payload = json.load(resp)
            return base64.b64decode(payload["content"])

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(
                f"cannot read blob {slug}/{blob_sha}: {_http.describe_failure(exc)}"
            ) from exc

    def read_blob_by_path(
        self, slug: str, commit_sha: str, path: str
    ) -> bytes:
        from urllib.request import Request, urlopen

        url = f"{self._raw_base_url}/{slug}/{commit_sha}/{path}"

        def _fetch() -> bytes:
            with urlopen(
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


class TreeTruncatedError(Exception):
    """The GitHub tree API returned a truncated response."""

    def __init__(self, slug: str, commit_sha: str) -> None:
        super().__init__(
            f"tree for {slug}@{commit_sha} was truncated by the API"
        )
        self.slug = slug
        self.commit_sha = commit_sha


class TreeReadError(Exception):
    """A GitHub tree/blob HTTP call failed after categorized retry."""
