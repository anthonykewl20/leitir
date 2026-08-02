"""Tree enumeration over a strictly pinned commit.

ADR-001 P2: the scoped-exhaustive searcher needs to enumerate every blob in a
declared repository at an immutable commit SHA.  ``TreeSource`` is the port;
``GitHubTreeSource`` is the production adapter that talks to the GitHub REST API.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class BlobEntry:
    """One blob discovered in a git tree."""

    path: str
    blob_sha: str
    size: int

    def __post_init__(self) -> None:
        if not self.path or not self.path.strip():
            raise ValueError("path must be non-empty")
        if not self.blob_sha or len(self.blob_sha) != 40:
            raise ValueError("blob_sha must be a 40-char hex string")
        if self.size < 0:
            raise ValueError("size must be non-negative")


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

    def __init__(self, token: str | None = None, timeout: int = 60) -> None:
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

    def _get_json(self, url: str) -> dict:
        from urllib import request as urllib_request

        request = urllib_request.Request(url, headers=self._headers())
        with urllib_request.urlopen(request, timeout=self._timeout) as resp:
            return json.load(resp)

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        url = f"{self._API}/repos/{slug}/git/trees/{commit_sha}?recursive=1"
        payload = self._get_json(url)
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
                )
            )
        return tuple(entries)

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        from urllib import request as urllib_request

        url = f"{self._API}/repos/{slug}/git/blobs/{blob_sha}"
        request = urllib_request.Request(url, headers=self._headers())
        with urllib_request.urlopen(request, timeout=self._timeout) as resp:
            payload = json.load(resp)
        import base64

        return base64.b64decode(payload["content"])

    def read_blob_by_path(
        self, slug: str, commit_sha: str, path: str
    ) -> bytes:
        from urllib import request as urllib_request

        url = f"{self._RAW}/{slug}/{commit_sha}/{path}"
        request = urllib_request.Request(url, headers={"User-Agent": "leitir"})
        with urllib_request.urlopen(request, timeout=self._timeout) as resp:
            return resp.read()

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
