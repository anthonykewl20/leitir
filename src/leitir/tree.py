"""Tree enumeration over a strictly pinned commit.

ADR-001 P2: the scoped-exhaustive searcher needs to enumerate every blob in a
declared repository at an immutable commit SHA.  ``TreeSource`` is the port;
``GitHubTreeSource`` is the production adapter that talks to the GitHub REST API.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from threading import Lock
from typing import Protocol, runtime_checkable

from leitir import _http

logger = logging.getLogger(__name__)

MAX_TREE_DEPTH = 64
# A truncation-recovery walk costs one request per distinct subtree.  GitHub
# truncates recursive listings far below the directory count of large repos:
# microsoft/TypeScript@b465fdb… exposes 2,002 subtree entries in its truncated
# recursive listing (OBSERVED 2026-08-18) and the walk needs one page per
# distinct subtree, so the budget must dwarf 256 while still bounding runaway
# walks fail-closed (visited-set dedup plus depth/entry budgets assist).
MAX_TREE_REQUESTS = 10_000
MAX_TREE_ENTRIES = 600_000
STREAM_CHUNK_SIZE = 64 * 1024
# Hard upper bound on the total bytes a single read_blob_stream call may
# yield.  GitHub blobs served through the git blobs API are at most 100 MiB;
# the tighter 64 MiB constant bounds runaway streams fail-closed while
# leaving headroom above the largest pinned canary fixture (2.4 MiB,
# OBSERVED 2026-08-20).  Chosen per #197's non-functional requirement
# ("bounded total bytes (constant value … recorded in PR)").
STREAM_MAX_BYTES = 64 * 1024 * 1024


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
        if not self.blob_sha or len(self.blob_sha) != 40 or not _is_hex(self.blob_sha):
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

    def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]: ...


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
        self._tree_cache_lock = Lock()
        self._tree_cache: OrderedDict[tuple[str, str], tuple[tuple[BlobEntry, ...], bool]] = OrderedDict()
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

    def _remember_tree(self, key: tuple[str, str], result: tuple[tuple[BlobEntry, ...], bool]) -> tuple[tuple[BlobEntry, ...], bool]:
        # Complete immutable listings only; never publish a failed walk's
        # partial_blobs. Bound both the shelf count and retained entry count.
        with self._tree_cache_lock:
            self._tree_cache[key] = result
            self._tree_cache.move_to_end(key)
            while len(self._tree_cache) > 4 or sum(len(value[0]) for value in self._tree_cache.values()) > MAX_TREE_ENTRIES:
                self._tree_cache.popitem(last=False)
        return result

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        commit_sha = _require_hex_sha(commit_sha)
        cache_key = (slug, commit_sha)
        with self._tree_cache_lock:
            cached = self._tree_cache.get(cache_key)
            if cached is not None:
                self._tree_cache.move_to_end(cache_key)
                return cached
        url = f"{self._base_url}/repos/{slug}/git/trees/{commit_sha}?recursive=1"
        logger.debug("tree API url=%s", url)
        payload = self._get_json(url, self._headers())
        if not isinstance(payload, dict):
            raise TreeEnumerationError(
                "malformed tree response: expected JSON object"
            )
        root_tree_sha = _require_response_sha(payload)
        truncated = _require_truncated(payload)
        if not truncated:
            blobs = _recursive_blobs(payload)
            logger.debug("tree fetched blobs=%d slug=%s sha=%s", len(blobs), slug, commit_sha[:12])
            return self._remember_tree(cache_key, (blobs, False))

        stack = [(root_tree_sha, "")]
        visited: set[tuple[str, str]] = set()
        cache: dict[str, tuple[dict[str, object], ...]] = {}
        blobs_by_path: dict[str, BlobEntry] = {}
        occupied_paths: set[str] = set()
        requests = 0
        entry_count = 0

        def partial_blobs() -> tuple[BlobEntry, ...]:
            return tuple(blobs_by_path[path] for path in sorted(blobs_by_path))

        while stack:
            tree_sha, prefix = stack.pop()
            try:
                tree_sha = _require_hex_sha(tree_sha)
            except TreeEnumerationError as exc:
                exc.attach_partial_blobs(partial_blobs())
                raise
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
                if not isinstance(subtree, dict):
                    raise TreeEnumerationError(
                        "malformed tree response: expected JSON object",
                        partial_blobs=partial_blobs(),
                    )
                try:
                    response_sha = _require_response_sha(subtree)
                    if response_sha != tree_sha:
                        raise TreeEnumerationError(
                            "malformed tree response: response SHA does not match requested tree"
                        )
                    nested_truncated = _require_truncated(subtree)
                except TreeEnumerationError as exc:
                    exc.attach_partial_blobs(partial_blobs())
                    raise
                if nested_truncated:
                    raise TreeTruncatedError(
                        slug, commit_sha, partial_blobs=partial_blobs()
                    )
                try:
                    cache[tree_sha] = tuple(
                        sorted(
                            _require_tree_array(subtree),
                            key=_validated_item_sort_key,
                        )
                    )
                except TreeEnumerationError as exc:
                    exc.attach_partial_blobs(partial_blobs())
                    raise
            subtrees: list[tuple[str, str]] = []
            for item in cache[tree_sha]:
                entry_count += 1
                if entry_count > MAX_TREE_ENTRIES:
                    raise TreeWalkBudgetError(
                        "tree walk entry budget exhausted", partial_blobs=partial_blobs()
                    )
                try:
                    path, kind, sha = _validated_item(
                        prefix, item, allow_nested_path=False
                    )
                    full_path = f"{prefix}/{path}" if prefix else path
                    if full_path in occupied_paths:
                        raise TreeEnumerationError("duplicate path in tree walk")
                    occupied_paths.add(full_path)
                    if kind == "blob":
                        blobs_by_path[full_path] = _blob_entry(full_path, sha, item)
                    elif kind == "tree":
                        subtrees.append((sha, full_path))
                except TreeEnumerationError as exc:
                    exc.attach_partial_blobs(partial_blobs())
                    raise
            stack.extend(reversed(subtrees))
        return self._remember_tree(cache_key, (partial_blobs(), True))

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        """Return the complete blob universe reachable from *commit_sha*.

        When GitHub marks the recursive listing truncated (large repositories
        such as microsoft/TypeScript), enumeration completes through the same
        deterministic, budgeted, non-recursive subtree walk that
        ``list_blobs_ex`` performs — a truncated top-level listing no longer
        raises ``TreeTruncatedError`` here and the result is never silently
        downgraded to a sample.  Enumeration inconsistencies fail closed with
        a typed ``TreeEnumerationError`` with the blobs recovered so far
        attached as ``partial_blobs``; transport exhaustion after categorized
        retry raises ``TreeReadError``, which carries no partial blobs.
        Non-truncated repositories keep the single-request recursive path
        with byte-identical output (same entries, same order).
        """
        blobs, _recovered = self.list_blobs_ex(slug, commit_sha)
        return blobs

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        import base64
        import binascii
        from urllib.request import Request

        try:
            canonical_blob_sha = _require_hex_sha(blob_sha)
        except TreeEnumerationError as exc:
            raise TreeReadError("cannot read blob: malformed requested blob SHA") from exc

        url = f"{self._base_url}/repos/{slug}/git/blobs/{canonical_blob_sha}"
        headers = self._headers()

        def _fetch() -> bytes:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                payload = json.load(resp)
            if not isinstance(payload, dict):
                raise TreeReadError("malformed blob response: expected JSON object")
            try:
                decoded = base64.b64decode(payload["content"])
            except (KeyError, TypeError, ValueError, binascii.Error) as exc:
                raise TreeReadError("malformed blob response: invalid content") from exc

            response_sha = payload.get("sha")
            if (
                not isinstance(response_sha, str)
                or len(response_sha) != 40
                or not _is_hex(response_sha)
                or response_sha.lower() != canonical_blob_sha
            ):
                raise TreeReadError(
                    "malformed blob response: response SHA does not match requested blob"
                )
            response_size = payload.get("size")
            if (
                isinstance(response_size, bool)
                or not isinstance(response_size, int)
                or response_size != len(decoded)
            ):
                raise TreeReadError(
                    "malformed blob response: size does not match decoded content"
                )
            if self.git_blob_sha(decoded) != canonical_blob_sha:
                raise TreeReadError(
                    "malformed blob response: content does not match requested blob SHA"
                )
            return decoded

        try:
            return self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(
                f"cannot read blob {slug}/{blob_sha}: {_http.describe_failure(exc)}"
            ) from exc

    def read_blob_stream(
        self, slug: str, blob_sha: str, *, max_bytes: int = STREAM_MAX_BYTES
    ) -> Iterator[bytes]:
        """Stream one blob's raw bytes with *part* of read_blob's discipline.

        What IS inherited from read_blob: the requested SHA is validated
        (``_require_hex_sha``) before any URL is built — a malformed or
        hostile ``blob_sha`` raises a typed :class:`TreeReadError` eagerly,
        never a raw ``HTTPError``/``AttributeError`` escape — connection
        setup goes through the shared categorized retry policy, transport
        failures surface as typed ``TreeReadError`` instead of escaping the
        taxonomy, and the response is closed promptly even when the consumer
        abandons the generator mid-iteration. The total streamed size is
        bounded by ``max_bytes`` (a stream crossing the bound fails closed
        with a typed error).

        What is NOT inherited: read_blob's response-envelope verification
        (response SHA == requested, declared size == decoded length,
        git-blob digest of decoded content == requested SHA). A raw stream
        has no JSON envelope to check, so the caller MUST verify the
        streamed bytes' digest and length itself — as
        ``streaming.score_blob_stream`` does (git-blob sha1 over the chunks
        plus a declared-size check).

        Mid-stream read failures are not retried here: bytes were already
        yielded, so a replay would duplicate them; they fail typed instead.
        The prior consumer-replay behavior is preserved at the consumer
        level: ``streaming.score_blob_stream`` wraps the entire consumption
        in its own retry seam, and each replay starts a fresh generator, so
        whole-attempt replay remains safe.
        """
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise TreeReadError("cannot stream blob: max_bytes must be a positive integer")
        try:
            canonical_blob_sha = _require_hex_sha(blob_sha)
        except TreeEnumerationError as exc:
            raise TreeReadError("cannot stream blob: malformed requested blob SHA") from exc
        return self._stream_blob(slug, canonical_blob_sha, max_bytes)

    def _stream_blob(
        self, slug: str, canonical_blob_sha: str, max_bytes: int
    ) -> Iterator[bytes]:
        from urllib.request import Request

        url = f"{self._base_url}/repos/{slug}/git/blobs/{canonical_blob_sha}"
        headers = self._headers()
        headers["Accept"] = "application/vnd.github.raw"

        def _open():
            return _http.safe_urlopen(
                Request(url, headers=headers), timeout=self._timeout
            )

        try:
            response = self._retry(_open)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise TreeReadError(
                f"cannot stream blob {slug}/{canonical_blob_sha}: "
                f"{_http.describe_failure(exc)}"
            ) from exc

        received = 0
        try:
            while True:
                try:
                    chunk = response.read(STREAM_CHUNK_SIZE)
                except _http.RETRIABLE_EXCEPTIONS as exc:
                    raise TreeReadError(
                        f"cannot stream blob {slug}/{canonical_blob_sha}: "
                        f"{_http.describe_failure(exc)}"
                    ) from exc
                if not chunk:
                    break
                received += len(chunk)
                if received > max_bytes:
                    raise TreeReadError(
                        f"cannot stream blob {slug}/{canonical_blob_sha}: "
                        f"streamed {received} bytes exceeds max_bytes={max_bytes}"
                    )
                yield chunk
        finally:
            # Context-manager discipline: an abandoned generator must not
            # leave the response open.  Closing through the attribute keeps
            # test doubles without ``close()`` working (they hold no fd).
            close = getattr(response, "close", None)
            if callable(close):
                close()

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


def _require_response_sha(payload: dict[str, object]) -> str:
    try:
        return _require_hex_sha(payload.get("sha"))
    except TreeEnumerationError as exc:
        raise TreeEnumerationError("malformed tree response: invalid response SHA") from exc


def _require_truncated(payload: dict[str, object]) -> bool:
    truncated = payload.get("truncated")
    if not isinstance(truncated, bool):
        raise TreeEnumerationError("malformed tree response: invalid truncated flag")
    return truncated


def _validated_item(
    prefix: str,
    item: dict[str, object],
    *,
    allow_nested_path: bool = True,
) -> tuple[str, str, str]:
    kind = item.get("type")
    path = item.get("path")
    sha = item.get("sha")
    if (
        kind not in ("blob", "tree", "commit")
        or not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\x00" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
        or (not allow_nested_path and "/" in path)
    ):
        raise TreeEnumerationError("malformed tree item")
    return path, kind, _require_hex_sha(sha)


def _validated_item_sort_key(item: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(item.get("path") or ""),
        str(item.get("type") or ""),
        str(item.get("sha") or ""),
    )


def _recursive_blobs(payload: dict[str, object]) -> tuple[BlobEntry, ...]:
    entries: dict[str, BlobEntry] = {}
    for item in _require_tree_array(payload):
        path, kind, sha = _validated_item("", item)
        if kind != "blob":
            continue
        if path in entries:
            raise TreeEnumerationError("duplicate path in recursive tree")
        entries[path] = _blob_entry(path, sha, item)
    return tuple(entries[path] for path in sorted(entries))


def _path_depth(prefix: str) -> int:
    return 0 if not prefix else prefix.count("/") + 1


def _require_hex_sha(value: object) -> str:
    if not isinstance(value, str) or len(value) != 40 or not _is_hex(value):
        raise TreeEnumerationError("malformed tree item")
    return value.lower()


def _is_hex(value: str) -> bool:
    return all(char in "0123456789abcdefABCDEF" for char in value)


def _blob_entry(
    path: str, sha: str, item: dict[str, object]
) -> BlobEntry:
    size = item.get("size")
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

    def attach_partial_blobs(self, blobs: tuple[BlobEntry, ...]) -> None:
        if not self.partial_blobs:
            self.partial_blobs = blobs


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
