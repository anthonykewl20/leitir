"""Global discovery via GitHub Code Search with honest coverage (ADR-001 P5).

``GlobalSearcher`` handles ``SearchSpec`` in ``GLOBAL_DISCOVERY`` mode. It
translates typed predicates into a GitHub Code Search query, fetches matching
blobs, evaluates them through language adapters for precise spans, and returns
a ``SearchReport`` whose coverage is always ``INDETERMINATE_GLOBAL``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from leitir import _http
from leitir.adapters import LanguageAdapter
from leitir.credentials import validate_secret
from leitir.engine import score_content
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    SearchMode,
    SearchReport,
    SearchSpec,
    SourceMatch,
)
from leitir.tree import TreeReadError, TreeSource, TreeTruncatedError

_API = "https://api.github.com"
_RAW = "https://raw.githubusercontent.com"
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
logger = logging.getLogger(__name__)


def _git_blob_sha(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()


@dataclass(frozen=True, slots=True)
class CodeSearchHit:
    """One file-level result from a code search API."""

    slug: str
    path: str
    blob_sha: str
    html_url: str

    def __post_init__(self) -> None:
        if not self.slug or "/" not in self.slug:
            raise ValueError("slug must look like 'owner/repo'")
        if not self.path or not self.path.strip():
            raise ValueError("path must be non-empty")
        if not _SHA1.fullmatch(self.blob_sha):
            raise ValueError("blob_sha must be a 40-char git SHA")


@dataclass(frozen=True, slots=True)
class CodeSearchPage:
    """One page of code search results."""

    hits: tuple[CodeSearchHit, ...]
    total_count: int
    incomplete_results: bool


@runtime_checkable
class CodeSearchPort(Protocol):
    """Port: execute one code search query and return one page of results."""

    def search(self, query: str, *, per_page: int = 10, page: int = 1) -> CodeSearchPage: ...


class GitHubCodeSearchTransport:
    """Production CodeSearchPort backed by the GitHub REST API."""

    def __init__(
        self,
        token: str | None = None,
        timeout: int = 30,
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
        from urllib.parse import urlsplit

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "leitir",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        endpoint = urlsplit(self._base_url)
        if self._token is not None:
            validate_secret(self._token, kind="token")
        if (
            self._token
            and endpoint.scheme == "https"
            and endpoint.hostname == "api.github.com"
        ):
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def search(self, query: str, *, per_page: int = 10, page: int = 1) -> CodeSearchPage:
        from urllib.parse import urlencode
        from urllib.request import Request

        params = urlencode({"q": query, "per_page": min(per_page, 100), "page": page})
        url = f"{self._base_url}/search/code?{params}"
        logger.debug("code search query=%s per_page=%d page=%d", query, min(per_page, 100), page)
        headers = self._headers()

        def _fetch() -> dict:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise CodeSearchError(
                f"GitHub code search failed: {_http.describe_failure(exc)}"
            ) from exc

        items = payload.get("items", [])
        hits: list[CodeSearchHit] = []
        for item in items:
            repo = item.get("repository", {})
            slug = repo.get("full_name", "")
            path = item.get("path", "")
            sha = item.get("sha", "")
            html_url = item.get("html_url", "")
            if not slug or not path or not _SHA1.fullmatch(sha):
                continue
            hits.append(CodeSearchHit(slug=slug, path=path, blob_sha=sha, html_url=html_url))

        logger.debug("code search total_count=%s hits=%d", payload.get("total_count", 0), len(hits))
        return CodeSearchPage(
            hits=tuple(hits),
            total_count=payload.get("total_count", 0),
            incomplete_results=bool(payload.get("incomplete_results", False)),
        )

    def resolve_head_sha(self, slug: str, branch: str | None = None) -> str:
        """Resolve a repository's default HEAD, or an explicitly named branch."""
        from urllib.parse import urlencode
        from urllib.request import Request

        query: dict[str, int | str] = {"per_page": 1}
        if branch is not None:
            query = {"sha": branch, "per_page": 1}
        url = f"{self._base_url}/repos/{slug}/commits?{urlencode(query)}"
        logger.debug("resolve head sha slug=%s branch=%s", slug, branch or "HEAD")
        headers = self._headers()

        def _fetch() -> list:
            with _http.safe_urlopen(Request(url, headers=headers), timeout=self._timeout) as resp:
                return json.load(resp)

        try:
            payload = self._retry(_fetch)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise CodeSearchError(
                f"cannot resolve {branch or 'HEAD'} for {slug}: {_http.describe_failure(exc)}"
            ) from exc
        if not payload or not isinstance(payload, list):
            raise CodeSearchError(f"empty commit list for {slug} at {branch or 'HEAD'}")
        sha = payload[0].get("sha")
        if not isinstance(sha, str) or not _SHA1.fullmatch(sha):
            raise CodeSearchError(f"invalid commit returned for {slug} at {branch or 'HEAD'}")
        return sha

    def read_blob_by_path(self, slug: str, commit_sha: str, path: str) -> bytes:
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
            raise CodeSearchError(
                f"cannot read blob {slug}/{commit_sha}/{path}: "
                f"{_http.describe_failure(exc)}"
            ) from exc


class CodeSearchError(Exception):
    """The code search API call failed."""


def build_query(spec: SearchSpec) -> str:
    """Translate must predicates into a GitHub Code Search query string."""
    terms: list[str] = []
    language: str | None = None

    for pred in spec.must:
        if pred.kind is PredicateKind.PATH:
            terms.append(f"path:{pred.value}")
        elif pred.kind in (
            PredicateKind.EXACT_TEXT,
            PredicateKind.IDENTIFIER,
            PredicateKind.TOKEN_SEQUENCE,
            PredicateKind.SYMBOL_DEFINITION,
            PredicateKind.SYMBOL_REFERENCE,
            PredicateKind.SIGNATURE,
            PredicateKind.CALL,
            PredicateKind.IMPORT,
        ) or pred.kind is PredicateKind.REGEX:
            terms.append(pred.value)
        if pred.language and language is None:
            language = pred.language

    if language:
        terms.append(f"language:{language}")

    return " ".join(terms)


class GlobalSearcher:
    """Executes a global-discovery search via GitHub Code Search."""

    def __init__(
        self,
        code_search: CodeSearchPort,
        tree_source: TreeSource,
        adapters: tuple[LanguageAdapter, ...],
        head_resolver: Callable[[str], str] | None = None,
        blob_reader: Callable[[str, str, str], bytes] | None = None,
        max_results: int = 30,
        max_pages: int = 10,
    ) -> None:
        if isinstance(max_results, bool) or not isinstance(max_results, int) or max_results < 1:
            raise ValueError("max_results must be a positive integer")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
            raise ValueError("max_pages must be a positive integer")
        self._search = code_search
        self._tree = tree_source
        self._adapters = adapters
        self._head_resolver = head_resolver
        self._blob_reader = blob_reader
        self._max_results = max_results
        self._max_pages = max_pages

    def search(self, spec: SearchSpec) -> SearchReport:
        if spec.mode is not SearchMode.GLOBAL_DISCOVERY:
            raise ValueError("GlobalSearcher only handles global_discovery")

        query = build_query(spec)
        head_cache: dict[str, str] = {}
        matches: list[SourceMatch] = []
        exclusions: dict[str, int] = {}
        files_indexed = 0
        files_eligible = 0
        incomplete_results = False
        per_page = min(self._max_results, 100)
        content_preds = tuple(
            predicate for predicate in spec.must if predicate.kind is not PredicateKind.PATH
        )

        for page_number in range(1, self._max_pages + 1):
            try:
                page = self._search.search(query, per_page=per_page, page=page_number)
            except (CodeSearchError, OSError):
                if page_number == 1:
                    raise
                incomplete_results = True
                break
            if page_number == 1:
                files_eligible = page.total_count
            incomplete_results = incomplete_results or page.incomplete_results

            for hit in page.hits:
                if files_indexed >= self._max_results:
                    break

                adapter = self._adapter_for(hit.path)
                if adapter is None:
                    exclusions["no_adapter"] = exclusions.get("no_adapter", 0) + 1
                    continue

                commit_sha = self._resolve_head(hit.slug, head_cache)
                if commit_sha is None:
                    exclusions["head_unresolved"] = exclusions.get("head_unresolved", 0) + 1
                    continue

                try:
                    verified_content = self._read_content(
                        hit.slug, commit_sha, hit.path, hit.blob_sha
                    )
                except UnicodeDecodeError:
                    exclusions["decode_failed"] = exclusions.get("decode_failed", 0) + 1
                    continue
                except (CodeSearchError, TreeReadError, TreeTruncatedError, OSError):
                    exclusions["fetch_failed"] = exclusions.get("fetch_failed", 0) + 1
                    continue
                if verified_content is None:
                    exclusions["provenance_mismatch"] = (
                        exclusions.get("provenance_mismatch", 0) + 1
                    )
                    continue

                content, blob_sha = verified_content
                matches.extend(
                    score_content(
                        content, adapter, hit.slug, commit_sha,
                        hit.path, blob_sha,
                        content_preds, spec.should, spec.must_not,
                    )
                )
                files_indexed += 1

            if files_indexed >= self._max_results:
                break
            if page.incomplete_results:
                break
            if not page.hits or len(page.hits) < per_page:
                break
            if page_number == self._max_pages:
                incomplete_results = True

        coverage = Coverage(
            status=CoverageStatus.INDETERMINATE_GLOBAL,
            files_eligible=files_eligible,
            files_indexed=files_indexed,
            files_excluded=sum(exclusions.values()),
            incomplete_results=incomplete_results,
            exclusions=exclusions,
        )
        return SearchReport(
            spec_digest=spec.digest(),
            coverage=coverage,
            matches=tuple(matches),
        )

    def _resolve_head(self, slug: str, cache: dict[str, str]) -> str | None:
        if slug in cache:
            return cache[slug]
        try:
            if self._head_resolver is not None:
                sha = self._head_resolver(slug)
            else:
                return None
        except (CodeSearchError, OSError):
            return None
        if not isinstance(sha, str) or not _SHA1.fullmatch(sha):
            return None
        cache[slug] = sha
        return sha

    def _read_content(
        self, slug: str, commit_sha: str, path: str, blob_sha: str
    ) -> tuple[str, str] | None:
        if self._blob_reader is not None:
            data = self._blob_reader(slug, commit_sha, path)
        else:
            read_at_commit = getattr(self._tree, "read_blob_at_commit", None)
            if not callable(read_at_commit):
                raise TreeReadError(
                    "tree source cannot read a path at a pinned commit"
                )
            data = read_at_commit(slug, commit_sha, path)
        digest = _git_blob_sha(data)
        if digest != blob_sha:
            return None
        return data.decode("utf-8"), digest

    def _adapter_for(self, path: str) -> LanguageAdapter | None:
        for adapter in self._adapters:
            if adapter.eligible(path):
                return adapter
        return None
