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
from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from leitir import _http
from leitir.adapters import LanguageAdapter
from leitir.credentials import validate_secret
from leitir.engine import path_matches, score_content
from leitir.materialize import _utc_now
from leitir.ranking import order_source_matches
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    QueryTranslation,
    Resolution,
    ResolutionStrategy,
    SearchMode,
    SearchReport,
    SearchSpec,
    SearchSpecError,
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


def _cross_checked_commit_sha(item_url: object, html_url: object) -> str | None:
    from urllib.parse import parse_qs, urlsplit

    if not isinstance(item_url, str) or not isinstance(html_url, str):
        return None
    query_ref = parse_qs(urlsplit(item_url).query).get("ref", [""])[0]
    html_match = re.search(r"/blob/([0-9a-f]{40})/", html_url)
    html_ref = html_match.group(1) if html_match is not None else ""
    if (
        not _SHA1.fullmatch(query_ref)
        or not _SHA1.fullmatch(html_ref)
        or query_ref != html_ref
    ):
        return None
    return query_ref


@dataclass(frozen=True, slots=True)
class CodeSearchHit:
    """One file-level result from a code search API."""

    slug: str
    path: str
    blob_sha: str
    html_url: str
    commit_sha: str

    def __post_init__(self) -> None:
        if not self.slug or "/" not in self.slug:
            raise ValueError("slug must look like 'owner/repo'")
        if not self.path or not self.path.strip():
            raise ValueError("path must be non-empty")
        if not _SHA1.fullmatch(self.blob_sha):
            raise ValueError("blob_sha must be a 40-char git SHA")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(self.commit_sha):
            raise ValueError("commit_sha must be a 40-char git SHA")


def hit_identity(hit: CodeSearchHit) -> tuple[str, str, str, str, str]:
    """Return the total-order file-level prefix of the P6 source identity."""
    return (hit.slug, hit.commit_sha, hit.path, hit.blob_sha, hit.html_url)


@dataclass(frozen=True, slots=True)
class DedupOutcome:
    """Pure result of collapsing search-index claims.

    ``collapsed`` means that the index claimed identical content or repeated
    the same repository path. It does not mean that collapsed hits' bytes were
    fetched or verified. ``groups`` retains each content-claim group so a
    failed representative can be promoted deterministically.
    """

    candidates: tuple[CodeSearchHit, ...]
    collapsed: int
    groups: tuple[tuple[CodeSearchHit, ...], ...]
    pin_disagreements: int = 0


def _collapse(
    hits: Iterable[CodeSearchHit],
    *,
    key: Callable[[CodeSearchHit], Hashable],
) -> tuple[list[CodeSearchHit], int, dict[CodeSearchHit, tuple[CodeSearchHit, ...]]]:
    grouped: dict[Hashable, list[CodeSearchHit]] = {}
    for hit in hits:
        grouped.setdefault(key(hit), []).append(hit)
    groups = [tuple(group) for group in grouped.values()]
    survivors = [group[0] for group in groups]
    return survivors, sum(len(group) - 1 for group in groups), dict(zip(survivors, groups, strict=False))


def dedup_hits(hits: Iterable[CodeSearchHit]) -> DedupOutcome:
    """Deterministically collapse duplicate index hits without doing I/O.

    Given identical fetch outcomes, representative selection is a pure
    function of the hit set. The representative is the first member in
    ``hit_identity`` order whose bytes verify.
    """
    ordered = sorted(hits, key=hit_identity)

    # The same pinned path cannot truthfully name two different git blobs.
    consistent: list[CodeSearchHit] = []
    pins: dict[tuple[str, str, str], str] = {}
    pin_disagreements = 0
    for hit in ordered:
        pin = (hit.slug, hit.commit_sha, hit.path)
        if pin in pins and pins[pin] != hit.blob_sha:
            pin_disagreements += 1
            continue
        pins[pin] = hit.blob_sha
        consistent.append(hit)

    survivors, collapsed1, _ = _collapse(
        consistent, key=lambda hit: (hit.slug, hit.path)
    )
    survivors, collapsed2, content_groups = _collapse(
        survivors, key=lambda hit: hit.blob_sha
    )
    return DedupOutcome(
        candidates=tuple(survivors),
        collapsed=collapsed1 + collapsed2,
        groups=tuple(content_groups[hit] for hit in survivors),
        pin_disagreements=pin_disagreements,
    )


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
            if not isinstance(item, dict):
                continue
            repo = item.get("repository", {})
            if not isinstance(repo, dict):
                continue
            slug = repo.get("full_name", "")
            path = item.get("path", "")
            sha = item.get("sha", "")
            html_url = item.get("html_url", "")
            item_url = item.get("url", "")
            if (
                not isinstance(slug, str)
                or not slug
                or not isinstance(path, str)
                or not path
                or not isinstance(sha, str)
                or not _SHA1.fullmatch(sha)
            ):
                continue
            commit_sha = _cross_checked_commit_sha(item_url, html_url)
            if commit_sha is None:
                continue
            hits.append(
                CodeSearchHit(
                    slug=slug,
                    path=path,
                    blob_sha=sha,
                    html_url=html_url,
                    commit_sha=commit_sha,
                )
            )

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


_LOSSLESS_QUERY_KINDS = frozenset(
    {
        PredicateKind.EXACT_TEXT,
        PredicateKind.IDENTIFIER,
        PredicateKind.TOKEN_SEQUENCE,
        PredicateKind.PATH,
        PredicateKind.SYMBOL_DEFINITION,
        PredicateKind.SYMBOL_REFERENCE,
        PredicateKind.SIGNATURE,
        PredicateKind.CALL,
        PredicateKind.IMPORT,
    }
)


def _compile_query(
    spec: SearchSpec,
) -> tuple[str, tuple[QueryTranslation, ...]]:
    """Translate predicates without silently weakening their semantics."""
    terms: list[str] = []
    language: str | None = None
    translations: list[QueryTranslation] = []

    for index, pred in enumerate(spec.must):
        if pred.kind not in _LOSSLESS_QUERY_KINDS:
            raise SearchSpecError(
                "REJECT_SEMANTIC_DEGRADATION: GitHub legacy code search cannot "
                f"express must predicate {pred.kind.value}"
            )
        if pred.kind is PredicateKind.PATH:
            emitted = f"path:{pred.value}"
        else:
            emitted = pred.value
        terms.append(emitted)
        translations.append(
            QueryTranslation(
                clause="must",
                predicate_index=index,
                kind=pred.kind,
                strategy=(
                    "github_superset_local_filter"
                    if pred.kind
                    in {
                        PredicateKind.PATH,
                        PredicateKind.SYMBOL_DEFINITION,
                        PredicateKind.SYMBOL_REFERENCE,
                        PredicateKind.SIGNATURE,
                        PredicateKind.CALL,
                        PredicateKind.IMPORT,
                    }
                    else "github_query"
                ),
                emitted_syntax=emitted,
            )
        )
        if pred.language and language is not None and pred.language != language:
            raise SearchSpecError(
                "REJECT_SEMANTIC_DEGRADATION: conflicting predicate languages"
            )
        if pred.language:
            language = pred.language

    for clause in ("should", "must_not"):
        for index, pred in enumerate(getattr(spec, clause)):
            if pred.kind is PredicateKind.PATH:
                raise SearchSpecError(
                    "REJECT_SEMANTIC_DEGRADATION: GitHub legacy code search cannot "
                    f"express {clause} PATH predicate"
                )
            translations.append(
                QueryTranslation(
                    clause=clause,
                    predicate_index=index,
                    kind=pred.kind,
                    strategy="local_filter",
                )
            )

    if language:
        terms.append(f"language:{language}")

    return " ".join(terms), tuple(translations)


def build_query(spec: SearchSpec) -> str:
    """Translate must predicates into a GitHub Code Search query string."""
    return _compile_query(spec)[0]


class GlobalSearcher:
    """Executes a global-discovery search via GitHub Code Search."""

    def __init__(
        self,
        code_search: CodeSearchPort,
        tree_source: TreeSource,
        adapters: tuple[LanguageAdapter, ...],
        blob_reader: Callable[[str, str, str], bytes] | None = None,
        max_results: int = 30,
        max_pages: int = 10,
        clock: Callable[[], str] | None = None,
    ) -> None:
        if isinstance(max_results, bool) or not isinstance(max_results, int) or max_results < 1:
            raise ValueError("max_results must be a positive integer")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
            raise ValueError("max_pages must be a positive integer")
        self._search = code_search
        self._tree = tree_source
        self._adapters = adapters
        self._blob_reader = blob_reader
        self._max_results = max_results
        self._max_pages = max_pages
        self._clock = clock or _utc_now

    def search(self, spec: SearchSpec) -> SearchReport:
        if spec.mode is not SearchMode.GLOBAL_DISCOVERY:
            raise ValueError("GlobalSearcher only handles global_discovery")

        query, query_translation = _compile_query(spec)
        matches: list[SourceMatch] = []
        exclusions: dict[str, int] = {}
        files_indexed = 0
        files_eligible = 0
        incomplete_results = False
        collected: list[CodeSearchHit] = []
        per_page = min(self._max_results, 100)
        content_preds = tuple(
            predicate for predicate in spec.must if predicate.kind is not PredicateKind.PATH
        )
        path_preds = tuple(
            predicate for predicate in spec.must if predicate.kind is PredicateKind.PATH
        )

        # Phase A: collect a deterministic candidate set without blob I/O.
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
            collected.extend(page.hits)
            provisional = dedup_hits(collected)
            adapter_eligible = sum(
                self._adapter_for(hit.path) is not None
                for hit in provisional.candidates
            )
            if adapter_eligible >= self._max_results:
                break
            if page.incomplete_results:
                break
            if not page.hits or len(page.hits) < per_page:
                break
            if page_number == self._max_pages:
                incomplete_results = True

        # Phase B: collapse only index claims. Collapsed members are not read.
        outcome = dedup_hits(collected)
        if outcome.pin_disagreements:
            exclusions["pin_disagreement"] = outcome.pin_disagreements
        eligible_groups: list[tuple[CodeSearchHit, ...]] = []
        for candidate, group in zip(outcome.candidates, outcome.groups, strict=True):
            if self._adapter_for(candidate.path) is None:
                exclusions["no_adapter"] = exclusions.get("no_adapter", 0) + 1
            else:
                eligible_groups.append(group)

        # Phase C: verify candidates in file-level P6 order. Verification
        # failures promote the next member of the same claimed-content group.
        attempts = 0
        promoted_attempted = 0
        verification_failed = False
        verified: list[CodeSearchHit] = []
        for group in eligible_groups:
            if attempts >= self._max_results:
                incomplete_results = True
                break
            for group_index, hit in enumerate(group):
                if attempts >= self._max_results:
                    incomplete_results = True
                    break
                if group_index >= 1:
                    promoted_attempted += 1
                attempts += 1
                if path_preds and not path_matches(hit.path, path_preds):
                    exclusions["path_mismatch"] = exclusions.get("path_mismatch", 0) + 1
                    continue
                adapter = self._adapter_for(hit.path)
                if adapter is None:
                    exclusions["no_adapter"] = exclusions.get("no_adapter", 0) + 1
                    continue
                commit_sha = getattr(hit, "commit_sha", None)
                if not isinstance(commit_sha, str) or not _SHA1.fullmatch(commit_sha):
                    exclusions["unpinned_hit"] = exclusions.get("unpinned_hit", 0) + 1
                    break
                html_match = (
                    re.search(r"/blob/([0-9a-f]{40})/", hit.html_url)
                    if isinstance(hit.html_url, str)
                    else None
                )
                if html_match is None:
                    exclusions["unpinned_hit"] = exclusions.get("unpinned_hit", 0) + 1
                    break
                if html_match.group(1) != commit_sha:
                    exclusions["pin_disagreement"] = (
                        exclusions.get("pin_disagreement", 0) + 1
                    )
                    break

                try:
                    verified_content = self._read_content(
                        hit.slug, commit_sha, hit.path, hit.blob_sha
                    )
                except UnicodeDecodeError:
                    exclusions["decode_failed"] = exclusions.get("decode_failed", 0) + 1
                    verification_failed = True
                    continue
                except (CodeSearchError, TreeReadError, TreeTruncatedError, OSError):
                    exclusions["fetch_failed"] = exclusions.get("fetch_failed", 0) + 1
                    verification_failed = True
                    continue
                if verified_content is None:
                    exclusions["provenance_mismatch"] = (
                        exclusions.get("provenance_mismatch", 0) + 1
                    )
                    verification_failed = True
                    continue

                content, blob_sha = verified_content
                verified.append(hit)
                matches.extend(
                    score_content(
                        content, adapter, hit.slug, commit_sha,
                        hit.path, blob_sha,
                        content_preds, spec.should, spec.must_not,
                    )
                )
                files_indexed += 1
                break

        if verification_failed and files_indexed < self._max_results:
            incomplete_results = True

        deduplicated = outcome.collapsed - promoted_attempted
        if deduplicated > 0:
            exclusions["deduplicated"] = deduplicated

        coverage = Coverage(
            status=CoverageStatus.INDETERMINATE_GLOBAL,
            files_eligible=files_eligible,
            files_indexed=files_indexed,
            files_excluded=sum(exclusions.values()),
            incomplete_results=incomplete_results,
            exclusions=exclusions,
        )
        report = SearchReport(
            spec_digest=spec.digest(),
            coverage=coverage,
            matches=order_source_matches(tuple(matches)),
            resolution=Resolution(
                strategy=ResolutionStrategy.INDEXED_COMMIT,
                as_of=self._clock(),
            ),
            query_translation=query_translation,
        )
        validate_report(report, tuple(verified))
        return report

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


def validate_report(report: SearchReport, hits: tuple[CodeSearchHit, ...]) -> None:
    """Reject global reports whose provenance is not derived from indexed hits."""
    resolution = getattr(report, "resolution", None)
    is_global = report.coverage.status is CoverageStatus.INDETERMINATE_GLOBAL
    if is_global and (
        resolution is None
        or resolution.strategy is not ResolutionStrategy.INDEXED_COMMIT
    ):
        raise ValueError("REJECT_MOVING_REFERENCE")
    if is_global and not report.query_translation:
        raise SearchSpecError("REJECT_SEMANTIC_DEGRADATION: missing query translation")
    if resolution is None or resolution.strategy is not ResolutionStrategy.INDEXED_COMMIT:
        return
    accepted = {
        (hit.slug, hit.commit_sha, hit.path, hit.blob_sha)
        for hit in hits
    }
    for match in report.matches:
        source = match.source
        identity = (source.slug, source.commit_sha, source.path, source.blob_sha)
        if identity not in accepted:
            raise ValueError("REJECT_MOVING_REFERENCE")
