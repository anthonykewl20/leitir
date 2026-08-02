"""Scoped-exhaustive search engine.

ADR-001 P2: given a ``SearchSpec`` in ``SCOPED_EXHAUSTIVE`` mode, enumerate
every blob in the declared scopes at their pinned commits, evaluate typed
predicates through language adapters, and return a ``SearchReport`` with honest
coverage accounting.
"""

from __future__ import annotations

from leitir.adapters import LanguageAdapter, SpanMatch
from leitir.search import (
    Coverage,
    CoverageStatus,
    Predicate,
    PredicateKind,
    SearchMode,
    SearchReport,
    SearchSpec,
    SourceMatch,
    SourceRef,
)
from leitir.tree import BlobEntry, TreeSource

MAX_BLOB_SIZE = 2 * 1024 * 1024


def _span_excluded(
    content: str,
    adapter: LanguageAdapter,
    span: SpanMatch,
    must_not: tuple[Predicate, ...],
) -> bool:
    for pred in must_not:
        if pred.kind is PredicateKind.PATH:
            continue
        hits = adapter.find_matches(content, (pred,))
        for hit in hits:
            if hit.start_line == span.start_line:
                return True
    return False


def score_content(
    content: str,
    adapter: LanguageAdapter,
    slug: str,
    commit_sha: str,
    path: str,
    blob_sha: str,
    content_must: tuple[Predicate, ...],
    should: tuple[Predicate, ...],
    must_not: tuple[Predicate, ...],
) -> list[SourceMatch]:
    """Score one blob's content against predicates and return ranked matches."""
    spans = adapter.find_matches(content, content_must) if content_must else ()
    if not spans and content_must:
        return []
    if not spans and not content_must:
        spans = adapter.find_matches(content, should) if should else ()

    matches: list[SourceMatch] = []
    for span in spans:
        if must_not and _span_excluded(content, adapter, span, must_not):
            continue

        matched_kinds = set(span.matched_kinds)
        should_boost = 0
        if should:
            for ss in adapter.find_matches(content, should):
                if ss.start_line == span.start_line:
                    matched_kinds.update(ss.matched_kinds)
                    should_boost += len(ss.matched_kinds)

        score = float(len(content_must) + should_boost)
        ref = SourceRef(
            slug=slug,
            commit_sha=commit_sha,
            path=path,
            blob_sha=blob_sha,
            start_line=span.start_line,
            end_line=span.end_line,
        )
        matches.append(
            SourceMatch(
                source=ref,
                score=score,
                matched_kinds=tuple(sorted(matched_kinds, key=lambda k: k.value)),
            )
        )
    return matches


class ScopedSearcher:
    """Executes a scoped-exhaustive search over pinned commits."""

    def __init__(
        self,
        tree_source: TreeSource,
        adapters: tuple[LanguageAdapter, ...],
        max_blob_size: int = MAX_BLOB_SIZE,
    ) -> None:
        self._tree = tree_source
        self._adapters = adapters
        self._max_blob_size = max_blob_size

    def search(self, spec: SearchSpec) -> SearchReport:
        if spec.mode is not SearchMode.SCOPED_EXHAUSTIVE:
            raise ValueError("ScopedSearcher only handles scoped_exhaustive")

        all_matches: list[SourceMatch] = []
        total_eligible = 0
        total_indexed = 0
        total_excluded = 0
        incomplete = False

        for scope in spec.scopes:
            blobs = self._tree.list_blobs(scope.slug, scope.commit_sha)
            eligible, indexed, excluded, matches, partial = self._search_scope(
                scope.slug, scope.commit_sha, blobs, spec
            )
            total_eligible += eligible
            total_indexed += indexed
            total_excluded += excluded
            all_matches.extend(matches)
            if partial:
                incomplete = True

        if total_indexed == total_eligible and not incomplete:
            status = CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
        else:
            status = CoverageStatus.PARTIAL

        coverage = Coverage(
            status=status,
            files_eligible=total_eligible,
            files_indexed=total_indexed,
            files_excluded=total_excluded,
            incomplete_results=incomplete,
        )
        return SearchReport(
            spec_digest=spec.digest(),
            coverage=coverage,
            matches=tuple(all_matches),
        )

    def _search_scope(
        self,
        slug: str,
        commit_sha: str,
        blobs: tuple[BlobEntry, ...],
        spec: SearchSpec,
    ) -> tuple[int, int, int, list[SourceMatch], bool]:
        path_preds = [
            p for p in spec.must if p.kind is PredicateKind.PATH
        ]
        content_must = tuple(
            p for p in spec.must if p.kind is not PredicateKind.PATH
        )
        must_not = spec.must_not
        should = spec.should

        eligible_blobs = [
            b for b in blobs if self._adapter_for(b.path) is not None
        ]
        if path_preds:
            eligible_blobs = [
                b
                for b in eligible_blobs
                if self._path_matches(b.path, path_preds)
            ]

        files_eligible = len(eligible_blobs)
        files_indexed = 0
        files_excluded = 0
        matches: list[SourceMatch] = []
        partial = False

        for blob in eligible_blobs:
            if blob.size > self._max_blob_size:
                files_excluded += 1
                partial = True
                continue

            try:
                data = self._tree.read_blob(slug, blob.blob_sha)
            except Exception:
                files_excluded += 1
                partial = True
                continue

            files_indexed += 1
            adapter = self._adapter_for(blob.path)
            if adapter is None:
                continue

            try:
                content = data.decode("utf-8", errors="replace")
            except Exception:
                continue

            if must_not and self._excluded(content, adapter, must_not):
                continue

            matches.extend(
                score_content(
                    content, adapter, slug, commit_sha,
                    blob.path, blob.blob_sha,
                    content_must, should, must_not,
                )
            )

        return files_eligible, files_indexed, files_excluded, matches, partial

    def _adapter_for(self, path: str) -> LanguageAdapter | None:
        for adapter in self._adapters:
            if adapter.eligible(path):
                return adapter
        return None

    def _path_matches(self, path: str, preds: list[Predicate]) -> bool:
        import re

        for pred in preds:
            if pred.kind is PredicateKind.PATH:
                if pred.value in path:
                    return True
                try:
                    if re.search(pred.value, path):
                        return True
                except re.error:
                    pass
        return False

    def _excluded(
        self,
        content: str,
        adapter: LanguageAdapter,
        must_not: tuple[Predicate, ...],
    ) -> bool:
        for pred in must_not:
            if pred.kind is PredicateKind.PATH:
                continue
            hits = adapter.find_matches(content, (pred,))
            if hits:
                return True
        return False
