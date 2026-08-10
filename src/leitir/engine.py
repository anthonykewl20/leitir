"""Scoped-exhaustive search engine.

ADR-001 P2: given a ``SearchSpec`` in ``SCOPED_EXHAUSTIVE`` mode, enumerate
every blob in the declared scopes at their pinned commits, evaluate typed
predicates through language adapters, and return a ``SearchReport`` with honest
coverage accounting.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from leitir.adapters import LanguageAdapter, SpanMatch
from leitir.adapters.languages import canonicalize_language
from leitir.materialize import _utc_now
from leitir.ranking import order_source_matches
from leitir.search import (
    Coverage,
    CoverageStatus,
    Predicate,
    PredicateKind,
    Resolution,
    ResolutionStrategy,
    SearchMode,
    SearchReport,
    SearchSpec,
    SearchSpecError,
    SourceMatch,
    SourceRef,
)
from leitir.tree import BlobEntry, TreeEnumerationError, TreeSource

MAX_BLOB_SIZE = 2 * 1024 * 1024


def _required_language(spec: SearchSpec) -> str | None:
    values = sorted(
        {
            canonicalize_language(predicate.language)
            for predicate in spec.must
            if predicate.language is not None
        }
    )
    if len(values) > 1:
        raise SearchSpecError("conflicting required predicate languages")
    return values[0] if values else None


def path_matches(path: str, predicates: Sequence[Predicate]) -> bool:
    """Return whether ``path`` satisfies any local PATH predicate."""
    for predicate in predicates:
        if predicate.kind is not PredicateKind.PATH:
            continue
        if predicate.value in path:
            return True
        try:
            if re.search(predicate.value, path):
                return True
        except re.error:
            pass
    return False


def _span_excluded(
    content: str,
    adapter: LanguageAdapter,
    span: SpanMatch,
    must_not: tuple[Predicate, ...],
    whole_file: bool = False,
) -> bool:
    for pred in must_not:
        if pred.kind is PredicateKind.PATH:
            continue
        hits = adapter.find_matches(content, (pred,))
        if whole_file and hits:
            return True
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
    whole_file: bool = False,
) -> list[SourceMatch]:
    """Score one blob's content against predicates and return ranked matches."""
    spans = (
        adapter.find_matches(content, content_must, whole_file=whole_file)
        if content_must
        else ()
    )
    if not spans and content_must:
        return []
    if not spans and not content_must:
        spans = adapter.find_matches(content, should) if should else ()

    whole_file_should_kinds: set[PredicateKind] = set()
    whole_file_should_boost = 0
    if whole_file:
        for pred in should:
            if adapter.find_matches(content, (pred,)):
                whole_file_should_kinds.add(pred.kind)
                whole_file_should_boost += 1

    matches: list[SourceMatch] = []
    for span in spans:
        if must_not and _span_excluded(
            content, adapter, span, must_not, whole_file=whole_file
        ):
            continue

        matched_kinds = set(span.matched_kinds)
        should_boost = whole_file_should_boost
        if whole_file:
            matched_kinds.update(whole_file_should_kinds)
        elif should:
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

        required_language = _required_language(spec)
        supported_languages = {
            canonicalize_language(adapter.language) for adapter in self._adapters
        }
        if (
            required_language is not None
            and required_language not in supported_languages
        ):
            raise SearchSpecError("unsupported required predicate language")
        all_matches: list[SourceMatch] = []
        total_eligible = 0
        total_indexed = 0
        total_excluded = 0
        incomplete = False

        for scope in spec.scopes:
            enumeration_excluded = 0
            try:
                blobs, recovered = self._tree.list_blobs_ex(
                    scope.slug, scope.commit_sha
                )
                enumeration_excluded = int(recovered)
            except TreeEnumerationError as exc:
                blobs = exc.partial_blobs
                recovered = False
                enumeration_excluded = 1
            eligible, indexed, excluded, matches, partial = self._search_scope(
                scope.slug, scope.commit_sha, blobs, spec, required_language
            )
            total_eligible += eligible
            total_indexed += indexed
            total_excluded += excluded + enumeration_excluded
            all_matches.extend(matches)
            if partial or recovered or enumeration_excluded:
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
            matches=order_source_matches(tuple(all_matches)),
            resolution=Resolution(
                strategy=ResolutionStrategy.DECLARED_SCOPE,
                as_of=_utc_now(),
            ),
        )

    def _search_scope(
        self,
        slug: str,
        commit_sha: str,
        blobs: tuple[BlobEntry, ...],
        spec: SearchSpec,
        required_language: str | None,
    ) -> tuple[int, int, int, list[SourceMatch], bool]:
        path_preds = [
            p for p in spec.must if p.kind is PredicateKind.PATH
        ]
        content_must = tuple(
            p for p in spec.must if p.kind is not PredicateKind.PATH
        )
        must_not = spec.must_not
        should = spec.should

        eligible_blobs = sorted(
            (
                blob
                for blob in blobs
                if self._adapter_for(blob.path, required_language) is not None
            ),
            key=lambda blob: (blob.path, blob.blob_sha),
        )
        if path_preds:
            eligible_blobs = [
                b
                for b in eligible_blobs
                if path_matches(b.path, path_preds)
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
            adapter = self._adapter_for(blob.path, required_language)
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
                    whole_file=spec.whole_file_must,
                )
            )

        return files_eligible, files_indexed, files_excluded, matches, partial

    def _adapter_for(
        self, path: str, required_language: str | None = None
    ) -> LanguageAdapter | None:
        for adapter in self._adapters:
            language = canonicalize_language(adapter.language)
            if (
                required_language is None or language == required_language
            ) and adapter.eligible(path):
                return adapter
        return None

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
