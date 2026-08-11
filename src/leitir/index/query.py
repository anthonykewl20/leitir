"""Sound trigram planning and independently verified indexed search."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from pathlib import Path
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

from leitir.adapters import LanguageAdapter
from leitir.adapters.languages import canonicalize_language
from leitir.engine import ScopedSearcher, _required_language, _score_content_ex, path_matches
from leitir.index.postings import intersect_sorted, iter_trigrams
from leitir.index.rank import dedupe_source_matches
from leitir.index.verify import ShelfRef, VerifiedIndexShelf, open_verified_shelf
from leitir.materialize import VerificationError, _utc_now
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
)


def _parsed_literal_runs(pattern: str) -> tuple[bytes, ...]:
    """Extract only literal runs guaranteed to occur in every regex match.

    This deliberately gives up on alternation and optional constructs rather
    than risk a false-negative candidate filter.
    """
    try:
        parsed = sre_parse.parse(pattern)
    except Exception:
        return ()
    if parsed.state.flags & sre_constants.SRE_FLAG_IGNORECASE:
        return ()

    def visit(tokens: Iterable[tuple[Any, Any]]) -> list[str]:
        runs: list[str] = []
        current: list[str] = []

        def flush() -> None:
            if current:
                runs.append("".join(current))
                current.clear()

        for operation, argument in tokens:
            if operation is sre_constants.LITERAL:
                current.append(chr(argument))
            elif operation is sre_constants.SUBPATTERN:
                flush()
                _group, add_flags, _delete_flags, child = argument
                if not add_flags & sre_constants.SRE_FLAG_IGNORECASE:
                    runs.extend(visit(child))
            elif operation in {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.POSSESSIVE_REPEAT}:
                flush()
                minimum, _maximum, repeated = argument
                if minimum > 0:
                    runs.extend(visit(repeated))
            elif operation is sre_constants.ASSERT:
                flush()
                direction, asserted = argument
                if direction >= 0:
                    runs.extend(visit(asserted))
            elif operation is sre_constants.BRANCH:
                # A run from only one branch is not necessarily present.
                flush()
            elif operation in {sre_constants.AT, sre_constants.SUCCESS}:
                continue
            else:
                flush()
        flush()
        return runs

    return tuple(
        run.encode("utf-8")
        for run in visit(parsed)
        if "\ufffd" not in run and len(run.encode("utf-8")) >= 3
    )


def predicate_literal_runs(predicate: Predicate) -> tuple[bytes, ...]:
    """Return sound required byte literals, or empty when no safe plan exists."""
    if predicate.kind is PredicateKind.EXACT_TEXT:
        encoded = predicate.value.encode("utf-8")
        return (encoded,) if "\ufffd" not in predicate.value and len(encoded) >= 3 else ()
    if predicate.kind is PredicateKind.REGEX:
        return _parsed_literal_runs(predicate.value)
    return ()


def candidate_ids(spec: SearchSpec, shelf: VerifiedIndexShelf, allowed: tuple[int, ...]) -> tuple[int, ...] | None:
    """Return a sound posting intersection; ``None`` requests fallback scanning."""
    grams: set[str] = set()
    usable = False
    for predicate in spec.must:
        if predicate.kind is PredicateKind.PATH:
            continue
        for run in predicate_literal_runs(predicate):
            usable = True
            grams.update(iter_trigrams(run))
    if not usable or not grams:
        return None
    posting_lists = tuple(shelf.postings.get(gram, ()) for gram in sorted(grams))
    return intersect_sorted(allowed, *posting_lists)


class IndexedSearcher:
    """Search verified local index shelves with exhaustive scoped fallback."""

    def __init__(
        self,
        corpus_root: Path,
        fallback: ScopedSearcher,
        adapters: tuple[LanguageAdapter, ...],
        *,
        require_index: bool = False,
        fallback_file_limit: int = 1_000,
    ) -> None:
        if fallback_file_limit < 1:
            raise ValueError("fallback_file_limit must be positive")
        self._root = corpus_root.expanduser().absolute()
        self._fallback = fallback
        self._adapters = adapters
        self._require_index = require_index
        self._fallback_file_limit = fallback_file_limit

    def _adapter_for(self, path: str, required_language: str | None) -> LanguageAdapter | None:
        for adapter in self._adapters:
            language = canonicalize_language(adapter.language)
            if (required_language is None or language == required_language) and adapter.eligible(path):
                return adapter
        return None

    def _shelves(self, slug: str, commit: str) -> tuple[ShelfRef, ...]:
        from leitir.corpus import load_sources

        result = {
            ShelfRef(entry["host"], entry["owner"], entry["repo"], entry["commit_sha"])
            for entry in load_sources(self._root)
            if f"{entry['owner']}/{entry['repo']}" == slug and entry["commit_sha"] == commit
        }
        return tuple(sorted(result))

    def _search_verified(
        self,
        shelf: VerifiedIndexShelf,
        spec: SearchSpec,
        required_language: str | None,
    ) -> tuple[int, int, int, list[SourceMatch], bool]:
        path_predicates = tuple(predicate for predicate in spec.must if predicate.kind is PredicateKind.PATH)
        allowed_documents = tuple(
            (doc_id, document, adapter)
            for doc_id, document in enumerate(shelf.documents)
            if (adapter := self._adapter_for(document.path, required_language)) is not None
            and (not path_predicates or path_matches(document.path, path_predicates))
        )
        allowed = tuple(doc_id for doc_id, _document, _adapter in allowed_documents)
        planned = candidate_ids(spec, shelf, allowed)
        incomplete = False
        if planned is None:
            selected = allowed_documents[: self._fallback_file_limit]
            incomplete = len(selected) != len(allowed_documents)
            indexed = len(selected)
        else:
            wanted = set(planned)
            selected = tuple(item for item in allowed_documents if item[0] in wanted)
            indexed = len(allowed_documents)

        content_must = tuple(predicate for predicate in spec.must if predicate.kind is not PredicateKind.PATH)
        matches: list[SourceMatch] = []
        excluded = 0
        for _doc_id, document, adapter in selected:
            data = shelf.read_document(document)
            content = data.decode("utf-8", errors="replace")
            parser_unavailable = False
            if spec.must_not:
                for predicate in spec.must_not:
                    if predicate.kind is PredicateKind.PATH:
                        continue
                    result = adapter.find_matches_ex(content, (predicate,))
                    parser_unavailable = parser_unavailable or result.parser_unavailable
                    if result.spans:
                        break
                else:
                    result = None
                if result is not None and result.spans:
                    if parser_unavailable:
                        excluded += 1
                        incomplete = True
                    continue
            blob_matches, score_parser_unavailable = _score_content_ex(
                content,
                adapter,
                shelf.shelf.slug,
                shelf.shelf.commit,
                document.path,
                document.blob_sha,
                content_must,
                spec.should,
                spec.must_not,
                whole_file=spec.whole_file_must,
            )
            if parser_unavailable or score_parser_unavailable:
                excluded += 1
                incomplete = True
            matches.extend(blob_matches)
        return len(allowed_documents), indexed, excluded, matches, incomplete

    def search(self, spec: SearchSpec) -> SearchReport:
        if spec.mode is not SearchMode.SCOPED_EXHAUSTIVE:
            raise ValueError("IndexedSearcher only handles scoped_exhaustive")
        required_language = _required_language(spec)
        supported = {canonicalize_language(adapter.language) for adapter in self._adapters}
        if required_language is not None and required_language not in supported:
            raise SearchSpecError("unsupported required predicate language")

        eligible = indexed = excluded = 0
        incomplete = False
        indexed_matches: list[SourceMatch] = []
        fallback_scopes = []
        for scope in sorted(spec.scopes, key=lambda item: (item.slug, item.commit_sha)):
            shelves = self._shelves(scope.slug, scope.commit_sha)
            if not shelves:
                if self._require_index:
                    raise VerificationError("required index does not cover declared scope")
                fallback_scopes.append(scope)
                incomplete = True
                continue
            scope_failed = False
            for shelf_ref in shelves:
                try:
                    with open_verified_shelf(self._root, shelf_ref) as shelf:
                        counts = self._search_verified(shelf, spec, required_language)
                    if self._require_index and counts[4]:
                        raise VerificationError("required index cannot exhaustively verify declared scope")
                    eligible += counts[0]
                    indexed += counts[1]
                    excluded += counts[2]
                    indexed_matches.extend(counts[3])
                    incomplete = incomplete or counts[4]
                except (OSError, ValueError, VerificationError):
                    scope_failed = True
            if scope_failed:
                if self._require_index:
                    raise VerificationError("required index does not cover declared scope")
                fallback_scopes.append(scope)
                incomplete = True

        fallback_report: SearchReport | None = None
        if fallback_scopes:
            fallback_report = self._fallback.search(dataclasses.replace(spec, scopes=tuple(fallback_scopes)))
            eligible += fallback_report.coverage.files_eligible
            indexed += fallback_report.coverage.files_indexed
            excluded += fallback_report.coverage.files_excluded
            indexed_matches.extend(fallback_report.matches)
            incomplete = True

        merged = dedupe_source_matches(indexed_matches)
        status = (
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
            if indexed == eligible and not incomplete
            else CoverageStatus.PARTIAL
        )
        return SearchReport(
            spec_digest=spec.digest(),
            coverage=Coverage(status, eligible, indexed, excluded, incomplete_results=incomplete),
            matches=order_source_matches(merged),
            resolution=Resolution(ResolutionStrategy.INDEXED_COMMIT, _utc_now()),
        )


__all__ = ["IndexedSearcher", "candidate_ids", "predicate_literal_runs"]
