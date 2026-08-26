"""Sound trigram planning and independently verified indexed search."""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Iterable
from pathlib import Path
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

from leitir.adapters import LanguageAdapter
from leitir.adapters.registry import trusted_adapter_language
from leitir.engine import ScopedSearcher, _required_language, _score_content_ex, path_matches_ex
from leitir.index.postings import intersect_sorted, iter_trigrams
from leitir.index.rank import dedupe_source_matches
from leitir.index.verify import IndexDocument, ShelfRef, VerifiedIndexShelf, open_verified_shelf
from leitir.matching import document_excluded_ex
from leitir.materialize import VerificationError, _utc_now
from leitir.ranking import order_source_matches
from leitir.search import (
    CorpusSearchReport,
    Coverage,
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    Resolution,
    ResolutionStrategy,
    SearchMode,
    SearchReport,
    SearchSpec,
    SearchSpecError,
    ShelfExclusion,
    SourceMatch,
    corpus_spec_digest,
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
            language = trusted_adapter_language(adapter)
            if language is None:
                continue
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
        path_budget_exceeded = False
        allowed_documents_list: list[tuple[int, IndexDocument, LanguageAdapter]] = []
        for doc_id, document in enumerate(shelf.documents):
            adapter = self._adapter_for(document.path, required_language)
            if adapter is None:
                continue
            if path_predicates:
                matched, exceeded = path_matches_ex(document.path, path_predicates)
                path_budget_exceeded = path_budget_exceeded or exceeded
                if not matched:
                    continue
            allowed_documents_list.append((doc_id, document, adapter))
        allowed_documents = tuple(allowed_documents_list)
        allowed = tuple(doc_id for doc_id, _document, _adapter in allowed_documents)
        planned = candidate_ids(spec, shelf, allowed)
        incomplete = path_budget_exceeded
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
                is_excluded, parser_unavailable = document_excluded_ex(
                    content, adapter, spec.must_not
                )
                if is_excluded:
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
        supported = {
            language
            for adapter in self._adapters
            if (language := trusted_adapter_language(adapter)) is not None
        }
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


def _corpus_eligibility(root: Path) -> tuple[tuple[ShelfRef, ...], list[ShelfExclusion]]:
    """Deterministically split the corpus into search-eligible and excluded shelves.

    Reuses ``shelves_from_corpus`` and ``ineligible_shelf_conditions`` -- the
    same eligibility contract already enforced by ``leitir index`` -- so a
    corpus-wide search never invents a parallel notion of "eligible". A shelf
    on an unsupported host (``ScopedSearcher``'s local-shelf fast path only
    ever reads ``github.com`` shelves), a registry-derived shelf with no
    immutable git commit, a drift-parity shelf, a partially-scoped shelf, or
    a shelf that outright fails load-time verification (tamper) is excluded
    and named here -- never silently scanned or silently dropped.

    ``shelves_from_corpus`` is called with ``strict=True``: if the catalog
    itself is corrupt or unreadable, the declared universe cannot be
    established at all, so this raises ``VerificationError`` rather than
    silently treating a corruption as an empty corpus (issue #266 P1). That
    is a materially different situation from a genuinely empty catalog
    (``FileNotFoundError``, which ``load_sources`` always reports as an
    honest empty list regardless of ``strict``): the former means real
    materialized shelves on disk may be getting silently skipped, while the
    latter means nothing was ever materialized.
    """
    from leitir.index.builder import ineligible_shelf_conditions, shelves_from_corpus

    shelves = shelves_from_corpus(root, strict=True)
    eligible: list[ShelfRef] = []
    excluded: list[ShelfExclusion] = []
    for shelf in shelves:
        if shelf.host != "github.com":
            excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, "unsupported_host"))
            continue
        try:
            conditions = ineligible_shelf_conditions(root, shelf)
        except Exception:
            excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, "verification_failed"))
            continue
        if "source" in conditions:
            excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, "registry_provenance"))
            continue
        if "parity" in conditions:
            excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, "drift_parity"))
            continue
        if "scope" in conditions:
            excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, "partial_tree_scope"))
            continue
        eligible.append(shelf)
    return tuple(sorted(eligible)), excluded


class CorpusSearcher:
    """Fan a scoped-exhaustive query out across every eligible materialized shelf.

    This is a fan-out plus aggregation layer only (issue #266): matching and
    ranking are entirely delegated, one shelf at a time, to the same
    ``ScopedSearcher`` (or ``IndexedSearcher``, with ``use_index=True``) that
    already backs single-scope ``leitir search``. Nothing here re-implements
    predicate matching, blob reading, or ranking.

    Coverage honesty (the critical contract): ``corpus_status`` is
    ``CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE`` only when every shelf in
    the corpus was both eligible and successfully searched to complete,
    file-level coverage. Any excluded shelf -- unindexed under
    ``require_index``, drift-parity, registry-derived, an unsupported host, or
    failing load-time (tamper) verification -- is reported by name in
    ``shelves_excluded`` and forces ``PARTIAL``. An empty corpus is reported
    honestly too: zero shelves searched, zero excluded, no matches -- never an
    error and never a false "complete" claim about dependencies that were
    never materialized in the first place.
    """

    def __init__(
        self,
        corpus_root: str | os.PathLike[str],
        scoped: ScopedSearcher,
        indexed: IndexedSearcher | None = None,
        *,
        use_index: bool = False,
        require_index: bool = False,
    ) -> None:
        if use_index and indexed is None:
            raise ValueError("use_index requires an IndexedSearcher")
        self._root = Path(corpus_root).expanduser().absolute()
        self._scoped = scoped
        self._indexed = indexed
        self._use_index = use_index
        self._require_index = require_index

    def search(
        self,
        must: tuple[Predicate, ...],
        should: tuple[Predicate, ...] = (),
        must_not: tuple[Predicate, ...] = (),
        whole_file_must: bool = False,
    ) -> CorpusSearchReport:
        digest = corpus_spec_digest(must, should, must_not, whole_file_must)
        eligible, excluded = _corpus_eligibility(self._root)

        all_matches: list[SourceMatch] = []
        total_eligible = total_indexed = total_excluded = 0
        exclusions: dict[str, int] = {}
        incomplete = False
        searched: list[tuple[str, str, str, str]] = []

        for shelf in eligible:
            scope = RepoScope(slug=shelf.slug, commit_sha=shelf.commit)
            spec = SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=must,
                should=should,
                must_not=must_not,
                scopes=(scope,),
                whole_file_must=whole_file_must,
            )
            try:
                if self._use_index:
                    assert self._indexed is not None
                    report = self._indexed.search(spec)
                else:
                    report = self._scoped.search(spec)
            except VerificationError:
                # Under --require-index this is exactly a shelf with no
                # verified local index: IndexedSearcher(require_index=True)
                # fails closed per scope rather than silently falling back to
                # a full scan. Any other verification failure (including a
                # tampered shelf discovered only while reading, past the
                # cheap eligibility pre-check above) lands here too -- either
                # way the shelf is excluded and named, not dropped silently.
                reason = "unindexed" if self._use_index and self._require_index else "verification_failed"
                excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, reason))
                continue
            except (OSError, ValueError):
                excluded.append(ShelfExclusion(shelf.host, shelf.owner, shelf.repo, shelf.commit, "verification_failed"))
                continue

            total_eligible += report.coverage.files_eligible
            total_indexed += report.coverage.files_indexed
            total_excluded += report.coverage.files_excluded
            for reason_key, count in report.coverage.exclusions.items():
                exclusions[reason_key] = exclusions.get(reason_key, 0) + count
            if report.coverage.incomplete_results or report.coverage.status is not CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE:
                incomplete = True
            all_matches.extend(report.matches)
            searched.append((shelf.host, shelf.owner, shelf.repo, shelf.commit))

        excluded_sorted = tuple(sorted(excluded, key=lambda item: item.identity))
        searched_sorted = tuple(sorted(set(searched)))
        merged = dedupe_source_matches(all_matches)
        file_status = (
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
            if (total_indexed == total_eligible and not incomplete)
            else CoverageStatus.PARTIAL
        )
        coverage = Coverage(
            status=file_status,
            files_eligible=total_eligible,
            files_indexed=total_indexed,
            files_excluded=total_excluded,
            incomplete_results=incomplete,
            exclusions=exclusions,
        )
        corpus_status = (
            CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
            if (not excluded_sorted and file_status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE)
            else CoverageStatus.PARTIAL
        )
        return CorpusSearchReport(
            spec_digest=digest,
            coverage=coverage,
            matches=order_source_matches(merged),
            resolution=Resolution(
                strategy=ResolutionStrategy.INDEXED_COMMIT if self._use_index else ResolutionStrategy.DECLARED_SCOPE,
                as_of=_utc_now(),
            ),
            shelves_searched=searched_sorted,
            shelves_excluded=excluded_sorted,
            shelves_declared_total=len(searched_sorted) + len(excluded_sorted),
            corpus_status=corpus_status,
        )


__all__ = [
    "CorpusSearcher",
    "IndexedSearcher",
    "candidate_ids",
    "predicate_literal_runs",
]
