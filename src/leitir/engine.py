"""Scoped-exhaustive search engine.

ADR-001 P2: given a ``SearchSpec`` in ``SCOPED_EXHAUSTIVE`` mode, enumerate
every blob in the declared scopes at their pinned commits, evaluate typed
predicates through language adapters, and return a ``SearchReport`` with honest
coverage accounting.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from leitir.warm import WarmSession

from leitir.adapters import LanguageAdapter, SpanMatch
from leitir.adapters.languages import canonicalize_language
from leitir.adapters.registry import trusted_adapter_language
from leitir.matching import document_excluded_ex
from leitir.materialize import (
    VerificationError,
    _target_lock,
    _utc_now,
    read_valid_manifest,
    target_path,
)
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
from leitir.streaming import score_blob_stream
from leitir.tree import BlobEntry, TreeEnumerationError, TreeSource

MAX_BLOB_SIZE = 2 * 1024 * 1024


class _LocalShelfReader:
    def __init__(self, target: Path, manifest: dict[str, object]) -> None:
        self._target = target
        self._manifest = manifest

    @property
    def fully_verified(self) -> bool:
        return (self._manifest.get("materialized_tree_hash_scope") == "full"
                and self._manifest.get("source") == "git-commit")

    @property
    def drift_git_only_count(self) -> int:
        count = self._manifest.get("only_in_git")
        return count if self._manifest.get("parity") == "drift" and isinstance(count, int) and count > 0 else 0

    def list_local_blobs(self) -> tuple[BlobEntry, ...]:
        """Enumerate the verified materialized universe without consulting GitHub."""

        blobs: list[BlobEntry] = []
        for path in sorted(self._target.rglob("*")):
            if path.name in {"leitir-manifest.json", "index.json"}:
                continue
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise VerificationError(f"cannot safely stat local blob: {path}") from exc
            if stat.S_ISDIR(metadata.st_mode):
                continue
            relative = path.relative_to(self._target).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                link = os.readlink(os.fsencode(path))
                data = link if isinstance(link, bytes) else os.fsencode(link)
                mode = "120000"
            elif stat.S_ISREG(metadata.st_mode):
                data = path.read_bytes()
                mode = "100755" if metadata.st_mode & stat.S_IXUSR else "100644"
            else:
                raise VerificationError(f"local blob is not a file: {relative}")
            digest = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
            blobs.append(BlobEntry(relative, digest, len(data), mode))
        return tuple(blobs)

    def read(self, blob: BlobEntry) -> bytes:
        return b"".join(self.stream(blob))

    def stream(self, blob: BlobEntry) -> Iterator[bytes]:
        path, metadata = self._path(blob)
        data_size = 0
        digest = hashlib.sha1(
            b"blob " + str(blob.size).encode("ascii") + b"\0"
        )
        try:
            if stat.S_ISLNK(metadata.st_mode):
                link = os.readlink(os.fsencode(path))
                data = link if isinstance(link, bytes) else os.fsencode(link)
                current = path.lstat()
                if not stat.S_ISLNK(current.st_mode) or not self._same_inode(
                    metadata, current
                ):
                    raise VerificationError(
                        f"local blob changed while reading: {blob.path}"
                    )
                data_size += len(data)
                digest.update(data)
                yield data
            elif stat.S_ISREG(metadata.st_mode):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags)
                try:
                    current = os.fstat(fd)
                    if not stat.S_ISREG(current.st_mode) or not self._same_inode(
                        metadata, current
                    ):
                        raise VerificationError(
                            f"local blob changed while opening: {blob.path}"
                        )
                    with os.fdopen(fd, "rb") as handle:
                        fd = -1
                        while chunk := handle.read(64 * 1024):
                            data_size += len(chunk)
                            digest.update(chunk)
                            yield chunk
                finally:
                    if fd >= 0:
                        os.close(fd)
            else:
                raise VerificationError(f"local blob is not a file: {blob.path}")
        except OSError as exc:
            raise VerificationError(
                f"cannot safely read local blob: {blob.path}"
            ) from exc

        if data_size != blob.size:
            raise VerificationError(f"local blob size mismatch: {blob.path}")
        if digest.hexdigest() == blob.blob_sha:
            return
        raise VerificationError(f"local blob digest mismatch: {blob.path}")

    def _path(self, blob: BlobEntry) -> tuple[Path, os.stat_result]:
        relative = Path(blob.path)
        if (
            not blob.path
            or "\0" in blob.path
            or relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
        ):
            raise VerificationError(f"local blob path is invalid: {blob.path!r}")
        current = self._target
        for index, part in enumerate(relative.parts):
            current /= part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise VerificationError(
                    f"cannot safely stat local blob: {blob.path}"
                ) from exc
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                raise VerificationError(
                    f"local blob parent is not a directory: {blob.path}"
                )
        if stat.S_ISLNK(metadata.st_mode):
            if blob.mode is not None and not blob.mode.startswith("120000"):
                raise VerificationError(f"local blob mode mismatch: {blob.path}")
        elif stat.S_ISREG(metadata.st_mode):
            if blob.mode is not None and not blob.mode.startswith("100"):
                raise VerificationError(f"local blob mode mismatch: {blob.path}")
        else:
            raise VerificationError(f"local blob is not a file: {blob.path}")
        return current, metadata

    @staticmethod
    def _same_inode(before: os.stat_result, after: os.stat_result) -> bool:
        return before.st_dev == after.st_dev and before.st_ino == after.st_ino


class _LocalBlobStream:
    def __init__(self, reader: _LocalShelfReader, blob: BlobEntry) -> None:
        self._reader = reader
        self._blob = blob

    def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
        if blob_sha != self._blob.blob_sha:
            raise VerificationError("local blob stream identity mismatch")
        yield from self._reader.stream(self._blob)


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


def path_matches_ex(path: str, predicates: Sequence[Predicate]) -> tuple[bool, bool]:
    """Return ``(matched, budget_exceeded)`` for whether ``path`` satisfies any PATH predicate.

    A PATH predicate value is tried both as a literal substring (unconditionally -- see
    below) and, opportunistically, as a regex against ``path``. The regex attempt is a ReDoS
    risk exactly like the ``regex:``/``signature:`` paths ``leitir._regex_budget`` already
    protects: a corpus can contain very long paths (deeply nested vendored trees are real),
    and a PATH predicate is never shape-checked at construction time the way ``regex:``
    predicates are (``Predicate.__post_init__`` skips the check for ``PredicateKind.PATH``
    on purpose, because a PATH value is legitimately used as a plain literal substring first
    -- rejecting construction outright on a catastrophic-looking literal would break that
    correct, common case). So the same two defenses from ``_regex_budget`` are applied here,
    at match time, only around the *regex* attempt:

    1. If ``predicate.value`` has a known catastrophic-backtracking shape
       (:func:`has_catastrophic_shape`), the regex attempt is skipped.
    2. If ``path`` is longer than :data:`MAX_REGEX_LINE_LENGTH`, the regex attempt is
       skipped (reusing the same cap as line matching -- ``PATH_MAX`` on Linux is 4096
       bytes, so this comfortably covers every real filesystem path while still bounding
       worst-case backtracking input length).

    The literal substring check (`predicate.value in path`) always runs first and is never
    skipped, so ordinary PATH predicates behave exactly as before. ``budget_exceeded`` is
    True whenever a regex attempt was skipped for either reason and no earlier predicate
    already matched; callers must treat that as an incomplete result (like
    ``parser_unavailable`` elsewhere in this module), never as a silent non-match.
    """
    from leitir._regex_budget import MAX_REGEX_LINE_LENGTH, has_catastrophic_shape

    budget_exceeded = False
    for predicate in predicates:
        if predicate.kind is not PredicateKind.PATH:
            continue
        if predicate.value in path:
            return True, budget_exceeded
        if has_catastrophic_shape(predicate.value) or len(path) > MAX_REGEX_LINE_LENGTH:
            budget_exceeded = True
            continue
        try:
            if re.search(predicate.value, path):
                return True, budget_exceeded
        except re.error:
            pass
    return False, budget_exceeded


def path_matches(path: str, predicates: Sequence[Predicate]) -> bool:
    """Return whether ``path`` satisfies any local PATH predicate.

    Convenience wrapper around :func:`path_matches_ex` for callers that do not need to
    surface budget-exceeded incompleteness (e.g. tests exercising ordinary predicates).
    """
    matched, _budget_exceeded = path_matches_ex(path, predicates)
    return matched


def _span_excluded_ex(
    content: str,
    adapter: LanguageAdapter,
    span: SpanMatch,
    must_not: tuple[Predicate, ...],
    whole_file: bool = False,
) -> tuple[bool, bool]:
    parser_unavailable = False
    for pred in must_not:
        if pred.kind is PredicateKind.PATH:
            continue
        result = adapter.find_matches_ex(content, (pred,))
        parser_unavailable = parser_unavailable or result.parser_unavailable
        if whole_file and result.spans:
            return True, parser_unavailable
        for hit in result.spans:
            if hit.start_line == span.start_line:
                return True, parser_unavailable
    return False, parser_unavailable


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
    matches, _parser_unavailable = _score_content_ex(
        content,
        adapter,
        slug,
        commit_sha,
        path,
        blob_sha,
        content_must,
        should,
        must_not,
        whole_file,
    )
    return matches


def _score_content_ex(
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
) -> tuple[list[SourceMatch], bool]:
    result = adapter.find_matches_ex(
        content, content_must, whole_file=whole_file
    )
    spans = result.spans
    parser_unavailable = result.parser_unavailable
    if not spans and content_must:
        return [], parser_unavailable
    if not spans and not content_must:
        should_result = adapter.find_matches_ex(content, should) if should else None
        if should_result is not None:
            spans = should_result.spans
            parser_unavailable = (
                parser_unavailable or should_result.parser_unavailable
            )

    whole_file_should_kinds: set[PredicateKind] = set()
    whole_file_should_boost = 0
    if whole_file:
        for pred in should:
            should_result = adapter.find_matches_ex(content, (pred,))
            parser_unavailable = (
                parser_unavailable or should_result.parser_unavailable
            )
            if should_result.spans:
                whole_file_should_kinds.add(pred.kind)
                whole_file_should_boost += 1

    matches: list[SourceMatch] = []
    for span in spans:
        if must_not:
            excluded, exclusion_parser_unavailable = _span_excluded_ex(
                content, adapter, span, must_not, whole_file=whole_file
            )
            parser_unavailable = (
                parser_unavailable or exclusion_parser_unavailable
            )
            if excluded:
                continue

        matched_kinds = set(span.matched_kinds)
        should_boost = whole_file_should_boost
        if whole_file:
            matched_kinds.update(whole_file_should_kinds)
        elif should:
            should_result = adapter.find_matches_ex(content, should)
            parser_unavailable = (
                parser_unavailable or should_result.parser_unavailable
            )
            for ss in should_result.spans:
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
    return matches, parser_unavailable


class ScopedSearcher:
    """Executes a scoped-exhaustive search over pinned commits."""

    def __init__(
        self,
        tree_source: TreeSource,
        adapters: tuple[LanguageAdapter, ...],
        max_blob_size: int = MAX_BLOB_SIZE,
        corpus_root: str | os.PathLike[str] | None = None,
        *,
        session: WarmSession | None = None,
    ) -> None:
        self._tree = tree_source
        self._adapters = adapters
        self._max_blob_size = max_blob_size
        selected_root = corpus_root or os.environ.get("LEITIR_HOME") or "~/.leitir"
        self._corpus_root = Path(selected_root).expanduser().absolute()
        self._session = session
        retry = getattr(tree_source, "_retry", None)
        self._retry: Callable[
            [Callable[[], tuple[list[SourceMatch], bool]]],
            tuple[list[SourceMatch], bool],
        ] = retry if callable(retry) else lambda operation: operation()

    def search(self, spec: SearchSpec) -> SearchReport:
        if spec.mode is not SearchMode.SCOPED_EXHAUSTIVE:
            raise ValueError("ScopedSearcher only handles scoped_exhaustive")

        required_language = _required_language(spec)
        supported_languages = {
            language
            for adapter in self._adapters
            if (language := trusted_adapter_language(adapter)) is not None
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
        exclusions: dict[str, int] = {}
        incomplete = False

        for scope in spec.scopes:
            with self._local_shelf(scope.slug, scope.commit_sha) as local_shelf:
                enumeration_excluded = 0
                if local_shelf is not None and local_shelf.fully_verified:
                    # Only exact Git shelves establish Git blob provenance.
                    # An artifact tree hash authenticates artifact bytes, not
                    # equivalence to the declared upstream commit.
                    blobs = local_shelf.list_local_blobs()
                    recovered = False
                    drift_excluded = local_shelf.drift_git_only_count
                else:
                    drift_excluded = local_shelf.drift_git_only_count if local_shelf is not None else 0
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
                    scope.slug,
                    scope.commit_sha,
                    blobs,
                    spec,
                    required_language,
                    local_shelf,
                )
            total_eligible += eligible
            total_indexed += indexed
            total_excluded += excluded + enumeration_excluded + drift_excluded
            if drift_excluded:
                exclusions["registry_artifact_git_only"] = exclusions.get("registry_artifact_git_only", 0) + drift_excluded
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
            exclusions=exclusions,
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
        local_shelf: _LocalShelfReader | None,
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
        path_budget_exceeded = False
        if path_preds:
            filtered_blobs = []
            for b in eligible_blobs:
                matched, exceeded = path_matches_ex(b.path, path_preds)
                path_budget_exceeded = path_budget_exceeded or exceeded
                if matched:
                    filtered_blobs.append(b)
            eligible_blobs = filtered_blobs

        files_eligible = len(eligible_blobs)
        files_indexed = 0
        files_excluded = 0
        matches: list[SourceMatch] = []
        partial = path_budget_exceeded

        for blob in eligible_blobs:
            if blob.size > self._max_blob_size:
                adapter = self._adapter_for(blob.path, required_language)
                if adapter is None:
                    continue
                try:
                    (
                        blob_matches,
                        was_excluded,
                        parser_unavailable,
                    ) = score_blob_stream(
                        cast(
                            TreeSource,
                            _LocalBlobStream(local_shelf, blob)
                            if local_shelf is not None
                            else self._tree,
                        ),
                        blob,
                        slug=slug,
                        commit_sha=commit_sha,
                        path=blob.path,
                        adapter=adapter,
                        spec=spec,
                        retry=self._retry,
                    )
                except VerificationError:
                    raise
                except Exception:
                    was_excluded = True
                    parser_unavailable = False
                    blob_matches = []
                if was_excluded:
                    files_excluded += 1
                    partial = True
                    continue
                files_indexed += 1
                if parser_unavailable:
                    files_excluded += 1
                    partial = True
                matches.extend(blob_matches)
                continue

            try:
                data = (
                    local_shelf.read(blob)
                    if local_shelf is not None
                    else self._tree.read_blob(slug, blob.blob_sha)
                )
            except VerificationError:
                raise
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

            parser_unavailable = False
            if must_not:
                excluded, parser_unavailable = document_excluded_ex(
                    content, adapter, must_not
                )
                if parser_unavailable:
                    files_excluded += 1
                    partial = True
                if excluded:
                    continue

            blob_matches, score_parser_unavailable = _score_content_ex(
                content,
                adapter,
                slug,
                commit_sha,
                blob.path,
                blob.blob_sha,
                content_must,
                should,
                must_not,
                whole_file=spec.whole_file_must,
            )
            if score_parser_unavailable and not parser_unavailable:
                files_excluded += 1
                partial = True
            matches.extend(blob_matches)

        return files_eligible, files_indexed, files_excluded, matches, partial

    @contextmanager
    def _local_shelf(
        self, slug: str, commit_sha: str
    ) -> Iterator[_LocalShelfReader | None]:
        owner, separator, repo = slug.rpartition("/")
        if not separator or not owner or not repo:
            yield None
            return
        try:
            target = target_path(
                self._corpus_root, owner, repo, commit_sha, host="github.com"
            )
        except ValueError:
            yield None
            return
        if not target.exists() or target.is_symlink():
            yield None
            return
        if self._session is None:
            with _target_lock(self._corpus_root, target, commit_sha):
                manifest = read_valid_manifest(
                    target, owner, repo, commit_sha, host="github.com"
                )
                if manifest is None:
                    raise VerificationError("existing local shelf has invalid or missing integrity metadata")
                yield _LocalShelfReader(target, manifest)
            return

        # ``call`` is reentrant, so a callable-API owner can bracket a whole
        # tool call while direct engine callers still get a safe one-shelf
        # window.  Streamed content keeps the cold path's per-target lock
        # held across the stream; the session memo may shortcut the manifest
        # read only when the writer-visible epoch advanced by exactly this
        # acquisition's single bump (ADR-0035 epoch amendment), so a foreign
        # writer between memo and lock still forces the full cold gate.
        with (
            self._session.call(),
            _target_lock(self._corpus_root, target, commit_sha),
        ):
            manifest = self._session.resolve_under_lock(
                target, owner, repo, commit_sha, host="github.com"
            )
            if manifest is None:
                manifest = read_valid_manifest(
                    target, owner, repo, commit_sha, host="github.com"
                )
                if manifest is not None:
                    self._session.record_under_lock(
                        target,
                        owner,
                        repo,
                        commit_sha,
                        manifest,
                        host="github.com",
                    )
            if manifest is None:
                raise VerificationError("existing local shelf has invalid or missing integrity metadata")
            yield _LocalShelfReader(target, manifest)

    def _adapter_for(
        self, path: str, required_language: str | None = None
    ) -> LanguageAdapter | None:
        for adapter in self._adapters:
            language = trusted_adapter_language(adapter)
            if language is None:
                continue
            if (
                required_language is None or language == required_language
            ) and adapter.eligible(path):
                return adapter
        return None
