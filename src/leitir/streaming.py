from __future__ import annotations

import codecs
import hashlib
from collections.abc import Callable

from leitir.adapters import LanguageAdapter
from leitir.ranking import source_identity
from leitir.search import (
    PredicateKind,
    SearchSpec,
    SourceMatch,
    SourceRef,
)
from leitir.tree import STREAM_CHUNK_SIZE, BlobEntry, TreeSource

MAX_LINE_BYTES = 512 * 1024


class StreamVerificationError(Exception):
    pass


def _merge_match(existing: SourceMatch, incoming: SourceMatch) -> SourceMatch:
    return SourceMatch(
        source=existing.source,
        score=max(existing.score, incoming.score),
        method="ast" if existing.method == incoming.method == "ast" else "heuristic",
        matched_kinds=tuple(
            sorted(
                set(existing.matched_kinds) | set(incoming.matched_kinds),
                key=lambda kind: kind.value,
            )
        ),
    )


def score_blob_stream(
    source: TreeSource,
    blob: BlobEntry,
    *,
    slug: str,
    commit_sha: str,
    path: str,
    adapter: LanguageAdapter,
    spec: SearchSpec,
    retry: Callable[
        [Callable[[], tuple[list[SourceMatch], bool]]],
        tuple[list[SourceMatch], bool],
    ],
) -> tuple[list[SourceMatch], bool, bool]:
    if spec.whole_file_must:
        return [], True, False
    content_must = tuple(
        predicate
        for predicate in spec.must
        if predicate.kind is not PredicateKind.PATH
    )

    def consume_one_attempt() -> tuple[list[SourceMatch], bool]:
        from leitir.engine import _score_content_ex

        digest = hashlib.sha1(b"blob %d\0" % blob.size)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        received = 0
        buffer = ""
        batch = ""
        line_bytes = 0
        line_offset = 0
        file_excluded = False
        parser_unavailable = False
        pending: dict[tuple[str, str, str, str, int, int], SourceMatch] = {}

        def flush_batch() -> None:
            nonlocal batch, file_excluded, line_offset, parser_unavailable
            if not batch:
                return
            if not file_excluded:
                for predicate in spec.must_not:
                    if predicate.kind is PredicateKind.PATH:
                        continue
                    exclusion_result = adapter.find_matches_ex(
                        batch, (predicate,), whole_file=False
                    )
                    parser_unavailable = (
                        parser_unavailable
                        or exclusion_result.parser_unavailable
                    )
                    if exclusion_result.spans:
                        file_excluded = True
                        break
            blob_matches, batch_parser_unavailable = _score_content_ex(
                batch,
                adapter,
                slug,
                commit_sha,
                path,
                blob.blob_sha,
                content_must,
                spec.should,
                spec.must_not,
                whole_file=False,
            )
            parser_unavailable = parser_unavailable or batch_parser_unavailable
            for match in blob_matches:
                local = match.source
                rebased = SourceMatch(
                    source=SourceRef(
                        slug=local.slug,
                        commit_sha=local.commit_sha,
                        path=local.path,
                        blob_sha=local.blob_sha,
                        start_line=local.start_line + line_offset,
                        end_line=local.end_line + line_offset,
                    ),
                    score=match.score,
                    matched_kinds=match.matched_kinds,
                    method=match.method,
                )
                identity = source_identity(rebased.source)
                prior = pending.get(identity)
                pending[identity] = (
                    rebased if prior is None else _merge_match(prior, rebased)
                )
            line_offset += batch.count("\n")
            batch = ""

        for chunk in source.read_blob_stream(slug, blob.blob_sha):
            if not isinstance(chunk, bytes):
                raise StreamVerificationError("stream chunk is not bytes")
            received += len(chunk)
            if received > blob.size:
                raise StreamVerificationError("stream exceeds declared size")
            digest.update(chunk)
            byte_parts = chunk.split(b"\n")
            line_bytes += len(byte_parts[0])
            if line_bytes > MAX_LINE_BYTES:
                raise StreamVerificationError("line exceeds max budget")
            for byte_line in byte_parts[1:]:
                line_bytes = len(byte_line)
                if line_bytes > MAX_LINE_BYTES:
                    raise StreamVerificationError("line exceeds max budget")
            buffer += decoder.decode(chunk, final=False)
            text_lines = buffer.split("\n")
            buffer = text_lines.pop()
            for line in text_lines:
                if len(line) > MAX_LINE_BYTES:
                    raise StreamVerificationError("line exceeds max budget")
                batch += line + "\n"
                if len(batch) >= STREAM_CHUNK_SIZE:
                    flush_batch()
            if len(buffer) > MAX_LINE_BYTES:
                raise StreamVerificationError("line exceeds max budget")
        buffer += decoder.decode(b"", final=True)
        if len(buffer) > MAX_LINE_BYTES:
            raise StreamVerificationError("line exceeds max budget")
        if buffer:
            batch += buffer
            buffer = ""
        flush_batch()
        if received != blob.size:
            raise StreamVerificationError("declared size mismatch")
        if digest.hexdigest() != blob.blob_sha:
            raise StreamVerificationError("git blob sha mismatch")
        if file_excluded:
            return [], parser_unavailable
        return [pending[key] for key in sorted(pending)], parser_unavailable

    matches, parser_unavailable = retry(consume_one_attempt)
    return matches, False, parser_unavailable
