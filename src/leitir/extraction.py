"""Step 3: deterministic extraction, sanitization, and evidence chunking.

Retrieved bytes are always treated as untrusted data.  This module has no model
or credential dependency; HTTP, document extraction, token accounting, sleep,
and clocks are replaceable for offline tests.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
import io
import json
import re
import time
import tokenize
from types import MappingProxyType
from typing import Callable, Protocol
from urllib.parse import quote, urlsplit

from .config import Config
from .contracts import ArtifactId, ErrorCode, EvidenceTier, StepStatus, WorkflowStep
from .discovery import DiscoveryCandidate, DiscoveryResult
from .protocols import ExecutionTraceRecorder
from .trace import (
    ArtifactKind,
    ArtifactReference,
    ExtractionAttemptData,
    ExtractionData,
    SecurityData,
    TraceSpan,
)


_RETRYABLE_STATUSES = frozenset({408, 409, 425, 429})
_TOKEN = re.compile(r"\w+|[^\w\s]", re.UNICODE)
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9._-]+)", re.I)
_INSTRUCTION_PATTERNS = (
    re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b",
        re.I,
    ),
    re.compile(r"\b(?:system|assistant|developer)\s*:\s*", re.I),
    re.compile(r"\byou\s+are\s+(?:chatgpt|an?\s+(?:ai|assistant|model))\b", re.I),
    re.compile(r"\b(?:follow|obey)\s+(?:these|the following|my)\s+instructions?\b", re.I),
    re.compile(
        r"\b(?:reveal|print|exfiltrate)\b.{0,40}"
        r"\b(?:secret|credential|api[_ -]?key)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:run|execute|install)\s+(?:this|the following)"
        r"\s+(?:command|code|package)\b",
        re.I,
    ),
)
_BOILERPLATE = re.compile(
    r"\b(?:accept all cookies|cookie preferences|privacy policy|terms of use|"
    r"skip to (?:main )?content|sign up for (?:our )?newsletter)\b",
    re.I,
)


@dataclass(frozen=True, slots=True)
class ExtractionHttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise TypeError("HTTP response status must be an integer")
        if not isinstance(self.body, bytes):
            raise TypeError("HTTP response body must be bytes")
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


class ExtractionFetcher(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: int | float,
    ) -> ExtractionHttpResponse: ...


class DocumentExtractor(Protocol):
    def extract(self, content: bytes, *, url: str) -> str | None: ...


class TokenCounter(Protocol):
    def count(self, text: str) -> int: ...

    def chunks(self, text: str, maximum_tokens: int) -> tuple[str, ...]: ...


class UrllibExtractionFetcher:
    """Bounded orchestration is owned by :class:`EvidenceExtractor`."""

    def __init__(self, *, max_bytes: int = 5_000_000) -> None:
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 1
        ):
            raise ValueError("max_bytes must be a positive integer")
        self._max_bytes = max_bytes

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: int | float,
    ) -> ExtractionHttpResponse:
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        request = Request(url=url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout) as response:
                return ExtractionHttpResponse(
                    status=response.status,
                    body=response.read(self._max_bytes + 1),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as exc:
            try:
                body = exc.read(self._max_bytes + 1)
            except Exception:
                body = b""
            return ExtractionHttpResponse(
                status=exc.code,
                body=body,
                headers=dict(exc.headers.items()) if exc.headers else {},
            )


class TrafilaturaDocumentExtractor:
    """Main-body Markdown extraction behind a small fixture-friendly seam."""

    def extract(self, content: bytes, *, url: str) -> str | None:
        import trafilatura

        return trafilatura.extract(
            content,
            url=url,
            output_format="markdown",
            include_comments=False,
            include_tables=True,
            favor_precision=True,
        )


class RegexTokenCounter:
    """Shared deterministic accounting used by parent records and chunks."""

    def count(self, text: str) -> int:
        return sum(1 for _ in _TOKEN.finditer(text))

    def chunks(self, text: str, maximum_tokens: int) -> tuple[str, ...]:
        if maximum_tokens < 1:
            raise ValueError("maximum_tokens must be positive")
        matches = tuple(_TOKEN.finditer(text))
        chunks: list[str] = []
        for start in range(0, len(matches), maximum_tokens):
            group = matches[start : start + maximum_tokens]
            chunks.append(text[group[0].start() : group[-1].end()])
        return tuple(chunks)


@dataclass(frozen=True, slots=True)
class EvidenceChunk:
    artifact_id: ArtifactId
    evidence_id: ArtifactId
    ordinal: int
    content: str
    content_reference: str
    token_count: int
    source_uri: str
    repository: str | None
    file_path: str | None
    revision: str | None

    def __post_init__(self) -> None:
        if self.ordinal < 1 or self.token_count < 1:
            raise ValueError("chunk ordinal and token count must be positive")
        if not self.content or not self.content_reference:
            raise ValueError("chunk content and reference must not be empty")


@dataclass(frozen=True, slots=True)
class ExtractionFailure:
    """Normalized terminal Step 3 failure, including the complete attempt trail."""

    category: str
    message: str
    retryable: bool
    exhausted: bool
    attempts: tuple[ExtractionAttemptData, ...]

    def __post_init__(self) -> None:
        if not self.category or not self.message:
            raise ValueError("failure category and message must not be empty")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    artifact_id: ArtifactId
    candidate: DiscoveryCandidate
    source_uri: str
    raw_bytes: bytes
    cleaned_text: str
    cleaned_content_reference: str | None
    total_cleaned_tokens: int
    comments_stripped: bool
    security_flags: tuple[str, ...]
    instruction_like_content: bool
    eligible: bool
    repository_stars: int | None
    star_threshold_passed: bool | None
    revision: str | None
    attempts: tuple[ExtractionAttemptData, ...]
    chunks: tuple[EvidenceChunk, ...]
    error_code: ErrorCode | None = None
    extraction_failure: str | None = None
    failure_details: ExtractionFailure | None = None

    def __post_init__(self) -> None:
        if self.total_cleaned_tokens < 0:
            raise ValueError("total_cleaned_tokens must not be negative")
        if sum(chunk.token_count for chunk in self.chunks) != self.total_cleaned_tokens:
            raise ValueError("parent and chunk token totals must reconcile")
        if not self.eligible and self.chunks:
            raise ValueError("ineligible evidence cannot expose synthesis chunks")
        if (self.extraction_failure is None) != (self.failure_details is None):
            raise ValueError("failure text and normalized details must be recorded together")

    @property
    def raw_byte_count(self) -> int:
        return len(self.raw_bytes)


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    records: tuple[EvidenceRecord, ...]

    @property
    def chunks(self) -> tuple[EvidenceChunk, ...]:
        return tuple(chunk for record in self.records for chunk in record.chunks)

    @property
    def total_cleaned_tokens(self) -> int:
        return sum(record.total_cleaned_tokens for record in self.records)


@dataclass(frozen=True, slots=True)
class _FetchOutcome:
    response: ExtractionHttpResponse | None
    attempts: tuple[ExtractionAttemptData, ...]
    failure: str | None


class EvidenceExtractor:
    """Convert Step 2 candidates into quarantined or chunked evidence records."""

    def __init__(
        self,
        fetcher: ExtractionFetcher,
        *,
        extractor: DocumentExtractor | Callable[..., str | None] | None = None,
        tokenizer: TokenCounter | None = None,
        config: Config | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetcher = fetcher
        self._extractor = extractor or TrafilaturaDocumentExtractor()
        self._tokenizer = tokenizer or RegexTokenCounter()
        self._config = config or Config.default()
        self._trace = trace_recorder
        self._sleep = sleep
        self._monotonic = monotonic

    def extract_all(
        self,
        candidates: DiscoveryResult | Iterable[DiscoveryCandidate],
        *,
        attempt_number: int = 1,
    ) -> ExtractionResult:
        values = (
            candidates.candidates
            if isinstance(candidates, DiscoveryResult)
            else candidates
        )
        return ExtractionResult(
            tuple(
                self.extract(candidate, attempt_number=attempt_number)
                for candidate in values
            )
        )

    def extract(
        self,
        candidate: DiscoveryCandidate,
        *,
        attempt_number: int = 1,
    ) -> EvidenceRecord:
        if not isinstance(candidate, DiscoveryCandidate):
            raise TypeError("candidate must be a DiscoveryCandidate")
        if (
            isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or attempt_number < 1
        ):
            raise ValueError("attempt_number must be a positive integer")

        started = self._monotonic()
        attempts: list[ExtractionAttemptData] = []
        stars: int | None = None
        threshold: bool | None = None
        revision = candidate.revision or _revision_from_url(candidate.canonical_url)
        source_uri = candidate.canonical_url

        if candidate.tier is EvidenceTier.TIER_3:
            if not candidate.repository or not candidate.file_path:
                return self._failure(
                    candidate, source_uri, b"", revision, attempts,
                    "missing_repository_file_identity", None, None, started,
                    attempt_number=attempt_number,
                )
            if not _valid_source_identity(
                candidate.repository, candidate.file_path, revision
            ):
                return self._failure(
                    candidate, source_uri, b"", revision, attempts,
                    "invalid_repository_file_revision_identity", None, None, started,
                    attempt_number=attempt_number,
                )
            stars = _integer_metadata(
                candidate,
                "repository_stars",
                "stars",
                "stargazers_count",
            )
            if stars is None or revision is None:
                metadata_url = (
                    "https://api.github.com/repos/"
                    + quote(candidate.repository, safe="/")
                )
                metadata = self._fetch(metadata_url, "repository_metadata")
                attempts.extend(metadata.attempts)
                if metadata.response is None:
                    return self._failure(
                        candidate, source_uri, b"", revision, attempts,
                        metadata.failure or "repository_metadata_failed",
                        stars, None, started, attempt_number=attempt_number,
                    )
                try:
                    document = json.loads(_decode(metadata.response))
                    if not isinstance(document, Mapping):
                        raise ValueError
                    if stars is None:
                        stars_value = document.get("stargazers_count")
                        if isinstance(stars_value, bool) or not isinstance(
                            stars_value, int
                        ):
                            raise ValueError
                        stars = stars_value
                    if revision is None:
                        default_branch = document.get("default_branch")
                        if not isinstance(default_branch, str) or not default_branch:
                            raise ValueError
                        revision = default_branch
                except (UnicodeError, json.JSONDecodeError, ValueError):
                    return self._failure(
                        candidate, source_uri, b"", revision, attempts,
                        "malformed_repository_metadata", stars, None, started,
                        attempt_number=attempt_number,
                    )
            threshold = stars >= self._config.github_min_stars
            if not threshold:
                return self._failure(
                    candidate, source_uri, b"", revision, attempts,
                    "repository_below_star_threshold", stars, False, started,
                    attempt_number=attempt_number,
                )
            source_uri = self._raw_url(
                candidate.repository,
                revision,
                candidate.file_path,
            )
            fetched = self._fetch(source_uri, "raw_source")
        else:
            fetched = self._fetch(source_uri, "document")

        attempts.extend(fetched.attempts)
        if fetched.response is None:
            return self._failure(
                candidate, source_uri, b"", revision, attempts,
                fetched.failure or "fetch_failed", stars, threshold, started,
                attempt_number=attempt_number,
            )

        raw = fetched.response.body
        try:
            decoded = _decode(fetched.response)
        except UnicodeError:
            return self._failure(
                candidate, source_uri, raw, revision, attempts,
                "unsupported_text_encoding", stars, threshold, started,
                attempt_number=attempt_number,
            )

        raw_flags = _security_flags(decoded)
        comments_stripped = False
        try:
            if candidate.tier is EvidenceTier.TIER_3:
                cleaned, comments_stripped = strip_python_comments(decoded)
            else:
                cleaned = self._extract_document(raw, source_uri)
        except Exception as exc:
            return self._failure(
                candidate, source_uri, raw, revision, attempts,
                f"sanitization_failed:{type(exc).__name__}", stars, threshold, started,
                error_code=(
                    ErrorCode.ERR_SECURITY_PROMPT_INJECTION
                    if raw_flags
                    else None
                ),
                security_flags=raw_flags,
                attempt_number=attempt_number,
            )

        cleaned = _normalize_cleaned(cleaned)
        security_flags = tuple(dict.fromkeys((*raw_flags, *_security_flags(cleaned))))
        if security_flags:
            return self._failure(
                candidate, source_uri, raw, revision, attempts,
                "instruction_like_content_quarantined", stars, threshold, started,
                error_code=ErrorCode.ERR_SECURITY_PROMPT_INJECTION,
                security_flags=security_flags,
                cleaned_text=cleaned,
                comments_stripped=comments_stripped,
                attempt_number=attempt_number,
            )
        if not cleaned or _material_boilerplate(cleaned):
            return self._failure(
                candidate, source_uri, raw, revision, attempts,
                "material_boilerplate_or_empty_extraction", stars, threshold, started,
                error_code=ErrorCode.ERR_SCRAPE_BOILERPLATE_LEAK,
                cleaned_text=cleaned,
                comments_stripped=comments_stripped,
                attempt_number=attempt_number,
            )

        evidence_id = _evidence_id(candidate, revision, raw, attempt_number)
        chunk_texts = self._tokenizer.chunks(cleaned, self._config.chunk_size)
        chunks = tuple(
            EvidenceChunk(
                artifact_id=ArtifactId(f"{evidence_id.value}-chunk-{ordinal:04d}"),
                evidence_id=evidence_id,
                ordinal=ordinal,
                content=text,
                content_reference=f"memory://step-3/{evidence_id.value}/chunk/{ordinal}",
                token_count=self._tokenizer.count(text),
                source_uri=source_uri,
                repository=candidate.repository,
                file_path=candidate.file_path,
                revision=revision,
            )
            for ordinal, text in enumerate(chunk_texts, 1)
        )
        record = EvidenceRecord(
            artifact_id=evidence_id,
            candidate=candidate,
            source_uri=source_uri,
            raw_bytes=raw,
            cleaned_text=cleaned,
            cleaned_content_reference=f"memory://step-3/{evidence_id.value}/cleaned",
            total_cleaned_tokens=self._tokenizer.count(cleaned),
            comments_stripped=comments_stripped,
            security_flags=(),
            instruction_like_content=False,
            eligible=True,
            repository_stars=stars,
            star_threshold_passed=threshold,
            revision=revision,
            attempts=tuple(attempts),
            chunks=chunks,
        )
        self._record(record, started, attempt_number)
        return record

    def _extract_document(self, raw: bytes, url: str) -> str:
        method = getattr(self._extractor, "extract", self._extractor)
        try:
            result = method(raw, url=url)
        except TypeError:
            result = method(raw, url)
        if result is None:
            return ""
        if not isinstance(result, str):
            raise ValueError("document extractor must return text or None")
        return result

    def _raw_url(self, repository: str, revision: str | None, path: str) -> str:
        if not revision:
            raise ValueError("Tier 3 raw retrieval requires a revision")
        owner_repo = quote(repository, safe="/")
        return (
            self._config.raw_content_endpoint.rstrip("/")
            + f"/{owner_repo}/{quote(revision, safe='')}/{quote(path, safe='/')}"
        )

    def _fetch(self, url: str, endpoint_kind: str) -> _FetchOutcome:
        history: list[ExtractionAttemptData] = []
        backoff = self._config.extraction_retry_initial_backoff_seconds
        for attempt in range(1, self._config.extraction_max_attempts + 1):
            started = self._monotonic()
            try:
                response = self._fetcher.get(
                    url,
                    headers={"Accept": "*/*", "User-Agent": "Leitir/1"},
                    timeout=self._config.extraction_timeout_seconds,
                )
            except Exception as exc:
                retryable = isinstance(exc, (TimeoutError, ConnectionError, OSError))
                category = type(exc).__name__
                history.append(
                    ExtractionAttemptData(
                        endpoint_kind, attempt,
                        max(0, (self._monotonic() - started) * 1000),
                        None, "error", category, retryable,
                    )
                )
                if retryable and attempt < self._config.extraction_max_attempts:
                    self._sleep(backoff)
                    backoff = min(
                        backoff * 2,
                        self._config.extraction_retry_max_backoff_seconds,
                    )
                    continue
                return _FetchOutcome(None, tuple(history), f"network:{category}")

            retryable = _retryable_status(response.status)
            if response.status < 200 or response.status >= 300:
                history.append(
                    ExtractionAttemptData(
                        endpoint_kind, attempt,
                        max(0, (self._monotonic() - started) * 1000),
                        response.status, "http_error", "http_status", retryable,
                    )
                )
                if retryable and attempt < self._config.extraction_max_attempts:
                    self._sleep(backoff)
                    backoff = min(
                        backoff * 2,
                        self._config.extraction_retry_max_backoff_seconds,
                    )
                    continue
                return _FetchOutcome(
                    None,
                    tuple(history),
                    f"http_status:{response.status}",
                )
            if len(response.body) > self._config.extraction_max_bytes:
                history.append(
                    ExtractionAttemptData(
                        endpoint_kind, attempt,
                        max(0, (self._monotonic() - started) * 1000),
                        response.status, "rejected", "download_too_large", False,
                    )
                )
                return _FetchOutcome(None, tuple(history), "download_too_large")
            history.append(
                ExtractionAttemptData(
                    endpoint_kind, attempt,
                    max(0, (self._monotonic() - started) * 1000),
                    response.status, "succeeded",
                )
            )
            return _FetchOutcome(response, tuple(history), None)
        raise AssertionError("bounded fetch loop did not return")

    def _failure(
        self,
        candidate: DiscoveryCandidate,
        source_uri: str,
        raw: bytes,
        revision: str | None,
        attempts: list[ExtractionAttemptData],
        failure: str,
        stars: int | None,
        threshold: bool | None,
        started: float,
        *,
        error_code: ErrorCode | None = None,
        security_flags: tuple[str, ...] = (),
        cleaned_text: str = "",
        comments_stripped: bool = False,
        attempt_number: int,
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            artifact_id=_evidence_id(candidate, revision, raw, attempt_number),
            candidate=candidate,
            source_uri=source_uri,
            raw_bytes=raw,
            cleaned_text=cleaned_text,
            cleaned_content_reference=None,
            total_cleaned_tokens=0,
            comments_stripped=comments_stripped,
            security_flags=security_flags,
            instruction_like_content=bool(security_flags),
            eligible=False,
            repository_stars=stars,
            star_threshold_passed=threshold,
            revision=revision,
            attempts=tuple(attempts),
            chunks=(),
            error_code=error_code,
            extraction_failure=failure,
            failure_details=_normalized_failure(failure, tuple(attempts), self._config),
        )
        self._record(record, started, attempt_number)
        return record

    def _record(self, record: EvidenceRecord, started: float, attempt_number: int) -> None:
        if self._trace is None:
            return
        input_id = ArtifactId(f"{record.artifact_id.value}-candidate")
        self._trace.add_artifact(
            ArtifactReference(
                artifact_id=input_id,
                kind=ArtifactKind.TOOL_OUTPUT,
                reference=record.candidate.canonical_url,
                tier=record.candidate.tier,
                metadata={"stage": "discovery_candidate"},
            )
        )
        self._trace.add_artifact(
            ArtifactReference(
                artifact_id=record.artifact_id,
                kind=ArtifactKind.TOOL_OUTPUT,
                reference=f"memory://step-3/{record.artifact_id.value}/raw",
                size_bytes=len(record.raw_bytes),
                digest=hashlib.sha256(record.raw_bytes).hexdigest(),
                tier=record.candidate.tier,
                metadata={
                    "source_uri": record.source_uri,
                    "repository": record.candidate.repository,
                    "file_path": record.candidate.file_path,
                    "revision": record.revision,
                    "eligible": record.eligible,
                    "stars_are_eligibility_only": record.repository_stars is not None,
                },
            )
        )
        for chunk in record.chunks:
            self._trace.add_artifact(
                ArtifactReference(
                    artifact_id=chunk.artifact_id,
                    kind=ArtifactKind.CLEANED_CHUNK,
                    reference=chunk.content_reference,
                    size_bytes=len(chunk.content.encode("utf-8")),
                    digest=hashlib.sha256(chunk.content.encode("utf-8")).hexdigest(),
                    tier=record.candidate.tier,
                    metadata={
                        "parent_artifact_id": record.artifact_id.value,
                        "ordinal": chunk.ordinal,
                        "token_count": chunk.token_count,
                        "source_uri": chunk.source_uri,
                        "revision": chunk.revision,
                    },
                )
            )
        normalized_error = record.error_code
        status = StepStatus.SUCCEEDED
        if record.extraction_failure:
            status = (
                StepStatus.SKIPPED
                if record.extraction_failure == "repository_below_star_threshold"
                else StepStatus.FAILED
            )
        self._trace.record_span(
            TraceSpan(
                step=WorkflowStep.EXTRACTION,
                status=status,
                latency_ms=max(0, (self._monotonic() - started) * 1000),
                input_artifact_ids=(input_id,),
                output_artifact_ids=(
                    record.artifact_id,
                    *(chunk.artifact_id for chunk in record.chunks),
                ),
                error_code=normalized_error,
                error_message=record.extraction_failure,
                retry_number=max((item.attempt - 1 for item in record.attempts), default=0),
                attempt_number=attempt_number,
                extraction=ExtractionData(
                    raw_bytes=len(record.raw_bytes),
                    cleaned_tokens=record.total_cleaned_tokens,
                    comments_stripped=record.comments_stripped,
                    source_tier=record.candidate.tier,
                    repository_stars=record.repository_stars,
                    extraction_failure=record.extraction_failure,
                    attempt_history=record.attempts,
                    star_threshold_passed=record.star_threshold_passed,
                    chunk_count=len(record.chunks),
                ),
                security=SecurityData(
                    flags=record.security_flags,
                    instruction_like_content=record.instruction_like_content,
                ),
            )
        )


def strip_python_comments(source: str) -> tuple[str, bool]:
    """Remove COMMENT tokens while preserving strings, lines, and indentation."""
    if not isinstance(source, str):
        raise TypeError("source must be text")
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    stripped = False
    rewritten: list[tokenize.TokenInfo] = []
    for token in tokens:
        if token.type == tokenize.COMMENT:
            stripped = True
            token = tokenize.TokenInfo(
                token.type,
                " " * len(token.string),
                token.start,
                token.end,
                token.line,
            )
        rewritten.append(token)
    return tokenize.untokenize(rewritten), stripped


def _decode(response: ExtractionHttpResponse) -> str:
    content_type = next(
        (value for key, value in response.headers.items() if key.lower() == "content-type"),
        "",
    )
    match = _CHARSET.search(content_type)
    encodings = [match.group(1)] if match else []
    encodings.extend(["utf-8-sig", "utf-8"])
    if not match:
        encodings.append("latin-1")
    last_error: UnicodeError | None = None
    for encoding in dict.fromkeys(encodings):
        try:
            return response.body.decode(encoding)
        except (LookupError, UnicodeError) as exc:
            if isinstance(exc, UnicodeError):
                last_error = exc
    if last_error is not None:
        raise last_error
    raise UnicodeError("unable to decode response")


def _normalize_cleaned(value: str) -> str:
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip()


def _security_flags(text: str) -> tuple[str, ...]:
    flags = []
    for index, pattern in enumerate(_INSTRUCTION_PATTERNS, 1):
        if pattern.search(text):
            flags.append(f"instruction_pattern_{index}")
    return tuple(flags)


def _material_boilerplate(text: str) -> bool:
    matches = len(_BOILERPLATE.findall(text))
    return matches >= 2 and matches * 20 >= max(1, len(text.split()))


def _retryable_status(status: int) -> bool:
    return status in _RETRYABLE_STATUSES or status >= 500


def _integer_metadata(candidate: DiscoveryCandidate, *keys: str) -> int | None:
    for mapping in (candidate.retrieval_metadata, candidate.source_metadata):
        for key in keys:
            value = mapping.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
    return None


def _valid_source_identity(
    repository: str,
    path: str,
    revision: str | None,
) -> bool:
    repository_parts = repository.split("/")
    if (
        len(repository_parts) != 2
        or any(not part or part in {".", ".."} for part in repository_parts)
    ):
        return False
    path_parts = path.split("/")
    if path.startswith("/") or any(part in {"", ".", ".."} for part in path_parts):
        return False
    return revision is None or (
        bool(revision.strip())
        and revision not in {".", ".."}
        and not any(character in revision for character in "\0\r\n?#")
    )


def _normalized_failure(
    message: str,
    attempts: tuple[ExtractionAttemptData, ...],
    config: Config,
) -> ExtractionFailure:
    category = message.split(":", 1)[0]
    last = attempts[-1] if attempts else None
    retryable = bool(last and last.retryable)
    exhausted = bool(
        retryable
        and last
        and last.attempt >= config.extraction_max_attempts
    )
    return ExtractionFailure(category, message, retryable, exhausted, attempts)


def _revision_from_url(url: str) -> str | None:
    parts = urlsplit(url).path.split("/")
    try:
        index = parts.index("blob")
    except ValueError:
        return None
    return parts[index + 1] if index + 1 < len(parts) and parts[index + 1] else None


def _evidence_id(
    candidate: DiscoveryCandidate,
    revision: str | None,
    raw: bytes,
    attempt_number: int,
) -> ArtifactId:
    material = "\0".join(
        (
            candidate.canonical_url,
            candidate.repository or "",
            candidate.file_path or "",
            revision or "",
            hashlib.sha256(raw).hexdigest(),
            str(attempt_number),
        )
    )
    return ArtifactId(f"evidence-{hashlib.sha256(material.encode()).hexdigest()[:20]}")


Step3Extractor = EvidenceExtractor
ExtractionCoordinator = EvidenceExtractor


__all__ = [
    "DocumentExtractor",
    "EvidenceChunk",
    "EvidenceExtractor",
    "EvidenceRecord",
    "ExtractionCoordinator",
    "ExtractionFetcher",
    "ExtractionFailure",
    "ExtractionHttpResponse",
    "ExtractionResult",
    "RegexTokenCounter",
    "Step3Extractor",
    "TokenCounter",
    "TrafilaturaDocumentExtractor",
    "UrllibExtractionFetcher",
    "strip_python_comments",
]
