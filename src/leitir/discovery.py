"""Step 2: deterministic targeted discovery.

Tier 1 and 2 queries are sent to an injected local SearXNG HTTP boundary.
Tier 3 queries are sent to authenticated GitHub Code Search.  The module
neither imports nor invokes a model client or fetches source content.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import posixpath
import time
from types import MappingProxyType
from typing import Callable, Protocol
from urllib.parse import (
    parse_qsl,
    quote,
    urlencode,
    urlsplit,
    urlunsplit,
)

from .config import Config
from .contracts import (
    ArtifactId,
    ErrorCode,
    EvidenceTier,
    QueryExpansionPlan,
    QueryRecord,
    StepStatus,
    WorkflowStep,
)
from .openrouter import CredentialError, _hashable_text
from .protocols import ExecutionTraceRecorder
from .trace import (
    ArtifactKind,
    ArtifactReference,
    DiscoveryAttemptData,
    DiscoveryChannelErrorData,
    DiscoveryData,
    TraceSpan,
)


_RETRYABLE_STATUSES = frozenset({408, 409, 425, 429})
DISCOVERY_INTER_QUERY_DELAY_SECONDS = 0.25
_TRACKING_PARAMETERS = frozenset(
    {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"}
)


class DiscoveryChannel(str, Enum):
    SEARXNG = "searxng"
    GITHUB_CODE_SEARCH = "github_code_search"


@dataclass(frozen=True, slots=True)
class DiscoveryHttpResponse:
    """Small fake-friendly response for the injected GET boundary."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise TypeError("HTTP response status must be an integer")
        if not isinstance(self.body, bytes):
            raise TypeError("HTTP response body must be bytes")
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


class DiscoveryHttpTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: int | float,
    ) -> DiscoveryHttpResponse: ...


class UrllibDiscoveryHttpTransport:
    """Standard-library GET transport; imports network modules only on use."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: int | float,
    ) -> DiscoveryHttpResponse:
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        request = Request(url=url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout) as response:
                return DiscoveryHttpResponse(
                    status=response.status,
                    body=response.read(),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as exc:
            try:
                body = exc.read()
            except Exception:
                body = b""
            return DiscoveryHttpResponse(
                status=exc.code,
                body=body,
                headers=dict(exc.headers.items()) if exc.headers else {},
            )


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    """Normalized Step 2 output.  Content retrieval remains Step 3's job."""

    canonical_url: str
    domain: str
    tier: EvidenceTier
    query_ids: tuple[str, ...]
    query_provenance: tuple[str, ...]
    channel: DiscoveryChannel
    source_metadata: Mapping[str, object]
    retrieval_metadata: Mapping[str, object]
    repository: str | None = None
    file_path: str | None = None
    revision: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tier, EvidenceTier):
            raise TypeError("tier must be an EvidenceTier")
        if not isinstance(self.channel, DiscoveryChannel):
            raise TypeError("channel must be a DiscoveryChannel")
        if not self.canonical_url or not self.domain:
            raise ValueError("canonical_url and domain must not be empty")
        if not self.query_ids or any(not value for value in self.query_ids):
            raise ValueError("query_ids must not be empty")
        if not self.query_provenance or any(
            not value for value in self.query_provenance
        ):
            raise ValueError("query_provenance must not be empty")
        object.__setattr__(
            self, "source_metadata", MappingProxyType(dict(self.source_metadata))
        )
        object.__setattr__(
            self,
            "retrieval_metadata",
            MappingProxyType(dict(self.retrieval_metadata)),
        )

    @property
    def originating_query_ids(self) -> tuple[str, ...]:
        return self.query_ids


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    candidates: tuple[DiscoveryCandidate, ...]
    discovery_data: DiscoveryData

    @property
    def partial(self) -> bool:
        return bool(self.discovery_data.partial_failures)


class DiscoveryZeroResultsError(RuntimeError):
    """No usable evidence remained after all applicable requests and retries."""

    code = ErrorCode.ERR_SEARCH_ZERO_RESULTS

    def __init__(self, discovery_data: DiscoveryData):
        self.discovery_data = discovery_data
        super().__init__(
            "targeted discovery returned zero usable results after retries"
        )


class DiscoveryAuthError(RuntimeError):
    """GitHub credentials were missing, invalid, or rejected."""

    code = ErrorCode.ERR_SEARCH_AUTH_REQUIRED

    def __init__(self, discovery_data: DiscoveryData):
        self.discovery_data = discovery_data
        super().__init__("GitHub auth required / failed")


class DiscoveryEnginesBlockedError(RuntimeError):
    """SearXNG reported that its configured engines were unavailable."""

    code = ErrorCode.ERR_SEARCH_ENGINES_BLOCKED

    def __init__(self, discovery_data: DiscoveryData):
        self.discovery_data = discovery_data
        super().__init__("SearXNG engines blocked/rate-limited")


class GitHubCredentialProvider:
    """Load a GitHub token without exposing its value in errors or traces."""

    def __init__(self, path: str | Path = "~/.config/gh/hosts.yml") -> None:
        self._path = Path(path)

    def get_github_token(self) -> str:
        env_token: str | None = None
        for variable in ("GH_TOKEN", "GITHUB_TOKEN"):
            value = os.environ.get(variable)
            if value:
                if (
                    env_token is not None
                    and _hashable_text(value) != _hashable_text(env_token)
                ):
                    raise CredentialError("GitHub credential aliases conflict")
                env_token = value
        if env_token:
            return self._validate(env_token)

        try:
            import yaml

            document = yaml.safe_load(
                self._path.expanduser().read_text(encoding="utf-8")
            )
        except Exception:
            raise CredentialError(
                "GitHub credential document could not be loaded"
            ) from None
        if not isinstance(document, Mapping) or not isinstance(
            document.get("users"), Mapping
        ):
            raise CredentialError("GitHub credential document is malformed")
        tokens = [
            entry["oauth_token"]
            for entry in document["users"].values()
            if isinstance(entry, Mapping)
            and isinstance(entry.get("oauth_token"), str)
        ]
        if not tokens:
            raise CredentialError("GitHub credential token is missing")
        if len({_hashable_text(token) for token in tokens}) > 1:
            raise CredentialError("GitHub credential aliases conflict")
        return self._validate(tokens[0])

    @staticmethod
    def _validate(token: str) -> str:
        if (
            not token
            or token != token.strip()
            or any(character in token for character in "\r\n")
        ):
            raise CredentialError("GitHub credential token is invalid")
        return token


@dataclass(slots=True)
class _Telemetry:
    attempts: list[DiscoveryAttemptData] = field(default_factory=list)
    errors: list[DiscoveryChannelErrorData] = field(default_factory=list)
    filtering_reasons: list[str] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    urls_found: int = 0
    before_filter: int = 0
    after_filter: int = 0


@dataclass(frozen=True, slots=True)
class _Page:
    candidates: tuple[DiscoveryCandidate, ...]
    item_count: int
    has_more: bool


class _Adapter:
    channel: DiscoveryChannel
    tiers: frozenset[EvidenceTier]

    def __init__(
        self,
        http: DiscoveryHttpTransport,
        *,
        config: Config | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        credentials: GitHubCredentialProvider | None = None,
    ) -> None:
        self._http = http
        self._config = config or Config.default()
        self._sleep = sleep
        self._monotonic = monotonic
        self._credentials = credentials

    def search(
        self,
        record: QueryRecord,
        query_id: str | None = None,
        telemetry: _Telemetry | None = None,
    ) -> tuple[DiscoveryCandidate, ...]:
        if not isinstance(record, QueryRecord):
            raise TypeError("record must be a validated QueryRecord")
        if record.tier not in self.tiers:
            raise ValueError(
                f"{self.channel.value} does not accept Tier {record.tier.value}"
            )
        query_id = query_id or query_record_id(record)
        telemetry = telemetry or _Telemetry()
        found: list[DiscoveryCandidate] = []
        for page in range(1, self._config.discovery_max_pages + 1):
            response = self._request(record, query_id, page, telemetry)
            if response is None:
                break
            try:
                parsed = self._parse_page(response.body, record, query_id, page, telemetry)
            except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                telemetry.filtering_reasons.append(
                    f"{self.channel.value}:malformed_response"
                )
                telemetry.errors.append(
                    DiscoveryChannelErrorData(
                        channel=self.channel.value,
                        query_id=query_id,
                        page=page,
                        category="malformed_response",
                        http_status=response.status,
                        attempts=1,
                        retryable=False,
                        exhausted=False,
                    )
                )
                break
            found.extend(parsed.candidates)
            if (
                len(found) >= self._config.discovery_max_results_per_query
                or not parsed.has_more
            ):
                break
        return tuple(found[: self._config.discovery_max_results_per_query])

    def _request(
        self,
        record: QueryRecord,
        query_id: str,
        page: int,
        telemetry: _Telemetry,
    ) -> DiscoveryHttpResponse | None:
        url = self._url(record, page)
        try:
            headers = self._headers()
        except CredentialError:
            telemetry.attempts.append(
                DiscoveryAttemptData(
                    channel=self.channel.value,
                    query_id=query_id,
                    page=page,
                    attempt=1,
                    latency_ms=0,
                    http_status=None,
                    outcome="error",
                    error_category="auth",
                    retryable=False,
                )
            )
            telemetry.errors.append(
                DiscoveryChannelErrorData(
                    channel=self.channel.value,
                    query_id=query_id,
                    page=page,
                    category="auth",
                    http_status=None,
                    attempts=1,
                    retryable=False,
                    exhausted=False,
                )
            )
            return None
        last_category = "transport"
        last_status: int | None = None
        last_retryable = False
        attempts = 0
        for attempt in range(1, self._config.discovery_max_attempts + 1):
            attempts = attempt
            response = None
            started = self._monotonic()
            try:
                response = self._http.get(
                    url,
                    headers=headers,
                    timeout=self._config.discovery_timeout_seconds,
                )
            except (TimeoutError, ConnectionError, OSError) as exc:
                last_category = (
                    "timeout" if isinstance(exc, TimeoutError) else "transport"
                )
                last_status = None
                last_retryable = True
                telemetry.attempts.append(
                    DiscoveryAttemptData(
                        channel=self.channel.value,
                        query_id=query_id,
                        page=page,
                        attempt=attempt,
                        latency_ms=(self._monotonic() - started) * 1000,
                        http_status=None,
                        outcome="error",
                        error_category=last_category,
                        retryable=True,
                    )
                )
            except Exception:
                last_category = "transport"
                last_status = None
                last_retryable = False
                telemetry.attempts.append(
                    DiscoveryAttemptData(
                        channel=self.channel.value,
                        query_id=query_id,
                        page=page,
                        attempt=attempt,
                        latency_ms=(self._monotonic() - started) * 1000,
                        http_status=None,
                        outcome="error",
                        error_category=last_category,
                        retryable=False,
                    )
                )
            else:
                telemetry.statuses.append(response.status)
                if 200 <= response.status < 300:
                    validation = self._validate_success(response)
                    if validation is None:
                        telemetry.attempts.append(
                            DiscoveryAttemptData(
                                channel=self.channel.value,
                                query_id=query_id,
                                page=page,
                                attempt=attempt,
                                latency_ms=(self._monotonic() - started) * 1000,
                                http_status=response.status,
                                outcome="success",
                            )
                        )
                        return response
                    last_status = response.status
                    last_category = validation
                    last_retryable = True
                else:
                    last_status = response.status
                    last_category = self._status_category(response.status)
                    last_retryable = _retryable_status(
                        response.status, channel=self.channel
                    )
                telemetry.attempts.append(
                    DiscoveryAttemptData(
                        channel=self.channel.value,
                        query_id=query_id,
                        page=page,
                        attempt=attempt,
                        latency_ms=(self._monotonic() - started) * 1000,
                        http_status=response.status,
                        outcome="error",
                        error_category=last_category,
                        retryable=last_retryable,
                    )
                )

            if not last_retryable or attempt == self._config.discovery_max_attempts:
                break
            backoff = min(
                self._config.discovery_retry_initial_backoff_seconds
                * (2 ** (attempt - 1)),
                self._config.discovery_retry_max_backoff_seconds,
            )
            retry_after = (
                response.headers.get("Retry-After")
                if response is not None
                else None
            )
            if retry_after is not None:
                try:
                    retry_after_seconds = float(retry_after)
                except (TypeError, ValueError):
                    retry_after_seconds = None
                if retry_after_seconds is not None:
                    backoff = min(
                        self._config.discovery_retry_max_backoff_seconds,
                        max(backoff, retry_after_seconds),
                    )
            self._sleep(backoff)

        telemetry.errors.append(
            DiscoveryChannelErrorData(
                channel=self.channel.value,
                query_id=query_id,
                page=page,
                category=last_category,
                http_status=last_status,
                attempts=attempts,
                retryable=last_retryable,
                exhausted=(
                    last_retryable
                    and attempts == self._config.discovery_max_attempts
                ),
            )
        )
        return None

    def _headers(self) -> Mapping[str, str]:
        raise NotImplementedError

    def _validate_success(
        self, response: DiscoveryHttpResponse
    ) -> str | None:
        return None

    def _status_category(self, status: int) -> str:
        return "rate_limit" if status in {403, 429} else "http_status"

    def _url(self, record: QueryRecord, page: int) -> str:
        raise NotImplementedError

    def _parse_page(
        self,
        body: bytes,
        record: QueryRecord,
        query_id: str,
        page: int,
        telemetry: _Telemetry,
    ) -> _Page:
        raise NotImplementedError


class SearXNGAdapter(_Adapter):
    """Local, unauthenticated JSON search for Tier 1–2 documentation."""

    channel = DiscoveryChannel.SEARXNG
    tiers = frozenset({EvidenceTier.TIER_1, EvidenceTier.TIER_2})

    def _headers(self) -> Mapping[str, str]:
        return {"Accept": "application/json", "User-Agent": "Leitir/1"}

    def _url(self, record: QueryRecord, page: int) -> str:
        params = {
            "q": record.discovery_query,
            "format": "json",
            "pageno": page,
        }
        if self._config.search_engines:
            params["engines"] = self._config.search_engines
        return f"{self._config.search_endpoint}?{urlencode(params)}"

    def _validate_success(
        self, response: DiscoveryHttpResponse
    ) -> str | None:
        try:
            document = json.loads(response.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return "malformed_response"
        if isinstance(document, Mapping) and document.get("unresponsive_engines"):
            return "engines_blocked"
        return None

    def _parse_page(
        self,
        body: bytes,
        record: QueryRecord,
        query_id: str,
        page: int,
        telemetry: _Telemetry,
    ) -> _Page:
        document = json.loads(body.decode("utf-8"))
        if not isinstance(document, Mapping) or not isinstance(
            document.get("results"), list
        ):
            raise ValueError("malformed SearXNG response")
        items = document["results"]
        telemetry.before_filter += len(items)
        candidates: list[DiscoveryCandidate] = []
        for rank, item in enumerate(items, 1):
            if not isinstance(item, Mapping):
                telemetry.filtering_reasons.append("searxng:malformed_item")
                continue
            raw_url = item.get("url")
            if isinstance(raw_url, str):
                telemetry.urls_found += 1
            normalized = canonicalize_url(raw_url)
            if normalized is None:
                telemetry.filtering_reasons.append("searxng:invalid_url")
                continue
            canonical_url, domain = normalized
            if not _is_site(domain, record.site):
                telemetry.filtering_reasons.append("searxng:outside_target_site")
                continue
            candidates.append(
                DiscoveryCandidate(
                    canonical_url=canonical_url,
                    domain=domain,
                    tier=record.tier,
                    query_ids=(query_id,),
                    query_provenance=record.provenance,
                    channel=self.channel,
                    source_metadata={
                        "title": _optional_text(item.get("title")),
                        "engine": _optional_text(item.get("engine")),
                    },
                    retrieval_metadata={"page": page, "rank": rank},
                )
            )
        telemetry.after_filter += len(candidates)
        return _Page(
            candidates=tuple(candidates),
            item_count=len(items),
            has_more=len(items) >= self._config.discovery_page_size,
        )


class GitHubCodeSearchAdapter(_Adapter):
    """Authenticated GitHub REST Code Search for Tier 3 file candidates."""

    channel = DiscoveryChannel.GITHUB_CODE_SEARCH
    tiers = frozenset({EvidenceTier.TIER_3})

    def _headers(self) -> Mapping[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Leitir/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._credentials is not None:
            token = self._credentials.get_github_token()
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _status_category(self, status: int) -> str:
        if status == 401:
            return "auth"
        return super()._status_category(status)

    def _url(self, record: QueryRecord, page: int) -> str:
        params = urlencode(
            {
                "q": record.query_text,
                "per_page": min(self._config.discovery_page_size, 10),
                "page": page,
            }
        )
        return f"{self._config.github_search_endpoint}?{params}"

    def _parse_page(
        self,
        body: bytes,
        record: QueryRecord,
        query_id: str,
        page: int,
        telemetry: _Telemetry,
    ) -> _Page:
        document = json.loads(body.decode("utf-8"))
        if not isinstance(document, Mapping) or not isinstance(
            document.get("items"), list
        ):
            raise ValueError("malformed GitHub response")
        items = document["items"]
        telemetry.before_filter += len(items)
        candidates: list[DiscoveryCandidate] = []
        for rank, item in enumerate(items, 1):
            if not isinstance(item, Mapping):
                telemetry.filtering_reasons.append("github_code_search:malformed_item")
                continue
            raw_url = item.get("html_url")
            if isinstance(raw_url, str):
                telemetry.urls_found += 1
            normalized = canonicalize_url(raw_url)
            repository = item.get("repository")
            path = item.get("path")
            full_name = (
                repository.get("full_name")
                if isinstance(repository, Mapping)
                else None
            )
            if (
                normalized is None
                or normalized[1] != "github.com"
                or not isinstance(full_name, str)
                or not full_name.strip()
                or not isinstance(path, str)
                or not path.strip()
            ):
                telemetry.filtering_reasons.append(
                    "github_code_search:malformed_item"
                )
                continue
            canonical_url, domain = normalized
            candidates.append(
                DiscoveryCandidate(
                    canonical_url=canonical_url,
                    domain=domain,
                    tier=EvidenceTier.TIER_3,
                    query_ids=(query_id,),
                    query_provenance=record.provenance,
                    channel=self.channel,
                    source_metadata={
                        "name": _optional_text(item.get("name")),
                        "sha": _optional_text(item.get("sha")),
                    },
                    retrieval_metadata={
                        "page": page,
                        "rank": rank,
                        "incomplete_results": bool(
                            document.get("incomplete_results", False)
                        ),
                    },
                    repository=full_name.strip(),
                    file_path=path.strip(),
                    revision=_github_revision(canonical_url),
                )
            )
        telemetry.after_filter += len(candidates)
        total = document.get("total_count")
        page_size = min(self._config.discovery_page_size, 10)
        has_more = (
            len(items) >= page_size
            and (
                not isinstance(total, int)
                or page * page_size < total
            )
        )
        return _Page(tuple(candidates), len(items), has_more)


class TargetedDiscovery:
    """Route a validated Step 1 plan and emit one authority-ordered stream."""

    def __init__(
        self,
        http: DiscoveryHttpTransport,
        *,
        config: Config | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        github_credential_provider: GitHubCredentialProvider | None = None,
    ) -> None:
        self._config = config or Config.default()
        self._trace = trace_recorder
        self._monotonic = monotonic
        self._sleep = sleep
        self._searxng = SearXNGAdapter(
            http,
            config=self._config,
            sleep=sleep,
            monotonic=monotonic,
        )
        self._github = GitHubCodeSearchAdapter(
            http,
            config=self._config,
            sleep=sleep,
            monotonic=monotonic,
            credentials=(
                github_credential_provider
                or GitHubCredentialProvider(self._config.github_credential_path)
            ),
        )

    def discover(
        self,
        plan: QueryExpansionPlan,
        *,
        attempt_number: int = 1,
    ) -> DiscoveryResult:
        if not isinstance(plan, QueryExpansionPlan):
            raise TypeError("plan must be a validated QueryExpansionPlan")
        if (
            isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or attempt_number < 1
        ):
            raise ValueError("attempt_number must be a positive integer")

        started = self._monotonic()
        telemetry = _Telemetry()
        raw_candidates: list[DiscoveryCandidate] = []
        for index, record in enumerate(plan.queries, 1):
            if index > 1:
                self._sleep(DISCOVERY_INTER_QUERY_DELAY_SECONDS)
            query_id = query_record_id(record, index=index)
            adapter = (
                self._github
                if record.tier is EvidenceTier.TIER_3
                else self._searxng
            )
            raw_candidates.extend(adapter.search(record, query_id, telemetry))

        candidates, duplicates = _deduplicate(raw_candidates)
        candidates = candidates[: self._config.discovery_max_results]
        failed_channels = tuple(
            dict.fromkeys(error.channel for error in telemetry.errors)
        )
        partial_failures = failed_channels if candidates else ()
        data = DiscoveryData(
            urls_found=telemetry.urls_found,
            usable_results=len(candidates),
            deduplication_count=duplicates,
            result_tiers=tuple(candidate.tier for candidate in candidates),
            source_domains=tuple(candidate.domain for candidate in candidates),
            http_statuses=tuple(telemetry.statuses),
            filtering_reasons=tuple(telemetry.filtering_reasons),
            before_filter_count=telemetry.before_filter,
            after_filter_count=telemetry.after_filter,
            attempts=tuple(telemetry.attempts),
            channel_errors=tuple(telemetry.errors),
            partial_failures=partial_failures,
        )
        latency_ms = (self._monotonic() - started) * 1000
        failure: (
            DiscoveryZeroResultsError
            | DiscoveryAuthError
            | DiscoveryEnginesBlockedError
            | None
        ) = None
        if not candidates:
            has_auth = any(
                error.category == "auth" for error in telemetry.errors
            )
            has_engines_blocked = any(
                error.category == "engines_blocked"
                for error in telemetry.errors
            )
            has_rate_limit = any(
                error.category == "rate_limit" for error in telemetry.errors
            )
            if has_auth:
                failure = DiscoveryAuthError(data)
            elif has_engines_blocked and not has_rate_limit:
                failure = DiscoveryEnginesBlockedError(data)
            else:
                failure = DiscoveryZeroResultsError(data)
        self._record(
            plan,
            attempt_number=attempt_number,
            candidates=candidates,
            data=data,
            latency_ms=latency_ms,
            failure=failure,
        )
        if failure is not None:
            raise failure
        return DiscoveryResult(candidates=candidates, discovery_data=data)

    def _record(
        self,
        plan: QueryExpansionPlan,
        *,
        attempt_number: int,
        candidates: tuple[DiscoveryCandidate, ...],
        data: DiscoveryData,
        latency_ms: float,
        failure: (
            DiscoveryZeroResultsError
            | DiscoveryAuthError
            | DiscoveryEnginesBlockedError
            | None
        ),
    ) -> None:
        if self._trace is None:
            return
        ids = _artifact_ids(plan.request.request_id, attempt_number)
        self._trace.add_artifact(
            ArtifactReference(
                artifact_id=ids[1],
                kind=ArtifactKind.TOOL_OUTPUT,
                reference=f"memory://step-2/{ids[1]}",
                media_type="application/json",
                metadata={
                    "candidate_count": len(candidates),
                    "channels": [
                        DiscoveryChannel.SEARXNG.value,
                        DiscoveryChannel.GITHUB_CODE_SEARCH.value,
                    ],
                    "credential_mode": "local-and-github-token",
                },
            )
        )
        self._trace.record_span(
            TraceSpan(
                step=WorkflowStep.DISCOVERY,
                status=StepStatus.FAILED if failure else StepStatus.SUCCEEDED,
                latency_ms=latency_ms,
                input_artifact_ids=(ids[0],),
                output_artifact_ids=(ids[1],),
                error_code=failure.code if failure else None,
                error_message=str(failure) if failure else None,
                retry_number=max(
                    (item.attempt - 1 for item in data.attempts), default=0
                ),
                attempt_number=attempt_number,
                discovery=data,
            )
        )


DiscoveryCoordinator = TargetedDiscovery


def query_record_id(record: QueryRecord, *, index: int = 0) -> str:
    """Return a stable non-secret ID for a Step 1 query record."""
    material = json.dumps(
        {
            "index": index,
            "query_text": record.query_text,
            "site": record.site,
            "tier": record.tier.value,
            "provenance": record.provenance,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"query-{hashlib.sha256(material.encode()).hexdigest()[:16]}"


def canonicalize_url(value: object) -> tuple[str, str] | None:
    """Normalize a public HTTP URL before filtering and deduplication."""
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value.strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username
        or parsed.password
    ):
        return None
    try:
        domain = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    scheme = parsed.scheme.lower()
    netloc = domain
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{domain}:{port}"
    path = parsed.path or "/"
    had_trailing_slash = path.endswith("/")
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = f"/{path}"
    if had_trailing_slash and path != "/":
        path += "/"
    # Preserve URL path delimiters while consistently escaping spaces/non-ASCII.
    path = quote(path, safe="/:@!$&'()*+,;=-._~%")
    query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.lower().startswith("utm_")
        and key.lower() not in _TRACKING_PARAMETERS
    ]
    query.sort()
    return (
        urlunsplit((scheme, netloc, path, urlencode(query, doseq=True), "")),
        domain,
    )


def _is_site(domain: str, site: str) -> bool:
    return domain == site or domain.endswith(f".{site}")


def _optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _github_revision(url: str) -> str | None:
    """Read the revision carried by a canonical GitHub blob URL."""
    parts = urlsplit(url).path.split("/")
    try:
        marker = parts.index("blob")
    except ValueError:
        return None
    if marker + 1 >= len(parts):
        return None
    return parts[marker + 1] or None


def _retryable_status(status: int, *, channel: DiscoveryChannel) -> bool:
    return (
        status in _RETRYABLE_STATUSES
        or status >= 500
        or (channel is DiscoveryChannel.GITHUB_CODE_SEARCH and status == 403)
    )


def _deduplicate(
    candidates: list[DiscoveryCandidate],
) -> tuple[tuple[DiscoveryCandidate, ...], int]:
    ordered = sorted(
        enumerate(candidates),
        key=lambda item: (item[1].tier.value, item[0]),
    )
    by_url: dict[str, DiscoveryCandidate] = {}
    order: list[str] = []
    duplicates = 0
    for _, candidate in ordered:
        existing = by_url.get(candidate.canonical_url)
        if existing is None:
            by_url[candidate.canonical_url] = candidate
            order.append(candidate.canonical_url)
            continue
        duplicates += 1
        query_ids = tuple(
            dict.fromkeys((*existing.query_ids, *candidate.query_ids))
        )
        provenance = tuple(
            dict.fromkeys(
                (*existing.query_provenance, *candidate.query_provenance)
            )
        )
        by_url[candidate.canonical_url] = replace(
            existing,
            query_ids=query_ids,
            query_provenance=provenance,
        )
    return tuple(by_url[url] for url in order), duplicates


def _artifact_ids(request_id: str, attempt: int) -> tuple[ArtifactId, ArtifactId]:
    token = hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:16]
    return (
        ArtifactId(f"step-1-{token}-attempt-{attempt}-queries"),
        ArtifactId(f"step-2-{token}-attempt-{attempt}-candidates"),
    )


__all__ = [
    "DiscoveryCandidate",
    "DiscoveryAuthError",
    "DiscoveryChannel",
    "DiscoveryCoordinator",
    "DiscoveryHttpResponse",
    "DiscoveryHttpTransport",
    "DiscoveryResult",
    "DiscoveryEnginesBlockedError",
    "DiscoveryZeroResultsError",
    "GitHubCredentialProvider",
    "GitHubCodeSearchAdapter",
    "SearXNGAdapter",
    "TargetedDiscovery",
    "UrllibDiscoveryHttpTransport",
    "canonicalize_url",
    "query_record_id",
]
