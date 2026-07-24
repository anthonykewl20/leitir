"""Secret-safe raw HTTP transport for Leitir's fixed OpenRouter Hy3 contract.

Importing this module does not read credentials or initialize an HTTP client.
The standard-library HTTP implementation imports ``urllib`` only when a request
is actually sent, and both the credential and HTTP boundaries are injectable
for offline tests.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import json
import logging
import math
from pathlib import Path
import time
from types import MappingProxyType
from typing import Callable, Protocol

from .config import (
    Config,
    OPENROUTER_CREDENTIAL_PATH,
    OPENROUTER_ENDPOINT,
    OPENROUTER_MODEL,
)
from .contracts import StepStatus, WorkflowStep
from .protocols import CredentialProvider, ExecutionTraceRecorder
from .trace import ModelData, ProviderUsage, TraceSpan


LOGGER = logging.getLogger(__name__)

_GENERATION_PARAMETERS = (
    "frequency_penalty",
    "min_p",
    "presence_penalty",
    "repetition_penalty",
    "temperature",
    "top_k",
    "top_p",
    "max_completion_tokens",
    "max_tokens",
    "stop",
    "response_format",
    "seed",
    "structured_outputs",
    "tool_choice",
    "tools",
)
_POLICY_CONTROLLED = frozenset(
    {
        "model",
        "messages",
        "reasoning",
        "reasoning_effort",
        "include_reasoning",
        "extra_body",
    }
)
_RETRYABLE_STATUSES = frozenset({408, 409, 425, 429})


class Hy3Purpose(str, Enum):
    """The four allowed Hy3 call purposes.

    ``REVIEW`` remains available for compatibility but is unused by the v1
    workflow loop.
    """

    QUERY_EXPANSION = "query_expansion"
    SYNTHESIS = "synthesis"
    REPAIR = "repair"
    REVIEW = "review"

    @property
    def reasoning_effort(self) -> str | None:
        if self is Hy3Purpose.QUERY_EXPANSION:
            return None
        return "high"

    @property
    def workflow_step(self) -> WorkflowStep:
        if self is Hy3Purpose.QUERY_EXPANSION:
            return WorkflowStep.QUERY_EXPANSION
        if self is Hy3Purpose.REPAIR:
            return WorkflowStep.VERIFICATION
        return WorkflowStep.SYNTHESIS


class OpenRouterError(RuntimeError):
    """Base class whose messages and metadata are safe to log."""


class CredentialError(OpenRouterError):
    """The single supported credential document could not provide a safe key."""


class RequestValidationError(OpenRouterError, ValueError):
    """A caller attempted to violate the fixed request contract."""


class ResponseValidationError(OpenRouterError):
    """OpenRouter returned a completed but malformed response."""

    def __init__(self, *, attempts: int) -> None:
        self.category = "malformed_response"
        self.attempts = attempts
        super().__init__(
            f"OpenRouter response was malformed (category={self.category}, "
            f"attempts={attempts})"
        )


class TransportError(OpenRouterError):
    """Normalized non-response, timeout, or HTTP-status failure."""

    def __init__(
        self,
        *,
        category: str,
        attempts: int,
        retryable: bool,
        exhausted: bool,
        status: int | None = None,
    ) -> None:
        self.category = category
        self.attempts = attempts
        self.retryable = retryable
        self.exhausted = exhausted
        self.status = status
        status_text = "none" if status is None else str(status)
        super().__init__(
            "OpenRouter transport failed "
            f"(category={category}, status={status_text}, attempts={attempts}, "
            f"retryable={str(retryable).lower()}, "
            f"exhausted={str(exhausted).lower()})"
        )

    def to_dict(self) -> dict[str, object]:
        """Return only safe retry metadata; response bodies and headers are absent."""
        return {
            "category": self.category,
            "status": self.status,
            "attempts": self.attempts,
            "retryable": self.retryable,
            "exhausted": self.exhausted,
        }


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Small fake-friendly response at the raw HTTP boundary."""

    status: int
    body: bytes

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise TypeError("HTTP response status must be an integer")
        if not isinstance(self.body, bytes):
            raise TypeError("HTTP response body must be bytes")


class HttpTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: int | float,
    ) -> HttpResponse: ...


class UrllibHttpTransport:
    """Raw standard-library HTTP implementation, created without side effects."""

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: int | float,
    ) -> HttpResponse:
        # Delayed imports preserve the package-wide import-purity contract.
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        request = Request(
            url=url,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                return HttpResponse(status=response.status, body=response.read())
        except HTTPError as exc:
            # HTTP status failures are data for the bounded retry policy.
            try:
                response_body = exc.read()
            except Exception:
                response_body = b""
            return HttpResponse(status=exc.code, body=response_body)


class OpenCodeCredentialProvider:
    """Load the OpenRouter key from the one permitted opencode auth document."""

    def __init__(self, path: str | Path = OPENROUTER_CREDENTIAL_PATH) -> None:
        self._path = Path(path)

    def get_openrouter_key(self) -> str:
        path = self._path.expanduser()
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise CredentialError(
                "OpenRouter credential document could not be loaded"
            ) from None
        if not isinstance(document, Mapping):
            raise CredentialError("OpenRouter credential document is malformed")
        provider = document.get("openrouter")
        if not isinstance(provider, Mapping):
            raise CredentialError("OpenRouter credential entry is missing")

        present = [
            provider[name] for name in ("key", "apiKey", "api_key") if name in provider
        ]
        if not present:
            raise CredentialError("OpenRouter credential key is missing")
        if len(present) > 1 and len(set(_hashable_text(item) for item in present)) > 1:
            raise CredentialError("OpenRouter credential aliases conflict")
        key = present[0]
        if (
            not isinstance(key, str)
            or not key
            or key != key.strip()
            or any(character in key for character in "\r\n")
        ):
            raise CredentialError("OpenRouter credential key is invalid")
        return key


def _hashable_text(value: object) -> tuple[type[object], str]:
    """Compare aliases without putting their secret values in an error."""
    return type(value), value if isinstance(value, str) else repr(type(value))


@dataclass(frozen=True, slots=True)
class Hy3Response:
    """Validated model response plus raw and normalized provider usage."""

    message: Mapping[str, object]
    raw_usage: Mapping[str, object] | None
    provider_usage: ProviderUsage
    model_data: ModelData
    attempts: int
    status: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", MappingProxyType(dict(self.message)))
        if self.raw_usage is not None:
            object.__setattr__(
                self, "raw_usage", MappingProxyType(dict(self.raw_usage))
            )

    @property
    def content(self) -> object:
        return self.message["content"]

    @property
    def usage(self) -> Mapping[str, object] | None:
        """Compatibility alias preserving missing usage as ``None``."""
        return self.raw_usage


class OpenRouterHy3Client:
    """One raw-HTTP Hy3 client enforcing Leitir's purpose-specific policy."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        credential_provider: CredentialProvider | None = None,
        http_transport: HttpTransport | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        sleep: Callable[[float], object] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or Config.default()
        if self._config.model != OPENROUTER_MODEL:
            raise RequestValidationError("the Hy3 model identity is fixed")
        if self._config.model_endpoint != OPENROUTER_ENDPOINT:
            raise RequestValidationError("the OpenRouter endpoint is fixed")
        self._credentials = credential_provider or OpenCodeCredentialProvider()
        self._http = http_transport or UrllibHttpTransport()
        self._trace_recorder = trace_recorder
        self._sleep = sleep
        self._monotonic = monotonic

    def query_expansion(
        self,
        messages: Sequence[Mapping[str, object]],
        *,
        options: Mapping[str, object] | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        attempt_number: int = 1,
        **forbidden: object,
    ) -> Hy3Response:
        return self._call(
            Hy3Purpose.QUERY_EXPANSION,
            messages,
            options=options,
            trace_recorder=trace_recorder,
            attempt_number=attempt_number,
            forbidden=forbidden,
        )

    def synthesis(
        self,
        messages: Sequence[Mapping[str, object]],
        *,
        options: Mapping[str, object] | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        attempt_number: int = 1,
        **forbidden: object,
    ) -> Hy3Response:
        return self._call(
            Hy3Purpose.SYNTHESIS,
            messages,
            options=options,
            trace_recorder=trace_recorder,
            attempt_number=attempt_number,
            forbidden=forbidden,
        )

    def repair(
        self,
        messages: Sequence[Mapping[str, object]],
        *,
        options: Mapping[str, object] | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        attempt_number: int = 1,
        **forbidden: object,
    ) -> Hy3Response:
        return self._call(
            Hy3Purpose.REPAIR,
            messages,
            options=options,
            trace_recorder=trace_recorder,
            attempt_number=attempt_number,
            forbidden=forbidden,
        )

    def review(
        self,
        messages: Sequence[Mapping[str, object]],
        *,
        options: Mapping[str, object] | None = None,
        trace_recorder: ExecutionTraceRecorder | None = None,
        attempt_number: int = 1,
        **forbidden: object,
    ) -> Hy3Response:
        """Compatibility operation; UNUSED by the v1 loop."""
        return self._call(
            Hy3Purpose.REVIEW,
            messages,
            options=options,
            trace_recorder=trace_recorder,
            attempt_number=attempt_number,
            forbidden=forbidden,
        )

    # Clear verb aliases make the purpose API natural without adding behavior.
    expand_queries = query_expansion
    synthesize = synthesis

    def _call(
        self,
        purpose: Hy3Purpose,
        messages: Sequence[Mapping[str, object]],
        *,
        options: Mapping[str, object] | None,
        trace_recorder: ExecutionTraceRecorder | None,
        attempt_number: int,
        forbidden: Mapping[str, object],
    ) -> Hy3Response:
        if (
            isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or attempt_number < 1
        ):
            raise RequestValidationError("attempt_number must be a positive integer")
        _reject_forbidden(forbidden)
        body = self._request_body(purpose, messages, options)
        try:
            serialized = json.dumps(
                body,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise RequestValidationError(
                "messages and generation options must be valid JSON"
            ) from None

        key = self._credentials.get_openrouter_key()
        if not isinstance(key, str) or not key or any(c in key for c in "\r\n"):
            raise CredentialError("OpenRouter credential key is invalid")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        }
        started = self._monotonic()
        response, attempts = self._send_with_retries(
            purpose=purpose,
            headers=headers,
            body=serialized,
        )
        result = self._parse_response(
            purpose=purpose,
            response=response,
            attempts=attempts,
        )
        recorder = trace_recorder or self._trace_recorder
        if recorder is not None:
            elapsed_ms = max(0, (self._monotonic() - started) * 1000)
            recorder.record_span(
                TraceSpan(
                    step=purpose.workflow_step,
                    status=StepStatus.SUCCEEDED,
                    latency_ms=elapsed_ms,
                    retry_number=attempts - 1,
                    attempt_number=attempt_number,
                    model=result.model_data,
                )
            )
        return result

    def _request_body(
        self,
        purpose: Hy3Purpose,
        messages: Sequence[Mapping[str, object]],
        options: Mapping[str, object] | None,
    ) -> dict[str, object]:
        normalized_messages = _messages(messages)
        normalized_options = _options(options)
        temperature = normalized_options.pop(
            "temperature", self._config.model_temperature
        )
        max_tokens = normalized_options.pop(
            "max_tokens", self._config.model_max_tokens
        )
        _temperature(temperature)
        _positive_token_limit("max_tokens", max_tokens)

        body: dict[str, object] = {
            "model": OPENROUTER_MODEL,
            "messages": normalized_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        for name in _GENERATION_PARAMETERS:
            if name in {"temperature", "max_tokens"}:
                continue
            if name in normalized_options:
                value = normalized_options[name]
                if name == "max_completion_tokens":
                    _positive_token_limit(name, value)
                body[name] = value
        effort = purpose.reasoning_effort
        if effort is not None:
            body["reasoning_effort"] = effort
        body["include_reasoning"] = False
        return body

    def _send_with_retries(
        self,
        *,
        purpose: Hy3Purpose,
        headers: Mapping[str, str],
        body: bytes,
    ) -> tuple[HttpResponse, int]:
        maximum = self._config.model_max_attempts
        for attempt in range(1, maximum + 1):
            try:
                response = self._http.post(
                    OPENROUTER_ENDPOINT,
                    headers=headers,
                    body=body,
                    timeout=self._config.model_timeout_seconds,
                )
            except Exception as exc:
                timeout = _is_timeout(exc)
                retryable = timeout
                if retryable and attempt < maximum:
                    self._retry(purpose, "timeout", None, attempt + 1, attempt)
                    continue
                raise TransportError(
                    category="timeout" if timeout else "transport",
                    status=None,
                    attempts=attempt,
                    retryable=retryable,
                    exhausted=retryable and attempt == maximum,
                ) from None

            if 200 <= response.status < 300:
                return response, attempt
            retryable = _retryable_status(response.status)
            if retryable and attempt < maximum:
                self._retry(
                    purpose, "http_status", response.status, attempt + 1, attempt
                )
                continue
            raise TransportError(
                category="http_status",
                status=response.status,
                attempts=attempt,
                retryable=retryable,
                exhausted=retryable and attempt == maximum,
            )
        raise AssertionError("bounded retry loop did not terminate")

    def _retry(
        self,
        purpose: Hy3Purpose,
        category: str,
        status: int | None,
        next_attempt: int,
        failed_attempt: int,
    ) -> None:
        delay = min(
            self._config.model_retry_initial_backoff_seconds
            * (2 ** (failed_attempt - 1)),
            self._config.model_retry_max_backoff_seconds,
        )
        LOGGER.warning(
            "retrying OpenRouter purpose=%s category=%s status=%s "
            "next_attempt=%d delay_seconds=%s",
            purpose.value,
            category,
            status,
            next_attempt,
            delay,
        )
        self._sleep(delay)

    def _parse_response(
        self,
        *,
        purpose: Hy3Purpose,
        response: HttpResponse,
        attempts: int,
    ) -> Hy3Response:
        try:
            payload = json.loads(response.body.decode("utf-8"))
            if not isinstance(payload, Mapping):
                raise TypeError
            choices = payload["choices"]
            if (
                not isinstance(choices, Sequence)
                or isinstance(choices, (str, bytes))
                or not choices
                or not isinstance(choices[0], Mapping)
            ):
                raise TypeError
            message = choices[0]["message"]
            if not isinstance(message, Mapping) or "content" not in message:
                raise TypeError
            raw_usage_value = payload.get("usage")
            if raw_usage_value is not None and not isinstance(
                raw_usage_value, Mapping
            ):
                raise TypeError
        except (
            UnicodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
        ):
            raise ResponseValidationError(attempts=attempts) from None

        raw_usage = (
            dict(raw_usage_value)
            if isinstance(raw_usage_value, Mapping)
            else None
        )
        provider_usage = ProviderUsage.from_openrouter(
            {"usage": raw_usage} if raw_usage is not None else {}
        )
        effort = purpose.reasoning_effort
        model_data = ModelData(
            model_used=OPENROUTER_MODEL,
            reasoning_effort_sent=effort,
            reasoning_effort_was_sent=effort is not None,
            include_reasoning_sent=False,
            usage=provider_usage,
        )
        return Hy3Response(
            message=dict(message),
            raw_usage=raw_usage,
            provider_usage=provider_usage,
            model_data=model_data,
            attempts=attempts,
            status=response.status,
        )


def _messages(
    messages: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    if isinstance(messages, (str, bytes)) or not isinstance(messages, Sequence):
        raise RequestValidationError("messages must be a non-empty sequence")
    if not messages:
        raise RequestValidationError("messages must not be empty")
    normalized: list[dict[str, object]] = []
    for message in messages:
        if not isinstance(message, Mapping):
            raise RequestValidationError("each message must be a mapping")
        if "role" not in message or not isinstance(message["role"], str):
            raise RequestValidationError("each message requires a string role")
        if not message["role"].strip():
            raise RequestValidationError("message roles must not be empty")
        if "content" not in message:
            raise RequestValidationError("each message requires content")
        blocked = _POLICY_CONTROLLED.intersection(message)
        if blocked:
            raise RequestValidationError(
                f"message contains policy-controlled field: {sorted(blocked)[0]}"
            )
        normalized.append(dict(message))
    return normalized


def _options(options: Mapping[str, object] | None) -> dict[str, object]:
    if options is None:
        return {}
    if not isinstance(options, Mapping):
        raise RequestValidationError("generation options must be a mapping")
    if any(not isinstance(name, str) for name in options):
        raise RequestValidationError("generation option names must be strings")
    supplied = set(options)
    policy = supplied.intersection(_POLICY_CONTROLLED)
    if "reasoning_effort" in policy and options["reasoning_effort"] == "no_think":
        raise RequestValidationError(
            "no_think is invalid; query expansion omits reasoning_effort"
        )
    if policy:
        raise RequestValidationError(
            f"generation option is policy-controlled: {sorted(policy)[0]}"
        )
    unsupported = supplied.difference(_GENERATION_PARAMETERS)
    if unsupported:
        raise RequestValidationError(
            f"unsupported generation option: {sorted(unsupported)[0]}"
        )
    return dict(options)


def _reject_forbidden(values: Mapping[str, object]) -> None:
    if not values:
        return
    if (
        "reasoning_effort" in values
        and values["reasoning_effort"] == "no_think"
    ):
        raise RequestValidationError(
            "no_think is invalid; query expansion omits reasoning_effort"
        )
    if "extra_body" in values:
        raise RequestValidationError("extra_body is not supported")
    name = sorted(values)[0]
    if name in _POLICY_CONTROLLED:
        raise RequestValidationError(f"{name} is policy-controlled")
    raise RequestValidationError(f"unsupported argument: {name}")


def _temperature(value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 2
    ):
        raise RequestValidationError(
            "temperature must be finite and between 0 and 2"
        )


def _positive_token_limit(name: str, value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 1_000_000
    ):
        raise RequestValidationError(
            f"{name} must be an integer between 1 and 1000000"
        )


def _retryable_status(status: int) -> bool:
    return status in _RETRYABLE_STATUSES or 500 <= status <= 599


def _is_timeout(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: object | None = exc
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TimeoutError):
            return True
        reason = getattr(current, "reason", None)
        if isinstance(reason, TimeoutError):
            return True
        current = current.__cause__ or current.__context__
    return False


__all__ = [
    "CredentialError",
    "HttpResponse",
    "HttpTransport",
    "Hy3Purpose",
    "Hy3Response",
    "OpenCodeCredentialProvider",
    "OpenRouterError",
    "OpenRouterHy3Client",
    "RequestValidationError",
    "ResponseValidationError",
    "TransportError",
    "UrllibHttpTransport",
]
