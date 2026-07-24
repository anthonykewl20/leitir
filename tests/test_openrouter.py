"""Offline contract tests for the purpose-specific OpenRouter Hy3 client."""

from __future__ import annotations

import json
import logging

import pytest

from leitir.config import Config, OPENROUTER_ENDPOINT
from leitir.contracts import WorkflowStep
from leitir.openrouter import (
    CredentialError,
    HttpResponse,
    OpenCodeCredentialProvider,
    OpenRouterHy3Client,
    RequestValidationError,
    ResponseValidationError,
    TransportError,
)


KEY = "synthetic-openrouter-key-never-use"
MESSAGES = [{"role": "user", "content": "Build exact queries."}]
SUCCESS = HttpResponse(
    200,
    json.dumps(
        {
            "choices": [{"message": {"role": "assistant", "content": "answer"}}],
            "usage": {
                "cost": 0.003,
                "prompt_tokens": 12,
                "completion_tokens": 9,
                "completion_tokens_details": {"reasoning_tokens": 7},
                "provider_extension": {"preserved": True},
            },
        }
    ).encode(),
)


class SyntheticCredentials:
    def get_openrouter_key(self):
        return KEY


class FakeHttp:
    def __init__(self, *events):
        self.events = list(events or [SUCCESS])
        self.calls = []

    def post(self, url, *, headers, body, timeout):
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return event


def client(http, **config):
    return OpenRouterHy3Client(
        Config(**config),
        credential_provider=SyntheticCredentials(),
        http_transport=http,
        sleep=lambda _delay: None,
    )


@pytest.mark.parametrize(
    ("method", "effort_fragment"),
    [
        ("query_expansion", b""),
        ("synthesis", b',"reasoning_effort":"high"'),
        ("repair", b',"reasoning_effort":"high"'),
        ("review", b',"reasoning_effort":"high"'),
    ],
)
def test_every_purpose_sends_exact_serialized_body(method, effort_fragment):
    http = FakeHttp(SUCCESS)
    result = getattr(client(http), method)(MESSAGES)
    expected = (
        b'{"model":"tencent/hy3","messages":[{"role":"user",'
        b'"content":"Build exact queries."}],"temperature":0,'
        b'"max_tokens":20000'
        + effort_fragment
        + b',"include_reasoning":false}'
    )
    assert http.calls == [
        {
            "url": "https://openrouter.ai/api/v1/chat/completions",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {KEY}",
            },
            "body": expected,
            "timeout": 900,
        }
    ]
    assert result.content == "answer"
    if method == "query_expansion":
        assert b"reasoning_effort" not in expected
        assert result.model_data.reasoning_effort_sent is None
        assert result.model_data.reasoning_effort_was_sent is False
    else:
        assert result.model_data.reasoning_effort_sent == "high"
        assert result.model_data.reasoning_effort_was_sent is True
    assert result.model_data.include_reasoning_sent is False


def test_validated_settings_and_allowlisted_options_remain_top_level():
    http = FakeHttp(SUCCESS)
    client(
        http,
        model_temperature=0.25,
        model_max_tokens=1234,
    ).synthesis(
        MESSAGES,
        options={
            "top_p": 0.9,
            "stop": ["DONE"],
            "seed": 42,
            "response_format": {"type": "json_object"},
        },
    )
    assert json.loads(http.calls[0]["body"]) == {
        "model": "tencent/hy3",
        "messages": MESSAGES,
        "temperature": 0.25,
        "max_tokens": 1234,
        "top_p": 0.9,
        "stop": ["DONE"],
        "response_format": {"type": "json_object"},
        "seed": 42,
        "reasoning_effort": "high",
        "include_reasoning": False,
    }
    assert "extra_body" not in json.loads(http.calls[0]["body"])


@pytest.mark.parametrize(
    "options",
    [
        {"reasoning_effort": "no_think"},
        {"reasoning_effort": "low"},
        {"include_reasoning": True},
        {"reasoning": {"effort": "low"}},
        {"extra_body": {"reasoning_effort": "high"}},
        {"model": "tencent/hy3-preview"},
        {"messages": []},
        {"unsupported": "fragment"},
        {1: "non-string-name"},
    ],
)
def test_policy_controlled_and_unsupported_options_are_rejected(options):
    http = FakeHttp(SUCCESS)
    with pytest.raises(RequestValidationError):
        client(http).synthesis(MESSAGES, options=options)
    assert http.calls == []


def test_direct_no_think_and_extra_body_arguments_are_rejected():
    http = FakeHttp(SUCCESS)
    with pytest.raises(RequestValidationError, match="no_think"):
        client(http).query_expansion(MESSAGES, reasoning_effort="no_think")
    with pytest.raises(RequestValidationError, match="extra_body"):
        client(http).synthesis(MESSAGES, extra_body={"temperature": 1})
    assert http.calls == []


@pytest.mark.parametrize(
    "bad_options",
    [
        {"temperature": float("nan")},
        {"temperature": True},
        {"max_tokens": 0},
        {"max_completion_tokens": 1.5},
    ],
)
def test_invalid_parameter_values_fail_before_credentials_or_http(bad_options):
    http = FakeHttp(SUCCESS)
    with pytest.raises(RequestValidationError):
        client(http).synthesis(MESSAGES, options=bad_options)
    assert http.calls == []


def test_retryable_statuses_use_bounded_capped_backoff(caplog):
    delays = []
    http = FakeHttp(
        HttpResponse(429, b"secret provider body"),
        HttpResponse(503, b"secret provider body"),
        HttpResponse(500, b"secret provider body"),
        SUCCESS,
    )
    api = OpenRouterHy3Client(
        Config(
            model_max_attempts=4,
            model_retry_initial_backoff_seconds=2,
            model_retry_max_backoff_seconds=3,
        ),
        credential_provider=SyntheticCredentials(),
        http_transport=http,
        sleep=delays.append,
    )
    with caplog.at_level(logging.WARNING, logger="leitir.openrouter"):
        response = api.synthesis(MESSAGES)
    assert response.attempts == 4
    assert len(http.calls) == 4
    assert delays == [2, 3, 3]
    rendered = caplog.text
    assert KEY not in rendered
    assert "Authorization" not in rendered
    assert "secret provider body" not in rendered


def test_timeouts_retry_and_exhaust_with_safe_metadata():
    http = FakeHttp(
        TimeoutError(f"Bearer {KEY}"),
        TimeoutError(f"Bearer {KEY}"),
        TimeoutError(f"Bearer {KEY}"),
    )
    with pytest.raises(TransportError) as caught:
        client(http, model_max_attempts=3).repair(MESSAGES)
    error = caught.value
    assert error.to_dict() == {
        "category": "timeout",
        "status": None,
        "attempts": 3,
        "retryable": True,
        "exhausted": True,
    }
    assert KEY not in str(error)
    assert "Bearer" not in str(error)
    assert len(http.calls) == 3


def test_non_retryable_status_and_transport_error_fail_immediately():
    http = FakeHttp(HttpResponse(400, f"Authorization: Bearer {KEY}".encode()))
    with pytest.raises(TransportError) as caught:
        client(http).synthesis(MESSAGES)
    assert caught.value.status == 400
    assert caught.value.retryable is False
    assert caught.value.attempts == 1
    assert KEY not in str(caught.value)

    http = FakeHttp(OSError(f"api_key={KEY}"))
    with pytest.raises(TransportError) as caught:
        client(http).synthesis(MESSAGES)
    assert caught.value.category == "transport"
    assert caught.value.attempts == 1
    assert KEY not in str(caught.value)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b"{}",
        b'{"choices":[]}',
        b'{"choices":[{"message":{}}]}',
        b'{"choices":[{"message":{"content":"ok"}}],"usage":"bad"}',
    ],
)
def test_malformed_completed_responses_are_not_retried(body):
    http = FakeHttp(HttpResponse(200, body), SUCCESS)
    with pytest.raises(ResponseValidationError) as caught:
        client(http).query_expansion(MESSAGES)
    assert caught.value.attempts == 1
    assert len(http.calls) == 1


def test_non_string_message_content_is_rejected():
    content = [{"type": "text", "text": "preserved"}]
    usage = {
        "cost": 0.001,
        "prompt_tokens": 4,
        "completion_tokens": 5,
        "completion_tokens_details": {"reasoning_tokens": 3},
        "vendor": {"detail": 99},
    }
    response = HttpResponse(
        200,
        json.dumps(
            {
                "choices": [
                    {"message": {"role": "assistant", "content": content, "x": 1}}
                ],
                "usage": usage,
            }
        ).encode(),
    )
    with pytest.raises(ResponseValidationError):
        client(FakeHttp(response)).synthesis(MESSAGES)


def test_missing_usage_stays_missing_and_normalization_flags_nulls():
    response = HttpResponse(
        200,
        b'{"choices":[{"message":{"role":"assistant","content":"ok"}}]}',
    )
    result = client(FakeHttp(response)).query_expansion(MESSAGES)
    assert result.content == "ok"
    assert result.usage is None
    assert result.provider_usage.cost_usd is None
    assert result.provider_usage.prompt_tokens is None
    assert result.provider_usage.completion_tokens is None
    assert result.provider_usage.reasoning_tokens is None
    assert set(result.provider_usage.missing_fields) == set(
        result.provider_usage.FIELD_PATHS
    )


class SpanCapture:
    def __init__(self):
        self.spans = []

    def record_span(self, span):
        self.spans.append(span)


@pytest.mark.parametrize(
    ("method", "step", "effort"),
    [
        ("query_expansion", WorkflowStep.QUERY_EXPANSION, None),
        ("synthesis", WorkflowStep.SYNTHESIS, "high"),
        ("repair", WorkflowStep.VERIFICATION, "high"),
        ("review", WorkflowStep.SYNTHESIS, "high"),
    ],
)
def test_successful_calls_emit_v1_02_model_spans(method, step, effort):
    recorder = SpanCapture()
    http = FakeHttp(HttpResponse(503, b""), SUCCESS)
    result = getattr(
        OpenRouterHy3Client(
            Config(model_retry_initial_backoff_seconds=0),
            credential_provider=SyntheticCredentials(),
            http_transport=http,
            trace_recorder=recorder,
            sleep=lambda _delay: None,
            monotonic=iter([10.0, 10.125]).__next__,
        ),
        method,
    )(MESSAGES, attempt_number=2)
    assert len(recorder.spans) == 1
    span = recorder.spans[0]
    assert span.step is step
    assert span.retry_number == 1
    assert span.attempt_number == 2
    assert span.latency_ms == 125
    assert span.model == result.model_data
    assert span.model.reasoning_effort_sent == effort
    assert span.model.include_reasoning_sent is False
    assert span.model.usage.raw_provider_fields["provider_extension"] == {
        "preserved": True
    }


@pytest.mark.parametrize("alias", ["key", "apiKey", "api_key"])
def test_credentials_accept_only_documented_aliases_under_openrouter(
    tmp_path, monkeypatch, alias
):
    sentinel_env = "must-not-be-used-from-environment"
    monkeypatch.setenv("OPENROUTER_API_KEY", sentinel_env)
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "some-other-provider": {"key": sentinel_env},
                "openrouter": {alias: KEY, "type": "api"},
            }
        )
    )
    assert OpenCodeCredentialProvider(path).get_openrouter_key() == KEY


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"key": KEY},
        {"openrouter": {}},
        {"openrouter": {"token": KEY}},
        {"openrouter": {"key": ""}},
        {"openrouter": {"key": "a", "apiKey": "b"}},
    ],
)
def test_bad_credentials_fail_without_revealing_document_values(tmp_path, document):
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(document))
    with pytest.raises(CredentialError) as caught:
        OpenCodeCredentialProvider(path).get_openrouter_key()
    rendered = str(caught.value)
    assert KEY not in rendered
    assert '"a"' not in rendered
    assert '"b"' not in rendered


def test_missing_or_invalid_credential_document_is_safe(tmp_path):
    for path in (tmp_path / "missing.json", tmp_path / "invalid.json"):
        if path.name == "invalid.json":
            path.write_text(f'{{"openrouter":{{"key":"{KEY}"}}')
        with pytest.raises(CredentialError) as caught:
            OpenCodeCredentialProvider(path).get_openrouter_key()
        assert KEY not in str(caught.value)
        assert str(path) not in str(caught.value)


def test_exact_endpoint_is_not_caller_replaceable():
    assert OPENROUTER_ENDPOINT == "https://openrouter.ai/api/v1/chat/completions"
    with pytest.raises(RequestValidationError, match="endpoint"):
        OpenRouterHy3Client(
            Config(model_endpoint="https://example.test/chat"),
            credential_provider=SyntheticCredentials(),
            http_transport=FakeHttp(SUCCESS),
        )
