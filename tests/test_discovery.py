"""Offline fixture tests for Step 2 targeted discovery."""

from __future__ import annotations

from collections import deque
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from leitir.config import Config
from leitir.contracts import (
    ErrorCode,
    EvidenceTier,
    QueryExpansionPlan,
    QueryRecord,
    StepStatus,
    WorkflowRequest,
    WorkflowStep,
)
from leitir.discovery import (
    DiscoveryChannel,
    DiscoveryHttpResponse,
    DiscoveryZeroResultsError,
    TargetedDiscovery,
    canonicalize_url,
)
from leitir.trace import TraceRecorder


def _plan(*, duplicate_doc_query: bool = False) -> QueryExpansionPlan:
    queries = [
        QueryRecord("fastapi errors", "fastapi.tiangolo.com", EvidenceTier.TIER_1, ("q1",)),
        QueryRecord("python exceptions", "docs.python.org", EvidenceTier.TIER_2, ("q2",)),
        QueryRecord("fastapi exception handler", "github.com", EvidenceTier.TIER_3, ("q3",)),
    ]
    if duplicate_doc_query:
        queries.insert(
            1,
            QueryRecord(
                "fastapi handlers",
                "fastapi.tiangolo.com",
                EvidenceTier.TIER_1,
                ("q1b",),
            ),
        )
    return QueryExpansionPlan(
        WorkflowRequest("request-discovery", "find FastAPI error handling"),
        tuple(queries),
    )


def _json_response(value, status=200):
    return DiscoveryHttpResponse(status, json.dumps(value).encode())


def _searx(*urls):
    return _json_response(
        {"results": [{"url": url, "title": f"result-{index}"} for index, url in enumerate(urls)]}
    )


def _github(*paths, total_count=None):
    items = [
        {
            "html_url": f"https://github.com/acme/project/blob/main/{path}",
            "name": path.rsplit("/", 1)[-1],
            "path": path,
            "sha": f"sha-{index}",
            "repository": {"full_name": "acme/project"},
        }
        for index, path in enumerate(paths)
    ]
    return _json_response(
        {
            "items": items,
            "total_count": len(items) if total_count is None else total_count,
            "incomplete_results": False,
        }
    )


class RoutingHttp:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, *, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        return self.handler(url, headers)


def test_routes_tiers_paginates_limits_normalizes_deduplicates_and_traces():
    def handler(url, _headers):
        parsed = urlsplit(url)
        params = parse_qs(parsed.query)
        if parsed.hostname == "localhost":
            query = params["q"][0]
            page = int(params["pageno"][0])
            if page == 2:
                return _searx()
            if "fastapi.tiangolo.com" in query:
                # Both Tier 1 records produce the same canonical URL.
                return _searx(
                    "HTTPS://FASTAPI.TIANGOLO.COM/tutorial/errors/?utm_source=x#top",
                    "https://fastapi.tiangolo.com/reference/",
                )
            return _searx("https://docs.python.org/3/library/exceptions.html")
        page = int(params["page"][0])
        assert page in {1, 2}
        return (
            _github("src/one.py", "src/two.py", total_count=3)
            if page == 1
            else _github("src/three.py", total_count=3)
        )

    http = RoutingHttp(handler)
    recorder = TraceRecorder("trace-discovery", "discovery")
    config = Config(
        discovery_page_size=2,
        discovery_max_results_per_query=3,
        discovery_max_pages=2,
        discovery_max_results=20,
    )
    result = TargetedDiscovery(
        http, config=config, trace_recorder=recorder
    ).discover(_plan(duplicate_doc_query=True))

    assert [item.tier for item in result.candidates] == sorted(
        [item.tier for item in result.candidates]
    )
    first = result.candidates[0]
    assert first.canonical_url == "https://fastapi.tiangolo.com/tutorial/errors/"
    assert first.domain == "fastapi.tiangolo.com"
    assert first.channel is DiscoveryChannel.SEARXNG
    assert len(first.query_ids) == 2
    assert result.discovery_data.deduplication_count == 2
    github = [item for item in result.candidates if item.tier is EvidenceTier.TIER_3]
    assert [item.file_path for item in github] == [
        "src/one.py",
        "src/two.py",
        "src/three.py",
    ]
    assert all(item.repository == "acme/project" for item in github)
    assert recorder._spans[-1].step is WorkflowStep.DISCOVERY
    assert recorder._spans[-1].status is StepStatus.SUCCEEDED
    assert recorder._spans[-1].discovery == result.discovery_data


def test_rate_limit_and_timeout_retry_with_capped_backoff_and_attempt_trace():
    outcomes = deque(
        [
            TimeoutError(),
            DiscoveryHttpResponse(429, b"{}"),
            _searx("https://fastapi.tiangolo.com/tutorial/errors/"),
        ]
    )
    sleeps = []

    def handler(url, _headers):
        if "fastapi.tiangolo.com" in url:
            outcome = outcomes.popleft()
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        if "docs.python.org" in url:
            return _searx("https://docs.python.org/3/library/exceptions.html")
        return _github("src/errors.py")

    result = TargetedDiscovery(
        RoutingHttp(handler),
        config=Config(
            discovery_max_attempts=3,
            discovery_retry_initial_backoff_seconds=2,
            discovery_retry_max_backoff_seconds=3,
        ),
        sleep=sleeps.append,
    ).discover(_plan())

    first_query_attempts = result.discovery_data.attempts[:3]
    assert [item.attempt for item in first_query_attempts] == [1, 2, 3]
    assert [item.error_category for item in first_query_attempts] == [
        "timeout",
        "rate_limit",
        None,
    ]
    assert sleeps == [2, 3]
    assert not result.partial


def test_partial_channel_failure_retains_evidence_and_explicit_failure_record():
    def handler(url, headers):
        if "api.github.com" in url:
            assert "Authorization" not in headers
            return DiscoveryHttpResponse(503, b"unavailable")
        assert "Authorization" not in headers
        if "fastapi.tiangolo.com" in url:
            return _searx("https://fastapi.tiangolo.com/tutorial/errors/")
        return _searx("https://docs.python.org/3/library/exceptions.html")

    result = TargetedDiscovery(
        RoutingHttp(handler),
        config=Config(
            discovery_max_attempts=2,
            discovery_retry_initial_backoff_seconds=0,
            discovery_retry_max_backoff_seconds=0,
        ),
        sleep=lambda _: None,
    ).discover(_plan())

    assert result.candidates
    assert result.partial
    assert result.discovery_data.partial_failures == ("github_code_search",)
    error = result.discovery_data.channel_errors[0]
    assert error.attempts == 2
    assert error.exhausted
    assert all(item.tier is not EvidenceTier.TIER_3 for item in result.candidates)


def test_non_retryable_status_stops_that_request_immediately():
    github_calls = 0

    def handler(url, _headers):
        nonlocal github_calls
        if "api.github.com" in url:
            github_calls += 1
            return DiscoveryHttpResponse(422, b"bad query")
        if "fastapi.tiangolo.com" in url:
            return _searx("https://fastapi.tiangolo.com/tutorial/errors/")
        return _searx("https://docs.python.org/3/library/exceptions.html")

    result = TargetedDiscovery(
        RoutingHttp(handler),
        config=Config(discovery_max_attempts=3),
        sleep=lambda _: pytest.fail("must not back off a non-retryable failure"),
    ).discover(_plan())

    assert github_calls == 1
    error = result.discovery_data.channel_errors[0]
    assert not error.retryable
    assert not error.exhausted
    assert error.attempts == 1


def test_zero_results_error_only_after_all_retryable_failures_are_exhausted():
    recorder = TraceRecorder("trace-total-failure", "discovery")
    http = RoutingHttp(lambda _url, _headers: DiscoveryHttpResponse(503, b"no"))
    discovery = TargetedDiscovery(
        http,
        config=Config(
            discovery_max_attempts=2,
            discovery_retry_initial_backoff_seconds=0,
            discovery_retry_max_backoff_seconds=0,
        ),
        trace_recorder=recorder,
        sleep=lambda _: None,
    )

    with pytest.raises(DiscoveryZeroResultsError) as caught:
        discovery.discover(_plan())

    assert caught.value.code is ErrorCode.ERR_SEARCH_ZERO_RESULTS
    assert len(http.calls) == 6  # three applicable queries, two attempts each
    assert len(caught.value.discovery_data.attempts) == 6
    assert all(item.exhausted for item in caught.value.discovery_data.channel_errors)
    span = recorder._spans[-1]
    assert span.status is StepStatus.FAILED
    assert span.error_code is ErrorCode.ERR_SEARCH_ZERO_RESULTS


def test_empty_and_malformed_results_are_filtered_and_can_partially_succeed():
    def handler(url, _headers):
        if "fastapi.tiangolo.com" in url:
            return _json_response({"results": [{"url": 4}, "bad"]})
        if "docs.python.org" in url:
            return _searx(
                "https://evil.example/result",
                "https://docs.python.org/3/library/exceptions.html",
            )
        return _json_response({"items": ["bad", {"html_url": "not a url"}]})

    result = TargetedDiscovery(RoutingHttp(handler)).discover(_plan())
    assert len(result.candidates) == 1
    assert result.candidates[0].domain == "docs.python.org"
    assert "searxng:invalid_url" in result.discovery_data.filtering_reasons
    assert "searxng:outside_target_site" in result.discovery_data.filtering_reasons
    assert "github_code_search:malformed_item" in result.discovery_data.filtering_reasons


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "HTTPS://Example.COM:443/a/../b/?z=2&utm_medium=x&a=1#frag",
            ("https://example.com/b/?a=1&z=2", "example.com"),
        ),
        ("https://user:secret@example.com/x", None),
        ("file:///tmp/x", None),
        (4, None),
    ],
)
def test_url_canonicalization(value, expected):
    assert canonicalize_url(value) == expected


def test_only_validated_step_one_plan_is_accepted_without_http_call():
    http = RoutingHttp(lambda _url, _headers: pytest.fail("must not call HTTP"))
    with pytest.raises(TypeError, match="QueryExpansionPlan"):
        TargetedDiscovery(http).discover(tuple(_plan().queries))  # type: ignore[arg-type]
