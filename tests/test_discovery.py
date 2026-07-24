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
    DiscoveryAuthError,
    DiscoveryChannel,
    DiscoveryEnginesBlockedError,
    DiscoveryHttpResponse,
    DiscoveryZeroResultsError,
    GitHubCodeSearchAdapter,
    GitHubCredentialProvider,
    SearXNGAdapter,
    TargetedDiscovery,
    canonicalize_url,
)
from leitir.openrouter import CredentialError
from leitir.trace import TraceRecorder


GITHUB_TOKEN = "github-test-token-not-real"


class SyntheticGitHubCredentials:
    def get_github_token(self):
        return GITHUB_TOKEN


def _targeted(http, **kwargs):
    return TargetedDiscovery(
        http,
        github_credential_provider=SyntheticGitHubCredentials(),
        **kwargs,
    )


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
    result = _targeted(
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
    assert (
        recorder.artifacts[-1].metadata["credential_mode"]
        == "local-and-github-token"
    )
    github_calls = [call for call in http.calls if "api.github.com" in call[0]]
    assert github_calls
    assert all(
        call[1]["Authorization"] == f"Bearer {GITHUB_TOKEN}"
        for call in github_calls
    )


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

    result = _targeted(
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
    assert sleeps == [2, 3, 0.25, 0.25]
    assert not result.partial


def test_retry_after_header_extends_backoff_but_respects_maximum():
    outcomes = deque(
        [
            DiscoveryHttpResponse(429, b"{}", {"Retry-After": "30"}),
            _github("src/errors.py"),
        ]
    )
    sleeps = []
    adapter = GitHubCodeSearchAdapter(
        RoutingHttp(lambda _url, _headers: outcomes.popleft()),
        config=Config(
            discovery_max_attempts=2,
            discovery_retry_initial_backoff_seconds=1,
            discovery_retry_max_backoff_seconds=4,
        ),
        sleep=sleeps.append,
        credentials=SyntheticGitHubCredentials(),
    )

    assert adapter.search(_plan().queries[-1])
    assert sleeps == [4]


def test_discovery_delays_between_queries_and_caps_github_page_size():
    sleeps = []

    def handler(url, _headers):
        if "api.github.com" in url:
            page = int(parse_qs(urlsplit(url).query)["page"][0])
            paths = (
                tuple(f"src/file-{index}.py" for index in range(10))
                if page == 1
                else ("src/final.py",)
            )
            return _github(*paths, total_count=11)
        return _searx(
            "https://fastapi.tiangolo.com/x"
            if "fastapi.tiangolo.com" in url
            else "https://docs.python.org/3/x"
        )

    http = RoutingHttp(handler)

    _targeted(
        http,
        config=Config(
            discovery_page_size=25,
            discovery_max_pages=2,
            discovery_max_results_per_query=20,
        ),
        sleep=sleeps.append,
    ).discover(_plan())

    assert sleeps == [0.25, 0.25]
    github_urls = [url for url, _, _ in http.calls if "api.github.com" in url]
    assert len(github_urls) == 2
    assert all(
        parse_qs(urlsplit(url).query)["per_page"] == ["10"]
        for url in github_urls
    )


def test_partial_channel_failure_retains_evidence_and_explicit_failure_record():
    def handler(url, headers):
        if "api.github.com" in url:
            assert headers["Authorization"] == f"Bearer {GITHUB_TOKEN}"
            return DiscoveryHttpResponse(503, b"unavailable")
        assert "Authorization" not in headers
        if "fastapi.tiangolo.com" in url:
            return _searx("https://fastapi.tiangolo.com/tutorial/errors/")
        return _searx("https://docs.python.org/3/library/exceptions.html")

    result = _targeted(
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

    result = _targeted(
        RoutingHttp(handler),
        config=Config(discovery_max_attempts=3),
        sleep=lambda seconds: (
            None
            if seconds == 0.25
            else pytest.fail("must not back off a non-retryable failure")
        ),
    ).discover(_plan())

    assert github_calls == 1
    error = result.discovery_data.channel_errors[0]
    assert not error.retryable
    assert not error.exhausted
    assert error.attempts == 1


def test_zero_results_error_only_after_all_retryable_failures_are_exhausted():
    recorder = TraceRecorder("trace-total-failure", "discovery")
    http = RoutingHttp(lambda _url, _headers: DiscoveryHttpResponse(503, b"no"))
    discovery = _targeted(
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

    result = _targeted(RoutingHttp(handler)).discover(_plan())
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
        _targeted(http).discover(tuple(_plan().queries))  # type: ignore[arg-type]


def test_github_adapter_sends_bearer_header_and_tags_401_as_auth():
    from leitir.discovery import _Telemetry

    http = RoutingHttp(
        lambda _url, _headers: DiscoveryHttpResponse(401, b"unauthorized")
    )
    adapter = GitHubCodeSearchAdapter(
        http,
        credentials=SyntheticGitHubCredentials(),
    )
    recorded = _Telemetry()

    assert adapter.search(_plan().queries[-1], telemetry=recorded) == ()
    assert http.calls[0][1] == {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "User-Agent": "Leitir/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    assert recorded.errors[0].category == "auth"
    assert recorded.errors[0].http_status == 401


def test_searxng_engines_blocked_retries_and_pins_configured_engine():
    outcomes = deque(
        [
            _json_response(
                {
                    "results": [],
                    "unresponsive_engines": [["duckduckgo", "CAPTCHA"]],
                }
            ),
            _searx("https://fastapi.tiangolo.com/tutorial/errors/"),
        ]
    )
    sleeps = []
    http = RoutingHttp(lambda _url, _headers: outcomes.popleft())
    adapter = SearXNGAdapter(
        http,
        config=Config(
            search_engines="brave",
            discovery_max_attempts=2,
            discovery_retry_initial_backoff_seconds=3,
            discovery_retry_max_backoff_seconds=3,
        ),
        sleep=sleeps.append,
    )
    from leitir.discovery import _Telemetry

    recorded = _Telemetry()
    candidates = adapter.search(_plan().queries[0], telemetry=recorded)

    assert len(candidates) == 1
    assert sleeps == [3]
    assert [attempt.error_category for attempt in recorded.attempts] == [
        "engines_blocked",
        None,
    ]
    assert parse_qs(urlsplit(http.calls[0][0]).query)["engines"] == ["brave"]


def test_terminal_auth_error_takes_precedence_and_is_traced():
    recorder = TraceRecorder("trace-auth", "discovery")

    def handler(url, _headers):
        if "api.github.com" in url:
            return DiscoveryHttpResponse(401, b"unauthorized")
        return _searx()

    with pytest.raises(DiscoveryAuthError) as caught:
        _targeted(
            RoutingHttp(handler),
            trace_recorder=recorder,
        ).discover(_plan())

    assert caught.value.code is ErrorCode.ERR_SEARCH_AUTH_REQUIRED
    assert recorder._spans[-1].error_code is ErrorCode.ERR_SEARCH_AUTH_REQUIRED


def test_terminal_engines_blocked_error_is_distinct():
    blocked = _json_response(
        {
            "results": [],
            "unresponsive_engines": [["duckduckgo", "rate limit"]],
        }
    )

    def handler(url, _headers):
        if "api.github.com" in url:
            return _github()
        return blocked

    with pytest.raises(DiscoveryEnginesBlockedError) as caught:
        _targeted(
            RoutingHttp(handler),
            config=Config(
                discovery_max_attempts=2,
                discovery_retry_initial_backoff_seconds=0,
                discovery_retry_max_backoff_seconds=0,
            ),
            sleep=lambda _: None,
        ).discover(_plan())

    assert caught.value.code is ErrorCode.ERR_SEARCH_ENGINES_BLOCKED


def test_engines_blocked_is_non_fatal_when_tier_three_returns_candidates():
    blocked = _json_response(
        {
            "results": [],
            "unresponsive_engines": [["duckduckgo", "rate limit"]],
        }
    )

    result = _targeted(
        RoutingHttp(
            lambda url, _headers: (
                _github("src/errors.py") if "api.github.com" in url else blocked
            )
        ),
        config=Config(
            discovery_max_attempts=1,
            discovery_retry_initial_backoff_seconds=0,
            discovery_retry_max_backoff_seconds=0,
        ),
        sleep=lambda _: None,
    ).discover(_plan())

    assert [candidate.tier for candidate in result.candidates] == [
        EvidenceTier.TIER_3
    ]
    assert result.partial
    assert result.discovery_data.partial_failures == ("searxng",)


def test_terminal_genuine_empty_results_remains_zero_results():
    def handler(url, _headers):
        return _github() if "api.github.com" in url else _searx()

    with pytest.raises(DiscoveryZeroResultsError) as caught:
        _targeted(RoutingHttp(handler)).discover(_plan())

    assert caught.value.code is ErrorCode.ERR_SEARCH_ZERO_RESULTS


def test_github_credentials_prefer_matching_environment_aliases(
    tmp_path, monkeypatch
):
    path = tmp_path / "hosts.yml"
    path.write_text(
        "users:\n  local-user:\n    oauth_token: file-test-token-not-real\n"
    )
    monkeypatch.setenv("GH_TOKEN", GITHUB_TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", GITHUB_TOKEN)

    assert GitHubCredentialProvider(path).get_github_token() == GITHUB_TOKEN


def test_github_credentials_parse_hosts_yaml(tmp_path, monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    path = tmp_path / "hosts.yml"
    path.write_text(
        "github.com:\n"
        "  user: local-user\n"
        "users:\n"
        "  local-user:\n"
        f"    oauth_token: {GITHUB_TOKEN}\n"
    )

    assert GitHubCredentialProvider(path).get_github_token() == GITHUB_TOKEN


@pytest.mark.parametrize(
    ("env_one", "env_two", "document"),
    [
        ("first-test-token", "second-test-token", None),
        (None, None, None),
        (None, None, "users: {}"),
        (None, None, "users:\n  one:\n    oauth_token: ' bad-token'"),
        (
            None,
            None,
            "users:\n"
            "  one:\n"
            "    oauth_token: first-test-token\n"
            "  two:\n"
            "    oauth_token: second-test-token\n",
        ),
    ],
)
def test_bad_github_credentials_are_redacted(
    tmp_path, monkeypatch, env_one, env_two, document
):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    if env_one is not None:
        monkeypatch.setenv("GH_TOKEN", env_one)
    if env_two is not None:
        monkeypatch.setenv("GITHUB_TOKEN", env_two)
    path = tmp_path / "hosts.yml"
    if document is not None:
        path.write_text(document)

    with pytest.raises(CredentialError) as caught:
        GitHubCredentialProvider(path).get_github_token()

    rendered = str(caught.value)
    for secret in ("first-test-token", "second-test-token", "bad-token"):
        assert secret not in rendered
    assert str(path) not in rendered
