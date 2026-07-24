"""Offline acceptance tests for Step 1 multi-query expansion."""

from __future__ import annotations

import json

import pytest

from leitir.config import Config, OPENROUTER_MODEL
from leitir.contracts import (
    ErrorCode,
    EvidenceTier,
    StepStatus,
    WorkflowRequest,
    WorkflowStep,
)
from leitir.expansion import (
    ExpansionMalformedError,
    QueryExpander,
    QueryRecord,
)
from leitir.openrouter import Hy3Response
from leitir.trace import ModelData, ProviderUsage, TraceRecorder


TASK = (
    "In Python, update FastAPI 0.110 error handling for a Pydantic 2.6 "
    "ValidationError: 'Input should be a valid string'."
)


def query(
    text: str,
    site: str,
    tier: int,
    provenance: list[str] | None = None,
) -> dict[str, object]:
    return {
        "query_text": text,
        "site": site,
        "tier": tier,
        "provenance": provenance or [f"model-query-{tier}"],
    }


VALID_QUERIES = [
    query(
        "Python FastAPI 0.110 Pydantic 2.6 ValidationError "
        "Input should be a valid string",
        "fastapi.tiangolo.com",
        1,
        ["official API contract"],
    ),
    query(
        "Python FastAPI 0.110 Pydantic 2.6 ValidationError "
        "Input should be a valid string",
        "docs.python.org",
        2,
        ["Python language behavior"],
    ),
    query(
        "Python FastAPI 0.110 Pydantic 2.6 ValidationError "
        "Input should be a valid string",
        "github.com",
        3,
        ["implementation examples"],
    ),
]


def model_response(content: object) -> Hy3Response:
    usage = ProviderUsage.from_openrouter(
        {
            "usage": {
                "cost": 0.002,
                "prompt_tokens": 30,
                "completion_tokens": 40,
                "completion_tokens_details": {"reasoning_tokens": 0},
            }
        }
    )
    model = ModelData(
        model_used=OPENROUTER_MODEL,
        reasoning_effort_sent=None,
        reasoning_effort_was_sent=False,
        include_reasoning_sent=False,
        usage=usage,
    )
    return Hy3Response(
        message={"role": "assistant", "content": content},
        raw_usage=dict(usage.raw_provider_fields),
        provider_usage=usage,
        model_data=model,
        attempts=1,
        status=200,
    )


class FakeHy3Client:
    def __init__(self, content: object):
        self.response = model_response(content)
        self.calls: list[tuple[object, object]] = []

    def query_expansion(self, messages, *, options=None):
        self.calls.append((messages, options))
        return self.response


def document(queries=VALID_QUERIES) -> str:
    return json.dumps({"queries": queries})


def request() -> WorkflowRequest:
    return WorkflowRequest(request_id="request-04", task=TASK)


def test_valid_task_yields_typed_site_bound_records_for_every_tier():
    client = FakeHy3Client(document())
    plan = QueryExpander(client).expand(request())

    assert {record.tier for record in plan.queries} == set(EvidenceTier)
    for tier in EvidenceTier:
        records = plan.for_tier(tier)
        assert records
        for record in records:
            assert isinstance(record, QueryRecord)
            assert record.query_text
            assert record.site
            assert record.discovery_query == f"{record.query_text} site:{record.site}"
            assert record.discovery_query.count("site:") == 1
    assert plan.for_tier(EvidenceTier.TIER_1)[0].site == "fastapi.tiangolo.com"
    assert plan.for_tier(EvidenceTier.TIER_2)[0].site == "docs.python.org"
    assert plan.for_tier(EvidenceTier.TIER_3)[0].site == "github.com"


def test_prompt_is_bounded_structured_and_preserves_request_constraints():
    client = FakeHy3Client(document())
    QueryExpander(client).expand(request())

    assert len(client.calls) == 1
    messages, options = client.calls[0]
    assert options == {"response_format": {"type": "json_object"}}
    prompt = "\n".join(message["content"] for message in messages)
    assert TASK in prompt
    for constraint in (
        "Python",
        "FastAPI",
        "0.110",
        "Pydantic",
        "2.6",
        "ValidationError",
        "Input should be a valid string",
    ):
        assert constraint in prompt
        assert all(
            constraint.casefold() in item["query_text"].casefold()
            for item in VALID_QUERIES
        )
    assert "site (bare domain)" in prompt
    assert "1 to 5 queries for EACH tier" in prompt


def test_normalized_duplicates_merge_provenance_in_stable_order():
    duplicates = [
        *VALID_QUERIES,
        query(
            " PYTHON fastapi 0.110 pydantic 2.6 validationerror "
            "INPUT SHOULD BE A VALID STRING ",
            "FASTAPI.TIANGOLO.COM",
            1,
            ["second contributor", "official API contract"],
        ),
    ]
    plan = QueryExpander(FakeHy3Client(document(duplicates))).expand(request())

    assert len(plan.queries) == 3
    assert plan.queries[0].provenance == (
        "official API contract",
        "second contributor",
    )


@pytest.mark.parametrize(
    "bad_record",
    [
        query("Python FastAPI", "", 1),
        query("Python FastAPI", "localhost", 1),
        query("Python FastAPI", "github.com", 1),
        query("Python FastAPI", "fastapi.tiangolo.com", 2),
        query("Python FastAPI", "docs.python.org", 3),
    ],
)
def test_invalid_or_wrong_tier_site_and_site_override_fail_closed(bad_record):
    values = [*VALID_QUERIES]
    values[bad_record["tier"] - 1] = bad_record
    recorder = TraceRecorder("trace-04", TASK)

    with pytest.raises(ExpansionMalformedError) as caught:
        QueryExpander(
            FakeHy3Client(document(values)), trace_recorder=recorder
        ).expand(request())

    assert caught.value.code is ErrorCode.ERR_EXPANSION_MALFORMED
    span = recorder._spans[-1]
    assert span.status is StepStatus.FAILED
    assert span.error_code is ErrorCode.ERR_EXPANSION_MALFORMED
    assert span.expansion is not None
    assert span.expansion.parse_status == "malformed"
    assert span.expansion.query_texts == ()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        "{}",
        '{"queries":"free form"}',
        '{"queries":[{"query_text":"x","site":"example.com","tier":1}]}',
        json.dumps({"queries": VALID_QUERIES[:2]}),
    ],
)
def test_malformed_output_never_returns_a_plan_and_records_parse_status(content):
    recorder = TraceRecorder("trace-malformed", TASK)
    with pytest.raises(ExpansionMalformedError):
        QueryExpander(
            FakeHy3Client(content), trace_recorder=recorder
        ).expand(request())

    assert len(recorder._spans) == 1
    span = recorder._spans[0]
    assert span.step is WorkflowStep.QUERY_EXPANSION
    assert span.status is StepStatus.FAILED
    assert span.error_code is ErrorCode.ERR_EXPANSION_MALFORMED
    assert span.expansion.parse_status == "malformed"


@pytest.mark.parametrize(
    "content",
    [
        f"```json\n{document()}\n```",
        f"Here is the expansion:\n{document()}\nLet me know if you need more.",
        json.dumps(
            {"queries": VALID_QUERIES, "explanation": "model prose", "count": 3}
        ),
        json.dumps({"result": {"queries": VALID_QUERIES, "extra": True}}),
        json.dumps(VALID_QUERIES),
        "{'queries': " + repr(VALID_QUERIES) + ",}",
    ],
)
def test_hy3_output_wrappers_and_json_like_variants_are_accepted(content):
    plan = QueryExpander(FakeHy3Client(content)).expand(request())

    assert len(plan.queries) == 3
    assert {record.tier for record in plan.queries} == set(EvidenceTier)


def test_hy3_query_records_are_normalized_without_weakening_invariants():
    values = [
        {
            **VALID_QUERIES[0],
            "query_text": "Python FastAPI site:evil.example",
            "site": "https://fastapi.tiangolo.com/docs/reference",
            "tier": "1",
            "provenance": "official API contract",
            "ignored": "extra record key",
        },
        {
            **VALID_QUERIES[1],
            "query_text": "Python behavior site:docs.python.org",
            "site": "site:docs.python.org",
            "tier": "2",
            "provenance": "Python language behavior",
        },
        {
            **VALID_QUERIES[2],
            "query_text": "Python implementation site:github.com",
            "site": "https://github.com/search?q=implementation",
            "tier": "3",
            "provenance": "implementation examples",
        },
    ]

    plan = QueryExpander(FakeHy3Client(document(values))).expand(request())

    assert [record.site for record in plan.queries] == [
        "fastapi.tiangolo.com",
        "docs.python.org",
        "github.com",
    ]
    assert [record.query_text for record in plan.queries] == [
        "Python FastAPI",
        "Python behavior",
        "Python implementation",
    ]
    assert all("site:" not in record.query_text for record in plan.queries)
    assert all(isinstance(record.tier, EvidenceTier) for record in plan.queries)
    assert plan.queries[0].provenance == ("official API contract",)


@pytest.mark.parametrize("tier", [True, False])
def test_bool_tier_is_still_rejected(tier):
    values = [*VALID_QUERIES]
    values[0] = {**values[0], "tier": tier}

    with pytest.raises(ExpansionMalformedError):
        QueryExpander(FakeHy3Client(document(values))).expand(request())


def test_success_span_records_queries_sites_tiers_parameters_usage_and_artifacts():
    recorder = TraceRecorder("trace-success", TASK)
    clock = iter([10.0, 10.125])
    plan = QueryExpander(
        FakeHy3Client(document()),
        trace_recorder=recorder,
        monotonic=lambda: next(clock),
    ).expand(request(), attempt_number=2)

    assert len(recorder._spans) == 1
    span = recorder._spans[0]
    assert span.step is WorkflowStep.QUERY_EXPANSION
    assert span.status is StepStatus.SUCCEEDED
    assert span.latency_ms == 125
    assert span.attempt_number == 2
    assert span.error_code is None
    assert span.model.model_used == OPENROUTER_MODEL
    assert span.model.reasoning_effort_sent is None
    assert span.model.reasoning_effort_was_sent is False
    assert span.model.include_reasoning_sent is False
    assert span.model.usage.reasoning_tokens == 0
    assert span.expansion.parse_status == "parsed"
    assert span.expansion.query_texts == tuple(item.query_text for item in plan.queries)
    assert span.expansion.sites == tuple(item.site for item in plan.queries)
    assert span.expansion.query_tiers == tuple(item.tier for item in plan.queries)
    assert span.expansion.target_tiers == tuple(EvidenceTier)
    assert len(recorder._artifacts) == 4
    assert set(span.input_artifact_ids + span.output_artifact_ids) == set(
        recorder._artifacts
    )
    parameters = recorder._artifacts[span.model.parameters_artifact_id]
    assert parameters.metadata["reasoning_effort"] == "absent"
    assert parameters.metadata["include_reasoning"] is False


def test_query_count_bounds_are_configurable_and_validated():
    with pytest.raises(ValueError, match="cannot exceed"):
        Config(
            expansion_min_queries_per_tier=2,
            expansion_max_queries_per_tier=1,
        )

    with pytest.raises(ExpansionMalformedError):
        QueryExpander(
            FakeHy3Client(document()),
            config=Config(
                expansion_min_queries_per_tier=2,
                expansion_max_queries_per_tier=3,
            ),
        ).expand(request())


def test_task_bound_is_enforced_before_the_model_call():
    client = FakeHy3Client(document())
    with pytest.raises(ValueError, match="max_task"):
        QueryExpander(
            client, config=Config(expansion_max_task_characters=10)
        ).expand(request())
    assert client.calls == []
