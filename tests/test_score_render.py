"""ADR-002 S8 deterministic renderer gates."""

from __future__ import annotations

import hashlib
import html
import json
import re

import pytest

from tools.score_engine import (
    POLICY_SCHEMA_VERSION,
    CheckMode,
    CheckPolicy,
    CheckResult,
    CheckStatus,
    Criterion,
    Decision,
    DimensionPolicy,
    EvidenceArtifact,
    Policy,
    Producer,
    Profile,
    Subject,
    canonical_json_bytes,
    evaluate,
    render_assessment_html,
    render_terminal_summary,
)

DIMENSIONS = (
    "engine_correctness",
    "output_effectiveness",
    "code_health",
    "test_adequacy",
    "process_supply_chain",
    "performance_operability",
)
CHECKS = tuple(
    f"{prefix}.render_contract"
    for prefix in ("engine", "output", "code", "test", "process", "performance")
)


def render_policy(
    *,
    offline_mode: CheckMode = CheckMode.REQUIRED,
    release_mode: CheckMode = CheckMode.REQUIRED,
) -> Policy:
    return Policy(
        schema_version=POLICY_SCHEMA_VERSION,
        id="render-policy-v1",
        dimensions=tuple(DimensionPolicy(item, 1) for item in DIMENSIONS),
        checks=tuple(
            CheckPolicy(
                id=check_id,
                dimension=dimension,
                weight=1,
                score_eligible=True,
                criterion=Criterion("gte", 0),
                offline_mode=offline_mode,
                release_mode=release_mode,
            )
            for check_id, dimension in zip(CHECKS, DIMENSIONS, strict=True)
        ),
    )


def render_assessment(
    *,
    profile: Profile = Profile.OFFLINE,
    status: CheckStatus = CheckStatus.PASS,
    score_bps: int | None = 10000,
):
    payload = b"renderer evidence\n"
    artifact = EvidenceArtifact(
        id="render.fixture",
        path="evidence/<img src=x onerror=alert(1)>.json",
        sha256=hashlib.sha256(payload).hexdigest(),
        content=payload,
    )
    results = []
    for index, check_id in enumerate(CHECKS):
        selected_status = status
        selected_score = score_bps
        results.append(
            CheckResult(
                id=check_id,
                status=selected_status,
                score_bps=selected_score,
                reason_code=(
                    "RENDER_UNKNOWN"
                    if selected_status is CheckStatus.UNKNOWN
                    else (
                        "RENDER_FAILED"
                        if selected_status is CheckStatus.FAIL
                        else "RENDER_PASSED"
                    )
                ),
                evidence=(
                    (
                        {"kind": "artifact", "value": artifact.id},
                        {"kind": "note", "value": "<script>alert(2)</script>"},
                    )
                    if index == 0
                    else ()
                ),
            )
        )
    return evaluate(
        render_policy(),
        tuple(results),
        profile=profile,
        subject=Subject(
            "https://example.invalid/<svg onload=alert(3)>",
            "1" * 40,
            "clean",
        ),
        producer=Producer("leitir-score-engine", "8", "2" * 40),
        evidence=(artifact,),
    )


def _embedded_canonical_json(rendered: bytes) -> str:
    match = re.search(
        rb'<pre id="canonical-assessment">(.*?)</pre>', rendered, re.DOTALL
    )
    assert match is not None
    return html.unescape(match.group(1).decode("utf-8"))


def test_html_embeds_the_exact_canonical_json_without_score_drift():
    assessment = render_assessment(
        status=CheckStatus.UNKNOWN,
        score_bps=None,
    )
    rendered = render_assessment_html(assessment)

    assert _embedded_canonical_json(rendered) == assessment.to_json()
    aggregate = assessment.to_dict()["aggregate"]
    for name in (
        "observed_score_bps",
        "lower_bound_bps",
        "upper_bound_bps",
        "included_weight",
        "eligible_weight",
    ):
        assert json.dumps(aggregate[name]).encode() in rendered
    assert canonical_json_bytes(assessment.to_dict()) == assessment.to_bytes()


def test_rendering_the_same_assessment_twice_is_byte_identical():
    assessment = render_assessment(status=CheckStatus.UNKNOWN, score_bps=None)
    assert render_assessment_html(assessment) == render_assessment_html(assessment)


def test_unknown_exact_score_is_unknown_with_bounds_never_zero():
    assessment = render_assessment(status=CheckStatus.UNKNOWN, score_bps=None)
    aggregate = assessment.aggregate.scores
    rendered = render_assessment_html(assessment).decode("utf-8")
    summary = render_terminal_summary(assessment)

    assert aggregate.score_bps is None
    assert '<span class="score score-unknown">unknown</span>' in rendered
    assert f"lower={aggregate.lower_bound_bps}" in rendered
    assert f"upper={aggregate.upper_bound_bps}" in rendered
    assert "score_bps=unknown" in summary
    assert "score_bps=0" not in summary


def test_measured_zero_is_rendered_as_zero_not_unknown():
    assessment = render_assessment(status=CheckStatus.FAIL, score_bps=0)
    rendered = render_assessment_html(assessment).decode("utf-8")

    assert assessment.checks[0].score_bps == 0
    assert '<td>0</td>' in rendered
    assert assessment.aggregate.decision is Decision.FAIL


def test_display_band_is_metadata_and_cannot_change_a_pass_decision():
    assessment = render_assessment(status=CheckStatus.PASS, score_bps=1)
    rendered = render_assessment_html(assessment).decode("utf-8")

    assert assessment.aggregate.decision is Decision.PASS
    assert 'data-display-only="true">critical</span>' in rendered
    assert "decision=<code>pass</code>" in rendered


def test_every_interpolated_path_and_evidence_value_is_html_escaped():
    rendered = render_assessment_html(render_assessment()).decode("utf-8")

    assert "<img src=x onerror=alert(1)>" not in rendered
    assert "<script>alert(2)</script>" not in rendered
    assert "<svg onload=alert(3)>" not in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in rendered


def test_noncanonical_reason_code_is_rejected_before_it_can_inject_markup():
    raw = render_assessment().to_dict()
    raw["checks"][0]["reason_code"] = "<script>alert(4)</script>"

    with pytest.raises(ValueError, match="reason_code"):
        render_assessment_html(raw)
