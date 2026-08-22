"""Opt-in live verification of the OpenSSF Scorecard REST adapter."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tools.score_engine import (
    PINNED_OPENSSF_SCORECARD_VERSION,
    CheckStatus,
    OpenSSFCollectionState,
    collect_openssf_scorecard,
    evaluate_process_supply_chain_collection,
    load_policy,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
    )
]

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "scorecard" / "policy-v1.json"


def test_fresh_public_payload_collects_and_matches_pinned_version():
    collection = collect_openssf_scorecard("ossf/scorecard")

    assert collection.state is OpenSSFCollectionState.AVAILABLE
    assert collection.http_status == 200
    raw = json.loads(collection.artifact.content)
    observed = datetime.fromisoformat(raw["date"].replace("Z", "+00:00"))
    assert datetime.now(UTC) - timedelta(days=7) <= observed <= datetime.now(UTC) + timedelta(minutes=5)

    evaluation = evaluate_process_supply_chain_collection(
        policy=load_policy(POLICY), collection=collection
    )
    assert evaluation.provenance.tool_version == PINNED_OPENSSF_SCORECARD_VERSION
    assert "OPENSSF_VERSION_MISMATCH" not in {
        item.reason_code for item in evaluation.checks
    }


def test_unindexed_leitir_subject_is_typed_unavailable_not_pass_or_error():
    collection = collect_openssf_scorecard("anthonykewl20/leitir")
    evaluation = evaluate_process_supply_chain_collection(
        policy=load_policy(POLICY), collection=collection
    )

    assert collection.state is OpenSSFCollectionState.UNAVAILABLE
    assert collection.http_status == 404
    assert collection.artifact is None
    assert all(item.status is CheckStatus.UNKNOWN for item in evaluation.checks)
    assert {item.reason_code for item in evaluation.checks} == {
        "OPENSSF_API_UNAVAILABLE"
    }
    assert all(item.score_bps is None for item in evaluation.checks)
