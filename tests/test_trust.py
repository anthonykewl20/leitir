from __future__ import annotations

import pytest

import leitir.trust as trust_module
from leitir.trust import _factor, _parity, _parse_timestamp, _verification, compute_trust


def _by_factor(result):
    return {item["factor"]: item for item in result.breakdown}


def test_factor_subscores_and_breakdown(tmp_path):
    (tmp_path / "tests").mkdir()
    manifest = {
        "verified": True,
        "parity": "exact",
        "license_confidence": "medium",
        "license_method": "filename",
        "docs_urls": ["https://example.test/docs"],
        "entry_points": ["README.md"],
        "artifact_checksum": "sha256:abc",
        "artifact_kind": "sdist",
        "has_tests": True,
        "published_at": "2025-01-01T00:00:00Z",
        "fetched_at": "2025-06-01T00:00:00Z",
    }
    result = compute_trust(manifest, tmp_path)
    factors = _by_factor(result)
    assert {name: item["score"] for name, item in factors.items()} == {
        "age": 100,
        "artifact_checksum": 100,
        "documentation": 100,
        "license": 65,
        "parity": 100,
        "tests": 100,
        "verification": 100,
    }
    assert list(factors) == sorted(factors)
    assert all(set(item) == {"factor", "score", "weight", "evidence"} for item in result.breakdown)
    assert result.score == 95


def test_negative_evidence_and_bounds(tmp_path):
    manifest = {
        "verified": False,
        "parity": "drift",
        "license_confidence": "low",
        "docs_urls": [],
        "entry_points": [],
        "source": "git-commit",
        "has_tests": False,
        "fetched_at": "2026-01-01T00:00:00Z",
        "published_at": "2000-01-01T00:00:00Z",
    }
    result = compute_trust(manifest, tmp_path)
    factors = _by_factor(result)
    assert factors["verification"]["score"] == 0
    assert factors["parity"]["score"] == 0
    assert factors["license"]["score"] == 25
    assert factors["documentation"]["score"] == 0
    assert factors["tests"]["score"] == 0
    assert factors["artifact_checksum"]["score"] == 0
    assert factors["age"]["score"] == 25
    assert result.score == 8


def test_missing_evidence_is_neutral_unknown_and_deterministic(tmp_path):
    first = compute_trust({}, tmp_path)
    second = compute_trust({}, tmp_path)
    assert first == second
    factors = _by_factor(first)
    assert set(factors) == {
        "age",
        "artifact_checksum",
        "documentation",
        "license",
        "parity",
        "tests",
        "verification",
    }
    for name in factors:
        assert factors[name]["score"] == 50
        assert factors[name]["evidence"]["state"] == "unknown"
    assert first.score == 50


def test_partial_checksum_is_unknown(tmp_path):
    factor = _by_factor(compute_trust({"artifact_kind": "sdist"}, tmp_path))["artifact_checksum"]
    assert factor["score"] == 50
    assert factor["evidence"]["state"] == "unknown"


def test_cached_git_test_presence_overrides_artifact_tree(tmp_path):
    present = _by_factor(
        compute_trust({"source": "registry-artifact", "has_tests": True}, tmp_path)
    )["tests"]
    (tmp_path / "tests").mkdir()
    absent = _by_factor(
        compute_trust({"source": "registry-artifact", "has_tests": False}, tmp_path)
    )["tests"]
    assert present["score"] == 100
    assert absent["score"] == 0


def test_artifact_test_presence_is_neutral_when_unknown(tmp_path):
    for manifest in (
        {"source": "registry-artifact"},
        {"source": "registry-artifact", "has_tests": None},
    ):
        factor = _by_factor(compute_trust(manifest, tmp_path))["tests"]
        assert factor["score"] == 50
        assert factor["evidence"]["state"] == "unknown"


def test_uncached_test_evidence_does_not_become_absent_from_directory_scan(tmp_path):
    assert not (tmp_path / "tests").exists()
    factor = _by_factor(compute_trust({"source": "git-commit"}, tmp_path))["tests"]
    assert factor["score"] == 50
    assert factor["evidence"]["state"] == "unknown"


@pytest.mark.parametrize(
    ("published_at", "expected_score", "expected_days"),
    [
        ("2025-01-01T00:00:00Z", 100, 151),
        ("2021-01-01T00:00:00+00:00", 50, 1612),
        ("2010-01-01T00:00:00Z", 25, 5630),
    ],
)
def test_published_at_populates_age_and_changes_weighted_score(
    tmp_path, published_at, expected_score, expected_days
):
    manifest = {
        "published_at": published_at,
        "fetched_at": "2025-06-01T00:00:00Z",
    }
    result = compute_trust(manifest, tmp_path)
    age = _by_factor(result)["age"]
    assert age["score"] == expected_score
    assert age["evidence"] == {
        "state": "known",
        "source": "published_at",
        "days_at_fetch": expected_days,
        "reason": "age measured at cached fetch time",
    }
    assert result.score == {100: 58, 50: 50, 25: 46}[expected_score]


def test_unvalidated_date_alias_does_not_supply_age_evidence(tmp_path):
    manifest = {
        "commit_date": "2025-01-01T00:00:00Z",
        "fetched_at": "2025-06-01T00:00:00Z",
    }

    age = _by_factor(compute_trust(manifest, tmp_path))["age"]

    assert age["score"] == 50
    assert age["evidence"]["state"] == "unknown"


def test_configured_weights_match_the_seven_factor_contract():
    assert trust_module._WEIGHTS == {
        "age": 15,
        "artifact_checksum": 15,
        "documentation": 10,
        "license": 15,
        "parity": 15,
        "tests": 10,
        "verification": 20,
    }
    assert sum(trust_module._WEIGHTS.values()) == 100


def test_swapping_age_and_tests_weights_changes_the_golden_score(tmp_path, monkeypatch):
    manifest = {
        "verified": False,
        "parity": "drift",
        "license_confidence": "low",
        "docs_urls": [],
        "entry_points": [],
        "source": "git-commit",
        "has_tests": False,
        "published_at": "2000-01-01T00:00:00Z",
        "fetched_at": "2026-01-01T00:00:00Z",
    }
    assert compute_trust(manifest, tmp_path).score == 8
    mutated = dict(trust_module._WEIGHTS)
    mutated["age"], mutated["tests"] = mutated["tests"], mutated["age"]
    monkeypatch.setattr(trust_module, "_WEIGHTS", mutated)
    assert compute_trust(manifest, tmp_path).score == 6


@pytest.mark.parametrize(
    "invalid",
    [True, False, 1.5, float("nan"), float("inf"), float("-inf"), "50", None],
)
def test_factor_rejects_non_integer_and_non_finite_scores(invalid):
    with pytest.raises(ValueError, match="factor score must be an integer"):
        _factor("age", invalid, {})


def test_factor_clamps_out_of_range_integer_scores():
    assert _factor("age", -1, {})["score"] == 0
    assert _factor("age", 101, {})["score"] == 100


@pytest.mark.parametrize(
    ("manifest", "score", "state"),
    [
        ({"verified": "sampled"}, 70, "sampled"),
        ({"verified": "archive-only"}, 40, "archive-only"),
        ({"verified": "invalid"}, 50, "unknown"),
    ],
)
def test_verification_distinguishes_supported_and_invalid_cached_states(
    manifest, score, state
):
    factor = _verification(manifest)

    assert factor["score"] == score
    assert factor["evidence"]["state"] == state


def test_parity_invalid_state_and_invalid_timestamps_are_neutral():
    assert _parity({"parity": "not-a-parity-state"})["evidence"]["state"] == "unknown"
    assert _parse_timestamp("not-a-timestamp") is None
    assert _parse_timestamp("2026-01-01T00:00:00") is None


@pytest.mark.parametrize(
    "malformed",
    [
        {"8j1u": False},
        ["high"],
        True,
        None,
        3,
    ],
)
def test_malformed_cached_license_confidence_is_unknown_not_a_crash(tmp_path, malformed):
    manifest = {"license_confidence": malformed, "license_method": None}
    factor = _by_factor(compute_trust(manifest, tmp_path))["license"]
    assert factor["score"] == 50
    assert factor["evidence"]["state"] == "unknown"
