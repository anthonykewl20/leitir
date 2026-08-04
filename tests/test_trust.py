from __future__ import annotations

from leitir.trust import compute_trust


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
    assert 0 <= result.score <= 100


def test_negative_evidence_and_bounds(tmp_path):
    manifest = {
        "verified": False,
        "parity": "drift",
        "license_confidence": "low",
        "docs_urls": [],
        "entry_points": [],
        "fetched_at": "2026-01-01T00:00:00Z",
        "commit_date": "2000-01-01T00:00:00Z",
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
    assert 0 <= result.score <= 100


def test_missing_evidence_is_neutral_unknown_and_deterministic(tmp_path):
    first = compute_trust({}, tmp_path)
    second = compute_trust({}, tmp_path)
    assert first == second
    factors = _by_factor(first)
    for name in ("age", "documentation", "parity", "verification"):
        assert factors[name]["score"] == 50
        assert factors[name]["evidence"]["state"] == "unknown"
    assert factors["license"]["evidence"]["state"] == "low"


def test_partial_checksum_is_unknown(tmp_path):
    factor = _by_factor(compute_trust({"artifact_kind": "sdist"}, tmp_path))["artifact_checksum"]
    assert factor["score"] == 50
    assert factor["evidence"]["state"] == "unknown"
