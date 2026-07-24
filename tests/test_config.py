"""Configuration defaults, validation, and deterministic serialization."""

from __future__ import annotations

import json

import pytest

from leitir.config import Config, OPENROUTER_MODEL


def test_normative_defaults_and_fixed_boundaries():
    config = Config.default()
    assert config.model == OPENROUTER_MODEL
    assert config.model_timeout_seconds == 900
    assert config.model_temperature == 0
    assert config.model_max_tokens == 20_000
    assert config.model_max_attempts == 3
    assert config.model_retry_initial_backoff_seconds == 1
    assert config.model_retry_max_backoff_seconds == 8
    assert config.max_repairs == 3
    assert config.sandbox_process_limit == 64
    assert config.sandbox_tmpfs_mb == 64
    assert config.chunk_size > 0
    assert config.max_evidence_tokens >= config.chunk_size
    assert config.per_run_spend_cap_usd == 0.05
    assert config.github_min_stars == 0
    assert config.github_credential_path == "~/.config/gh/hosts.yml"
    assert config.search_engines is None
    assert config.language.value == "python"
    assert config.test_command == "pytest"
    assert [tier.value for tier in config.evidence_tiers] == [1, 2, 3]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("chunk_size", 0),
        ("chunk_size", 100_001),
        ("max_evidence_tokens", 0),
        ("max_evidence_tokens", 1_000_001),
        ("model_timeout_seconds", 0),
        ("model_temperature", float("nan")),
        ("model_temperature", True),
        ("model_max_tokens", 0),
        ("model_max_attempts", 0),
        ("model_max_attempts", 11),
        ("model_retry_initial_backoff_seconds", -1),
        ("model_retry_max_backoff_seconds", 301),
        ("discovery_max_results", 0),
        ("extraction_max_bytes", 0),
        ("extraction_max_attempts", 0),
        ("extraction_retry_initial_backoff_seconds", -1),
        ("extraction_retry_max_backoff_seconds", 301),
        ("github_min_stars", -1),
        ("sandbox_timeout_seconds", 0),
        ("sandbox_memory_mb", 32),
        ("sandbox_cpu_count", 0),
        ("sandbox_process_limit", 7),
        ("sandbox_max_output_bytes", 0),
        ("sandbox_tmpfs_mb", 0),
        ("max_repairs", 4),
        ("max_repairs", -1),
        ("per_run_spend_cap_usd", 0),
        ("per_run_spend_cap_usd", float("nan")),
    ],
)
def test_bounded_values_rejected(name, value):
    with pytest.raises((TypeError, ValueError)):
        Config(**{name: value})


def test_chunk_cannot_exceed_evidence_budget():
    with pytest.raises(ValueError, match="chunk_size"):
        Config(chunk_size=101, max_evidence_tokens=100)


def test_github_star_gate_remains_configurable_from_zero():
    assert Config(github_min_stars=0).github_min_stars == 0
    assert Config(github_min_stars=5).github_min_stars == 5


def test_model_retry_initial_backoff_cannot_exceed_cap():
    with pytest.raises(ValueError, match="backoff"):
        Config(
            model_retry_initial_backoff_seconds=2,
            model_retry_max_backoff_seconds=1,
        )


def test_extraction_retry_initial_backoff_cannot_exceed_cap():
    with pytest.raises(ValueError, match="backoff"):
        Config(
            extraction_retry_initial_backoff_seconds=2,
            extraction_retry_max_backoff_seconds=1,
        )


@pytest.mark.parametrize(
    "endpoint",
    ["", "openrouter.ai/api", "file:///tmp/socket", "https://user:pass@example.test"],
)
def test_invalid_or_credential_bearing_endpoint_rejected(endpoint):
    with pytest.raises(ValueError):
        Config(model_endpoint=endpoint)


def test_model_is_exact_and_transport_is_distinct():
    config = Config()
    assert config.model == "tencent/hy3"
    assert "openrouter.ai" in config.model_endpoint
    with pytest.raises(ValueError):
        Config(model="tencent/hy3-preview")


@pytest.mark.parametrize(
    ("field", "value"),
    [("language", "go"), ("test_command", "go test"), ("evidence_tiers", (1, 2, 3, 4))],
)
def test_fixed_boundaries_are_not_constructor_options(field, value):
    with pytest.raises(TypeError):
        Config(**{field: value})


def test_serialization_is_deterministic_json_and_contains_no_secret():
    config = Config()
    first = config.serialize()
    second = config.serialize()
    assert first == second
    assert first == json.dumps(
        json.loads(first), sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    assert "authorization" not in first.lower()
    assert "bearer" not in first.lower()
    assert "api_key" not in first.lower()
