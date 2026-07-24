"""Validated, serializable v1 configuration.

This module deliberately does not load configuration, credentials, or environment
variables.  A later composition root may construct :class:`Config` and inject a
credential provider.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import math
from urllib.parse import urlsplit

from .contracts import EvidenceTier, TargetLanguage


OPENROUTER_MODEL = "tencent/hy3"
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_CREDENTIAL_PATH = "~/.local/share/opencode/auth.json"


def _bounded_int(name: str, value: int, *, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _endpoint(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{name} must not contain credentials")
    if parsed.fragment:
        raise ValueError(f"{name} must not contain a fragment")


@dataclass(frozen=True, slots=True)
class Config:
    """All configurable boundaries owned by the v1 foundation.

    Python, ``pytest``, evidence Tiers 1–3, the OpenRouter model identity, and
    the single credential location are fixed rather than user-selectable.
    """

    model_endpoint: str = OPENROUTER_ENDPOINT
    search_endpoint: str = "http://localhost:8080/search"
    github_search_endpoint: str = "https://api.github.com/search/code"
    raw_content_endpoint: str = "https://raw.githubusercontent.com"
    model: str = OPENROUTER_MODEL
    model_timeout_seconds: int = 900

    discovery_max_results: int = 50
    discovery_timeout_seconds: int = 30
    extraction_max_bytes: int = 5_000_000
    extraction_timeout_seconds: int = 60
    github_min_stars: int = 101

    chunk_size: int = 2_000
    max_evidence_tokens: int = 20_000

    sandbox_timeout_seconds: int = 120
    sandbox_memory_mb: int = 512
    sandbox_cpu_count: int = 1
    sandbox_max_output_bytes: int = 1_000_000

    max_repairs: int = 3
    per_run_spend_cap_usd: float = 0.05

    language: TargetLanguage = field(
        default=TargetLanguage.PYTHON, init=False, repr=False
    )
    test_command: str = field(default="pytest", init=False, repr=False)
    evidence_tiers: tuple[EvidenceTier, ...] = field(
        default=(
            EvidenceTier.TIER_1,
            EvidenceTier.TIER_2,
            EvidenceTier.TIER_3,
        ),
        init=False,
        repr=False,
    )
    credential_path: str = field(
        default=OPENROUTER_CREDENTIAL_PATH, init=False, repr=False
    )

    def __post_init__(self) -> None:
        for name in (
            "model_endpoint",
            "search_endpoint",
            "github_search_endpoint",
            "raw_content_endpoint",
        ):
            _endpoint(name, getattr(self, name))

        if self.model != OPENROUTER_MODEL:
            raise ValueError(f"model is fixed to {OPENROUTER_MODEL!r}")

        bounds = {
            "model_timeout_seconds": (1, 3_600),
            "discovery_max_results": (1, 1_000),
            "discovery_timeout_seconds": (1, 300),
            "extraction_max_bytes": (1, 100_000_000),
            "extraction_timeout_seconds": (1, 900),
            "github_min_stars": (101, 10_000_000),
            "chunk_size": (1, 100_000),
            "max_evidence_tokens": (1, 1_000_000),
            "sandbox_timeout_seconds": (1, 3_600),
            "sandbox_memory_mb": (64, 65_536),
            "sandbox_cpu_count": (1, 128),
            "sandbox_max_output_bytes": (1, 100_000_000),
            "max_repairs": (0, 3),
        }
        for name, (minimum, maximum) in bounds.items():
            _bounded_int(name, getattr(self, name), minimum=minimum, maximum=maximum)
        if self.chunk_size > self.max_evidence_tokens:
            raise ValueError("chunk_size cannot exceed max_evidence_tokens")
        cap = self.per_run_spend_cap_usd
        if isinstance(cap, bool) or not isinstance(cap, (int, float)):
            raise TypeError("per_run_spend_cap_usd must be numeric")
        if not math.isfinite(cap) or cap <= 0 or cap > 1_000:
            raise ValueError(
                "per_run_spend_cap_usd must be finite, positive, and at most 1000"
            )

    @classmethod
    def default(cls) -> Config:
        """Return the fully validated v1 defaults without reading external state."""
        return cls()

    @property
    def openrouter_endpoint(self) -> str:
        """Compatibility name making the provider distinct from the model."""
        return self.model_endpoint

    @property
    def repair_limit(self) -> int:
        return self.max_repairs

    @property
    def spend_cap_usd(self) -> float:
        return self.per_run_spend_cap_usd

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic, JSON-compatible and secret-free mapping."""
        values = asdict(self)
        values["language"] = self.language.value
        values["evidence_tiers"] = [tier.value for tier in self.evidence_tiers]
        return values

    def serialize(self) -> str:
        """Serialize with stable key order and separators for trace reproducibility."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )

