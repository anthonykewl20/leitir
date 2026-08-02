"""Deterministic evidence scoring engine for ADR-002 S1-S9.

This standalone module intentionally imports no Leitir package code.  It owns
the policy vocabulary, integer scoring arithmetic, non-compensating gate, and
canonical provenance envelope, offline engine-correctness collectors, and the
ranked-output effectiveness adapter.  Later slices own the remaining
assessment dimensions.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP, localcontext
from enum import Enum, IntEnum
from fractions import Fraction
import hashlib
from html import escape as _html_escape
from importlib import machinery
from importlib import metadata as importlib_metadata
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Iterable, Iterator, Mapping, Sequence, TextIO
from xml.etree import ElementTree


ASSESSMENT_SCHEMA_VERSION = "leitir-assessment-v1"
POLICY_SCHEMA_VERSION = "leitir-score-policy-v1"
RUN_ENVELOPE_SCHEMA_VERSION = "leitir-score-run-envelope-v1"
SCORE_ENGINE_VERSION = "9"
DIMENSION_IDS = (
    "engine_correctness",
    "output_effectiveness",
    "code_health",
    "test_adequacy",
    "process_supply_chain",
    "performance_operability",
)

_CHECK_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_POLICY_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_ID = re.compile(r"^[a-z][a-z0-9_.-]*$")
_NORMALIZATION_ID = re.compile(r"^[a-z][a-z0-9-]*-v[1-9][0-9]*$")
_REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TASK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

_BENCHMARK_MANIFEST_SCHEMA_VERSION = "leitir-benchmark-manifest-v1"
_BENCHMARK_RUN_SCHEMA_VERSION = "leitir-benchmark-run-v1"
_BENCHMARK_QRELS_SCHEMA_VERSION = "leitir-benchmark-qrels-v1"
_RETRIEVAL_LANGUAGES = ("go", "python", "rust")
_RETRIEVAL_CUTOFF = 10
_OUTPUT_CHECK_IDS = (
    "output.average_precision_at_10",
    "output.complete_scoped_coverage",
    "output.exact_target_at_10",
    "output.language_strata",
    "output.ndcg_at_10",
    "output.pinned_benchmark",
    "output.precision_at_10",
    "output.precision_at_5",
    "output.predicate_strata",
    "output.recall_at_10",
    "output.reciprocal_rank_at_10",
    "output.success_at_1",
    "output.success_at_10",
    "output.success_at_5",
    "output.total_ordering",
)

_SCORE_TOOL_VERSIONS_SCHEMA_VERSION = "leitir-score-tool-versions-v1"
_CODE_SCOPE_SCHEMA_VERSION = "leitir-code-scope-v1"
_MUTMUT_EVIDENCE_SCHEMA_VERSION = "leitir-mutmut-evidence-v1"
PINNED_SCORE_TOOL_VERSIONS = {
    "coverage": "7.15.2",
    "ir_measures": "0.4.3",
    "mutmut": "3.7.0",
    "pytrec-eval-terrier": "0.5.10",
    "radon": "6.0.1",
}
_CODE_HEALTH_CHECK_IDS = (
    "code.complexity_distribution",
    "code.complexity_maximum",
    "code.maintainability_index",
    "code.production_scope_parsed",
    "code.scope_declared",
)
_TEST_ADEQUACY_CHECK_IDS = (
    "test.branch_coverage",
    "test.coverage_scope",
    "test.line_coverage",
    "test.mutation_controls",
    "test.mutation_score",
)
_SCOPE_KINDS = ("production", "generated", "vendored", "fixture")
_APPLICABILITY_KINDS = ("statements", "branches", "mutants")

PINNED_OPENSSF_SCORECARD_VERSION = "v5.5.0"
PINNED_OPENSSF_SCORECARD_COMMIT = (
    "c395761df6afe1a69e476bc60a013a94bcbc153f"
)
OPENSSF_SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com"
_MAX_OPENSSF_ARTIFACT_BYTES = 16 * 1024 * 1024
_PROCESS_CONTROL_CHECK_ID = "process.supply_chain_evidence"
OPENSSF_SELECTED_CHECKS = (
    ("process.branch_protection", "Branch-Protection"),
    ("process.ci_tests", "CI-Tests"),
    ("process.code_review", "Code-Review"),
    ("process.dependency_update_tool", "Dependency-Update-Tool"),
    ("process.fuzzing", "Fuzzing"),
    ("process.pinned_dependencies", "Pinned-Dependencies"),
    ("process.signed_releases", "Signed-Releases"),
    ("process.vulnerabilities", "Vulnerabilities"),
)
_PROCESS_CHECK_IDS = (
    _PROCESS_CONTROL_CHECK_ID,
    *(check_id for check_id, _ in OPENSSF_SELECTED_CHECKS),
)

PINNED_ASV_VERSION = "0.6.6"
_ASV_RESULT_SCHEMA_VERSION = 2
_PERFORMANCE_RUNNER_SCHEMA_VERSION = "leitir-performance-runner-v1"
_LIVE_LATENCY_SCHEMA_VERSION = "leitir-live-network-latency-v1"
_PERFORMANCE_CONTROL_CHECK_ID = "performance.controlled_baseline"
_PERFORMANCE_LATENCY_CHECK_ID = "performance.live_network_latency"
_PERFORMANCE_MAGNITUDE_FACTOR = Decimal("1.10")
_PERFORMANCE_P_THRESHOLD = Decimal("0.002")
_PERFORMANCE_MIN_SAMPLES = 6
_ASV_RESULT_COLUMNS = (
    "result",
    "params",
    "version",
    "started_at",
    "duration",
    "stats_ci_99_a",
    "stats_ci_99_b",
    "stats_q_25",
    "stats_q_75",
    "stats_number",
    "stats_repeat",
    "samples",
    "profile",
)
_OPENSSF_CAPABILITY_NAMES = {
    "branch_protection",
    "checks",
    "contents",
    "public_api",
    "pull_requests",
    "releases",
    "repository_metadata",
    "vulnerabilities",
}


ADR001_OFFLINE_GATE_TESTS = (
    "tests/test_search.py",
    "tests/test_search_e2e.py",
    "tests/test_engine.py",
    "tests/test_engine_e2e.py",
    "tests/test_adapters_multi.py",
    "tests/test_resolver.py",
    "tests/test_resolver_e2e.py",
    "tests/test_cli.py",
    "tests/test_cli_e2e.py",
    "tests/test_global.py",
    "tests/test_global_e2e.py",
    "tests/test_ranking.py",
    "tests/test_bench.py",
)
_PYTEST_JUNIT_PATH = ".leitir-score/evidence/adr001-offline-junit.xml"
ADR001_OFFLINE_GATE_ARGV = (
    "python",
    "-m",
    "pytest",
    *ADR001_OFFLINE_GATE_TESTS,
    "-p",
    "no:cacheprovider",
    f"--junitxml={_PYTEST_JUNIT_PATH}",
)
_MAX_JUNIT_BYTES = 16 * 1024 * 1024
_RETIRED_V1_MODULES = (
    "_jsonutil",
    "config",
    "contracts",
    "discovery",
    "evaluation",
    "expansion",
    "extraction",
    "openrouter",
    "orchestrator",
    "protocols",
    "synthesis",
    "trace",
    "verification",
)


class CheckStatus(str, Enum):
    """The complete result vocabulary defined by ADR-002 section 3."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"


class CheckMode(str, Enum):
    """Whether a check participates in the non-compensating gate."""

    REQUIRED = "required"
    ADVISORY = "advisory"


class Profile(str, Enum):
    """The two assessment profiles defined by ADR-002 section 12."""

    OFFLINE = "offline"
    RELEASE = "release"


class Decision(str, Enum):
    """A policy decision, independent of the diagnostic scalar score."""

    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class ExitCode(IntEnum):
    """Stable process exits from ADR-002 section 12."""

    COMPLETE_PASS = 0
    KNOWN_FAILURE = 1
    INVALID_USAGE_OR_POLICY = 2
    INDETERMINATE = 3


class BlockerKind(str, Enum):
    """Why a required check prevents an unqualified pass."""

    KNOWN_FAILURE = "known_failure"
    UNRESOLVED = "unresolved"
    MISSING_RESULT = "missing_result"


class StandardReason(str, Enum):
    """Engine-owned reason codes; adapters may supply domain reason codes."""

    POLICY_CHECK_MISSING = "POLICY_CHECK_MISSING"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_non_negative_int(value: object, name: str) -> None:
    if not _is_int(value) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _validate_positive_int(value: object, name: str) -> None:
    if not _is_int(value) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _validate_score(value: object, name: str = "score_bps") -> None:
    if not _is_int(value) or not 0 <= value <= 10000:
        raise ValueError(f"{name} must be an integer from 0 through 10000")


def _validate_canonical_path(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        raise ValueError(f"{name} must be a normalized relative POSIX path")


@dataclass(frozen=True, slots=True, eq=False)
class _FrozenTextMap(Mapping[str, str]):
    """A sorted, immutable, hashable mapping used inside frozen contracts."""

    entries: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, str]) -> _FrozenTextMap:
        return cls(tuple(sorted(value.items())))

    def __getitem__(self, key: str) -> str:
        for item_key, item_value in self.entries:
            if item_key == key:
                return item_value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and dict(self.entries) == dict(other.items())

    def __hash__(self) -> int:
        return hash(self.entries)


def _round_half_up_fraction(numerator: int, denominator: int) -> int:
    """Round a non-negative exact fraction to an integer, half away from zero."""
    _validate_non_negative_int(numerator, "numerator")
    _validate_positive_int(denominator, "denominator")
    precision = max(len(str(numerator)), len(str(denominator))) + 16
    with localcontext() as context:
        context.prec = precision
        value = Decimal(numerator) / Decimal(denominator)
        return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def proportional_score_bps(numerator: int, denominator: int) -> int | None:
    """Return ``round_half_up(10000 * n / d)`` or null for a zero denominator."""
    _validate_non_negative_int(numerator, "numerator")
    _validate_non_negative_int(denominator, "denominator")
    if numerator > denominator:
        raise ValueError("numerator cannot exceed denominator")
    if denominator == 0:
        return None
    return _round_half_up_fraction(10000 * numerator, denominator)


def score_from_counts(counts: Iterable[tuple[int, int]]) -> int | None:
    """Aggregate raw sufficient statistics before deriving one ratio."""
    total_numerator = 0
    total_denominator = 0
    seen = False
    for item in counts:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("counts must contain (numerator, denominator) tuples")
        numerator, denominator = item
        _validate_non_negative_int(numerator, "numerator")
        _validate_non_negative_int(denominator, "denominator")
        if numerator > denominator:
            raise ValueError("numerator cannot exceed denominator")
        total_numerator += numerator
        total_denominator += denominator
        seen = True
    if not seen:
        raise ValueError("counts must contain at least one pair")
    return proportional_score_bps(total_numerator, total_denominator)


def weighted_score_bps(values: Iterable[tuple[int, int]]) -> int:
    """Return the positive-integer-weighted basis-point score."""
    weighted_total = 0
    total_weight = 0
    seen = False
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("values must contain (score_bps, weight) tuples")
        score_bps, weight = item
        _validate_score(score_bps)
        _validate_positive_int(weight, "weight")
        weighted_total += score_bps * weight
        total_weight += weight
        seen = True
    if not seen:
        raise ValueError("values must contain at least one score")
    return _round_half_up_fraction(weighted_total, total_weight)


def display_band(score_bps: int) -> str:
    """Return display-only continuity metadata; this is never called by the gate."""
    _validate_score(score_bps)
    if score_bps < 4000:
        return "critical"
    if score_bps < 6000:
        return "serious"
    if score_bps < 8000:
        return "fair"
    return "good"


@dataclass(frozen=True, slots=True)
class Criterion:
    """A typed policy criterion copied into the canonical assessment."""

    op: str
    value: int

    def __post_init__(self) -> None:
        if self.op not in {"eq", "gte", "lte"}:
            raise ValueError("criterion op must be one of: eq, gte, lte")
        _validate_score(self.value, "criterion value")

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "value": self.value}


@dataclass(frozen=True, slots=True)
class ApplicabilityRule:
    """A versioned policy predicate that can authorize not-applicable."""

    rule: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not self.rule.strip():
            raise ValueError("applicability rule must be non-empty text")

    def to_dict(self) -> dict[str, str]:
        return {"rule": self.rule}


@dataclass(frozen=True, slots=True)
class DimensionPolicy:
    """Explicit versioned influence of one assessment dimension."""

    id: str
    weight: int

    def __post_init__(self) -> None:
        if self.id not in DIMENSION_IDS:
            raise ValueError(f"unknown dimension ID: {self.id!r}")
        _validate_positive_int(self.weight, "dimension weight")

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "weight": self.weight}


@dataclass(frozen=True, slots=True)
class CheckPolicy:
    """Policy-owned identity, weighting, profile mode, and applicability."""

    id: str
    dimension: str
    weight: int
    score_eligible: bool
    criterion: Criterion
    offline_mode: CheckMode
    release_mode: CheckMode
    applicability: ApplicabilityRule | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CHECK_ID.fullmatch(self.id):
            raise ValueError("check ID must be lowercase dotted snake-case")
        if self.dimension not in DIMENSION_IDS:
            raise ValueError(f"unknown check dimension: {self.dimension!r}")
        _validate_positive_int(self.weight, "check weight")
        if not isinstance(self.score_eligible, bool):
            raise TypeError("score_eligible must be a bool")
        if not isinstance(self.criterion, Criterion):
            raise TypeError("criterion must be a Criterion")
        if not isinstance(self.offline_mode, CheckMode):
            raise TypeError("offline_mode must be a CheckMode")
        if not isinstance(self.release_mode, CheckMode):
            raise TypeError("release_mode must be a CheckMode")
        if self.applicability is not None and not isinstance(
            self.applicability, ApplicabilityRule
        ):
            raise TypeError("applicability must be an ApplicabilityRule or None")

    def mode_for(self, profile: Profile) -> CheckMode:
        if not isinstance(profile, Profile):
            raise TypeError("profile must be a Profile")
        if profile is Profile.OFFLINE:
            return self.offline_mode
        return self.release_mode

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "dimension": self.dimension,
            "weight": self.weight,
            "score_eligible": self.score_eligible,
            "criterion": self.criterion.to_dict(),
            "modes": {
                "offline": self.offline_mode.value,
                "release": self.release_mode.value,
            },
            "applicability": (
                None if self.applicability is None else self.applicability.to_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class Policy:
    """The complete versioned set of expected checks and dimension weights."""

    schema_version: str
    id: str
    dimensions: tuple[DimensionPolicy, ...]
    checks: tuple[CheckPolicy, ...]
    waivers: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != POLICY_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {POLICY_SCHEMA_VERSION!r}")
        if not isinstance(self.id, str) or not _POLICY_ID.fullmatch(self.id):
            raise ValueError("policy ID must be lowercase kebab-case")
        if not isinstance(self.dimensions, tuple) or any(
            not isinstance(item, DimensionPolicy) for item in self.dimensions
        ):
            raise TypeError("dimensions must be a tuple of DimensionPolicy")
        dimension_ids = [item.id for item in self.dimensions]
        if tuple(dimension_ids) != DIMENSION_IDS:
            raise ValueError(
                "policy must declare all six dimensions in canonical order"
            )
        if not isinstance(self.checks, tuple) or any(
            not isinstance(item, CheckPolicy) for item in self.checks
        ):
            raise TypeError("checks must be a tuple of CheckPolicy")
        if not self.checks:
            raise ValueError("policy must declare at least one check")
        check_ids = [item.id for item in self.checks]
        if len(set(check_ids)) != len(check_ids):
            raise ValueError("policy check IDs must be unique")
        declared_dimensions = set(dimension_ids)
        if any(item.dimension not in declared_dimensions for item in self.checks):
            raise ValueError("every check dimension must be declared by the policy")
        if set(item.dimension for item in self.checks) != declared_dimensions:
            raise ValueError("every policy dimension must contain at least one check")
        if not isinstance(self.waivers, tuple):
            raise TypeError("waivers must be a tuple")
        if self.waivers:
            raise ValueError("policy v1 does not permit waivers")
        object.__setattr__(
            self,
            "checks",
            tuple(sorted(self.checks, key=lambda item: item.id)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "dimensions": [item.to_dict() for item in self.dimensions],
            "checks": [item.to_dict() for item in self.checks],
            "waivers": [],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CommandExecution:
    """Exact subprocess provenance attached to one raw evidence artifact."""

    argv: tuple[str, ...]
    process_exit: int
    collector_reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv:
            raise TypeError("argv must be a non-empty tuple")
        if any(not isinstance(item, str) or not item for item in self.argv):
            raise ValueError("argv entries must be non-empty text")
        if not _is_int(self.process_exit):
            raise TypeError("process_exit must be an integer")
        if not isinstance(
            self.collector_reason_code, str
        ) or not _REASON_CODE.fullmatch(self.collector_reason_code):
            raise ValueError("collector_reason_code must be uppercase snake-case")

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "process_exit": self.process_exit,
            "collector_reason_code": self.collector_reason_code,
        }


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A source location bound to its exact repository blob."""

    path: str
    blob_digest: str
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        _validate_canonical_path(self.path, "source path")
        if not isinstance(self.blob_digest, str) or not (
            _SHA1.fullmatch(self.blob_digest) or _SHA256.fullmatch(self.blob_digest)
        ):
            raise ValueError("blob_digest must be a 40- or 64-char lowercase hex digest")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("start_line and end_line must be provided together")
        if self.start_line is not None and self.end_line is not None:
            _validate_positive_int(self.start_line, "start_line")
            _validate_positive_int(self.end_line, "end_line")
            if self.start_line > self.end_line:
                raise ValueError("start_line cannot exceed end_line")

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.path,
            0 if self.start_line is None else self.start_line,
            0 if self.end_line is None else self.end_line,
            self.blob_digest,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "blob_digest": self.blob_digest,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    """Evidence bytes plus the canonical provenance retained for them.

    ``content`` is evaluation input and is deliberately excluded from canonical
    output.  Its pinned SHA-256 is verified at construction, so altered bytes
    never reach scoring as apparently valid evidence.  Collector formats may
    normalize explicitly identified volatile fields before constructing the
    artifact.  In that case ``raw_content`` and ``raw_sha256`` retain the exact
    collected-byte identity for a separate run envelope; they never enter the
    canonical assessment digest.
    """

    id: str
    path: str
    sha256: str
    content: bytes = field(repr=False, compare=False)
    command: CommandExecution | None = None
    sources: tuple[SourceSpan, ...] = ()
    normalization: str | None = None
    raw_sha256: str | None = field(default=None, repr=False, compare=False)
    raw_content: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _EVIDENCE_ID.fullmatch(self.id):
            raise ValueError("evidence ID must be a lowercase stable identifier")
        _validate_canonical_path(self.path, "evidence path")
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ValueError("evidence sha256 must be a 64-char lowercase hex digest")
        if not isinstance(self.content, bytes):
            raise TypeError("evidence content must be bytes")
        if hashlib.sha256(self.content).hexdigest() != self.sha256:
            raise ValueError("evidence content does not match its declared sha256")
        normalized_fields = (
            self.normalization,
            self.raw_sha256,
            self.raw_content,
        )
        if any(item is not None for item in normalized_fields):
            if not all(item is not None for item in normalized_fields):
                raise ValueError(
                    "normalized evidence requires normalization, raw_sha256, and raw_content"
                )
            if not isinstance(self.normalization, str) or not _NORMALIZATION_ID.fullmatch(
                self.normalization
            ):
                raise ValueError("evidence normalization must be a versioned identifier")
            if not isinstance(self.raw_sha256, str) or not _SHA256.fullmatch(
                self.raw_sha256
            ):
                raise ValueError("raw evidence sha256 must be lowercase SHA-256")
            if not isinstance(self.raw_content, bytes):
                raise TypeError("raw evidence content must be bytes")
            if hashlib.sha256(self.raw_content).hexdigest() != self.raw_sha256:
                raise ValueError("raw evidence content does not match its declared sha256")
        if self.command is not None and not isinstance(
            self.command, CommandExecution
        ):
            raise TypeError("evidence command must be a CommandExecution or None")
        if not isinstance(self.sources, tuple) or any(
            not isinstance(item, SourceSpan) for item in self.sources
        ):
            raise TypeError("evidence sources must be a tuple of SourceSpan")
        source_keys = [item.sort_key() for item in self.sources]
        if len(set(source_keys)) != len(source_keys):
            raise ValueError("evidence source spans must be unique")
        object.__setattr__(
            self,
            "sources",
            tuple(sorted(self.sources, key=SourceSpan.sort_key)),
        )

    @classmethod
    def from_path(
        cls,
        *,
        id: str,
        path: str | Path,
        canonical_path: str,
        sha256: str,
        command: CommandExecution | None = None,
        sources: tuple[SourceSpan, ...] = (),
    ) -> EvidenceArtifact:
        if not isinstance(path, (str, Path)):
            raise TypeError("path must be text or Path")
        return cls(
            id=id,
            path=canonical_path,
            sha256=sha256,
            content=Path(path).read_bytes(),
            command=command,
            sources=sources,
        )

    def sort_key(self) -> tuple[str, str, str]:
        return (self.id, self.path, self.sha256)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.id,
            "path": self.path,
            "sha256": self.sha256,
            "command": None if self.command is None else self.command.to_dict(),
            "sources": [item.to_dict() for item in self.sources],
        }
        if self.normalization is not None:
            result["normalization"] = self.normalization
        return result


@dataclass(frozen=True, slots=True)
class RawEvidenceProvenance:
    """Exact collected-byte identity kept outside assessment identity."""

    id: str
    path: str
    raw_sha256: str
    canonical_sha256: str
    normalization: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _EVIDENCE_ID.fullmatch(self.id):
            raise ValueError("raw evidence ID must be a lowercase stable identifier")
        _validate_canonical_path(self.path, "raw evidence path")
        for value, name in (
            (self.raw_sha256, "raw_sha256"),
            (self.canonical_sha256, "canonical_sha256"),
        ):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError(f"{name} must be lowercase SHA-256")
        if not isinstance(self.normalization, str) or not _NORMALIZATION_ID.fullmatch(
            self.normalization
        ):
            raise ValueError("raw evidence normalization must be versioned")

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.id, self.path, self.canonical_sha256, self.raw_sha256)

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "path": self.path,
            "raw_sha256": self.raw_sha256,
            "canonical_sha256": self.canonical_sha256,
            "normalization": self.normalization,
        }


def _normalized_exclusions(
    exclusions: object,
) -> tuple[tuple[str, int], ...]:
    if not isinstance(exclusions, tuple):
        raise TypeError("exclusions must be a tuple of (reason, count) pairs")
    exclusion_names: list[str] = []
    for item in exclusions:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("exclusions must contain (reason, count) tuples")
        reason, count = item
        if not isinstance(reason, str) or not _REASON_CODE.fullmatch(reason):
            raise ValueError("exclusion reasons must be uppercase snake-case")
        _validate_non_negative_int(count, "exclusion count")
        exclusion_names.append(reason)
    if len(set(exclusion_names)) != len(exclusion_names):
        raise ValueError("exclusion reasons must be unique")
    return tuple(sorted(exclusions))


def _normalized_check_evidence(
    evidence: object,
) -> tuple[Mapping[str, str], ...]:
    if not isinstance(evidence, tuple):
        raise TypeError("evidence must be a tuple of mappings")
    normalized: list[_FrozenTextMap] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            raise TypeError("evidence must be a tuple of mappings")
        if set(item) != {"kind", "value"}:
            raise ValueError("evidence entries require exactly kind and value")
        if any(
            not isinstance(value, str) or not value.strip() for value in item.values()
        ):
            raise ValueError("evidence kind and value must be non-empty text")
        normalized.append(_FrozenTextMap.from_mapping(item))
    return tuple(sorted(normalized, key=lambda item: (item["kind"], item["value"])))


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One submitted measurement before policy metadata is applied."""

    id: str
    status: CheckStatus
    score_bps: int | None
    reason_code: str
    numerator: int | None = None
    denominator: int | None = None
    exclusions: tuple[tuple[str, int], ...] = ()
    evidence: tuple[Mapping[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CHECK_ID.fullmatch(self.id):
            raise ValueError("check ID must be lowercase dotted snake-case")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("reason_code must be uppercase snake-case")
        if self.status in {CheckStatus.PASS, CheckStatus.FAIL}:
            _validate_score(self.score_bps)
        elif self.score_bps is not None:
            raise ValueError(f"{self.status.value} requires score_bps=None")
        if (self.numerator is None) != (self.denominator is None):
            raise ValueError("numerator and denominator must be provided together")
        if self.numerator is not None and self.denominator is not None:
            _validate_non_negative_int(self.numerator, "numerator")
            _validate_non_negative_int(self.denominator, "denominator")
            if self.numerator > self.denominator:
                raise ValueError("numerator cannot exceed denominator")
            if self.denominator == 0 and self.status in {
                CheckStatus.PASS,
                CheckStatus.FAIL,
            }:
                raise ValueError("a zero denominator cannot produce pass or fail")
        object.__setattr__(
            self, "exclusions", _normalized_exclusions(self.exclusions)
        )
        object.__setattr__(
            self, "evidence", _normalized_check_evidence(self.evidence)
        )


@dataclass(frozen=True, slots=True)
class AssessedCheck:
    """A result enriched only from the governing policy."""

    id: str
    dimension: str
    mode: CheckMode
    status: CheckStatus
    score_bps: int | None
    weight: int
    score_eligible: bool
    criterion: Criterion
    reason_code: str
    numerator: int | None
    denominator: int | None
    exclusions: tuple[tuple[str, int], ...]
    evidence: tuple[Mapping[str, str], ...]
    missing: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _CHECK_ID.fullmatch(self.id):
            raise ValueError("check ID must be lowercase dotted snake-case")
        if self.dimension not in DIMENSION_IDS:
            raise ValueError(f"unknown check dimension: {self.dimension!r}")
        if not isinstance(self.mode, CheckMode):
            raise TypeError("mode must be a CheckMode")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")
        if self.status in {CheckStatus.PASS, CheckStatus.FAIL}:
            _validate_score(self.score_bps)
        elif self.score_bps is not None:
            raise ValueError(f"{self.status.value} requires score_bps=None")
        _validate_positive_int(self.weight, "check weight")
        if not isinstance(self.score_eligible, bool):
            raise TypeError("score_eligible must be a bool")
        if not isinstance(self.criterion, Criterion):
            raise TypeError("criterion must be a Criterion")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("reason_code must be uppercase snake-case")
        object.__setattr__(
            self, "exclusions", _normalized_exclusions(self.exclusions)
        )
        object.__setattr__(
            self, "evidence", _normalized_check_evidence(self.evidence)
        )
        if not isinstance(self.missing, bool):
            raise TypeError("missing must be a bool")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "dimension": self.dimension,
            "mode": self.mode.value,
            "status": self.status.value,
            "score_bps": self.score_bps,
            "weight": self.weight,
            "score_eligible": self.score_eligible,
            "criterion": self.criterion.to_dict(),
            "reason_code": self.reason_code,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "exclusions": dict(self.exclusions),
            "evidence": [dict(item) for item in self.evidence],
            "missing": self.missing,
        }


@dataclass(frozen=True, slots=True)
class ScoreAggregate:
    """Exact, observed, and pessimistic/optimistic bounded diagnostics."""

    score_bps: int | None
    observed_score_bps: int | None
    lower_bound_bps: int | None
    upper_bound_bps: int | None
    included_weight: int
    eligible_weight: int

    def __post_init__(self) -> None:
        for name in (
            "score_bps",
            "observed_score_bps",
            "lower_bound_bps",
            "upper_bound_bps",
        ):
            value = getattr(self, name)
            if value is not None:
                _validate_score(value, name)
        _validate_non_negative_int(self.included_weight, "included_weight")
        _validate_non_negative_int(self.eligible_weight, "eligible_weight")
        if self.included_weight > self.eligible_weight:
            raise ValueError("included_weight cannot exceed eligible_weight")
        if self.eligible_weight == 0 and any(
            value is not None
            for value in (
                self.score_bps,
                self.observed_score_bps,
                self.lower_bound_bps,
                self.upper_bound_bps,
            )
        ):
            raise ValueError("an ineligible aggregate cannot contain scores")
        if self.score_bps is not None and self.included_weight != self.eligible_weight:
            raise ValueError("an exact score requires all eligible weight")
        if self.included_weight == 0 and self.observed_score_bps is not None:
            raise ValueError("an observed score requires included weight")
        if (
            self.lower_bound_bps is not None
            and self.upper_bound_bps is not None
            and self.lower_bound_bps > self.upper_bound_bps
        ):
            raise ValueError("lower_bound_bps cannot exceed upper_bound_bps")

    def to_dict(self) -> dict[str, object]:
        return {
            "score_bps": self.score_bps,
            "observed_score_bps": self.observed_score_bps,
            "lower_bound_bps": self.lower_bound_bps,
            "upper_bound_bps": self.upper_bound_bps,
            "included_weight": self.included_weight,
            "eligible_weight": self.eligible_weight,
        }


@dataclass(frozen=True, slots=True)
class DimensionAssessment:
    """One dimension scored before its explicit overall policy weight."""

    id: str
    weight: int
    aggregate: ScoreAggregate

    def __post_init__(self) -> None:
        if self.id not in DIMENSION_IDS:
            raise ValueError(f"unknown dimension ID: {self.id!r}")
        _validate_positive_int(self.weight, "dimension weight")
        if not isinstance(self.aggregate, ScoreAggregate):
            raise TypeError("aggregate must be a ScoreAggregate")

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "weight": self.weight, **self.aggregate.to_dict()}


@dataclass(frozen=True, slots=True)
class Blocker:
    """A required failure or unresolved result retained in canonical output."""

    check_id: str
    kind: BlockerKind
    status: CheckStatus
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.check_id, str) or not _CHECK_ID.fullmatch(
            self.check_id
        ):
            raise ValueError("blocker check_id must be lowercase dotted snake-case")
        if not isinstance(self.kind, BlockerKind):
            raise TypeError("kind must be a BlockerKind")
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be a CheckStatus")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("blocker reason_code must be uppercase snake-case")

    def sort_key(self) -> tuple[int, str, str]:
        precedence = {
            BlockerKind.KNOWN_FAILURE: 0,
            BlockerKind.MISSING_RESULT: 1,
            BlockerKind.UNRESOLVED: 1,
        }
        return (precedence[self.kind], self.check_id, self.reason_code)

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class GateAggregate:
    """The gate vector plus the independently-computed overall diagnostic."""

    decision: Decision
    complete: bool
    scores: ScoreAggregate
    blockers: tuple[Blocker, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            raise TypeError("decision must be a Decision")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a bool")
        if not isinstance(self.scores, ScoreAggregate):
            raise TypeError("scores must be a ScoreAggregate")
        if not isinstance(self.blockers, tuple) or any(
            not isinstance(item, Blocker) for item in self.blockers
        ):
            raise TypeError("blockers must be a tuple of Blocker")
        object.__setattr__(
            self,
            "blockers",
            tuple(sorted(self.blockers, key=Blocker.sort_key)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "complete": self.complete,
            **self.scores.to_dict(),
            "blockers": [item.to_dict() for item in self.blockers],
        }


@dataclass(frozen=True, slots=True)
class Subject:
    """Repository commit identity, including development-tree provenance."""

    repository: str
    commit_sha: str
    worktree: str
    patch_sha256: str | None = None
    untracked_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise ValueError("repository must be non-empty text")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("commit_sha must be a 40-char git SHA")
        if self.worktree not in {"clean", "dirty"}:
            raise ValueError("worktree must be clean or dirty")
        if self.worktree == "clean":
            if self.patch_sha256 is not None or self.untracked_sha256 is not None:
                raise ValueError("a clean subject cannot contain dirty-tree digests")
        else:
            if not isinstance(self.patch_sha256, str) or not _SHA256.fullmatch(
                self.patch_sha256
            ):
                raise ValueError("a dirty subject requires patch_sha256")
            if not isinstance(self.untracked_sha256, str) or not _SHA256.fullmatch(
                self.untracked_sha256
            ):
                raise ValueError("a dirty subject requires untracked_sha256")

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "worktree": self.worktree,
        }
        if self.worktree == "dirty":
            result["patch_sha256"] = self.patch_sha256
            result["untracked_sha256"] = self.untracked_sha256
        return result


@dataclass(frozen=True, slots=True)
class Producer:
    """Minimal producer identity required by the canonical v1 shape."""

    name: str
    version: str
    commit_sha: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("producer name must be non-empty text")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("producer version must be non-empty text")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("producer commit_sha must be a 40-char git SHA")

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "commit_sha": self.commit_sha,
        }


@dataclass(frozen=True, slots=True)
class Assessment:
    """Canonical assessment artifact whose exact bytes define its identity."""

    schema_version: str
    profile: Profile
    subject: Subject
    producer: Producer
    policy_id: str
    policy_sha256: str
    checks: tuple[AssessedCheck, ...]
    dimensions: tuple[DimensionAssessment, ...]
    aggregate: GateAggregate
    evidence: tuple[EvidenceArtifact, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {ASSESSMENT_SCHEMA_VERSION!r}")
        if not isinstance(self.profile, Profile):
            raise TypeError("profile must be a Profile")
        if not isinstance(self.subject, Subject):
            raise TypeError("subject must be a Subject")
        if not isinstance(self.producer, Producer):
            raise TypeError("producer must be a Producer")
        if not isinstance(self.policy_sha256, str) or not _SHA256.fullmatch(
            self.policy_sha256
        ):
            raise ValueError("policy_sha256 must be a 64-char sha256 hex string")
        if not isinstance(self.policy_id, str) or not _POLICY_ID.fullmatch(
            self.policy_id
        ):
            raise ValueError("policy_id must be lowercase kebab-case")
        if not isinstance(self.checks, tuple) or any(
            not isinstance(item, AssessedCheck) for item in self.checks
        ):
            raise TypeError("checks must be a tuple of AssessedCheck")
        check_ids = [item.id for item in self.checks]
        if len(set(check_ids)) != len(check_ids):
            raise ValueError("assessment check IDs must be unique")
        if not isinstance(self.dimensions, tuple) or any(
            not isinstance(item, DimensionAssessment) for item in self.dimensions
        ):
            raise TypeError("dimensions must be a tuple of DimensionAssessment")
        if tuple(item.id for item in self.dimensions) != DIMENSION_IDS:
            raise ValueError(
                "assessment must contain all dimensions in canonical order"
            )
        if not isinstance(self.aggregate, GateAggregate):
            raise TypeError("aggregate must be a GateAggregate")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, EvidenceArtifact) for item in self.evidence
        ):
            raise TypeError("evidence must be a tuple of EvidenceArtifact")
        evidence_ids = [item.id for item in self.evidence]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("assessment evidence IDs must be unique")
        object.__setattr__(
            self,
            "checks",
            tuple(sorted(self.checks, key=lambda item: item.id)),
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(self.evidence, key=EvidenceArtifact.sort_key)),
        )

    @property
    def exit_code(self) -> ExitCode:
        return decision_exit_code(self.aggregate.decision)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile.value,
            "subject": self.subject.to_dict(),
            "producer": self.producer.to_dict(),
            "policy": {"id": self.policy_id, "sha256": self.policy_sha256},
            "checks": [item.to_dict() for item in self.checks],
            "evidence": [item.to_dict() for item in self.evidence],
            "dimensions": [item.to_dict() for item in self.dimensions],
            "aggregate": self.aggregate.to_dict(),
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class RunEnvelope:
    """Volatile execution metadata bound to, but outside, an assessment."""

    subject_sha256: str
    started_at_utc: str
    finished_at_utc: str
    duration_ns: int
    host: Mapping[str, str]
    log_paths: tuple[str, ...]
    raw_evidence: tuple[RawEvidenceProvenance, ...] = ()
    schema_version: str = RUN_ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RUN_ENVELOPE_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {RUN_ENVELOPE_SCHEMA_VERSION!r}"
            )
        if not isinstance(self.subject_sha256, str) or not _SHA256.fullmatch(
            self.subject_sha256
        ):
            raise ValueError("subject_sha256 must be a 64-char sha256 hex string")
        for name in ("started_at_utc", "finished_at_utc"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty text")
        _validate_non_negative_int(self.duration_ns, "duration_ns")
        if not isinstance(self.host, Mapping) or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or not value
            for key, value in self.host.items()
        ):
            raise TypeError("host must map non-empty text keys to text values")
        object.__setattr__(self, "host", _FrozenTextMap.from_mapping(self.host))
        if not isinstance(self.log_paths, tuple) or any(
            not isinstance(item, str) or not item for item in self.log_paths
        ):
            raise TypeError("log_paths must be a tuple of non-empty text paths")
        object.__setattr__(self, "log_paths", tuple(sorted(self.log_paths)))
        if not isinstance(self.raw_evidence, tuple) or any(
            not isinstance(item, RawEvidenceProvenance) for item in self.raw_evidence
        ):
            raise TypeError("raw_evidence must be a tuple of RawEvidenceProvenance")
        raw_keys = [item.sort_key() for item in self.raw_evidence]
        if len(set(raw_keys)) != len(raw_keys):
            raise ValueError("run-envelope raw evidence entries must be unique")
        object.__setattr__(
            self,
            "raw_evidence",
            tuple(sorted(self.raw_evidence, key=RawEvidenceProvenance.sort_key)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "subject": {"sha256": self.subject_sha256},
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "duration_ns": self.duration_ns,
            "host": dict(self.host),
            "log_paths": list(self.log_paths),
            "raw_evidence": [item.to_dict() for item in self.raw_evidence],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())


def _canonical_json(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize the canonical compact UTF-8 representation used for identity."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_patch_sha256(patch: bytes) -> str:
    """Hash the exact bytes emitted by the engine's fixed canonical diff argv."""
    if not isinstance(patch, bytes):
        raise TypeError("patch must be bytes")
    return hashlib.sha256(patch).hexdigest()


def untracked_inputs_sha256(inputs: Mapping[str, bytes]) -> str:
    """Hash a sorted canonical manifest of untracked paths and content digests."""
    if not isinstance(inputs, Mapping):
        raise TypeError("inputs must map canonical paths to bytes")
    manifest: list[dict[str, object]] = []
    for path, content in inputs.items():
        _validate_canonical_path(path, "untracked path")
        if not isinstance(content, bytes):
            raise TypeError("untracked input content must be bytes")
        manifest.append(
            {
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    manifest.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


_CANONICAL_GIT_WORKTREE_CONFIG = (
    "-c",
    "core.quotePath=false",
    "-c",
    f"core.excludesFile={os.devnull}",
    "-c",
    "core.filemode=true",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.safecrlf=false",
    "-c",
    "core.eol=lf",
    "-c",
    f"core.attributesFile={os.devnull}",
    "-c",
    "filter.lfs.clean=",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.process=",
    "-c",
    "filter.lfs.required=false",
)


class _GitCommand(Enum):
    """Engine-owned Git argv; policy and callers can select no command text."""

    REPOSITORY = ("git", "remote", "get-url", "origin")
    COMMIT = ("git", "rev-parse", "--verify", "HEAD")
    STATUS = (
        "git",
        *_CANONICAL_GIT_WORKTREE_CONFIG,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    PATCH = (
        "git",
        *_CANONICAL_GIT_WORKTREE_CONFIG,
        "-c",
        "color.ui=false",
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--diff-algorithm=myers",
        "--no-indent-heuristic",
        "--ignore-submodules=none",
        "--submodule=short",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "HEAD",
        "--",
    )
    UNTRACKED = (
        "git",
        "-c",
        "core.quotePath=false",
        "-c",
        f"core.excludesFile={os.devnull}",
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )


def _sanitized_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_fixed_git(root: Path, command: _GitCommand) -> bytes:
    import subprocess

    completed = subprocess.run(
        command.value,
        cwd=str(root),
        shell=False,
        check=False,
        capture_output=True,
        env=_sanitized_git_environment(),
    )
    if completed.returncode != 0:
        raise ValueError(
            f"fixed git command {command.name.lower()} failed with exit "
            f"{completed.returncode}"
        )
    if not isinstance(completed.stdout, bytes):
        raise TypeError("fixed git command stdout must be bytes")
    return completed.stdout


def _single_utf8_line(value: bytes, name: str) -> str:
    try:
        decoded = value.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must be UTF-8") from exc
    if not decoded or "\n" in decoded or "\r" in decoded:
        raise ValueError(f"{name} must contain exactly one non-empty line")
    return decoded


def _read_untracked_inputs(root: Path, encoded_paths: bytes) -> dict[str, bytes]:
    inputs: dict[str, bytes] = {}
    for encoded_path in encoded_paths.split(b"\0"):
        if not encoded_path:
            continue
        try:
            path = encoded_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("untracked paths must be UTF-8") from exc
        _validate_canonical_path(path, "untracked path")
        local_path = root / Path(*PurePosixPath(path).parts)
        if local_path.is_symlink():
            content = os.fsencode(os.readlink(local_path))
        else:
            if not local_path.is_file():
                raise ValueError(f"untracked input is not a regular file: {path}")
            content = local_path.read_bytes()
        inputs[path] = content
    return inputs


def subject_from_repository(
    root: str | Path,
    *,
    repository: str | None = None,
) -> Subject:
    """Read subject identity with fixed Git argv and no import-time execution."""
    if not isinstance(root, (str, Path)):
        raise TypeError("root must be text or Path")
    repository_root = Path(root).resolve()
    if not repository_root.is_dir():
        raise ValueError("root must be an existing directory")
    if repository is not None and (
        not isinstance(repository, str) or not repository.strip()
    ):
        raise ValueError("repository must be non-empty text or None")
    if repository is None:
        try:
            repository_url = _single_utf8_line(
                _run_fixed_git(repository_root, _GitCommand.REPOSITORY),
                "repository URL",
            )
        except ValueError as exc:
            raise ValueError(
                "origin repository URL is unavailable; pass the repository= keyword"
            ) from exc
    else:
        repository_url = repository
    commit_sha = _single_utf8_line(
        _run_fixed_git(repository_root, _GitCommand.COMMIT),
        "commit SHA",
    )
    status = _run_fixed_git(repository_root, _GitCommand.STATUS)
    if not status:
        return Subject(
            repository=repository_url,
            commit_sha=commit_sha,
            worktree="clean",
        )
    patch = _run_fixed_git(repository_root, _GitCommand.PATCH)
    untracked_paths = _run_fixed_git(repository_root, _GitCommand.UNTRACKED)
    untracked_inputs = _read_untracked_inputs(repository_root, untracked_paths)
    return Subject(
        repository=repository_url,
        commit_sha=commit_sha,
        worktree="dirty",
        patch_sha256=canonical_patch_sha256(patch),
        untracked_sha256=untracked_inputs_sha256(untracked_inputs),
    )


def _sanitized_collector_environment(root: Path) -> dict[str, str]:
    """Return the fixed, credential-free environment for offline collectors."""
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(root / "src"),
        "PYTHONUTF8": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TZ": "UTC",
    }


_JUNIT_VOLATILE_ATTRIBUTES = frozenset(
    {"timestamp", "hostname", "time", "duration"}
)


def _canonicalize_pytest_junit(content: bytes) -> bytes:
    """Return C14N XML with only collector-runtime attributes removed."""
    if len(content) > _MAX_JUNIT_BYTES:
        raise ValueError("JUnit artifact exceeds the fixed size limit")
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("JUnit artifact must not contain DTD or entity declarations")
    try:
        root = ElementTree.fromstring(content)
    except (ElementTree.ParseError, ValueError) as exc:
        raise ValueError("JUnit artifact is malformed XML") from exc
    for element in root.iter():
        for attribute in tuple(element.attrib):
            if _xml_local_name(attribute) in _JUNIT_VOLATILE_ATTRIBUTES:
                del element.attrib[attribute]
    serialized = ElementTree.tostring(root, encoding="unicode")
    return ElementTree.canonicalize(serialized).encode("utf-8")


def _normalized_evidence_artifact(
    *,
    id: str,
    path: str,
    raw_content: bytes,
    canonical_content: bytes,
    normalization: str,
    command: CommandExecution | None = None,
) -> EvidenceArtifact:
    """Bind canonical evaluation bytes and exact raw bytes without conflating them."""
    return EvidenceArtifact(
        id=id,
        path=path,
        sha256=hashlib.sha256(canonical_content).hexdigest(),
        content=canonical_content,
        command=command,
        normalization=normalization,
        raw_sha256=hashlib.sha256(raw_content).hexdigest(),
        raw_content=raw_content,
    )


def _pytest_collector_artifact(
    *, content: bytes, process_exit: int, reason_code: str
) -> EvidenceArtifact:
    command = CommandExecution(
        argv=ADR001_OFFLINE_GATE_ARGV,
        process_exit=process_exit,
        collector_reason_code=reason_code,
    )
    try:
        canonical = _canonicalize_pytest_junit(content)
    except ValueError:
        return EvidenceArtifact(
            id="engine.pytest-junit",
            path=_PYTEST_JUNIT_PATH,
            sha256=hashlib.sha256(content).hexdigest(),
            content=content,
            command=command,
        )
    return _normalized_evidence_artifact(
        id="engine.pytest-junit",
        path=_PYTEST_JUNIT_PATH,
        raw_content=content,
        canonical_content=canonical,
        normalization="pytest-junit-volatile-v1",
        command=command,
    )


def _discard_pytest_junit(path: Path) -> None:
    """Best-effort cleanup; callers still return empty error evidence on failure."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # A path that cannot be removed is never read by the current run.  A
        # later run must remove it successfully before starting pytest, or it
        # also returns COLLECTOR_FILESYSTEM_ERROR without reading stale bytes.
        pass


def collect_adr001_pytest_junit(root: str | Path) -> EvidenceArtifact:
    """Execute ADR-001's cumulative offline gate and collect its JUnit XML.

    The test paths are copied verbatim from ADR-001.  Only deterministic
    collector options are appended.  Neither policy nor callers can supply
    command text or an output path.
    """
    import subprocess

    if not isinstance(root, (str, Path)):
        raise TypeError("root must be text or Path")
    repository_root = Path(root).resolve()
    if not repository_root.is_dir():
        raise ValueError("root must be an existing directory")
    output_path = repository_root / Path(*PurePosixPath(_PYTEST_JUNIT_PATH).parts)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.unlink(missing_ok=True)
    except OSError:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"",
            process_exit=-1,
            reason_code="COLLECTOR_FILESYSTEM_ERROR",
        )
    try:
        completed = subprocess.run(
            ADR001_OFFLINE_GATE_ARGV,
            cwd=str(repository_root),
            shell=False,
            check=False,
            capture_output=True,
            env=_sanitized_collector_environment(repository_root),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"", process_exit=-1, reason_code="COLLECTOR_TIMEOUT"
        )
    except OSError:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"",
            process_exit=-1,
            reason_code="COLLECTOR_EXECUTION_ERROR",
        )
    try:
        if not output_path.is_file():
            return _pytest_collector_artifact(
                content=b"",
                process_exit=completed.returncode,
                reason_code="COLLECTOR_ARTIFACT_MISSING",
            )
        content = output_path.read_bytes()
    except OSError:
        _discard_pytest_junit(output_path)
        return _pytest_collector_artifact(
            content=b"",
            process_exit=completed.returncode,
            reason_code="COLLECTOR_FILESYSTEM_ERROR",
        )
    return _pytest_collector_artifact(
        content=content,
        process_exit=completed.returncode,
        reason_code="COLLECTOR_COMPLETE",
    )


def _artifact_references(
    artifacts: Iterable[EvidenceArtifact],
) -> tuple[Mapping[str, str], ...]:
    return tuple(
        {"kind": "artifact", "value": artifact.id} for artifact in artifacts
    )


def _error_result(
    check_id: str,
    reason_code: str,
    artifacts: tuple[EvidenceArtifact, ...],
    *,
    status: CheckStatus = CheckStatus.ERROR,
) -> CheckResult:
    if status not in {CheckStatus.ERROR, CheckStatus.UNKNOWN, CheckStatus.SKIPPED}:
        raise ValueError("unresolved result helper requires an unresolved status")
    return CheckResult(
        id=check_id,
        status=status,
        score_bps=None,
        reason_code=reason_code,
        evidence=_artifact_references(artifacts),
    )


def _binary_result(
    check_id: str,
    passed: bool,
    *,
    pass_reason: str,
    fail_reason: str,
    artifacts: tuple[EvidenceArtifact, ...] = (),
    numerator: int = 1,
    denominator: int = 1,
) -> CheckResult:
    return CheckResult(
        id=check_id,
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        score_bps=10000 if passed else 0,
        reason_code=pass_reason if passed else fail_reason,
        numerator=numerator if passed else 0,
        denominator=denominator,
        evidence=_artifact_references(artifacts),
    )


def _xml_local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _junit_count(element: ElementTree.Element, name: str) -> int:
    raw = element.get(name)
    if raw is None or not raw.isascii() or not raw.isdecimal():
        raise ValueError(f"JUnit testsuite {name} must be a non-negative integer")
    return int(raw)


def _pytest_junit_counts(content: bytes) -> tuple[int, int, int, int]:
    if len(content) > _MAX_JUNIT_BYTES:
        raise ValueError("JUnit artifact exceeds the fixed size limit")
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("JUnit artifact must not contain DTD or entity declarations")
    try:
        root = ElementTree.fromstring(content)
    except (ElementTree.ParseError, ValueError) as exc:
        raise ValueError("JUnit artifact is malformed XML") from exc
    root_name = _xml_local_name(root.tag)
    if root_name == "testsuite":
        suites = (root,)
    elif root_name == "testsuites":
        suites = tuple(
            item for item in root if _xml_local_name(item.tag) == "testsuite"
        )
    else:
        raise ValueError("JUnit root must be testsuite or testsuites")
    if not suites:
        raise ValueError("JUnit artifact contains no testsuite")

    declared = tuple(
        sum(_junit_count(suite, name) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    )
    tests, failures, errors, skipped = declared
    if failures + errors + skipped > tests:
        raise ValueError("JUnit outcome counts exceed collected tests")

    cases = tuple(
        item
        for suite in suites
        for item in suite.iter()
        if _xml_local_name(item.tag) == "testcase"
    )
    case_failures = 0
    case_errors = 0
    case_skipped = 0
    for case in cases:
        outcomes = [_xml_local_name(item.tag) for item in case]
        case_failures += outcomes.count("failure")
        case_errors += outcomes.count("error")
        case_skipped += outcomes.count("skipped")
        if sum(name in {"failure", "error", "skipped"} for name in outcomes) > 1:
            raise ValueError("JUnit testcase contains multiple terminal outcomes")
    if (len(cases), case_failures, case_errors, case_skipped) != declared:
        raise ValueError("JUnit declared counts do not match testcase outcomes")
    return declared


def evaluate_pytest_junit(artifact: EvidenceArtifact) -> CheckResult:
    """Require a fixed-command, nonempty, green ADR-001 pytest run."""
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    artifacts = (artifact,)
    if (
        artifact.command is None
        or artifact.command.argv != ADR001_OFFLINE_GATE_ARGV
    ):
        return _error_result(
            "engine.offline_contracts", "PYTEST_COMMAND_PROVENANCE_INVALID", artifacts
        )
    if artifact.command.collector_reason_code != "COLLECTOR_COMPLETE":
        return _error_result(
            "engine.offline_contracts",
            artifact.command.collector_reason_code,
            artifacts,
        )
    try:
        tests, failures, errors, skipped = _pytest_junit_counts(artifact.content)
    except ValueError:
        return _error_result(
            "engine.offline_contracts", "PYTEST_JUNIT_MALFORMED", artifacts
        )
    if tests == 0:
        return _binary_result(
            "engine.offline_contracts",
            False,
            pass_reason="PYTEST_GREEN_NONZERO",
            fail_reason="PYTEST_ZERO_TESTS_COLLECTED",
            artifacts=artifacts,
        )
    passed = tests - failures - errors - skipped
    skip_exclusions = (("PYTEST_SKIPPED", skipped),) if skipped else ()
    process_exit = artifact.command.process_exit
    if failures or errors or process_exit == 1:
        return CheckResult(
            id="engine.offline_contracts",
            status=CheckStatus.FAIL,
            score_bps=proportional_score_bps(passed, tests),
            reason_code=(
                "PYTEST_TEST_FAILURES"
                if failures or errors
                else "PYTEST_NON_GREEN_EXIT"
            ),
            numerator=passed,
            denominator=tests,
            exclusions=skip_exclusions,
            evidence=_artifact_references(artifacts),
        )
    if process_exit != 0:
        return _error_result(
            "engine.offline_contracts", "PYTEST_EXECUTION_ERROR", artifacts
        )
    if skipped == tests:
        return CheckResult(
            id="engine.offline_contracts",
            status=CheckStatus.SKIPPED,
            score_bps=None,
            reason_code="PYTEST_ALL_TESTS_SKIPPED",
            numerator=0,
            denominator=tests,
            exclusions=skip_exclusions,
            evidence=_artifact_references(artifacts),
        )
    if skipped:
        return CheckResult(
            id="engine.offline_contracts",
            status=CheckStatus.FAIL,
            score_bps=proportional_score_bps(passed, tests),
            reason_code="PYTEST_TESTS_SKIPPED",
            numerator=passed,
            denominator=tests,
            exclusions=skip_exclusions,
            evidence=_artifact_references(artifacts),
        )
    return CheckResult(
        id="engine.offline_contracts",
        status=CheckStatus.PASS,
        score_bps=10000,
        reason_code="PYTEST_GREEN_NONZERO",
        numerator=passed,
        denominator=tests,
        exclusions=skip_exclusions,
        evidence=_artifact_references(artifacts),
    )


def _load_json_object(artifact: EvidenceArtifact, name: str) -> Mapping[str, object]:
    def reject_constant(value: str) -> object:
        raise ValueError(f"{name} contains non-finite number {value}")

    try:
        decoded = json.loads(artifact.content, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{name} is not strict JSON") from exc
    if not isinstance(decoded, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    return decoded


def _object_keys(raw: object, keys: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{name} must be an object")
    if set(raw) != keys:
        raise ValueError(f"{name} has an invalid field set")
    return raw


def _list_value(raw: object, name: str, *, nonempty: bool = False) -> list[object]:
    if not isinstance(raw, list) or (nonempty and not raw):
        qualifier = "a nonempty" if nonempty else "a"
        raise ValueError(f"{name} must be {qualifier} list")
    return raw


def _non_negative_json_int(value: object, name: str) -> int:
    if not _is_int(value) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _finite_json_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a JSON number")
    decimal = Decimal(str(value))
    if not decimal.is_finite():
        raise ValueError(f"{name} must be finite")
    return decimal


def _benchmark_tasks(artifact: EvidenceArtifact) -> list[object]:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark run"),
        {"schema_version", "benchmark", "tasks"},
        "benchmark run",
    )
    if raw["schema_version"] != "leitir-benchmark-run-v1":
        raise ValueError("benchmark run schema version is unsupported")
    return _list_value(raw["tasks"], "benchmark tasks", nonempty=True)


def evaluate_deterministic_replay(
    artifacts: tuple[EvidenceArtifact, ...],
) -> CheckResult:
    """Compare baseline, repeated, and input-permuted canonical run bytes."""
    if not isinstance(artifacts, tuple) or any(
        not isinstance(item, EvidenceArtifact) for item in artifacts
    ):
        raise TypeError("artifacts must be a tuple of EvidenceArtifact")
    if len(artifacts) != 3:
        return _error_result(
            "engine.deterministic_replay", "REPLAY_EVIDENCE_INCOMPLETE", artifacts
        )
    return _binary_result(
        "engine.deterministic_replay",
        artifacts[0].content == artifacts[1].content == artifacts[2].content,
        pass_reason="REPLAY_AND_PERMUTATION_IDENTICAL",
        fail_reason="NONDETERMINISTIC_OUTPUT",
        artifacts=artifacts,
    )


def _source_identity_from_result(result: object) -> tuple[str, str, str, str, int, int]:
    result_raw = _object_keys(
        result,
        {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"},
        "ranked result",
    )
    source = _object_keys(
        result_raw["source"],
        {"slug", "commit_sha", "path", "blob_sha", "start_line", "end_line", "permalink"},
        "result source",
    )
    start_line = _non_negative_json_int(source["start_line"], "start_line")
    end_line = _non_negative_json_int(source["end_line"], "end_line")
    if start_line < 1 or end_line < start_line:
        raise ValueError("result source line span is invalid")
    values = (
        source["slug"],
        source["commit_sha"],
        source["path"],
        source["blob_sha"],
    )
    if any(not isinstance(value, str) for value in values):
        raise ValueError("result source identity fields must be text")
    return (*values, start_line, end_line)


def _total_order_is_valid(artifact: EvidenceArtifact) -> bool:
    tasks = _benchmark_tasks(artifact)
    task_ids: list[str] = []
    for task in tasks:
        task_raw = _object_keys(
            task,
            {"task_id", "language", "spec_digest", "coverage", "results"},
            "benchmark task",
        )
        task_id = task_raw["task_id"]
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise ValueError("task_id must be lowercase kebab-case")
        task_ids.append(task_id)
        results = _list_value(task_raw["results"], "ranked results")
        decorated: list[tuple[tuple[object, ...], int, int]] = []
        identities: list[tuple[str, str, str, str, int, int]] = []
        for result in results:
            result_raw = _object_keys(
                result,
                {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"},
                "ranked result",
            )
            _finite_json_decimal(result_raw["score"], "score")
            normalized = _finite_json_decimal(
                result_raw["normalized_score"], "normalized_score"
            )
            if not Decimal(0) <= normalized <= Decimal(1):
                raise ValueError("normalized_score must be within zero and one")
            identity = _source_identity_from_result(result)
            rank = _non_negative_json_int(result_raw["rank"], "rank")
            rank_score = _non_negative_json_int(result_raw["rank_score"], "rank_score")
            identities.append(identity)
            decorated.append(((-normalized, *identity), rank, rank_score))
        if len(set(identities)) != len(identities):
            return False
        expected_keys = sorted(item[0] for item in decorated)
        if [item[0] for item in decorated] != expected_keys:
            return False
        count = len(decorated)
        if [item[1] for item in decorated] != list(range(1, count + 1)):
            return False
        if [item[2] for item in decorated] != list(range(count, 0, -1)):
            return False
    return task_ids == sorted(task_ids) and len(set(task_ids)) == len(task_ids)


def evaluate_total_ordering(artifact: EvidenceArtifact) -> CheckResult:
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        passed = _total_order_is_valid(artifact)
    except ValueError:
        return _error_result("engine.total_ordering", "RANKED_RUN_MALFORMED", (artifact,))
    return _binary_result(
        "engine.total_ordering",
        passed,
        pass_reason="ADR001_TOTAL_ORDER_VALID",
        fail_reason="ADR001_TOTAL_ORDER_INVALID",
        artifacts=(artifact,),
    )


def _result_provenance_is_valid(artifact: EvidenceArtifact) -> bool:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark run"),
        {"schema_version", "benchmark", "tasks"},
        "benchmark run",
    )
    if raw["schema_version"] != "leitir-benchmark-run-v1":
        raise ValueError("benchmark run schema version is unsupported")
    benchmark = _object_keys(
        raw["benchmark"], {"id", "manifest_sha256"}, "benchmark identity"
    )
    if not isinstance(benchmark["id"], str) or not benchmark["id"]:
        raise ValueError("benchmark ID must be non-empty text")
    if not isinstance(benchmark["manifest_sha256"], str) or not _SHA256.fullmatch(
        benchmark["manifest_sha256"]
    ):
        raise ValueError("benchmark manifest digest is invalid")
    tasks = _list_value(raw["tasks"], "benchmark tasks", nonempty=True)
    for task in tasks:
        task_raw = _object_keys(
            task,
            {"task_id", "language", "spec_digest", "coverage", "results"},
            "benchmark task",
        )
        if not isinstance(task_raw["task_id"], str) or not _TASK_ID.fullmatch(
            task_raw["task_id"]
        ):
            raise ValueError("task_id must be lowercase kebab-case")
        if task_raw["language"] not in {"python", "rust", "go"}:
            raise ValueError("task language is invalid")
        if not isinstance(task_raw["spec_digest"], str) or not _SHA256.fullmatch(
            task_raw["spec_digest"]
        ):
            raise ValueError("task spec digest is invalid")
        for result in _list_value(task_raw["results"], "ranked results"):
            identity = _source_identity_from_result(result)
            slug, commit_sha, path, blob_sha, start_line, end_line = identity
            if not _REPO_SLUG.fullmatch(slug):
                raise ValueError("result repository slug is invalid")
            if not _SHA1.fullmatch(commit_sha) or not _SHA1.fullmatch(blob_sha):
                raise ValueError("result commit or blob provenance is invalid")
            _validate_canonical_path(path, "result source path")
            result_raw = _object_keys(
                result,
                {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"},
                "ranked result",
            )
            source = result_raw["source"]
            expected_permalink = (
                f"https://github.com/{slug}/blob/{commit_sha}/{path}"
                f"#L{start_line}-L{end_line}"
            )
            if source["permalink"] != expected_permalink:
                return False
            matched_kinds = result_raw["matched_kinds"]
            if not isinstance(matched_kinds, list) or not matched_kinds or any(
                not isinstance(item, str) or not item for item in matched_kinds
            ):
                raise ValueError("matched_kinds must be a nonempty text list")
    return True


def evaluate_result_provenance(artifact: EvidenceArtifact) -> CheckResult:
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        passed = _result_provenance_is_valid(artifact)
    except ValueError:
        return _error_result(
            "engine.result_provenance", "RESULT_PROVENANCE_MALFORMED", (artifact,)
        )
    return _binary_result(
        "engine.result_provenance",
        passed,
        pass_reason="RESULT_PROVENANCE_VALID",
        fail_reason="RESULT_PROVENANCE_MISMATCH",
        artifacts=(artifact,),
    )


def _coverage(raw: object) -> tuple[str, int, int, int, bool]:
    coverage = _object_keys(
        raw,
        {"status", "files_eligible", "files_indexed", "files_excluded", "incomplete_results"},
        "coverage",
    )
    status = coverage["status"]
    if not isinstance(status, str):
        raise ValueError("coverage status must be text")
    eligible = _non_negative_json_int(coverage["files_eligible"], "files_eligible")
    indexed = _non_negative_json_int(coverage["files_indexed"], "files_indexed")
    excluded = _non_negative_json_int(coverage["files_excluded"], "files_excluded")
    incomplete = coverage["incomplete_results"]
    if not isinstance(incomplete, bool) or indexed > eligible:
        raise ValueError("coverage counters or incomplete flag are invalid")
    return status, eligible, indexed, excluded, incomplete


def _scoped_coverage_is_valid(artifact: EvidenceArtifact) -> bool:
    for task in _benchmark_tasks(artifact):
        task_raw = _object_keys(
            task,
            {"task_id", "language", "spec_digest", "coverage", "results"},
            "benchmark task",
        )
        status, eligible, indexed, _excluded, incomplete = _coverage(
            task_raw["coverage"]
        )
        if (
            status != "complete_for_declared_universe"
            or indexed != eligible
            or incomplete
        ):
            return False
    return True


def evaluate_scoped_coverage(artifact: EvidenceArtifact) -> CheckResult:
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        passed = _scoped_coverage_is_valid(artifact)
    except ValueError:
        return _error_result(
            "engine.scoped_coverage", "SCOPED_COVERAGE_MALFORMED", (artifact,)
        )
    return _binary_result(
        "engine.scoped_coverage",
        passed,
        pass_reason="DECLARED_UNIVERSE_COMPLETE",
        fail_reason="DECLARED_UNIVERSE_PARTIAL",
        artifacts=(artifact,),
    )


def evaluate_global_no_exhaustiveness(artifact: EvidenceArtifact) -> CheckResult:
    """Require dedicated global evidence to retain INDETERMINATE_GLOBAL."""
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        raw = _object_keys(
            _load_json_object(artifact, "global search report"),
            {"spec_digest", "coverage", "matches"},
            "global search report",
        )
        if not isinstance(raw["spec_digest"], str) or not _SHA256.fullmatch(
            raw["spec_digest"]
        ):
            raise ValueError("global search spec digest is invalid")
        _list_value(raw["matches"], "global matches")
        status, _eligible, _indexed, _excluded, _incomplete = _coverage(
            raw["coverage"]
        )
    except ValueError:
        return _error_result(
            "engine.global_no_exhaustiveness",
            "GLOBAL_COVERAGE_MALFORMED",
            (artifact,),
        )
    if status == "complete_for_declared_universe":
        reason = "GLOBAL_EXHAUSTIVENESS_OVERCLAIM"
    else:
        reason = "GLOBAL_COVERAGE_NOT_INDETERMINATE"
    return _binary_result(
        "engine.global_no_exhaustiveness",
        status == "indeterminate_global",
        pass_reason="INDETERMINATE_GLOBAL_PRESERVED",
        fail_reason=reason,
        artifacts=(artifact,),
    )


def evaluate_retired_surfaces_absent(root: str | Path) -> CheckResult:
    """Fail if any retired v1 top-level module remains importable from src."""
    if not isinstance(root, (str, Path)):
        raise TypeError("root must be text or Path")
    module_root = Path(root).resolve() / "src" / "leitir"
    try:
        children = tuple(module_root.iterdir())
    except OSError:
        return _error_result(
            "engine.retired_surfaces_absent", "RETIRED_SURFACE_SCOPE_UNREADABLE", ()
        )
    import_suffixes = tuple(machinery.all_suffixes()) + (".pyi",)
    repository_root = Path(root).resolve()
    present = sorted(
        child.relative_to(repository_root).as_posix()
        for child in children
        for module in _RETIRED_V1_MODULES
        if (child.is_dir() and child.name == module)
        or (child.is_file() and child.name in {f"{module}{suffix}" for suffix in import_suffixes})
    )
    evidence = (
        {"kind": "scope", "value": "src/leitir top-level import surfaces"},
        {
            "kind": "retired_modules",
            "value": ",".join(_RETIRED_V1_MODULES),
        },
    )
    return CheckResult(
        id="engine.retired_surfaces_absent",
        status=CheckStatus.PASS if not present else CheckStatus.FAIL,
        score_bps=10000 if not present else 0,
        reason_code=(
            "RETIRED_SURFACES_ABSENT" if not present else "RETIRED_SURFACES_PRESENT"
        ),
        numerator=1 if not present else 0,
        denominator=1,
        evidence=evidence
        + tuple({"kind": "present_surface", "value": item} for item in present),
    )


def evaluate_engine_correctness_evidence(
    *,
    pytest_junit: EvidenceArtifact,
    replay_artifacts: tuple[EvidenceArtifact, ...],
    global_report: EvidenceArtifact,
    repository_root: str | Path,
) -> tuple[CheckResult, ...]:
    """Evaluate the complete ADR-002 S3 engine-correctness check vector."""
    primary_run = replay_artifacts[0] if replay_artifacts else None
    if primary_run is None:
        artifact_checks = (
            _error_result("engine.total_ordering", "RANKED_RUN_MISSING", ()),
            _error_result("engine.result_provenance", "RANKED_RUN_MISSING", ()),
            _error_result("engine.scoped_coverage", "RANKED_RUN_MISSING", ()),
        )
    else:
        artifact_checks = (
            evaluate_total_ordering(primary_run),
            evaluate_result_provenance(primary_run),
            evaluate_scoped_coverage(primary_run),
        )
    return tuple(
        sorted(
            (
                evaluate_pytest_junit(pytest_junit),
                evaluate_deterministic_replay(replay_artifacts),
                *artifact_checks,
                evaluate_global_no_exhaustiveness(global_report),
                evaluate_retired_surfaces_absent(repository_root),
            ),
            key=lambda item: item.id,
        )
    )


@dataclass(frozen=True, slots=True)
class ScopeApplicability:
    """A versioned N/A predicate and its human-auditable evidence."""

    state: str
    evidence: str

    def __post_init__(self) -> None:
        if self.state not in {"expected", "proven_none"}:
            raise ValueError("scope applicability state must be expected or proven_none")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("scope applicability requires non-empty evidence")

    def to_dict(self) -> dict[str, str]:
        return {"state": self.state, "evidence": self.evidence}


@dataclass(frozen=True, slots=True)
class DeclaredCodeScope:
    """Explicit production/generated/vendored/fixture measurement universes."""

    scopes: Mapping[str, tuple[str, ...]]
    applicability: Mapping[str, ScopeApplicability]

    def __post_init__(self) -> None:
        if set(self.scopes) != set(_SCOPE_KINDS):
            raise ValueError("code scope must explicitly declare all four scope kinds")
        normalized_scopes: dict[str, tuple[str, ...]] = {}
        all_paths: list[str] = []
        for kind in _SCOPE_KINDS:
            paths = self.scopes[kind]
            if not isinstance(paths, tuple):
                raise TypeError(f"{kind} scope must be a tuple")
            for path in paths:
                _validate_canonical_path(path, f"{kind} scope path")
            if len(set(paths)) != len(paths):
                raise ValueError(f"{kind} scope paths must be unique")
            normalized_scopes[kind] = tuple(sorted(paths))
            all_paths.extend(paths)
        if len(set(all_paths)) != len(all_paths):
            raise ValueError("declared scope paths must not overlap")
        if set(self.applicability) != set(_APPLICABILITY_KINDS) or any(
            not isinstance(item, ScopeApplicability)
            for item in self.applicability.values()
        ):
            raise ValueError("scope must declare statements, branches, and mutants applicability")
        object.__setattr__(self, "scopes", _FrozenTupleMap(normalized_scopes))
        object.__setattr__(
            self,
            "applicability",
            _FrozenApplicabilityMap(self.applicability),
        )

    @property
    def production(self) -> tuple[str, ...]:
        return self.scopes["production"]

    @property
    def all_paths(self) -> tuple[str, ...]:
        return tuple(sorted(path for paths in self.scopes.values() for path in paths))

    def to_dict(self) -> dict[str, object]:
        return {
            "scopes": {kind: list(self.scopes[kind]) for kind in _SCOPE_KINDS},
            "applicability": {
                kind: self.applicability[kind].to_dict()
                for kind in _APPLICABILITY_KINDS
            },
        }


@dataclass(frozen=True, slots=True)
class _FrozenTupleMap(Mapping[str, tuple[str, ...]]):
    entries: tuple[tuple[str, tuple[str, ...]], ...]

    def __init__(self, value: Mapping[str, tuple[str, ...]]) -> None:
        object.__setattr__(self, "entries", tuple(sorted(value.items())))

    def __getitem__(self, key: str) -> tuple[str, ...]:
        return dict(self.entries)[key]

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.entries)

    def __len__(self) -> int:
        return len(self.entries)


@dataclass(frozen=True, slots=True)
class _FrozenApplicabilityMap(Mapping[str, ScopeApplicability]):
    entries: tuple[tuple[str, ScopeApplicability], ...]

    def __init__(self, value: Mapping[str, ScopeApplicability]) -> None:
        object.__setattr__(self, "entries", tuple(sorted(value.items())))

    def __getitem__(self, key: str) -> ScopeApplicability:
        return dict(self.entries)[key]

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.entries)

    def __len__(self) -> int:
        return len(self.entries)


@dataclass(frozen=True, slots=True)
class ComplexityReport:
    file_count: int
    parsed_file_count: int
    unmeasured_files: tuple[str, ...]
    parse_error_files: tuple[str, ...]
    block_count: int
    maximum: int | None
    mean_milli: int | None
    distribution: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "file_count": self.file_count,
            "parsed_file_count": self.parsed_file_count,
            "measurement_coverage": {
                "numerator": self.parsed_file_count,
                "denominator": self.file_count,
            },
            "unmeasured_files": list(self.unmeasured_files),
            "parse_error_files": list(self.parse_error_files),
            "block_count": self.block_count,
            "maximum": self.maximum,
            "mean_milli": self.mean_milli,
            "distribution": dict(self.distribution),
        }


@dataclass(frozen=True, slots=True)
class MaintainabilityIndexReport:
    measured_file_count: int
    missing_files: tuple[str, ...]
    error_files: tuple[str, ...]
    minimum_bps: int | None
    maximum_bps: int | None
    mean_bps: int | None
    distribution: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "diagnostic_only": True,
            "measured_file_count": self.measured_file_count,
            "missing_files": list(self.missing_files),
            "error_files": list(self.error_files),
            "minimum_bps": self.minimum_bps,
            "maximum_bps": self.maximum_bps,
            "mean_bps": self.mean_bps,
            "distribution": dict(self.distribution),
        }


@dataclass(frozen=True, slots=True)
class CodeHealthEvaluation:
    scope: DeclaredCodeScope
    complexity: ComplexityReport
    maintainability_index: MaintainabilityIndexReport
    checks: tuple[CheckResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope.to_dict(),
            "complexity": self.complexity.to_dict(),
            "maintainability_index": self.maintainability_index.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CoverageReport:
    declared_file_count: int
    measured_file_count: int
    unmeasured_files: tuple[str, ...]
    lines_covered: int
    lines_total: int
    branches_covered: int
    branches_total: int
    per_scope_coverage: tuple[tuple[str, tuple[int, int]], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "declared_file_count": self.declared_file_count,
            "measured_file_count": self.measured_file_count,
            "measurement_coverage": {
                "numerator": self.measured_file_count,
                "denominator": self.declared_file_count,
            },
            "unmeasured_files": list(self.unmeasured_files),
            "lines": {"covered": self.lines_covered, "total": self.lines_total},
            "branches": {
                "covered": self.branches_covered,
                "total": self.branches_total,
            },
            "per_scope_measurement_coverage": {
                kind: {"numerator": counts[0], "denominator": counts[1]}
                for kind, counts in self.per_scope_coverage
            },
        }


@dataclass(frozen=True, slots=True)
class MutationReport:
    counts: tuple[tuple[str, int], ...]
    completed_valid_mutants: int
    unresolved_mutants: int
    excluded_mutants: int

    def to_dict(self) -> dict[str, object]:
        return {
            "counts": dict(self.counts),
            "completed_valid_mutants": self.completed_valid_mutants,
            "unresolved_mutants": self.unresolved_mutants,
            "excluded_mutants": self.excluded_mutants,
        }


@dataclass(frozen=True, slots=True)
class TestAdequacyEvaluation:
    scope: DeclaredCodeScope
    coverage: CoverageReport
    mutation: MutationReport
    checks: tuple[CheckResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope.to_dict(),
            "coverage": self.coverage.to_dict(),
            "mutation": self.mutation.to_dict(),
        }


def _declared_code_scope(artifact: EvidenceArtifact) -> DeclaredCodeScope:
    raw = _object_keys(
        _load_json_object(artifact, "code scope"),
        {"schema_version", "scopes", "applicability"},
        "code scope",
    )
    if raw["schema_version"] != _CODE_SCOPE_SCHEMA_VERSION:
        raise ValueError("code scope schema version is unsupported")
    scopes_raw = _object_keys(raw["scopes"], set(_SCOPE_KINDS), "code scopes")
    scopes: dict[str, tuple[str, ...]] = {}
    for kind in _SCOPE_KINDS:
        paths = _list_value(scopes_raw[kind], f"{kind} scope")
        if any(not isinstance(path, str) for path in paths):
            raise ValueError(f"{kind} scope paths must be text")
        scopes[kind] = tuple(paths)
    applicability_raw = _object_keys(
        raw["applicability"], set(_APPLICABILITY_KINDS), "scope applicability"
    )
    applicability: dict[str, ScopeApplicability] = {}
    for kind in _APPLICABILITY_KINDS:
        item = _object_keys(
            applicability_raw[kind], {"state", "evidence"}, f"{kind} applicability"
        )
        applicability[kind] = ScopeApplicability(
            state=item["state"], evidence=item["evidence"]
        )
    return DeclaredCodeScope(scopes=scopes, applicability=applicability)


def _score_tool_versions(artifact: EvidenceArtifact) -> Mapping[str, str]:
    raw = _object_keys(
        _load_json_object(artifact, "score tool versions"),
        {"schema_version", "tools"},
        "score tool versions",
    )
    if raw["schema_version"] != _SCORE_TOOL_VERSIONS_SCHEMA_VERSION:
        raise ValueError("score tool versions schema version is unsupported")
    tools = _object_keys(
        raw["tools"], set(PINNED_SCORE_TOOL_VERSIONS), "score tool versions map"
    )
    if any(not isinstance(name, str) or not name for name in tools.values()):
        raise ValueError("score tool versions must be non-empty text")
    return tools


def _require_pinned_tool(
    versions_artifact: EvidenceArtifact, tool_name: str
) -> None:
    versions = _score_tool_versions(versions_artifact)
    if versions[tool_name] != PINNED_SCORE_TOOL_VERSIONS[tool_name]:
        raise ValueError(f"{tool_name} version does not match scoring lock")


def _policy_check(policy: Policy, check_id: str) -> CheckPolicy:
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy")
    try:
        return next(item for item in policy.checks if item.id == check_id)
    except StopIteration as exc:
        raise ValueError(f"policy does not declare {check_id}") from exc


def _criterion_matches(criterion: Criterion, score_bps: int) -> bool:
    if criterion.op == "eq":
        return score_bps == criterion.value
    if criterion.op == "gte":
        return score_bps >= criterion.value
    return score_bps <= criterion.value


def _ratio_meets_criterion(
    criterion: Criterion, numerator: int, denominator: int
) -> bool:
    """Compare an exact ratio without consulting its rounded display score."""
    left = 10000 * numerator
    right = criterion.value * denominator
    if criterion.op == "eq":
        return left == right
    if criterion.op == "gte":
        return left >= right
    return left <= right


def _scored_result(
    *,
    policy: Policy,
    check_id: str,
    score_bps: int,
    pass_reason: str,
    fail_reason: str,
    artifacts: tuple[EvidenceArtifact, ...],
    numerator: int | None = None,
    denominator: int | None = None,
    evidence: tuple[Mapping[str, str], ...] = (),
) -> CheckResult:
    passed = _criterion_matches(_policy_check(policy, check_id).criterion, score_bps)
    return CheckResult(
        id=check_id,
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        score_bps=score_bps,
        reason_code=pass_reason if passed else fail_reason,
        numerator=numerator,
        denominator=denominator,
        evidence=_artifact_references(artifacts) + evidence,
    )


def _ratio_result(
    *,
    policy: Policy,
    check_id: str,
    numerator: int,
    denominator: int,
    pass_reason: str,
    fail_reason: str,
    artifacts: tuple[EvidenceArtifact, ...],
    evidence: tuple[Mapping[str, str], ...] = (),
) -> CheckResult:
    score_bps = proportional_score_bps(numerator, denominator)
    if score_bps is None:
        raise ValueError("ratio result requires a nonzero denominator")
    passed = _ratio_meets_criterion(
        _policy_check(policy, check_id).criterion, numerator, denominator
    )
    return CheckResult(
        id=check_id,
        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
        score_bps=score_bps,
        reason_code=pass_reason if passed else fail_reason,
        numerator=numerator,
        denominator=denominator,
        evidence=_artifact_references(artifacts) + evidence,
    )


def _radon_rank(complexity: int) -> str:
    if complexity <= 5:
        return "A"
    if complexity <= 10:
        return "B"
    if complexity <= 20:
        return "C"
    if complexity <= 30:
        return "D"
    if complexity <= 40:
        return "E"
    return "F"


def _radon_complexities(blocks: object, name: str) -> list[int]:
    values: list[int] = []
    for index, block in enumerate(_list_value(blocks, name)):
        if not isinstance(block, Mapping):
            raise ValueError(f"{name}[{index}] must be an object")
        complexity = _non_negative_json_int(
            block.get("complexity"), f"{name}[{index}].complexity"
        )
        if complexity < 1 or block.get("rank") != _radon_rank(complexity):
            raise ValueError("Radon complexity and rank disagree")
        for required_text in ("name", "type"):
            if not isinstance(block.get(required_text), str) or not block[required_text]:
                raise ValueError(f"Radon block {required_text} must be non-empty text")
        values.append(complexity)
        for nested_name in ("methods", "closures"):
            nested = block.get(nested_name, [])
            values.extend(_radon_complexities(nested, f"{name}[{index}].{nested_name}"))
    return values


def _empty_complexity_report(scope: DeclaredCodeScope) -> ComplexityReport:
    return ComplexityReport(
        file_count=len(scope.production),
        parsed_file_count=0,
        unmeasured_files=scope.production,
        parse_error_files=(),
        block_count=0,
        maximum=None,
        mean_milli=None,
        distribution=tuple((rank, 0) for rank in "ABCDEF"),
    )


def _empty_mi_report(scope: DeclaredCodeScope) -> MaintainabilityIndexReport:
    return MaintainabilityIndexReport(
        measured_file_count=0,
        missing_files=scope.production,
        error_files=(),
        minimum_bps=None,
        maximum_bps=None,
        mean_bps=None,
        distribution=(("A", 0), ("B", 0), ("C", 0)),
    )


def evaluate_code_health_evidence(
    *,
    policy: Policy,
    scope_artifact: EvidenceArtifact,
    tool_versions: EvidenceArtifact,
    radon_complexity: EvidenceArtifact,
    radon_mi: EvidenceArtifact,
) -> CodeHealthEvaluation:
    """Consume Radon JSON without allowing missing or unparsed files to vanish."""
    artifacts = (scope_artifact, tool_versions, radon_complexity, radon_mi)
    try:
        scope = _declared_code_scope(scope_artifact)
    except (TypeError, ValueError):
        placeholder = DeclaredCodeScope(
            scopes={kind: () for kind in _SCOPE_KINDS},
            applicability={
                kind: ScopeApplicability("expected", "malformed scope evidence")
                for kind in _APPLICABILITY_KINDS
            },
        )
        return CodeHealthEvaluation(
            scope=placeholder,
            complexity=_empty_complexity_report(placeholder),
            maintainability_index=_empty_mi_report(placeholder),
            checks=tuple(
                _error_result(check_id, "CODE_SCOPE_MALFORMED", artifacts)
                for check_id in _CODE_HEALTH_CHECK_IDS
            ),
        )
    try:
        _require_pinned_tool(tool_versions, "radon")
    except (TypeError, ValueError):
        return CodeHealthEvaluation(
            scope=scope,
            complexity=_empty_complexity_report(scope),
            maintainability_index=_empty_mi_report(scope),
            checks=tuple(
                _error_result(check_id, "RADON_VERSION_MISMATCH", artifacts)
                for check_id in _CODE_HEALTH_CHECK_IDS
            ),
        )

    scope_check = _binary_result(
        "code.scope_declared",
        True,
        pass_reason="CODE_SCOPES_EXPLICIT",
        fail_reason="CODE_SCOPES_AMBIGUOUS",
        artifacts=artifacts,
    )
    try:
        raw_cc = _load_json_object(radon_complexity, "Radon complexity")
        undeclared = sorted(set(raw_cc) - set(scope.all_paths))
        if undeclared:
            raise ValueError("Radon measured undeclared files")
        present = set(raw_cc) & set(scope.production)
        unmeasured = tuple(sorted(set(scope.production) - present))
        parse_errors: list[str] = []
        complexities: list[int] = []
        parsed = 0
        for path in sorted(present):
            value = raw_cc[path]
            if isinstance(value, Mapping) and set(value) == {"error"}:
                if not isinstance(value["error"], str) or not value["error"]:
                    raise ValueError("Radon parser error must be non-empty text")
                parse_errors.append(path)
                continue
            complexities.extend(_radon_complexities(value, f"Radon blocks for {path}"))
            parsed += 1
    except (TypeError, ValueError):
        complexity = _empty_complexity_report(scope)
        parser_check = _error_result(
            "code.production_scope_parsed", "RADON_JSON_MALFORMED", artifacts
        )
        complexity_check = _error_result(
            "code.complexity_maximum", "RADON_JSON_MALFORMED", artifacts
        )
        distribution_check = _error_result(
            "code.complexity_distribution", "RADON_JSON_MALFORMED", artifacts
        )
    else:
        distribution = tuple(
            (rank, sum(_radon_rank(value) == rank for value in complexities))
            for rank in "ABCDEF"
        )
        mean_milli = (
            None
            if not complexities
            else _round_half_up_fraction(sum(complexities) * 1000, len(complexities))
        )
        complexity = ComplexityReport(
            file_count=len(scope.production),
            parsed_file_count=parsed,
            unmeasured_files=unmeasured,
            parse_error_files=tuple(parse_errors),
            block_count=len(complexities),
            maximum=max(complexities) if complexities else None,
            mean_milli=mean_milli,
            distribution=distribution,
        )
        coverage_evidence = (
            {"kind": "parser_coverage", "value": f"{parsed}/{len(scope.production)}"},
            {"kind": "parse_error_count", "value": str(len(parse_errors))},
            {"kind": "unmeasured_file_count", "value": str(len(unmeasured))},
        )
        if parse_errors:
            parser_check = CheckResult(
                id="code.production_scope_parsed",
                status=CheckStatus.ERROR,
                score_bps=None,
                reason_code="RADON_PARSE_FAILURE",
                numerator=parsed,
                denominator=len(scope.production),
                exclusions=(("PARSE_FAILURE", len(parse_errors)),),
                evidence=_artifact_references(artifacts)
                + coverage_evidence
                + tuple(
                    {"kind": "parse_error_file", "value": path}
                    for path in parse_errors
                ),
            )
        elif unmeasured or not scope.production:
            parser_check = CheckResult(
                id="code.production_scope_parsed",
                status=CheckStatus.UNKNOWN,
                score_bps=None,
                reason_code=(
                    "RADON_PRODUCTION_FILE_UNMEASURED"
                    if unmeasured
                    else "PRODUCTION_SCOPE_EMPTY"
                ),
                numerator=parsed,
                denominator=len(scope.production),
                exclusions=(("UNMEASURED_FILE", len(unmeasured)),),
                evidence=_artifact_references(artifacts) + coverage_evidence,
            )
        else:
            parser_check = _ratio_result(
                policy=policy,
                check_id="code.production_scope_parsed",
                numerator=parsed,
                denominator=len(scope.production),
                pass_reason="RADON_PRODUCTION_SCOPE_PARSED",
                fail_reason="RADON_PRODUCTION_SCOPE_INCOMPLETE",
                artifacts=artifacts,
                evidence=coverage_evidence,
            )
        distribution_evidence = (
            {"kind": "complexity_distribution", "value": _canonical_json(dict(distribution))},
            {"kind": "complexity_block_count", "value": str(len(complexities))},
            {"kind": "complexity_mean_milli", "value": str(mean_milli)},
            {"kind": "complexity_maximum", "value": str(complexity.maximum)},
        )
        if parse_errors:
            complexity_check = _error_result(
                "code.complexity_maximum", "RADON_PARSE_FAILURE", artifacts
            )
            distribution_check = _error_result(
                "code.complexity_distribution", "RADON_PARSE_FAILURE", artifacts
            )
        elif unmeasured:
            complexity_check = _error_result(
                "code.complexity_maximum", "RADON_SCOPE_INCOMPLETE", artifacts,
                status=CheckStatus.UNKNOWN,
            )
            distribution_check = _error_result(
                "code.complexity_distribution", "RADON_SCOPE_INCOMPLETE", artifacts,
                status=CheckStatus.UNKNOWN,
            )
        elif complexity.maximum is None:
            complexity_check = _error_result(
                "code.complexity_maximum", "NO_COMPLEXITY_BLOCKS", artifacts,
                status=CheckStatus.UNKNOWN,
            )
            distribution_check = _error_result(
                "code.complexity_distribution", "NO_COMPLEXITY_BLOCKS", artifacts,
                status=CheckStatus.UNKNOWN,
            )
        else:
            maximum_score = max(0, 10000 - 100 * (complexity.maximum - 1))
            complexity_check = _scored_result(
                policy=policy,
                check_id="code.complexity_maximum",
                score_bps=maximum_score,
                pass_reason="COMPLEXITY_MAXIMUM_WITHIN_POLICY",
                fail_reason="COMPLEXITY_MAXIMUM_EXCEEDS_POLICY",
                artifacts=artifacts,
                numerator=1,
                denominator=1,
                evidence=distribution_evidence,
            )
            distribution_check = _binary_result(
                "code.complexity_distribution",
                True,
                pass_reason="COMPLEXITY_DISTRIBUTION_REPORTED",
                fail_reason="COMPLEXITY_DISTRIBUTION_MISSING",
                artifacts=artifacts,
            )
            distribution_check = CheckResult(
                id=distribution_check.id,
                status=distribution_check.status,
                score_bps=distribution_check.score_bps,
                reason_code=distribution_check.reason_code,
                numerator=len(complexities),
                denominator=len(complexities),
                evidence=distribution_check.evidence + distribution_evidence,
            )

    try:
        raw_mi = _load_json_object(radon_mi, "Radon maintainability index")
        if set(raw_mi) - set(scope.all_paths):
            raise ValueError("Radon MI measured undeclared files")
        mi_values: list[int] = []
        mi_errors: list[str] = []
        for path in sorted(set(raw_mi) & set(scope.production)):
            value = raw_mi[path]
            if isinstance(value, Mapping) and set(value) == {"error"}:
                mi_errors.append(path)
                continue
            decimal = _finite_json_decimal(value, f"MI for {path}")
            if not Decimal(0) <= decimal <= Decimal(100):
                raise ValueError("Radon MI must be within zero and 100")
            mi_values.append(
                int((decimal * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            )
        mi_missing = tuple(sorted(set(scope.production) - set(raw_mi)))
        mi_distribution = (
            ("A", sum(value >= 2000 for value in mi_values)),
            ("B", sum(1000 <= value < 2000 for value in mi_values)),
            ("C", sum(value < 1000 for value in mi_values)),
        )
        mi_report = MaintainabilityIndexReport(
            measured_file_count=len(mi_values),
            missing_files=mi_missing,
            error_files=tuple(mi_errors),
            minimum_bps=min(mi_values) if mi_values else None,
            maximum_bps=max(mi_values) if mi_values else None,
            mean_bps=(
                _round_half_up_fraction(sum(mi_values), len(mi_values))
                if mi_values else None
            ),
            distribution=mi_distribution,
        )
        mi_evidence = (
            {"kind": "diagnostic_only", "value": "true"},
            {"kind": "mi_distribution", "value": _canonical_json(dict(mi_distribution))},
            {"kind": "mi_minimum_bps", "value": str(mi_report.minimum_bps)},
            {"kind": "mi_maximum_bps", "value": str(mi_report.maximum_bps)},
            {"kind": "mi_mean_bps", "value": str(mi_report.mean_bps)},
        )
        if mi_errors:
            mi_check = _error_result(
                "code.maintainability_index", "RADON_MI_PARSE_FAILURE", artifacts
            )
        elif mi_missing or not mi_values:
            mi_check = _error_result(
                "code.maintainability_index", "RADON_MI_INCOMPLETE", artifacts,
                status=CheckStatus.UNKNOWN,
            )
        else:
            mi_check = CheckResult(
                id="code.maintainability_index",
                status=CheckStatus.PASS,
                score_bps=mi_report.mean_bps,
                reason_code="MI_DIAGNOSTIC_REPORTED",
                numerator=len(mi_values),
                denominator=len(scope.production),
                evidence=_artifact_references(artifacts) + mi_evidence,
            )
    except (TypeError, ValueError):
        mi_report = _empty_mi_report(scope)
        mi_check = _error_result(
            "code.maintainability_index", "RADON_MI_JSON_MALFORMED", artifacts
        )

    return CodeHealthEvaluation(
        scope=scope,
        complexity=complexity,
        maintainability_index=mi_report,
        checks=tuple(
            sorted(
                (
                    scope_check,
                    parser_check,
                    complexity_check,
                    distribution_check,
                    mi_check,
                ),
                key=lambda item: item.id,
            )
        ),
    )


def _coverage_summary(raw: object, name: str) -> tuple[int, int, int, int]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{name} must be an object")
    required = {"covered_lines", "num_statements", "covered_branches", "num_branches"}
    if not required <= set(raw):
        raise ValueError(f"{name} is missing exact coverage counters")
    covered_lines = _non_negative_json_int(raw["covered_lines"], f"{name}.covered_lines")
    statements = _non_negative_json_int(raw["num_statements"], f"{name}.num_statements")
    covered_branches = _non_negative_json_int(raw["covered_branches"], f"{name}.covered_branches")
    branches = _non_negative_json_int(raw["num_branches"], f"{name}.num_branches")
    if covered_lines > statements or covered_branches > branches:
        raise ValueError(f"{name} coverage counters are inconsistent")
    return covered_lines, statements, covered_branches, branches


def _empty_coverage_report(scope: DeclaredCodeScope) -> CoverageReport:
    return CoverageReport(
        declared_file_count=len(scope.production),
        measured_file_count=0,
        unmeasured_files=scope.production,
        lines_covered=0,
        lines_total=0,
        branches_covered=0,
        branches_total=0,
        per_scope_coverage=tuple((kind, (0, len(scope.scopes[kind]))) for kind in _SCOPE_KINDS),
    )


_MUTMUT_OUTCOMES = (
    "killed",
    "survived",
    "no_test",
    "timeout",
    "crash",
    "internal_error",
    "suspicious",
    "pending",
    "excluded_equivalent",
    "excluded_invalid",
)


def _normalize_mutmut_exit(exit_code: int | None) -> str:
    if exit_code is None or exit_code in {2, 34}:
        return "pending"
    if exit_code == 1:
        return "killed"
    if exit_code == 0:
        return "survived"
    if exit_code in {5, 33}:
        return "no_test"
    if exit_code in {-24, 24, 36, 152, 255}:
        return "timeout"
    if exit_code in {-11, -9}:
        return "crash"
    if exit_code == 3:
        return "internal_error"
    return "suspicious"


def _empty_mutation_report() -> MutationReport:
    return MutationReport(
        counts=tuple((name, 0) for name in _MUTMUT_OUTCOMES),
        completed_valid_mutants=0,
        unresolved_mutants=0,
        excluded_mutants=0,
    )


def _not_applicable_result(
    *,
    policy: Policy,
    check_id: str,
    reason_code: str,
    applicability: ScopeApplicability,
    artifacts: tuple[EvidenceArtifact, ...],
) -> CheckResult:
    if _policy_check(policy, check_id).applicability is None:
        return _error_result(check_id, "POLICY_APPLICABILITY_MISSING", artifacts)
    return CheckResult(
        id=check_id,
        status=CheckStatus.NOT_APPLICABLE,
        score_bps=None,
        reason_code=reason_code,
        numerator=0,
        denominator=0,
        evidence=_artifact_references(artifacts)
        + ({"kind": "applicability_proof", "value": applicability.evidence},),
    )


def evaluate_test_adequacy_evidence(
    *,
    policy: Policy,
    scope_artifact: EvidenceArtifact,
    tool_versions: EvidenceArtifact,
    coverage_json: EvidenceArtifact,
    mutmut_json: EvidenceArtifact,
) -> TestAdequacyEvaluation:
    """Consume exact coverage counters and normalize raw mutmut exit outcomes."""
    artifacts = (scope_artifact, tool_versions, coverage_json, mutmut_json)
    try:
        scope = _declared_code_scope(scope_artifact)
    except (TypeError, ValueError):
        scope = DeclaredCodeScope(
            scopes={kind: () for kind in _SCOPE_KINDS},
            applicability={
                kind: ScopeApplicability("expected", "malformed scope evidence")
                for kind in _APPLICABILITY_KINDS
            },
        )
        return TestAdequacyEvaluation(
            scope=scope,
            coverage=_empty_coverage_report(scope),
            mutation=_empty_mutation_report(),
            checks=tuple(
                _error_result(check_id, "CODE_SCOPE_MALFORMED", artifacts)
                for check_id in _TEST_ADEQUACY_CHECK_IDS
            ),
        )
    try:
        _require_pinned_tool(tool_versions, "coverage")
        _require_pinned_tool(tool_versions, "mutmut")
    except (TypeError, ValueError):
        return TestAdequacyEvaluation(
            scope=scope,
            coverage=_empty_coverage_report(scope),
            mutation=_empty_mutation_report(),
            checks=tuple(
                _error_result(check_id, "SCORING_TOOL_VERSION_MISMATCH", artifacts)
                for check_id in _TEST_ADEQUACY_CHECK_IDS
            ),
        )

    try:
        raw_coverage = _load_json_object(coverage_json, "coverage.py JSON")
        meta = raw_coverage.get("meta")
        files = raw_coverage.get("files")
        totals = raw_coverage.get("totals")
        if (
            not isinstance(meta, Mapping)
            or meta.get("version") != PINNED_SCORE_TOOL_VERSIONS["coverage"]
            or meta.get("branch_coverage") is not True
        ):
            raise ValueError("coverage.py JSON version mismatch")
        if not isinstance(files, Mapping) or not isinstance(totals, Mapping):
            raise ValueError("coverage.py JSON files and totals must be objects")
        if set(files) - set(scope.all_paths):
            raise ValueError("coverage.py measured undeclared files")
        per_file: dict[str, tuple[int, int, int, int]] = {}
        for path, file_raw in files.items():
            if not isinstance(path, str) or not isinstance(file_raw, Mapping):
                raise ValueError("coverage.py file entries are malformed")
            per_file[path] = _coverage_summary(file_raw.get("summary"), f"coverage summary for {path}")
        total_counts = _coverage_summary(totals, "coverage totals")
        summed_counts = tuple(sum(item[index] for item in per_file.values()) for index in range(4))
        if total_counts != summed_counts:
            raise ValueError("coverage.py totals disagree with file counters")
        production_measured = sorted(set(scope.production) & set(per_file))
        unmeasured = tuple(sorted(set(scope.production) - set(per_file)))
        production_counts = tuple(
            sum(per_file[path][index] for path in production_measured)
            for index in range(4)
        )
        per_scope = tuple(
            (
                kind,
                (
                    len(set(scope.scopes[kind]) & set(per_file)),
                    len(scope.scopes[kind]),
                ),
            )
            for kind in _SCOPE_KINDS
        )
        coverage = CoverageReport(
            declared_file_count=len(scope.production),
            measured_file_count=len(production_measured),
            unmeasured_files=unmeasured,
            lines_covered=production_counts[0],
            lines_total=production_counts[1],
            branches_covered=production_counts[2],
            branches_total=production_counts[3],
            per_scope_coverage=per_scope,
        )
    except (TypeError, ValueError):
        coverage = _empty_coverage_report(scope)
        coverage_checks = (
            _error_result("test.coverage_scope", "COVERAGE_JSON_MALFORMED", artifacts),
            _error_result("test.line_coverage", "COVERAGE_JSON_MALFORMED", artifacts),
            _error_result("test.branch_coverage", "COVERAGE_JSON_MALFORMED", artifacts),
        )
    else:
        coverage_evidence = (
            {"kind": "coverage_scope", "value": f"{coverage.measured_file_count}/{coverage.declared_file_count}"},
            {"kind": "line_counts", "value": f"{coverage.lines_covered}/{coverage.lines_total}"},
            {"kind": "branch_counts", "value": f"{coverage.branches_covered}/{coverage.branches_total}"},
            {"kind": "per_scope_coverage", "value": _canonical_json({kind: list(counts) for kind, counts in per_scope})},
        )
        if unmeasured or not scope.production:
            coverage_scope_check = CheckResult(
                id="test.coverage_scope",
                status=CheckStatus.UNKNOWN,
                score_bps=None,
                reason_code=("COVERAGE_PRODUCTION_FILE_UNMEASURED" if unmeasured else "PRODUCTION_SCOPE_EMPTY"),
                numerator=coverage.measured_file_count,
                denominator=coverage.declared_file_count,
                exclusions=(("UNMEASURED_FILE", len(unmeasured)),),
                evidence=_artifact_references(artifacts) + coverage_evidence,
            )
            line_check = _error_result(
                "test.line_coverage", "COVERAGE_SCOPE_INCOMPLETE", artifacts,
                status=CheckStatus.UNKNOWN,
            )
            branch_check = _error_result(
                "test.branch_coverage", "COVERAGE_SCOPE_INCOMPLETE", artifacts,
                status=CheckStatus.UNKNOWN,
            )
        else:
            coverage_scope_check = _ratio_result(
                policy=policy,
                check_id="test.coverage_scope",
                numerator=coverage.measured_file_count,
                denominator=coverage.declared_file_count,
                pass_reason="COVERAGE_PRODUCTION_SCOPE_COMPLETE",
                fail_reason="COVERAGE_PRODUCTION_SCOPE_INCOMPLETE",
                artifacts=artifacts,
                evidence=coverage_evidence,
            )
            if coverage.lines_total == 0:
                if scope.applicability["statements"].state == "proven_none":
                    line_check = _not_applicable_result(
                        policy=policy,
                        check_id="test.line_coverage",
                        reason_code="NO_STATEMENTS_PROVEN",
                        applicability=scope.applicability["statements"],
                        artifacts=artifacts,
                    )
                else:
                    line_check = CheckResult(
                        id="test.line_coverage",
                        status=CheckStatus.UNKNOWN,
                        score_bps=None,
                        reason_code="ZERO_STATEMENTS_UNRESOLVED",
                        numerator=0,
                        denominator=0,
                        evidence=_artifact_references(artifacts) + coverage_evidence,
                    )
            else:
                line_check = _ratio_result(
                    policy=policy,
                    check_id="test.line_coverage",
                    numerator=coverage.lines_covered,
                    denominator=coverage.lines_total,
                    pass_reason="LINE_COVERAGE_MEETS_POLICY",
                    fail_reason="LINE_COVERAGE_BELOW_POLICY",
                    artifacts=artifacts,
                    evidence=coverage_evidence,
                )
            if coverage.branches_total == 0:
                if scope.applicability["branches"].state == "proven_none":
                    branch_check = _not_applicable_result(
                        policy=policy,
                        check_id="test.branch_coverage",
                        reason_code="NO_BRANCHES_PROVEN",
                        applicability=scope.applicability["branches"],
                        artifacts=artifacts,
                    )
                else:
                    branch_check = CheckResult(
                        id="test.branch_coverage",
                        status=CheckStatus.UNKNOWN,
                        score_bps=None,
                        reason_code="ZERO_BRANCHES_UNRESOLVED",
                        numerator=0,
                        denominator=0,
                        evidence=_artifact_references(artifacts) + coverage_evidence,
                    )
            else:
                branch_check = _ratio_result(
                    policy=policy,
                    check_id="test.branch_coverage",
                    numerator=coverage.branches_covered,
                    denominator=coverage.branches_total,
                    pass_reason="BRANCH_COVERAGE_MEETS_POLICY",
                    fail_reason="BRANCH_COVERAGE_BELOW_POLICY",
                    artifacts=artifacts,
                    evidence=coverage_evidence,
                )
        coverage_checks = (coverage_scope_check, line_check, branch_check)

    try:
        raw_mutmut = _object_keys(
            _load_json_object(mutmut_json, "mutmut evidence"),
            {"schema_version", "tool", "clean_control", "sentinel", "mutants"},
            "mutmut evidence",
        )
        if raw_mutmut["schema_version"] != _MUTMUT_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("mutmut evidence schema is unsupported")
        tool = _object_keys(raw_mutmut["tool"], {"name", "version"}, "mutmut tool")
        if tool != {"name": "mutmut", "version": PINNED_SCORE_TOOL_VERSIONS["mutmut"]}:
            raise ValueError("mutmut evidence version mismatch")
        clean = _object_keys(
            raw_mutmut["clean_control"], {"exit_code", "tests_collected"}, "mutmut clean control"
        )
        sentinel = _object_keys(
            raw_mutmut["sentinel"], {"exit_code", "expected_failure_observed"}, "mutmut sentinel"
        )
        clean_exit = clean["exit_code"]
        tests_collected = _non_negative_json_int(clean["tests_collected"], "clean tests_collected")
        sentinel_exit = sentinel["exit_code"]
        if not _is_int(clean_exit) or not _is_int(sentinel_exit) or not isinstance(sentinel["expected_failure_observed"], bool):
            raise ValueError("mutmut control exits are malformed")
        counts = {name: 0 for name in _MUTMUT_OUTCOMES}
        mutant_ids: list[str] = []
        for item in _list_value(raw_mutmut["mutants"], "mutmut mutants"):
            mutant = _object_keys(item, {"id", "exit_code", "exclusion"}, "mutmut mutant")
            mutant_id = mutant["id"]
            if not isinstance(mutant_id, str) or not mutant_id:
                raise ValueError("mutmut mutant ID must be non-empty text")
            mutant_ids.append(mutant_id)
            exit_code = mutant["exit_code"]
            if exit_code is not None and not _is_int(exit_code):
                raise ValueError("mutmut mutant exit_code must be integer or null")
            exclusion = mutant["exclusion"]
            if exclusion is not None:
                exclusion_raw = _object_keys(exclusion, {"reason", "evidence"}, "mutant exclusion")
                reason = exclusion_raw["reason"]
                evidence_value = exclusion_raw["evidence"]
                if reason not in {"EQUIVALENT_MUTANT", "INVALID_MUTANT"} or not isinstance(evidence_value, str) or not evidence_value.strip():
                    raise ValueError("mutant exclusion requires an allowed reason and evidence")
                counts["excluded_equivalent" if reason == "EQUIVALENT_MUTANT" else "excluded_invalid"] += 1
            else:
                counts[_normalize_mutmut_exit(exit_code)] += 1
        if len(set(mutant_ids)) != len(mutant_ids):
            raise ValueError("mutmut mutant IDs must be unique")
        completed = counts["killed"] + counts["survived"] + counts["no_test"]
        unresolved = sum(counts[name] for name in ("timeout", "crash", "internal_error", "suspicious", "pending"))
        excluded = counts["excluded_equivalent"] + counts["excluded_invalid"]
        mutation = MutationReport(
            counts=tuple((name, counts[name]) for name in _MUTMUT_OUTCOMES),
            completed_valid_mutants=completed,
            unresolved_mutants=unresolved,
            excluded_mutants=excluded,
        )
    except (TypeError, ValueError):
        mutation = _empty_mutation_report()
        mutation_checks = (
            _error_result("test.mutation_controls", "MUTMUT_EVIDENCE_MALFORMED", artifacts),
            _error_result("test.mutation_score", "MUTMUT_EVIDENCE_MALFORMED", artifacts),
        )
    else:
        mutation_evidence = (
            {"kind": "mutation_counts", "value": _canonical_json(dict(mutation.counts))},
            {"kind": "completed_valid_mutants", "value": str(completed)},
            {"kind": "unresolved_mutants", "value": str(unresolved)},
            {"kind": "excluded_mutants", "value": str(excluded)},
        )
        controls_pass = (
            clean_exit == 0
            and tests_collected > 0
            and sentinel_exit == 1
            and sentinel["expected_failure_observed"] is True
        )
        controls_check = _binary_result(
            "test.mutation_controls",
            controls_pass,
            pass_reason="MUTATION_CONTROLS_VALID",
            fail_reason="MUTATION_CONTROLS_INVALID",
            artifacts=artifacts,
        )
        controls_check = CheckResult(
            id=controls_check.id,
            status=(controls_check.status if controls_pass else CheckStatus.ERROR),
            score_bps=(controls_check.score_bps if controls_pass else None),
            reason_code=controls_check.reason_code,
            numerator=(1 if controls_pass else 0),
            denominator=1,
            evidence=controls_check.evidence + mutation_evidence,
        )
        if not controls_pass:
            mutation_check = _error_result(
                "test.mutation_score", "MUTATION_CONTROLS_INVALID", artifacts
            )
        elif unresolved:
            mutation_check = CheckResult(
                id="test.mutation_score",
                status=CheckStatus.UNKNOWN,
                score_bps=None,
                reason_code="MUTATION_OUTCOMES_UNRESOLVED",
                numerator=counts["killed"],
                denominator=completed,
                exclusions=tuple(
                    (reason.upper(), counts[reason])
                    for reason in ("timeout", "crash", "internal_error", "suspicious", "pending")
                    if counts[reason]
                ),
                evidence=_artifact_references(artifacts) + mutation_evidence,
            )
        elif completed == 0:
            if scope.applicability["mutants"].state == "proven_none":
                mutation_check = _not_applicable_result(
                    policy=policy,
                    check_id="test.mutation_score",
                    reason_code="NO_MUTANTS_PROVEN",
                    applicability=scope.applicability["mutants"],
                    artifacts=artifacts,
                )
            else:
                mutation_check = CheckResult(
                    id="test.mutation_score",
                    status=CheckStatus.UNKNOWN,
                    score_bps=None,
                    reason_code="ZERO_COMPLETED_MUTANTS_UNRESOLVED",
                    numerator=0,
                    denominator=0,
                    evidence=_artifact_references(artifacts) + mutation_evidence,
                )
        else:
            mutation_check = _ratio_result(
                policy=policy,
                check_id="test.mutation_score",
                numerator=counts["killed"],
                denominator=completed,
                pass_reason="MUTATION_SCORE_MEETS_POLICY",
                fail_reason="MUTATION_SCORE_BELOW_POLICY",
                artifacts=artifacts,
                evidence=mutation_evidence,
            )
        mutation_checks = (controls_check, mutation_check)

    return TestAdequacyEvaluation(
        scope=scope,
        coverage=coverage,
        mutation=mutation,
        checks=tuple(sorted((*coverage_checks, *mutation_checks), key=lambda item: item.id)),
    )


class OpenSSFCollectionState(str, Enum):
    """Typed outcome of an OpenSSF Scorecard REST collection attempt."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class GitHubCapabilities:
    """Credential-free capability metadata; token values are never accepted."""

    token_kind: str
    granted: tuple[str, ...] = ()
    unavailable: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.token_kind not in {
            "anonymous",
            "classic",
            "fine_grained",
            "github_app",
            "unknown",
        }:
            raise ValueError("token_kind is not a supported capability label")
        for name, values in (
            ("granted", self.granted),
            ("unavailable", self.unavailable),
        ):
            if not isinstance(values, tuple):
                raise TypeError(f"{name} capabilities must be a tuple")
            if any(value not in _OPENSSF_CAPABILITY_NAMES for value in values):
                raise ValueError(f"{name} contains an unknown capability")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} capabilities must be unique")
        if set(self.granted) & set(self.unavailable):
            raise ValueError("a capability cannot be both granted and unavailable")
        object.__setattr__(self, "granted", tuple(sorted(self.granted)))
        object.__setattr__(self, "unavailable", tuple(sorted(self.unavailable)))

    @property
    def token_present(self) -> bool | None:
        if self.token_kind == "unknown":
            return None
        return self.token_kind != "anonymous"

    def to_dict(self) -> dict[str, object]:
        return {
            "token_kind": self.token_kind,
            "token_present": self.token_present,
            "granted": list(self.granted),
            "unavailable": list(self.unavailable),
        }


@dataclass(frozen=True, slots=True)
class OpenSSFApplicability:
    """Evidence that satisfies one policy-owned not-applicable predicate."""

    check_id: str
    predicate: str
    evidence: str

    def __post_init__(self) -> None:
        if self.check_id not in {item[0] for item in OPENSSF_SELECTED_CHECKS}:
            raise ValueError("applicability check_id is not an OpenSSF-selected check")
        if not isinstance(self.predicate, str) or not self.predicate.strip():
            raise ValueError("applicability predicate must be non-empty text")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("applicability evidence must be non-empty text")


@dataclass(frozen=True, slots=True)
class OpenSSFCollection:
    """A raw REST artifact or a typed reason why no artifact was available."""

    repository: str
    state: OpenSSFCollectionState
    collected_at: str
    capabilities: GitHubCapabilities
    reason_code: str
    artifact: EvidenceArtifact | None = None
    http_status: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPO_SLUG.fullmatch(
            self.repository
        ):
            raise ValueError("repository must be an owner/repository slug")
        if not isinstance(self.state, OpenSSFCollectionState):
            raise TypeError("state must be an OpenSSFCollectionState")
        _validate_openssf_timestamp(self.collected_at, "collected_at")
        if not isinstance(self.capabilities, GitHubCapabilities):
            raise TypeError("capabilities must be GitHubCapabilities")
        if not isinstance(self.reason_code, str) or not _REASON_CODE.fullmatch(
            self.reason_code
        ):
            raise ValueError("collection reason_code must be uppercase snake-case")
        if self.http_status is not None and (
            not _is_int(self.http_status) or not 100 <= self.http_status <= 599
        ):
            raise ValueError("http_status must be a valid HTTP status or None")
        if self.state is OpenSSFCollectionState.AVAILABLE:
            if not isinstance(self.artifact, EvidenceArtifact):
                raise TypeError("available collection requires an EvidenceArtifact")
        elif self.artifact is not None:
            raise ValueError("unavailable or error collection cannot contain an artifact")


@dataclass(frozen=True, slots=True)
class OpenSSFProvenance:
    """Pinned identity and observation metadata extracted from raw Scorecard JSON."""

    repository: str
    repository_commit: str
    tool_version: str
    tool_commit: str
    observed_at: str
    raw_artifact_sha256: str
    capabilities: GitHubCapabilities

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not self.repository.startswith(
            "github.com/"
        ):
            raise ValueError("OpenSSF repository must start with github.com/")
        if not _SHA1.fullmatch(self.repository_commit):
            raise ValueError("OpenSSF repository commit must be a SHA-1")
        if not isinstance(self.tool_version, str) or not self.tool_version:
            raise ValueError("OpenSSF tool version must be non-empty text")
        if not _SHA1.fullmatch(self.tool_commit):
            raise ValueError("OpenSSF tool commit must be a SHA-1")
        _validate_openssf_timestamp(self.observed_at, "OpenSSF observation time")
        if not _SHA256.fullmatch(self.raw_artifact_sha256):
            raise ValueError("OpenSSF raw artifact digest must be a SHA-256")
        if not isinstance(self.capabilities, GitHubCapabilities):
            raise TypeError("OpenSSF capabilities must be GitHubCapabilities")

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "repository_commit": self.repository_commit,
            "tool_version": self.tool_version,
            "tool_commit": self.tool_commit,
            "observed_at": self.observed_at,
            "raw_artifact_sha256": self.raw_artifact_sha256,
            "capabilities": self.capabilities.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ProcessSupplyChainEvaluation:
    """Selected OpenSSF facts; the upstream aggregate has no field here."""

    collection_state: OpenSSFCollectionState
    checks: tuple[CheckResult, ...]
    provenance: OpenSSFProvenance | None
    aggregate_disposition: str = "discarded"

    def __post_init__(self) -> None:
        if not isinstance(self.collection_state, OpenSSFCollectionState):
            raise TypeError("collection_state must be an OpenSSFCollectionState")
        if not isinstance(self.checks, tuple) or any(
            not isinstance(item, CheckResult) for item in self.checks
        ):
            raise TypeError("checks must be a tuple of CheckResult")
        if tuple(item.id for item in self.checks) != tuple(
            sorted(_PROCESS_CHECK_IDS)
        ):
            raise ValueError("process evaluation must contain every selected check")
        if self.provenance is not None and not isinstance(
            self.provenance, OpenSSFProvenance
        ):
            raise TypeError("provenance must be OpenSSFProvenance or None")
        if self.aggregate_disposition != "discarded":
            raise ValueError("the OpenSSF aggregate must always be discarded")

    def to_dict(self) -> dict[str, object]:
        return {
            "collection_state": self.collection_state.value,
            "aggregate_disposition": self.aggregate_disposition,
            "provenance": (
                None if self.provenance is None else self.provenance.to_dict()
            ),
            "checks": [
                {
                    "id": item.id,
                    "status": item.status.value,
                    "score_bps": item.score_bps,
                    "reason_code": item.reason_code,
                    "numerator": item.numerator,
                    "denominator": item.denominator,
                    "exclusions": dict(item.exclusions),
                    "evidence": [dict(entry) for entry in item.evidence],
                }
                for item in self.checks
            ],
        }


class OpenSSFEvaluationError(ValueError):
    """Stable reason-coded rejection of malformed or mismatched raw evidence."""

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        provenance: OpenSSFProvenance | None = None,
    ) -> None:
        if not _REASON_CODE.fullmatch(reason_code):
            raise ValueError("OpenSSF error reason must be uppercase snake-case")
        super().__init__(message)
        self.reason_code = reason_code
        self.provenance = provenance


def _validate_openssf_timestamp(value: object, name: str) -> str:
    from datetime import datetime

    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{name} must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} must be a UTC RFC3339 timestamp") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be a UTC RFC3339 timestamp")
    return value


def _utc_now_text() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def collect_openssf_scorecard(
    repository: str,
    *,
    timeout_seconds: int = 30,
    collected_at: str | None = None,
) -> OpenSSFCollection:
    """Fetch public raw Scorecard JSON without reading or sending a credential."""
    from urllib import error as urllib_error
    from urllib import request as urllib_request
    from urllib.parse import quote

    if not isinstance(repository, str) or not _REPO_SLUG.fullmatch(repository):
        raise ValueError("repository must be an owner/repository slug")
    _validate_positive_int(timeout_seconds, "timeout_seconds")
    observation = collected_at or _utc_now_text()
    _validate_openssf_timestamp(observation, "collected_at")
    capabilities = GitHubCapabilities(
        token_kind="anonymous", granted=("public_api",)
    )
    owner, name = repository.split("/", 1)
    url = f"{OPENSSF_SCORECARD_API}/{quote(owner)}/{quote(name)}"
    request = urllib_request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "leitir-score-engine/adr-002-s6",
        },
    )
    try:
        with urllib_request.urlopen(request, timeout=timeout_seconds) as response:
            content = response.read(_MAX_OPENSSF_ARTIFACT_BYTES + 1)
            status = getattr(response, "status", 200)
    except urllib_error.HTTPError as exc:
        state = (
            OpenSSFCollectionState.UNAVAILABLE
            if exc.code == 404
            else OpenSSFCollectionState.ERROR
        )
        return OpenSSFCollection(
            repository=repository,
            state=state,
            collected_at=observation,
            capabilities=capabilities,
            reason_code=(
                "OPENSSF_API_UNAVAILABLE"
                if state is OpenSSFCollectionState.UNAVAILABLE
                else "OPENSSF_API_HTTP_ERROR"
            ),
            http_status=exc.code,
        )
    except (urllib_error.URLError, TimeoutError, OSError):
        return OpenSSFCollection(
            repository=repository,
            state=OpenSSFCollectionState.UNAVAILABLE,
            collected_at=observation,
            capabilities=capabilities,
            reason_code="OPENSSF_API_UNAVAILABLE",
        )
    if status != 200:
        return OpenSSFCollection(
            repository=repository,
            state=OpenSSFCollectionState.ERROR,
            collected_at=observation,
            capabilities=capabilities,
            reason_code="OPENSSF_API_HTTP_ERROR",
            http_status=status,
        )
    if len(content) > _MAX_OPENSSF_ARTIFACT_BYTES:
        return OpenSSFCollection(
            repository=repository,
            state=OpenSSFCollectionState.ERROR,
            collected_at=observation,
            capabilities=capabilities,
            reason_code="OPENSSF_ARTIFACT_TOO_LARGE",
            http_status=status,
        )
    artifact = EvidenceArtifact(
        id="process.openssf-scorecard",
        path=f".leitir-score/evidence/openssf-{owner}-{name}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )
    return OpenSSFCollection(
        repository=repository,
        state=OpenSSFCollectionState.AVAILABLE,
        collected_at=observation,
        capabilities=capabilities,
        reason_code="OPENSSF_API_ARTIFACT_COLLECTED",
        artifact=artifact,
        http_status=status,
    )


def _openssf_provenance_evidence(
    provenance: OpenSSFProvenance | None,
    capabilities: GitHubCapabilities,
) -> tuple[Mapping[str, str], ...]:
    evidence: tuple[Mapping[str, str], ...] = (
        {
            "kind": "github_capabilities",
            "value": _canonical_json(capabilities.to_dict()),
        },
    )
    if provenance is None:
        return evidence
    return evidence + tuple(
        {"kind": kind, "value": str(value)}
        for kind, value in (
            ("repository", provenance.repository),
            ("repository_commit", provenance.repository_commit),
            ("scorecard_version", provenance.tool_version),
            ("scorecard_commit", provenance.tool_commit),
            ("observation_time", provenance.observed_at),
            ("raw_artifact_sha256", provenance.raw_artifact_sha256),
        )
    )


def _redacted_openssf_reason(reason: str) -> str:
    """Defensively redact common GitHub/Bearer token forms from output evidence."""
    reason = re.sub(r"github_pat_[A-Za-z0-9_]+", "[REDACTED]", reason)
    reason = re.sub(r"gh[pousr]_[A-Za-z0-9_]+", "[REDACTED]", reason)
    return re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", reason
    )


def _openssf_unresolved_result(
    check_id: str,
    reason_code: str,
    *,
    artifact: EvidenceArtifact | None,
    provenance: OpenSSFProvenance | None,
    capabilities: GitHubCapabilities,
    status: CheckStatus,
    extra_evidence: tuple[Mapping[str, str], ...] = (),
) -> CheckResult:
    artifacts = () if artifact is None else (artifact,)
    return CheckResult(
        id=check_id,
        status=status,
        score_bps=None,
        reason_code=reason_code,
        evidence=_artifact_references(artifacts)
        + _openssf_provenance_evidence(provenance, capabilities)
        + extra_evidence,
    )


def _openssf_error_evaluation(
    *,
    reason_code: str,
    artifact: EvidenceArtifact | None,
    provenance: OpenSSFProvenance | None,
    capabilities: GitHubCapabilities,
    state: OpenSSFCollectionState = OpenSSFCollectionState.ERROR,
    status: CheckStatus = CheckStatus.ERROR,
    extra_evidence: tuple[Mapping[str, str], ...] = (),
) -> ProcessSupplyChainEvaluation:
    return ProcessSupplyChainEvaluation(
        collection_state=state,
        provenance=provenance,
        checks=tuple(
            sorted(
                (
                    _openssf_unresolved_result(
                        check_id,
                        reason_code,
                        artifact=artifact,
                        provenance=provenance,
                        capabilities=capabilities,
                        status=status,
                        extra_evidence=extra_evidence,
                    )
                    for check_id in _PROCESS_CHECK_IDS
                ),
                key=lambda item: item.id,
            )
        ),
    )


def _parse_openssf_scorecard(
    artifact: EvidenceArtifact,
    capabilities: GitHubCapabilities,
    expected_repository: str | None,
) -> tuple[OpenSSFProvenance, dict[str, Mapping[str, object]], bool]:
    try:
        raw = _object_keys(
            _load_json_object(artifact, "OpenSSF Scorecard JSON"),
            {"date", "repo", "scorecard", "score", "checks"},
            "OpenSSF Scorecard JSON",
        )
        repository = _object_keys(raw["repo"], {"name", "commit"}, "OpenSSF repo")
        scorecard = _object_keys(
            raw["scorecard"], {"version", "commit"}, "OpenSSF scorecard"
        )
        if not isinstance(repository["name"], str):
            raise ValueError("OpenSSF repository name must be text")
        provenance = OpenSSFProvenance(
            repository=repository["name"],
            repository_commit=repository["commit"],
            tool_version=scorecard["version"],
            tool_commit=scorecard["commit"],
            observed_at=_validate_openssf_timestamp(raw["date"], "OpenSSF date"),
            raw_artifact_sha256=artifact.sha256,
            capabilities=capabilities,
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise OpenSSFEvaluationError(
            "OPENSSF_ARTIFACT_MALFORMED", "OpenSSF artifact is malformed"
        ) from exc
    if expected_repository is not None and provenance.repository != (
        f"github.com/{expected_repository}"
    ):
        raise OpenSSFEvaluationError(
            "OPENSSF_REPOSITORY_MISMATCH",
            "OpenSSF artifact repository does not match requested repository",
            provenance=provenance,
        )
    if provenance.tool_version != PINNED_OPENSSF_SCORECARD_VERSION:
        raise OpenSSFEvaluationError(
            "OPENSSF_VERSION_MISMATCH",
            "OpenSSF Scorecard version does not match the ADR-002 pin",
            provenance=provenance,
        )
    if provenance.tool_commit != PINNED_OPENSSF_SCORECARD_COMMIT:
        raise OpenSSFEvaluationError(
            "OPENSSF_TOOL_COMMIT_MISMATCH",
            "OpenSSF Scorecard commit does not match the ADR-002 pin",
            provenance=provenance,
        )
    checks: dict[str, Mapping[str, object]] = {}
    duplicate_selected = False
    selected_names = {name for _, name in OPENSSF_SELECTED_CHECKS}
    try:
        for index, item in enumerate(_list_value(raw["checks"], "OpenSSF checks")):
            if not isinstance(item, Mapping):
                raise TypeError(f"OpenSSF check {index} must be an object")
            name = item.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("OpenSSF check name must be non-empty text")
            if name not in selected_names:
                continue
            check = _object_keys(
                item,
                {"name", "score", "reason", "details", "documentation"},
                f"OpenSSF check {index}",
            )
            documentation = _object_keys(
                check["documentation"],
                {"short", "url"},
                f"OpenSSF check {index} documentation",
            )
            score = check["score"]
            reason = check["reason"]
            details = check["details"]
            if not _is_int(score) or not -1 <= score <= 10:
                raise ValueError("OpenSSF check score must be an integer from -1 to 10")
            if not isinstance(reason, str) or not reason:
                raise ValueError("OpenSSF check reason must be non-empty text")
            if details is not None and (
                not isinstance(details, list)
                or any(not isinstance(detail, str) for detail in details)
            ):
                raise ValueError("OpenSSF check details must be null or a string list")
            if any(
                not isinstance(documentation[field], str)
                or not documentation[field]
                for field in ("short", "url")
            ):
                raise ValueError("OpenSSF check documentation must be non-empty text")
            if name in checks:
                duplicate_selected = True
            else:
                checks[name] = check
    except (TypeError, ValueError, KeyError) as exc:
        raise OpenSSFEvaluationError(
            "OPENSSF_ARTIFACT_MALFORMED",
            "OpenSSF selected check evidence is malformed",
            provenance=provenance,
        ) from exc
    return provenance, checks, duplicate_selected


def evaluate_process_supply_chain_evidence(
    *,
    policy: Policy,
    scorecard_artifact: EvidenceArtifact,
    capabilities: GitHubCapabilities,
    expected_repository: str | None = None,
    applicability: tuple[OpenSSFApplicability, ...] = (),
) -> ProcessSupplyChainEvaluation:
    """Normalize policy-selected Scorecard checks and never its aggregate."""
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy")
    if not isinstance(scorecard_artifact, EvidenceArtifact):
        raise TypeError("scorecard_artifact must be an EvidenceArtifact")
    if not isinstance(capabilities, GitHubCapabilities):
        raise TypeError("capabilities must be GitHubCapabilities")
    if expected_repository is not None and (
        not isinstance(expected_repository, str)
        or not _REPO_SLUG.fullmatch(expected_repository)
    ):
        raise ValueError("expected_repository must be an owner/repository slug")
    if not isinstance(applicability, tuple) or any(
        not isinstance(item, OpenSSFApplicability) for item in applicability
    ):
        raise TypeError("applicability must be a tuple of OpenSSFApplicability")
    applicability_by_id = {item.check_id: item for item in applicability}
    if len(applicability_by_id) != len(applicability):
        raise ValueError("applicability check IDs must be unique")
    for check_id in _PROCESS_CHECK_IDS:
        _policy_check(policy, check_id)
    try:
        provenance, raw_checks, duplicate_selected = _parse_openssf_scorecard(
            scorecard_artifact, capabilities, expected_repository
        )
    except OpenSSFEvaluationError as exc:
        return _openssf_error_evaluation(
            reason_code=exc.reason_code,
            artifact=scorecard_artifact,
            provenance=exc.provenance,
            capabilities=capabilities,
        )

    common = _artifact_references((scorecard_artifact,)) + (
        _openssf_provenance_evidence(provenance, capabilities)
    )
    expected_names = {name for _, name in OPENSSF_SELECTED_CHECKS}
    check_set_exact = not duplicate_selected and set(raw_checks) == expected_names
    checks: list[CheckResult] = []
    if check_set_exact:
        checks.append(
            CheckResult(
                id=_PROCESS_CONTROL_CHECK_ID,
                status=CheckStatus.PASS,
                score_bps=10000,
                reason_code="OPENSSF_SELECTED_CHECK_SET_COMPLETE",
                numerator=len(raw_checks),
                denominator=len(expected_names),
                evidence=common,
            )
        )
    else:
        checks.append(
            _openssf_unresolved_result(
                _PROCESS_CONTROL_CHECK_ID,
                "OPENSSF_SELECTED_CHECK_SET_CHANGED",
                artifact=scorecard_artifact,
                provenance=provenance,
                capabilities=capabilities,
                status=CheckStatus.ERROR,
                extra_evidence=(
                    {
                        "kind": "selected_checks_present",
                        "value": _canonical_json(sorted(raw_checks)),
                    },
                ),
            )
        )

    for check_id, openssf_name in OPENSSF_SELECTED_CHECKS:
        applicability_proof = applicability_by_id.get(check_id)
        if applicability_proof is not None:
            policy_applicability = _policy_check(policy, check_id).applicability
            if (
                policy_applicability is None
                or policy_applicability.rule != applicability_proof.predicate
            ):
                checks.append(
                    _openssf_unresolved_result(
                        check_id,
                        "OPENSSF_APPLICABILITY_EVIDENCE_INVALID",
                        artifact=scorecard_artifact,
                        provenance=provenance,
                        capabilities=capabilities,
                        status=CheckStatus.ERROR,
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        id=check_id,
                        status=CheckStatus.NOT_APPLICABLE,
                        score_bps=None,
                        reason_code="OPENSSF_NOT_APPLICABLE_PROVEN",
                        evidence=common
                        + (
                            {
                                "kind": "applicability_predicate",
                                "value": applicability_proof.predicate,
                            },
                            {
                                "kind": "applicability_proof",
                                "value": applicability_proof.evidence,
                            },
                        ),
                    )
                )
            continue
        raw_check = raw_checks.get(openssf_name)
        if raw_check is None:
            checks.append(
                _openssf_unresolved_result(
                    check_id,
                    "OPENSSF_SELECTED_CHECK_MISSING",
                    artifact=scorecard_artifact,
                    provenance=provenance,
                    capabilities=capabilities,
                    status=CheckStatus.UNKNOWN,
                )
            )
            continue
        raw_score = int(raw_check["score"])
        raw_reason = str(raw_check["reason"])
        check_evidence = (
            {"kind": "openssf_check", "value": openssf_name},
            {"kind": "openssf_raw_score", "value": str(raw_score)},
            {"kind": "openssf_reason", "value": _redacted_openssf_reason(raw_reason)},
        )
        if raw_score == -1:
            folded_reason = raw_reason.casefold()
            if (
                "token" in folded_reason
                or "permission" in folded_reason
                or "authentication" in folded_reason
                or openssf_name == "Branch-Protection"
                and "branch_protection" in capabilities.unavailable
            ):
                reason_code = "OPENSSF_INSUFFICIENT_AUTH"
            elif "unsupported" in folded_reason or "not supported" in folded_reason:
                reason_code = "OPENSSF_CHECK_UNSUPPORTED"
            else:
                reason_code = "OPENSSF_CHECK_INCONCLUSIVE"
            checks.append(
                _openssf_unresolved_result(
                    check_id,
                    reason_code,
                    artifact=scorecard_artifact,
                    provenance=provenance,
                    capabilities=capabilities,
                    status=CheckStatus.UNKNOWN,
                    extra_evidence=check_evidence,
                )
            )
            continue
        checks.append(
            _scored_result(
                policy=policy,
                check_id=check_id,
                score_bps=raw_score * 1000,
                pass_reason="OPENSSF_CHECK_MEETS_POLICY",
                fail_reason="OPENSSF_CHECK_BELOW_POLICY",
                artifacts=(scorecard_artifact,),
                evidence=_openssf_provenance_evidence(provenance, capabilities)
                + check_evidence,
            )
        )
    return ProcessSupplyChainEvaluation(
        collection_state=OpenSSFCollectionState.AVAILABLE,
        provenance=provenance,
        checks=tuple(sorted(checks, key=lambda item: item.id)),
    )


def evaluate_process_supply_chain_collection(
    *,
    policy: Policy,
    collection: OpenSSFCollection,
    applicability: tuple[OpenSSFApplicability, ...] = (),
) -> ProcessSupplyChainEvaluation:
    """Evaluate a live collection while preserving unavailable as unknown."""
    if not isinstance(collection, OpenSSFCollection):
        raise TypeError("collection must be an OpenSSFCollection")
    if collection.state is OpenSSFCollectionState.AVAILABLE:
        return evaluate_process_supply_chain_evidence(
            policy=policy,
            scorecard_artifact=collection.artifact,
            capabilities=collection.capabilities,
            expected_repository=collection.repository,
            applicability=applicability,
        )
    status = (
        CheckStatus.UNKNOWN
        if collection.state is OpenSSFCollectionState.UNAVAILABLE
        else CheckStatus.ERROR
    )
    return _openssf_error_evaluation(
        reason_code=collection.reason_code,
        artifact=None,
        provenance=None,
        capabilities=collection.capabilities,
        state=collection.state,
        status=status,
        extra_evidence=(
            {"kind": "repository", "value": collection.repository},
        ),
    )


class PerformanceEvaluationError(ValueError):
    """A controlled-performance contract fault with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class MannWhitneyResult:
    """Two-sided Mann-Whitney normal approximation with tie correction."""

    u: Decimal
    variance: Fraction
    z: Decimal
    p_value: Decimal


@dataclass(frozen=True, slots=True)
class PerformanceSampleSummary:
    """Raw samples plus extrema; no average can hide their distribution."""

    samples: tuple[Decimal, ...]
    minimum: Decimal
    maximum: Decimal

    @property
    def count(self) -> int:
        return len(self.samples)


@dataclass(frozen=True, slots=True)
class PerformanceBenchmarkComparison:
    name: str
    benchmark_version: str
    baseline_median: Decimal
    candidate_median: Decimal | None
    baseline: PerformanceSampleSummary
    candidate: PerformanceSampleSummary | None
    mann_whitney: MannWhitneyResult | None
    status: CheckStatus
    reason_code: str


@dataclass(frozen=True, slots=True)
class PerformanceEvaluation:
    asv_version: str
    environment_fingerprint: str
    comparisons: tuple[PerformanceBenchmarkComparison, ...]
    checks: tuple[CheckResult, ...]


@dataclass(frozen=True, slots=True)
class _ASVBenchmarkResult:
    name: str
    median: Decimal | None
    version: str
    samples: tuple[Decimal, ...]


@dataclass(frozen=True, slots=True)
class _ASVRun:
    params: Mapping[str, object]
    python: str
    requirements: Mapping[str, object]
    env_name: str
    env_vars: Mapping[str, object]
    benchmarks: Mapping[str, _ASVBenchmarkResult]


def _performance_json_object(
    artifact: EvidenceArtifact, name: str
) -> Mapping[str, object]:
    def reject_constant(value: str) -> object:
        raise ValueError(f"{name} contains non-finite number {value}")

    try:
        decoded = json.loads(
            artifact.content,
            parse_float=Decimal,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PerformanceEvaluationError(
            "PERFORMANCE_HARNESS_ERROR", f"{name} is not strict JSON"
        ) from exc
    if not isinstance(decoded, Mapping):
        raise PerformanceEvaluationError(
            "PERFORMANCE_HARNESS_ERROR", f"{name} must be a JSON object"
        )
    return decoded


def _performance_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise PerformanceEvaluationError(
            "PERFORMANCE_HARNESS_ERROR", f"{name} must be a JSON number"
        )
    result = Decimal(value)
    if not result.is_finite() or result <= 0:
        raise PerformanceEvaluationError(
            "PERFORMANCE_HARNESS_ERROR", f"{name} must be finite and positive"
        )
    return result


def _asv_run(artifact: EvidenceArtifact, name: str) -> _ASVRun:
    raw = _performance_json_object(artifact, name)
    expected_keys = {
        "version",
        "commit_hash",
        "env_name",
        "date",
        "params",
        "python",
        "requirements",
        "env_vars",
        "durations",
        "result_columns",
        "results",
    }
    if set(raw) != expected_keys or raw["version"] != _ASV_RESULT_SCHEMA_VERSION:
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} is not pinned ASV v2 output"
        )
    columns = raw["result_columns"]
    if not isinstance(columns, list) or tuple(columns) != _ASV_RESULT_COLUMNS:
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_SCHEMA_MISMATCH",
            f"{name} result columns do not match pinned ASV",
        )
    if not isinstance(raw["commit_hash"], str) or not _SHA1.fullmatch(
        raw["commit_hash"]
    ):
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} commit hash is invalid"
        )
    params = raw["params"]
    requirements = raw["requirements"]
    env_vars = raw["env_vars"]
    durations = raw["durations"]
    results = raw["results"]
    if not all(
        isinstance(item, Mapping)
        for item in (params, requirements, env_vars, durations)
    ):
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} environment fields are invalid"
        )
    if not isinstance(raw["python"], str) or not raw["python"]:
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} python is invalid"
        )
    if not isinstance(raw["env_name"], str) or not raw["env_name"]:
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} environment name is invalid"
        )
    if not isinstance(results, Mapping) or not results:
        raise PerformanceEvaluationError(
            (
                "PERFORMANCE_BASELINE_MISSING"
                if name == "baseline"
                else "PERFORMANCE_HARNESS_ERROR"
            ),
            f"{name} contains no benchmark results",
        )
    benchmarks: dict[str, _ASVBenchmarkResult] = {}
    for benchmark_name, raw_values in results.items():
        if not isinstance(benchmark_name, str) or not benchmark_name:
            raise PerformanceEvaluationError(
                "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} benchmark name is invalid"
            )
        if (
            not isinstance(raw_values, list)
            or len(raw_values) < 3
            or len(raw_values) > len(columns)
        ):
            raise PerformanceEvaluationError(
                "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} benchmark row is invalid"
            )
        # ASV's compact v2 writer may omit trailing null columns from a row.
        values = dict(zip(columns, raw_values))
        if values["params"] != []:
            raise PerformanceEvaluationError(
                "PERFORMANCE_ASV_SCHEMA_MISMATCH",
                "parameterized ASV benchmarks require separately named policy checks",
            )
        result_values = values["result"]
        sample_values = values.get("samples")
        version = values["version"]
        if not isinstance(result_values, list) or len(result_values) != 1:
            raise PerformanceEvaluationError(
                "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} result value is invalid"
            )
        if not isinstance(version, str) or not version:
            raise PerformanceEvaluationError(
                "PERFORMANCE_BENCHMARK_VERSION_MISMATCH",
                f"{name} benchmark version is missing",
            )
        median = (
            None
            if result_values[0] is None
            else _performance_decimal(result_values[0], f"{name} median")
        )
        if sample_values is None and median is None:
            samples_raw = None
        elif not isinstance(sample_values, list) or len(sample_values) != 1:
            raise PerformanceEvaluationError(
                "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} samples are invalid"
            )
        else:
            samples_raw = sample_values[0]
        if samples_raw is None:
            samples: tuple[Decimal, ...] = ()
        elif isinstance(samples_raw, list):
            samples = tuple(
                _performance_decimal(item, f"{name} sample") for item in samples_raw
            )
        else:
            raise PerformanceEvaluationError(
                "PERFORMANCE_ASV_SCHEMA_MISMATCH", f"{name} samples are invalid"
            )
        benchmarks[benchmark_name] = _ASVBenchmarkResult(
            name=benchmark_name,
            median=median,
            version=version,
            samples=samples,
        )
    return _ASVRun(
        params=params,
        python=raw["python"],
        requirements=requirements,
        env_name=raw["env_name"],
        env_vars=env_vars,
        benchmarks=benchmarks,
    )


def _controlled_runner(
    artifact: EvidenceArtifact,
) -> tuple[str, tuple[str, ...], str | None]:
    raw = _performance_json_object(artifact, "controlled runner output")
    expected = {
        "schema_version",
        "asv_version",
        "controlled",
        "environment_fingerprint",
        "interleave_order",
        "harness_error",
    }
    if set(raw) != expected or raw["schema_version"] != _PERFORMANCE_RUNNER_SCHEMA_VERSION:
        raise PerformanceEvaluationError(
            "PERFORMANCE_HARNESS_ERROR", "controlled runner output has an invalid schema"
        )
    if raw["asv_version"] != PINNED_ASV_VERSION:
        raise PerformanceEvaluationError(
            "PERFORMANCE_ASV_VERSION_MISMATCH", "ASV version does not match the pin"
        )
    if raw["controlled"] is not True:
        raise PerformanceEvaluationError(
            "PERFORMANCE_RUNNER_MISMATCH", "runner is not declared controlled"
        )
    fingerprint = raw["environment_fingerprint"]
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        raise PerformanceEvaluationError(
            "PERFORMANCE_ENVIRONMENT_MISMATCH", "environment fingerprint is invalid"
        )
    order = raw["interleave_order"]
    if (
        not isinstance(order, list)
        or len(order) < 2
        or any(
            not isinstance(item, str) or item not in {"baseline", "candidate"}
            for item in order
        )
        or order.count("baseline") != order.count("candidate")
        or any(left == right for left, right in zip(order, order[1:]))
    ):
        raise PerformanceEvaluationError(
            "PERFORMANCE_NOT_INTERLEAVED",
            "baseline and candidate were not run in alternating order",
        )
    harness_error = raw["harness_error"]
    if harness_error is not None and (
        not isinstance(harness_error, str) or not harness_error.strip()
    ):
        raise PerformanceEvaluationError(
            "PERFORMANCE_HARNESS_ERROR", "harness error must be text or null"
        )
    return fingerprint, tuple(order), harness_error


def _mann_whitney_decimal_samples(
    values: Iterable[int | float | Decimal], name: str
) -> tuple[Decimal, ...]:
    samples: list[Decimal] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
            raise TypeError(f"{name} samples must be numbers")
        sample = Decimal(str(value))
        if not sample.is_finite():
            raise ValueError(f"{name} samples must be finite")
        samples.append(sample)
    if not samples:
        raise ValueError(f"{name} samples must not be empty")
    return tuple(samples)


def mann_whitney_u_two_sided(
    first: Iterable[int | float | Decimal],
    second: Iterable[int | float | Decimal],
) -> MannWhitneyResult:
    """Return a two-sided asymptotic U test with ties and continuity correction.

    The approximation is policy-owned and only used after the six-sample floor.
    Ranks and tie variance are exact integer/Fraction arithmetic; only the final
    normal survival function uses ``math.erfc``.
    """
    first_samples = _mann_whitney_decimal_samples(first, "first")
    second_samples = _mann_whitney_decimal_samples(second, "second")
    tagged = sorted(
        [(value, 0) for value in first_samples]
        + [(value, 1) for value in second_samples],
        key=lambda item: item[0],
    )
    rank_sum_twice = 0
    tie_term = 0
    start = 0
    while start < len(tagged):
        end = start + 1
        while end < len(tagged) and tagged[end][0] == tagged[start][0]:
            end += 1
        doubled_rank = start + end + 1
        rank_sum_twice += doubled_rank * sum(
            group == 0 for _, group in tagged[start:end]
        )
        tie_count = end - start
        tie_term += tie_count**3 - tie_count
        start = end
    n_first = len(first_samples)
    n_second = len(second_samples)
    total = n_first + n_second
    u_first_twice = rank_sum_twice - n_first * (n_first + 1)
    u_second_twice = 2 * n_first * n_second - u_first_twice
    u_twice = min(u_first_twice, u_second_twice)
    variance = Fraction(n_first * n_second, 12) * (
        Fraction(total + 1) - Fraction(tie_term, total * (total - 1))
    )
    if variance == 0:
        z = 0.0
        p_value = 1.0
    else:
        mean_u = Fraction(n_first * n_second, 2)
        distance = abs(Fraction(u_twice, 2) - mean_u)
        corrected = max(Fraction(0), distance - Fraction(1, 2))
        z = float(corrected) / math.sqrt(float(variance))
        p_value = min(1.0, math.erfc(z / math.sqrt(2.0)))
    return MannWhitneyResult(
        u=Decimal(u_twice) / Decimal(2),
        variance=variance,
        z=Decimal(str(z)),
        p_value=Decimal(str(p_value)),
    )


def _sample_summary(samples: tuple[Decimal, ...]) -> PerformanceSampleSummary:
    return PerformanceSampleSummary(
        samples=samples,
        minimum=min(samples),
        maximum=max(samples),
    )


def _performance_result(
    *,
    status: CheckStatus,
    reason_code: str,
    artifacts: tuple[EvidenceArtifact, ...],
    comparisons: tuple[PerformanceBenchmarkComparison, ...],
) -> CheckResult:
    evidence: list[Mapping[str, str]] = list(_artifact_references(artifacts))
    for item in comparisons:
        evidence.extend(
            (
                {"kind": "benchmark", "value": item.name},
                {"kind": "baseline_median", "value": str(item.baseline_median)},
                {"kind": "baseline_sample_count", "value": str(item.baseline.count)},
                {"kind": "baseline_minimum", "value": str(item.baseline.minimum)},
                {"kind": "baseline_maximum", "value": str(item.baseline.maximum)},
            )
        )
        if item.candidate_median is not None and item.candidate is not None:
            evidence.extend(
                (
                    {"kind": "candidate_median", "value": str(item.candidate_median)},
                    {"kind": "candidate_sample_count", "value": str(item.candidate.count)},
                    {"kind": "candidate_minimum", "value": str(item.candidate.minimum)},
                    {"kind": "candidate_maximum", "value": str(item.candidate.maximum)},
                )
            )
        if item.mann_whitney is not None:
            evidence.extend(
                (
                    {"kind": "mann_whitney_u", "value": str(item.mann_whitney.u)},
                    {"kind": "mann_whitney_p", "value": str(item.mann_whitney.p_value)},
                )
            )
    return CheckResult(
        id=_PERFORMANCE_CONTROL_CHECK_ID,
        status=status,
        score_bps=(10000 if status is CheckStatus.PASS else 0)
        if status in {CheckStatus.PASS, CheckStatus.FAIL}
        else None,
        reason_code=reason_code,
        evidence=tuple(evidence),
    )


def _failed_performance_evaluation(
    reason_code: str,
    artifacts: tuple[EvidenceArtifact, ...],
) -> PerformanceEvaluation:
    return PerformanceEvaluation(
        asv_version=PINNED_ASV_VERSION,
        environment_fingerprint="unknown",
        comparisons=(),
        checks=(
            _error_result(
                _PERFORMANCE_CONTROL_CHECK_ID,
                reason_code,
                artifacts,
                status=CheckStatus.ERROR,
            ),
        ),
    )


def evaluate_performance_evidence(
    *,
    runner_output: EvidenceArtifact,
    baseline_asv: EvidenceArtifact | None,
    candidate_asv: EvidenceArtifact,
) -> PerformanceEvaluation:
    """Evaluate pinned, interleaved ASV results without collecting benchmarks."""
    supplied = tuple(
        item
        for item in (runner_output, baseline_asv, candidate_asv)
        if isinstance(item, EvidenceArtifact)
    )
    if not isinstance(runner_output, EvidenceArtifact):
        raise TypeError("runner_output must be an EvidenceArtifact")
    if baseline_asv is not None and not isinstance(baseline_asv, EvidenceArtifact):
        raise TypeError("baseline_asv must be an EvidenceArtifact or None")
    if not isinstance(candidate_asv, EvidenceArtifact):
        raise TypeError("candidate_asv must be an EvidenceArtifact")
    if baseline_asv is None:
        return _failed_performance_evaluation("PERFORMANCE_BASELINE_MISSING", supplied)
    try:
        fingerprint, _, harness_error = _controlled_runner(runner_output)
        if harness_error is not None:
            raise PerformanceEvaluationError(
                "PERFORMANCE_HARNESS_ERROR", "controlled runner reported a harness error"
            )
        baseline = _asv_run(baseline_asv, "baseline")
        candidate = _asv_run(candidate_asv, "candidate")
        run_fingerprint = baseline.params.get("environment_fingerprint")
        if (
            run_fingerprint != fingerprint
            or candidate.params.get("environment_fingerprint") != fingerprint
        ):
            raise PerformanceEvaluationError(
                "PERFORMANCE_ENVIRONMENT_MISMATCH", "ASV environment fingerprints do not match"
            )
        if baseline.params != candidate.params:
            raise PerformanceEvaluationError(
                "PERFORMANCE_RUNNER_MISMATCH", "ASV machine parameters do not match"
            )
        if (
            baseline.python != candidate.python
            or baseline.requirements != candidate.requirements
            or baseline.env_name != candidate.env_name
            or baseline.env_vars != candidate.env_vars
        ):
            raise PerformanceEvaluationError(
                "PERFORMANCE_ENVIRONMENT_MISMATCH", "ASV environments do not match"
            )
        if set(baseline.benchmarks) != set(candidate.benchmarks):
            raise PerformanceEvaluationError(
                "PERFORMANCE_HARNESS_ERROR", "baseline and candidate benchmark sets differ"
            )
        comparisons: list[PerformanceBenchmarkComparison] = []
        for benchmark_name in sorted(baseline.benchmarks):
            before = baseline.benchmarks[benchmark_name]
            after = candidate.benchmarks[benchmark_name]
            if before.version != after.version:
                raise PerformanceEvaluationError(
                    "PERFORMANCE_BENCHMARK_VERSION_MISMATCH",
                    f"benchmark version changed for {benchmark_name}",
                )
            if before.median is None or not before.samples:
                raise PerformanceEvaluationError(
                    "PERFORMANCE_BASELINE_MISSING",
                    f"successful baseline is missing for {benchmark_name}",
                )
            baseline_summary = _sample_summary(before.samples)
            if after.median is None:
                comparisons.append(
                    PerformanceBenchmarkComparison(
                        name=benchmark_name,
                        benchmark_version=before.version,
                        baseline_median=before.median,
                        candidate_median=None,
                        baseline=baseline_summary,
                        candidate=None,
                        mann_whitney=None,
                        status=CheckStatus.FAIL,
                        reason_code="PERFORMANCE_CANDIDATE_FUNCTIONAL_FAILURE",
                    )
                )
                continue
            if not after.samples:
                raise PerformanceEvaluationError(
                    "PERFORMANCE_HARNESS_ERROR",
                    f"candidate samples are missing for {benchmark_name}",
                )
            candidate_summary = _sample_summary(after.samples)
            if (
                baseline_summary.count < _PERFORMANCE_MIN_SAMPLES
                or candidate_summary.count < _PERFORMANCE_MIN_SAMPLES
            ):
                status = CheckStatus.UNKNOWN
                reason_code = "PERFORMANCE_INSUFFICIENT_SAMPLES"
                statistic = None
            elif after.median <= before.median * _PERFORMANCE_MAGNITUDE_FACTOR:
                status = CheckStatus.PASS
                reason_code = "PERFORMANCE_NO_HARD_REGRESSION"
                statistic = None
            else:
                statistic = mann_whitney_u_two_sided(before.samples, after.samples)
                if statistic.p_value < _PERFORMANCE_P_THRESHOLD:
                    status = CheckStatus.FAIL
                    reason_code = "PERFORMANCE_SIGNIFICANT_REGRESSION"
                else:
                    status = CheckStatus.UNKNOWN
                    reason_code = "PERFORMANCE_REGRESSION_INCONCLUSIVE"
            comparisons.append(
                PerformanceBenchmarkComparison(
                    name=benchmark_name,
                    benchmark_version=before.version,
                    baseline_median=before.median,
                    candidate_median=after.median,
                    baseline=baseline_summary,
                    candidate=candidate_summary,
                    mann_whitney=statistic,
                    status=status,
                    reason_code=reason_code,
                )
            )
    except PerformanceEvaluationError as exc:
        return _failed_performance_evaluation(exc.reason_code, supplied)
    normalized = tuple(comparisons)
    failures = tuple(item for item in normalized if item.status is CheckStatus.FAIL)
    unresolved = tuple(item for item in normalized if item.status is CheckStatus.UNKNOWN)
    if failures:
        status = CheckStatus.FAIL
        reason_code = (
            "PERFORMANCE_CANDIDATE_FUNCTIONAL_FAILURE"
            if any(
                item.reason_code == "PERFORMANCE_CANDIDATE_FUNCTIONAL_FAILURE"
                for item in failures
            )
            else "PERFORMANCE_SIGNIFICANT_REGRESSION"
        )
    elif unresolved:
        status = CheckStatus.UNKNOWN
        reason_code = (
            "PERFORMANCE_INSUFFICIENT_SAMPLES"
            if any(
                item.reason_code == "PERFORMANCE_INSUFFICIENT_SAMPLES"
                for item in unresolved
            )
            else "PERFORMANCE_REGRESSION_INCONCLUSIVE"
        )
    else:
        status = CheckStatus.PASS
        reason_code = "PERFORMANCE_NO_HARD_REGRESSION"
    check = _performance_result(
        status=status,
        reason_code=reason_code,
        artifacts=supplied,
        comparisons=normalized,
    )
    return PerformanceEvaluation(
        asv_version=PINNED_ASV_VERSION,
        environment_fingerprint=fingerprint,
        comparisons=normalized,
        checks=(check,),
    )


def evaluate_live_network_latency(artifact: EvidenceArtifact) -> CheckResult:
    """Validate and retain latency diagnostics without applying a threshold."""
    if not isinstance(artifact, EvidenceArtifact):
        raise TypeError("artifact must be an EvidenceArtifact")
    try:
        raw = _performance_json_object(artifact, "live network latency")
        if (
            set(raw) != {"schema_version", "measurements"}
            or raw["schema_version"] != _LIVE_LATENCY_SCHEMA_VERSION
        ):
            raise PerformanceEvaluationError(
                "PERFORMANCE_LATENCY_HARNESS_ERROR",
                "latency evidence has an invalid schema",
            )
        measurements = raw["measurements"]
        if not isinstance(measurements, list) or not measurements:
            raise PerformanceEvaluationError(
                "PERFORMANCE_LATENCY_UNAVAILABLE", "latency evidence has no measurements"
            )
        evidence: list[Mapping[str, str]] = list(_artifact_references((artifact,)))
        sample_count = 0
        for measurement in measurements:
            if not isinstance(measurement, Mapping) or set(measurement) != {
                "endpoint",
                "samples_ms",
            }:
                raise PerformanceEvaluationError(
                    "PERFORMANCE_LATENCY_HARNESS_ERROR", "latency measurement is invalid"
                )
            endpoint = measurement["endpoint"]
            samples = measurement["samples_ms"]
            if (
                not isinstance(endpoint, str)
                or not endpoint
                or not isinstance(samples, list)
                or not samples
            ):
                raise PerformanceEvaluationError(
                    "PERFORMANCE_LATENCY_UNAVAILABLE", "latency measurement is incomplete"
                )
            parsed = tuple(
                _performance_decimal(item, "latency sample") for item in samples
            )
            sample_count += len(parsed)
            evidence.extend(
                (
                    {"kind": "endpoint", "value": endpoint},
                    {"kind": "sample_count", "value": str(len(parsed))},
                    {"kind": "minimum_ms", "value": str(min(parsed))},
                    {"kind": "maximum_ms", "value": str(max(parsed))},
                )
            )
        return CheckResult(
            id=_PERFORMANCE_LATENCY_CHECK_ID,
            status=CheckStatus.PASS,
            score_bps=10000,
            reason_code="PERFORMANCE_LATENCY_OBSERVED_ADVISORY",
            numerator=sample_count,
            denominator=sample_count,
            evidence=tuple(evidence),
        )
    except PerformanceEvaluationError as exc:
        return _error_result(
            _PERFORMANCE_LATENCY_CHECK_ID,
            exc.reason_code,
            (artifact,),
            status=CheckStatus.UNKNOWN,
        )


SourceIdentity = tuple[str, str, str, str, int, int]


class RetrievalEvaluationError(ValueError):
    """A stable evaluation error for malformed or mismatched retrieval evidence."""

    def __init__(self, reason_code: str, message: str) -> None:
        if not _REASON_CODE.fullmatch(reason_code):
            raise ValueError("retrieval error reason must be uppercase snake-case")
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class RetrievalMetrics:
    """Per-task or macro-averaged IR metrics on the unit interval."""

    ndcg_at_10: float
    reciprocal_rank_at_10: float
    success_at_1: float
    success_at_5: float
    success_at_10: float
    recall_at_10: float
    precision_at_5: float | None
    precision_at_10: float | None
    average_precision_at_10: float | None

    def __post_init__(self) -> None:
        for name in (
            "ndcg_at_10",
            "reciprocal_rank_at_10",
            "success_at_1",
            "success_at_5",
            "success_at_10",
            "recall_at_10",
            "precision_at_5",
            "precision_at_10",
            "average_precision_at_10",
        ):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.0 <= value <= 1.0
            ):
                raise ValueError(f"{name} must be null or a finite unit-interval value")

    def to_bps_dict(self) -> dict[str, int | None]:
        return {
            name: _metric_bps(getattr(self, name))
            for name in (
                "ndcg_at_10",
                "reciprocal_rank_at_10",
                "success_at_1",
                "success_at_5",
                "success_at_10",
                "recall_at_10",
                "precision_at_5",
                "precision_at_10",
                "average_precision_at_10",
            )
        }


@dataclass(frozen=True, slots=True)
class RetrievalTaskEvaluation:
    task_id: str
    language: str
    predicate_kinds: tuple[str, ...]
    judgments_complete: bool
    metrics: RetrievalMetrics
    exact_target_rank: int | None
    result_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "language": self.language,
            "predicate_kinds": list(self.predicate_kinds),
            "judgments_complete": self.judgments_complete,
            "metrics_bps": self.metrics.to_bps_dict(),
            "exact_target_rank": self.exact_target_rank,
            "result_count": self.result_count,
        }


@dataclass(frozen=True, slots=True)
class RetrievalStratum:
    kind: str
    value: str
    task_ids: tuple[str, ...]
    complete_task_count: int
    metrics: RetrievalMetrics

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "task_ids": list(self.task_ids),
            "task_count": len(self.task_ids),
            "complete_task_count": self.complete_task_count,
            "metrics_bps": self.metrics.to_bps_dict(),
        }


@dataclass(frozen=True, slots=True)
class RetrievalCrossCheck:
    """Optional pinned ir_measures/pytrec comparison of S4's metric kernel."""

    status: str
    reason_code: str
    installed_versions: tuple[tuple[str, str], ...]
    standard_library_bps: tuple[tuple[str, int], ...]
    authoritative_bps: tuple[tuple[str, int], ...]
    disagreements: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"agree", "disagree", "skipped", "error"}:
            raise ValueError("retrieval cross-check status is invalid")
        if not _REASON_CODE.fullmatch(self.reason_code):
            raise ValueError("retrieval cross-check reason code is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "installed_versions": dict(self.installed_versions),
            "standard_library_bps": dict(self.standard_library_bps),
            "authoritative_bps": dict(self.authoritative_bps),
            "disagreements": list(self.disagreements),
        }


@dataclass(frozen=True, slots=True)
class RetrievalEvaluation:
    benchmark_id: str
    manifest_sha256: str
    aggregate: RetrievalMetrics
    tasks: tuple[RetrievalTaskEvaluation, ...]
    language_strata: tuple[RetrievalStratum, ...]
    predicate_strata: tuple[RetrievalStratum, ...]
    checks: tuple[CheckResult, ...]
    authoritative_qrels: Mapping[str, Mapping[str, int]]
    authoritative_run: Mapping[str, Mapping[str, int]]
    cross_check: RetrievalCrossCheck

    def to_dict(self) -> dict[str, object]:
        return {
            "benchmark": {
                "id": self.benchmark_id,
                "manifest_sha256": self.manifest_sha256,
            },
            "aggregate_metrics_bps": self.aggregate.to_bps_dict(),
            "tasks": [item.to_dict() for item in self.tasks],
            "strata": {
                "language": [item.to_dict() for item in self.language_strata],
                "predicate": [item.to_dict() for item in self.predicate_strata],
            },
            "authoritative_cross_check": self.cross_check.to_dict(),
        }


def _metric_bps(value: float | None) -> int | None:
    if value is None:
        return None
    return int(
        (Decimal(str(value)) * Decimal(10000)).quantize(
            Decimal("1"), rounding=ROUND_HALF_UP
        )
    )


def _validate_source_identity(identity: object, name: str) -> SourceIdentity:
    if not isinstance(identity, tuple) or len(identity) != 6:
        raise TypeError(f"{name} must be a six-field SourceRef tuple")
    slug, commit_sha, path, blob_sha, start_line, end_line = identity
    if not isinstance(slug, str) or not _REPO_SLUG.fullmatch(slug):
        raise ValueError(f"{name} repository slug is invalid")
    if not isinstance(commit_sha, str) or not _SHA1.fullmatch(commit_sha):
        raise ValueError(f"{name} commit_sha is invalid")
    _validate_canonical_path(path, f"{name} path")
    if not isinstance(blob_sha, str) or not _SHA1.fullmatch(blob_sha):
        raise ValueError(f"{name} blob_sha is invalid")
    if (
        not _is_int(start_line)
        or not _is_int(end_line)
        or start_line < 1
        or end_line < start_line
    ):
        raise ValueError(f"{name} line span is invalid")
    return identity


def _source_identity_from_qrel(raw: object, name: str) -> SourceIdentity:
    source = _object_keys(
        raw,
        {"slug", "commit_sha", "path", "blob_sha", "start_line", "end_line"},
        name,
    )
    identity = (
        source["slug"],
        source["commit_sha"],
        source["path"],
        source["blob_sha"],
        source["start_line"],
        source["end_line"],
    )
    try:
        return _validate_source_identity(identity, name)
    except (TypeError, ValueError) as exc:
        raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", str(exc)) from exc


def _source_identity_text(identity: SourceIdentity) -> str:
    return _canonical_json(list(identity))


def compute_retrieval_metrics(
    ranked_result_ids: tuple[SourceIdentity, ...],
    judgments: Mapping[SourceIdentity, int],
    *,
    judgments_complete: bool,
) -> RetrievalMetrics:
    """Compute ADR-002's standard-library metric kernel for one task.

    nDCG uses the qrel grade itself as linear gain.  Unjudged results have gain
    zero and retain their rank.  Binary useful relevance is grade >= 1, while
    exact-target RR and Success use grade >= 2.
    """
    if not isinstance(ranked_result_ids, tuple):
        raise TypeError("ranked_result_ids must be a tuple")
    normalized_results = tuple(
        _validate_source_identity(item, "ranked result identity")
        for item in ranked_result_ids
    )
    if len(set(normalized_results)) != len(normalized_results):
        raise ValueError("ranked results contain duplicate SourceRef identities")
    if not isinstance(judgments, Mapping):
        raise TypeError("judgments must be a mapping")
    normalized_judgments: dict[SourceIdentity, int] = {}
    for identity, grade in judgments.items():
        checked = _validate_source_identity(identity, "qrel identity")
        if not _is_int(grade) or grade not in {0, 1, 2}:
            raise ValueError("qrel grade must be 0, 1, or 2")
        normalized_judgments[checked] = grade
    if 2 not in normalized_judgments.values():
        raise ValueError("every scored task requires at least one grade-2 target")
    if not isinstance(judgments_complete, bool):
        raise TypeError("judgments_complete must be a bool")

    top_ten = normalized_results[:_RETRIEVAL_CUTOFF]
    gains = [normalized_judgments.get(identity, 0) for identity in top_ten]
    dcg = math.fsum(
        gain / math.log2(rank + 1)
        for rank, gain in enumerate(gains, start=1)
    )
    ideal_gains = sorted(normalized_judgments.values(), reverse=True)[:_RETRIEVAL_CUTOFF]
    ideal_dcg = math.fsum(
        gain / math.log2(rank + 1)
        for rank, gain in enumerate(ideal_gains, start=1)
    )
    ndcg = dcg / ideal_dcg

    exact_rank = next(
        (
            rank
            for rank, identity in enumerate(top_ten, start=1)
            if normalized_judgments.get(identity, 0) == 2
        ),
        None,
    )
    useful_total = sum(grade >= 1 for grade in normalized_judgments.values())
    useful_hits = [normalized_judgments.get(identity, 0) >= 1 for identity in top_ten]
    recall = sum(useful_hits) / useful_total

    precision_at_5: float | None = None
    precision_at_10: float | None = None
    average_precision_at_10: float | None = None
    if judgments_complete:
        precision_at_5 = sum(useful_hits[:5]) / 5
        precision_at_10 = sum(useful_hits) / 10
        hits = 0
        precision_sum = 0.0
        for rank, relevant in enumerate(useful_hits, start=1):
            if relevant:
                hits += 1
                precision_sum += hits / rank
        average_precision_at_10 = precision_sum / min(useful_total, _RETRIEVAL_CUTOFF)

    return RetrievalMetrics(
        ndcg_at_10=ndcg,
        reciprocal_rank_at_10=0.0 if exact_rank is None else 1.0 / exact_rank,
        success_at_1=float(exact_rank == 1),
        success_at_5=float(exact_rank is not None and exact_rank <= 5),
        success_at_10=float(exact_rank is not None),
        recall_at_10=recall,
        precision_at_5=precision_at_5,
        precision_at_10=precision_at_10,
        average_precision_at_10=average_precision_at_10,
    )


def _macro_metrics(tasks: tuple[RetrievalTaskEvaluation, ...]) -> RetrievalMetrics:
    if not tasks:
        raise ValueError("metric aggregation requires at least one task")

    def mean(name: str, *, complete_only: bool = False) -> float | None:
        values = [
            getattr(item.metrics, name)
            for item in tasks
            if not complete_only or item.judgments_complete
        ]
        known = [value for value in values if value is not None]
        return None if not known else math.fsum(known) / len(known)

    return RetrievalMetrics(
        ndcg_at_10=mean("ndcg_at_10") or 0.0,
        reciprocal_rank_at_10=mean("reciprocal_rank_at_10") or 0.0,
        success_at_1=mean("success_at_1") or 0.0,
        success_at_5=mean("success_at_5") or 0.0,
        success_at_10=mean("success_at_10") or 0.0,
        recall_at_10=mean("recall_at_10") or 0.0,
        precision_at_5=mean("precision_at_5", complete_only=True),
        precision_at_10=mean("precision_at_10", complete_only=True),
        average_precision_at_10=mean("average_precision_at_10", complete_only=True),
    )


def _manifest_contract(
    artifact: EvidenceArtifact,
) -> tuple[str, str, dict[str, tuple[str, tuple[str, ...], frozenset[SourceIdentity]]]]:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark manifest"),
        {"schema_version", "benchmark_id", "tasks"},
        "benchmark manifest",
    )
    if raw["schema_version"] != _BENCHMARK_MANIFEST_SCHEMA_VERSION:
        raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "unsupported manifest schema")
    benchmark_id = raw["benchmark_id"]
    if not isinstance(benchmark_id, str) or not _TASK_ID.fullmatch(benchmark_id):
        raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid benchmark ID")
    tasks_raw = _list_value(raw["tasks"], "manifest tasks", nonempty=True)
    normalized_tasks: list[dict[str, object]] = []
    tasks: dict[str, tuple[str, tuple[str, ...], frozenset[SourceIdentity]]] = {}
    language_counts = {language: 0 for language in _RETRIEVAL_LANGUAGES}
    for task in tasks_raw:
        task_raw = _object_keys(
            task,
            {"id", "language", "scope", "must", "should", "must_not", "expected_results", "pin_source"},
            "manifest task",
        )
        task_id = task_raw["id"]
        language = task_raw["language"]
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid manifest task ID")
        if task_id in tasks:
            raise RetrievalEvaluationError("DUPLICATE_TASK_ID", "manifest task IDs must be unique")
        if language not in language_counts:
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid task language")
        language_counts[language] += 1
        scope = _object_keys(task_raw["scope"], {"slug", "commit_sha"}, "task scope")
        scope_slug = scope["slug"]
        scope_commit = scope["commit_sha"]
        if not isinstance(scope_slug, str) or not _REPO_SLUG.fullmatch(scope_slug):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid task scope slug")
        if not isinstance(scope_commit, str) or not _SHA1.fullmatch(scope_commit):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid task scope commit")
        predicate_kinds: set[str] = set()
        for field_name in ("must", "should", "must_not"):
            for predicate in _list_value(task_raw[field_name], f"task {field_name}"):
                if not isinstance(predicate, Mapping) or set(predicate) not in (
                    {"kind", "value"},
                    {"kind", "value", "language"},
                ):
                    raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "predicate has an invalid field set")
                predicate_raw = predicate
                kind = predicate_raw["kind"]
                if not isinstance(kind, str) or not kind:
                    raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid predicate kind")
                if not isinstance(predicate_raw["value"], str) or not predicate_raw["value"]:
                    raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid predicate value")
                predicate_language = predicate_raw.get("language")
                if predicate_language is not None and (
                    not isinstance(predicate_language, str) or not predicate_language
                ):
                    raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid predicate language")
                predicate_kinds.add(kind)
        if not predicate_kinds:
            raise RetrievalEvaluationError("PREDICATE_STRATUM_MISSING", "manifest task has no predicate stratum")
        if not isinstance(task_raw["pin_source"], str) or not task_raw["pin_source"].strip():
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "manifest pin_source must be nonempty text")
        expected_list = _list_value(task_raw["expected_results"], "expected results", nonempty=True)
        expected = frozenset(
            _source_identity_from_qrel(item, "expected result") for item in expected_list
        )
        if len(expected) != len(expected_list):
            raise RetrievalEvaluationError("DUPLICATE_QREL_ID", "expected result identities must be unique")
        if any(identity[:2] != (scope_slug, scope_commit) for identity in expected):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "expected result is outside task scope")
        tasks[task_id] = (language, tuple(sorted(predicate_kinds)), expected)
        normalized_task = dict(task_raw)
        normalized_expected = []
        for identity in sorted(expected):
            slug, commit_sha, path, blob_sha, start_line, end_line = identity
            normalized_expected.append(
                {
                    "slug": slug,
                    "commit_sha": commit_sha,
                    "path": path,
                    "blob_sha": blob_sha,
                    "start_line": start_line,
                    "end_line": end_line,
                    "permalink": (
                        f"https://github.com/{slug}/blob/{commit_sha}/{path}"
                        f"#L{start_line}-L{end_line}"
                    ),
                }
            )
        normalized_task["expected_results"] = normalized_expected
        normalized_tasks.append(normalized_task)
    if any(count < 4 for count in language_counts.values()):
        raise RetrievalEvaluationError("LANGUAGE_STRATUM_MISSING", "manifest requires at least four tasks per language")
    normalized = dict(raw)
    normalized["tasks"] = sorted(normalized_tasks, key=lambda item: item["id"])
    digest = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    return benchmark_id, digest, tasks


def _qrels_contract(
    artifact: EvidenceArtifact,
    *,
    benchmark_id: str,
    manifest_sha256: str,
    manifest_tasks: Mapping[str, tuple[str, tuple[str, ...], frozenset[SourceIdentity]]],
) -> dict[str, tuple[bool, dict[SourceIdentity, int]]]:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark qrels"),
        {"schema_version", "benchmark", "tasks"},
        "benchmark qrels",
    )
    if raw["schema_version"] != _BENCHMARK_QRELS_SCHEMA_VERSION:
        raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "unsupported qrels schema")
    benchmark = _object_keys(raw["benchmark"], {"id", "manifest_sha256"}, "qrels benchmark")
    if benchmark != {"id": benchmark_id, "manifest_sha256": manifest_sha256}:
        raise RetrievalEvaluationError("MANIFEST_DIGEST_MISMATCH", "qrels benchmark identity does not match manifest")
    tasks: dict[str, tuple[bool, dict[SourceIdentity, int]]] = {}
    for task in _list_value(raw["tasks"], "qrel tasks", nonempty=True):
        task_raw = _object_keys(task, {"task_id", "judgments_complete", "judgments"}, "qrel task")
        task_id = task_raw["task_id"]
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid qrel task ID")
        if task_id in tasks:
            raise RetrievalEvaluationError("DUPLICATE_TASK_ID", "qrel task IDs must be unique")
        complete = task_raw["judgments_complete"]
        if not isinstance(complete, bool):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "judgments_complete must be a bool")
        judgments: dict[SourceIdentity, int] = {}
        for judgment in _list_value(task_raw["judgments"], "qrel judgments", nonempty=True):
            judgment_raw = _object_keys(judgment, {"grade", "source"}, "qrel judgment")
            grade = judgment_raw["grade"]
            if not _is_int(grade) or grade not in {0, 1, 2}:
                raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "qrel grade must be 0, 1, or 2")
            identity = _source_identity_from_qrel(judgment_raw["source"], "qrel source")
            if identity in judgments:
                raise RetrievalEvaluationError("DUPLICATE_QREL_ID", "qrel identities must be unique per task")
            judgments[identity] = grade
        expected = manifest_tasks.get(task_id)
        if expected is not None:
            scope = next(iter(expected[2]))[:2]
            if any(identity[:2] != scope for identity in judgments):
                raise RetrievalEvaluationError("QREL_SCOPE_MISMATCH", "qrel source is outside the task scope")
            grade_two = frozenset(identity for identity, grade in judgments.items() if grade == 2)
            if grade_two != expected[2]:
                raise RetrievalEvaluationError("GRADE_TWO_TARGET_MISMATCH", "grade-2 qrels must exactly match manifest expected results")
        tasks[task_id] = (complete, judgments)
    if set(tasks) != set(manifest_tasks):
        raise RetrievalEvaluationError("TASK_SET_MISMATCH", "qrels task set must exactly equal manifest query set")
    return tasks


def _run_contract(
    artifact: EvidenceArtifact,
    *,
    benchmark_id: str,
    manifest_sha256: str,
    manifest_tasks: Mapping[str, tuple[str, tuple[str, ...], frozenset[SourceIdentity]]],
) -> tuple[dict[str, tuple[tuple[SourceIdentity, ...], tuple[int, ...]]], bool]:
    raw = _object_keys(
        _load_json_object(artifact, "benchmark run"),
        {"schema_version", "benchmark", "tasks"},
        "benchmark run",
    )
    if raw["schema_version"] != _BENCHMARK_RUN_SCHEMA_VERSION:
        raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "unsupported run schema")
    benchmark = _object_keys(raw["benchmark"], {"id", "manifest_sha256"}, "run benchmark")
    if benchmark != {"id": benchmark_id, "manifest_sha256": manifest_sha256}:
        raise RetrievalEvaluationError("MANIFEST_DIGEST_MISMATCH", "run benchmark identity does not match manifest")
    tasks: dict[str, tuple[tuple[SourceIdentity, ...], tuple[int, ...]]] = {}
    complete_coverage = True
    for task in _list_value(raw["tasks"], "run tasks", nonempty=True):
        task_raw = _object_keys(task, {"task_id", "language", "spec_digest", "coverage", "results"}, "run task")
        task_id = task_raw["task_id"]
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid run task ID")
        if task_id in tasks:
            raise RetrievalEvaluationError("DUPLICATE_TASK_ID", "run task IDs must be unique")
        manifest_task = manifest_tasks.get(task_id)
        if manifest_task is not None and task_raw["language"] != manifest_task[0]:
            raise RetrievalEvaluationError("TASK_LANGUAGE_MISMATCH", "run language does not match manifest")
        if not isinstance(task_raw["spec_digest"], str) or not _SHA256.fullmatch(task_raw["spec_digest"]):
            raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "invalid run spec digest")
        status, eligible, indexed, _excluded, incomplete = _coverage(task_raw["coverage"])
        complete_coverage &= status == "complete_for_declared_universe" and eligible == indexed and not incomplete
        identities: list[SourceIdentity] = []
        ordering_keys: list[tuple[object, ...]] = []
        ranks: list[int] = []
        rank_scores: list[int] = []
        for result in _list_value(task_raw["results"], "ranked results"):
            result_raw = _object_keys(result, {"source", "score", "normalized_score", "rank", "rank_score", "matched_kinds"}, "ranked result")
            _finite_json_decimal(result_raw["score"], "score")
            normalized = _finite_json_decimal(result_raw["normalized_score"], "normalized_score")
            if not Decimal(0) <= normalized <= Decimal(1):
                raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "normalized score is outside zero and one")
            try:
                identity = _source_identity_from_result(result)
                identity = _validate_source_identity(identity, "run result identity")
            except (TypeError, ValueError) as exc:
                raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", str(exc)) from exc
            if manifest_task is not None and identity[:2] != next(iter(manifest_task[2]))[:2]:
                raise RetrievalEvaluationError("RESULT_SCOPE_MISMATCH", "run result is outside the task scope")
            source = result_raw["source"]
            expected_permalink = (
                f"https://github.com/{identity[0]}/blob/{identity[1]}/{identity[2]}"
                f"#L{identity[4]}-L{identity[5]}"
            )
            if source["permalink"] != expected_permalink:
                raise RetrievalEvaluationError("RESULT_PROVENANCE_MISMATCH", "run result permalink does not match SourceRef")
            matched_kinds = result_raw["matched_kinds"]
            if not isinstance(matched_kinds, list) or not matched_kinds or any(
                not isinstance(kind, str) or not kind for kind in matched_kinds
            ):
                raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "matched_kinds must be a nonempty text list")
            rank = _non_negative_json_int(result_raw["rank"], "rank")
            rank_score = _non_negative_json_int(result_raw["rank_score"], "rank_score")
            if rank < 1 or rank_score < 1:
                raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", "rank and rank_score must be positive")
            identities.append(identity)
            ordering_keys.append((-normalized, *identity))
            ranks.append(rank)
            rank_scores.append(rank_score)
        if len(set(identities)) != len(identities):
            raise RetrievalEvaluationError("DUPLICATE_RESULT_ID", "run contains duplicate SourceRef identities")
        if ordering_keys != sorted(ordering_keys) or ranks != list(range(1, len(ranks) + 1)):
            raise RetrievalEvaluationError("RANKED_RUN_TOTAL_ORDER_INVALID", "run is not in P6 total order")
        if len(set(rank_scores)) != len(rank_scores) or any(
            left <= right for left, right in zip(rank_scores, rank_scores[1:])
        ):
            raise RetrievalEvaluationError("RANKED_RUN_TOTAL_ORDER_INVALID", "rank_score must be unique and strictly descending")
        tasks[task_id] = (tuple(identities), tuple(rank_scores))
    if set(tasks) != set(manifest_tasks):
        raise RetrievalEvaluationError("TASK_SET_MISMATCH", "run task set must exactly equal manifest query set")
    return tasks, complete_coverage


def _retrieval_strata(
    tasks: tuple[RetrievalTaskEvaluation, ...], kind: str
) -> tuple[RetrievalStratum, ...]:
    if kind == "language":
        values = sorted({item.language for item in tasks})
        selected = lambda item, value: item.language == value
    elif kind == "predicate":
        values = sorted({value for item in tasks for value in item.predicate_kinds})
        selected = lambda item, value: value in item.predicate_kinds
    else:
        raise ValueError("stratum kind must be language or predicate")
    strata = []
    for value in values:
        members = tuple(item for item in tasks if selected(item, value))
        strata.append(
            RetrievalStratum(
                kind=kind,
                value=value,
                task_ids=tuple(item.task_id for item in members),
                complete_task_count=sum(item.judgments_complete for item in members),
                metrics=_macro_metrics(members),
            )
        )
    return tuple(strata)


def _retrieval_metric_result(
    metric_name: str,
    value: float | None,
    artifacts: tuple[EvidenceArtifact, ...],
) -> CheckResult:
    check_id = f"output.{metric_name}"
    if value is None:
        return CheckResult(
            id=check_id,
            status=CheckStatus.NOT_APPLICABLE,
            score_bps=None,
            reason_code="QRELS_INSUFFICIENTLY_COMPLETE",
            evidence=_artifact_references(artifacts)
            + ({"kind": "applicability", "value": "no task has sufficiently complete qrels"},),
        )
    return CheckResult(
        id=check_id,
        status=CheckStatus.PASS,
        score_bps=_metric_bps(value),
        reason_code="RETRIEVAL_METRIC_COMPUTED",
        evidence=_artifact_references(artifacts),
    )


def _authoritative_retrieval_cross_check(
    aggregate: RetrievalMetrics,
    qrels: Mapping[str, Mapping[str, int]],
    run: Mapping[str, Mapping[str, int]],
) -> RetrievalCrossCheck:
    """Cross-check through the explicitly selected pytrec provider when present."""
    metric_names = (
        "ndcg_at_10",
        "reciprocal_rank_at_10",
        "success_at_1",
        "success_at_5",
        "success_at_10",
        "recall_at_10",
    )
    standard = tuple(
        (name, int(_metric_bps(getattr(aggregate, name)))) for name in metric_names
    )
    installed: dict[str, str] = {}
    missing: list[str] = []
    for distribution in ("ir_measures", "pytrec-eval-terrier"):
        try:
            installed[distribution] = importlib_metadata.version(distribution)
        except importlib_metadata.PackageNotFoundError:
            missing.append(distribution)
    versions = tuple(sorted(installed.items()))
    mismatched = tuple(
        name
        for name, version in versions
        if version != PINNED_SCORE_TOOL_VERSIONS[name]
    )
    if mismatched:
        return RetrievalCrossCheck(
            status="error",
            reason_code="RETRIEVAL_TOOL_VERSION_MISMATCH",
            installed_versions=versions,
            standard_library_bps=standard,
            authoritative_bps=(),
            disagreements=(),
        )
    if missing:
        return RetrievalCrossCheck(
            status="skipped",
            reason_code="SCORING_LOCK_NOT_INSTALLED",
            installed_versions=versions,
            standard_library_bps=standard,
            authoritative_bps=(),
            disagreements=(),
        )
    try:
        from ir_measures import RR, Recall, Success, nDCG
        from ir_measures.providers.pytrec_eval_provider import PytrecEvalProvider

        measure_pairs = (
            ("ndcg_at_10", nDCG @ 10),
            ("reciprocal_rank_at_10", RR(rel=2) @ 10),
            ("success_at_1", Success(rel=2) @ 1),
            ("success_at_5", Success(rel=2) @ 5),
            ("success_at_10", Success(rel=2) @ 10),
            ("recall_at_10", Recall(rel=1) @ 10),
        )
        measures = [measure for _, measure in measure_pairs]
        values = PytrecEvalProvider().evaluator(measures, dict(qrels)).calc_aggregate(
            dict(run)
        )
        authoritative = tuple(
            (name, int(_metric_bps(float(values[measure]))))
            for name, measure in measure_pairs
        )
    except Exception:
        return RetrievalCrossCheck(
            status="error",
            reason_code="AUTHORITATIVE_RETRIEVAL_CROSS_CHECK_ERROR",
            installed_versions=versions,
            standard_library_bps=standard,
            authoritative_bps=(),
            disagreements=(),
        )
    standard_map = dict(standard)
    authoritative_map = dict(authoritative)
    disagreements = tuple(
        name for name in metric_names if standard_map[name] != authoritative_map[name]
    )
    return RetrievalCrossCheck(
        status="disagree" if disagreements else "agree",
        reason_code=(
            "AUTHORITATIVE_RETRIEVAL_DISAGREEMENT"
            if disagreements
            else "AUTHORITATIVE_RETRIEVAL_AGREEMENT"
        ),
        installed_versions=versions,
        standard_library_bps=standard,
        authoritative_bps=authoritative,
        disagreements=disagreements,
    )


def evaluate_retrieval(
    *,
    manifest: EvidenceArtifact,
    qrels: EvidenceArtifact,
    benchmark_run: EvidenceArtifact,
) -> RetrievalEvaluation:
    """Validate and score one P6 ranked benchmark artifact against pinned qrels."""
    artifacts = (manifest, qrels, benchmark_run)
    if any(not isinstance(item, EvidenceArtifact) for item in artifacts):
        raise TypeError("manifest, qrels, and benchmark_run must be EvidenceArtifact values")
    try:
        benchmark_id, manifest_sha256, manifest_tasks = _manifest_contract(manifest)
        qrel_tasks = _qrels_contract(
            qrels,
            benchmark_id=benchmark_id,
            manifest_sha256=manifest_sha256,
            manifest_tasks=manifest_tasks,
        )
        run_tasks, complete_coverage = _run_contract(
            benchmark_run,
            benchmark_id=benchmark_id,
            manifest_sha256=manifest_sha256,
            manifest_tasks=manifest_tasks,
        )
    except RetrievalEvaluationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise RetrievalEvaluationError("RETRIEVAL_EVIDENCE_MALFORMED", str(exc)) from exc

    task_evaluations: list[RetrievalTaskEvaluation] = []
    authoritative_qrels: dict[str, dict[str, int]] = {}
    authoritative_run: dict[str, dict[str, int]] = {}
    for task_id in sorted(manifest_tasks):
        language, predicates, _expected = manifest_tasks[task_id]
        judgments_complete, judgments = qrel_tasks[task_id]
        result_ids, rank_scores = run_tasks[task_id]
        metrics = compute_retrieval_metrics(
            result_ids, judgments, judgments_complete=judgments_complete
        )
        exact_rank = next(
            (
                rank
                for rank, identity in enumerate(result_ids, start=1)
                if judgments.get(identity) == 2
            ),
            None,
        )
        task_evaluations.append(
            RetrievalTaskEvaluation(
                task_id=task_id,
                language=language,
                predicate_kinds=predicates,
                judgments_complete=judgments_complete,
                metrics=metrics,
                exact_target_rank=exact_rank,
                result_count=len(result_ids),
            )
        )
        authoritative_qrels[task_id] = {
            _source_identity_text(identity): grade
            for identity, grade in sorted(judgments.items())
        }
        authoritative_run[task_id] = {
            _source_identity_text(identity): rank_score
            for identity, rank_score in zip(result_ids, rank_scores, strict=True)
        }
    tasks = tuple(task_evaluations)
    aggregate = _macro_metrics(tasks)
    language_strata = _retrieval_strata(tasks, "language")
    predicate_strata = _retrieval_strata(tasks, "predicate")
    exact_at_cutoff = sum(
        item.exact_target_rank is not None and item.exact_target_rank <= _RETRIEVAL_CUTOFF
        for item in tasks
    )
    checks = [
        _binary_result(
            "output.pinned_benchmark",
            True,
            pass_reason="PINNED_QRELS_QUERY_SET_VALID",
            fail_reason="PINNED_QRELS_QUERY_SET_INVALID",
            artifacts=artifacts,
        ),
        _binary_result(
            "output.complete_scoped_coverage",
            complete_coverage,
            pass_reason="SCOPED_BENCHMARK_COVERAGE_COMPLETE",
            fail_reason="SCOPED_BENCHMARK_COVERAGE_PARTIAL",
            artifacts=artifacts,
        ),
        _binary_result(
            "output.total_ordering",
            True,
            pass_reason="P6_TOTAL_ORDER_VALID",
            fail_reason="P6_TOTAL_ORDER_INVALID",
            artifacts=artifacts,
        ),
        CheckResult(
            id="output.exact_target_at_10",
            status=CheckStatus.PASS if exact_at_cutoff == len(tasks) else CheckStatus.FAIL,
            score_bps=proportional_score_bps(exact_at_cutoff, len(tasks)),
            reason_code="EXACT_TARGET_CUTOFF_COMPLETE" if exact_at_cutoff == len(tasks) else "EXACT_TARGET_CUTOFF_MISSED",
            numerator=exact_at_cutoff,
            denominator=len(tasks),
            evidence=_artifact_references(artifacts),
        ),
        CheckResult(
            id="output.language_strata",
            status=CheckStatus.PASS,
            score_bps=10000,
            reason_code="LANGUAGE_STRATA_REPORTED",
            numerator=len(language_strata),
            denominator=len(language_strata),
            evidence=_artifact_references(artifacts)
            + tuple({"kind": "language_stratum", "value": item.value} for item in language_strata),
        ),
        CheckResult(
            id="output.predicate_strata",
            status=CheckStatus.PASS,
            score_bps=10000,
            reason_code="PREDICATE_STRATA_REPORTED",
            numerator=len(predicate_strata),
            denominator=len(predicate_strata),
            evidence=_artifact_references(artifacts)
            + tuple({"kind": "predicate_stratum", "value": item.value} for item in predicate_strata),
        ),
    ]
    for metric_name in (
        "ndcg_at_10",
        "reciprocal_rank_at_10",
        "success_at_1",
        "success_at_5",
        "success_at_10",
        "recall_at_10",
        "precision_at_5",
        "precision_at_10",
        "average_precision_at_10",
    ):
        checks.append(
            _retrieval_metric_result(metric_name, getattr(aggregate, metric_name), artifacts)
        )
    return RetrievalEvaluation(
        benchmark_id=benchmark_id,
        manifest_sha256=manifest_sha256,
        aggregate=aggregate,
        tasks=tasks,
        language_strata=language_strata,
        predicate_strata=predicate_strata,
        checks=tuple(sorted(checks, key=lambda item: item.id)),
        authoritative_qrels=authoritative_qrels,
        authoritative_run=authoritative_run,
        cross_check=_authoritative_retrieval_cross_check(
            aggregate, authoritative_qrels, authoritative_run
        ),
    )


def evaluate_output_effectiveness_evidence(
    *,
    manifest: EvidenceArtifact,
    qrels: EvidenceArtifact,
    benchmark_run: EvidenceArtifact,
) -> tuple[CheckResult, ...]:
    """Return policy checks, mapping retrieval contract faults to evaluation errors."""
    artifacts = tuple(
        item
        for item in (manifest, qrels, benchmark_run)
        if isinstance(item, EvidenceArtifact)
    )
    try:
        return evaluate_retrieval(
            manifest=manifest, qrels=qrels, benchmark_run=benchmark_run
        ).checks
    except RetrievalEvaluationError as exc:
        return tuple(
            _error_result(check_id, exc.reason_code, artifacts)
            for check_id in _OUTPUT_CHECK_IDS
        )


def _score_checks(checks: tuple[AssessedCheck, ...]) -> ScoreAggregate:
    eligible = tuple(
        item
        for item in checks
        if item.score_eligible and item.status is not CheckStatus.NOT_APPLICABLE
    )
    known = tuple(
        item
        for item in eligible
        if item.status in {CheckStatus.PASS, CheckStatus.FAIL}
    )
    eligible_weight = sum(item.weight for item in eligible)
    included_weight = sum(item.weight for item in known)
    if eligible_weight == 0:
        return ScoreAggregate(None, None, None, None, 0, 0)
    observed = (
        weighted_score_bps(
            (int(item.score_bps), item.weight) for item in known
        )
        if known
        else None
    )
    exact = observed if included_weight == eligible_weight else None
    known_total = sum(int(item.score_bps) * item.weight for item in known)
    unresolved_weight = eligible_weight - included_weight
    lower = _round_half_up_fraction(known_total, eligible_weight)
    upper = _round_half_up_fraction(
        known_total + 10000 * unresolved_weight,
        eligible_weight,
    )
    return ScoreAggregate(
        score_bps=exact,
        observed_score_bps=observed,
        lower_bound_bps=lower,
        upper_bound_bps=upper,
        included_weight=included_weight,
        eligible_weight=eligible_weight,
    )


def _score_dimensions(
    dimensions: tuple[DimensionAssessment, ...],
) -> ScoreAggregate:
    eligible = tuple(item for item in dimensions if item.aggregate.eligible_weight > 0)
    observed = tuple(
        item for item in eligible if item.aggregate.observed_score_bps is not None
    )
    eligible_weight = sum(item.weight for item in eligible)
    included_weight = sum(item.weight for item in observed)
    if eligible_weight == 0:
        return ScoreAggregate(None, None, None, None, 0, 0)
    observed_score = (
        weighted_score_bps(
            (int(item.aggregate.observed_score_bps), item.weight)
            for item in observed
        )
        if observed
        else None
    )
    exact = (
        weighted_score_bps(
            (int(item.aggregate.score_bps), item.weight) for item in eligible
        )
        if all(item.aggregate.score_bps is not None for item in eligible)
        else None
    )
    lower = weighted_score_bps(
        (int(item.aggregate.lower_bound_bps), item.weight)
        for item in eligible
    )
    upper = weighted_score_bps(
        (int(item.aggregate.upper_bound_bps), item.weight)
        for item in eligible
    )
    return ScoreAggregate(
        score_bps=exact,
        observed_score_bps=observed_score,
        lower_bound_bps=lower,
        upper_bound_bps=upper,
        included_weight=included_weight,
        eligible_weight=eligible_weight,
    )


def _gate(checks: tuple[AssessedCheck, ...], scores: ScoreAggregate) -> GateAggregate:
    required = tuple(item for item in checks if item.mode is CheckMode.REQUIRED)

    # This ordering is the ADR-002 section 4 precedence: all known failures are
    # selected first; unresolved required checks are considered only after the
    # decision is fixed as fail-or-indeterminate.  Both vectors remain output.
    failures = tuple(
        Blocker(
            check_id=item.id,
            kind=BlockerKind.KNOWN_FAILURE,
            status=item.status,
            reason_code=item.reason_code,
        )
        for item in required
        if item.status is CheckStatus.FAIL
    )
    unresolved = tuple(
        Blocker(
            check_id=item.id,
            kind=(
                BlockerKind.MISSING_RESULT if item.missing else BlockerKind.UNRESOLVED
            ),
            status=item.status,
            reason_code=item.reason_code,
        )
        for item in required
        if item.status
        in {CheckStatus.UNKNOWN, CheckStatus.ERROR, CheckStatus.SKIPPED}
    )
    if failures:
        decision = Decision.FAIL
    elif unresolved:
        decision = Decision.INDETERMINATE
    else:
        decision = Decision.PASS
    return GateAggregate(
        decision=decision,
        complete=not unresolved,
        scores=scores,
        blockers=failures + unresolved,
    )


def evaluate(
    policy: Policy,
    results: tuple[CheckResult, ...],
    *,
    profile: Profile,
    subject: Subject,
    producer: Producer,
    evidence: tuple[EvidenceArtifact, ...] = (),
) -> Assessment:
    """Apply policy metadata, score dimensions, and evaluate the hard gate."""
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy")
    if not isinstance(results, tuple) or any(
        not isinstance(item, CheckResult) for item in results
    ):
        raise TypeError("results must be a tuple of CheckResult")
    if not isinstance(profile, Profile):
        raise TypeError("profile must be a Profile")
    if not isinstance(subject, Subject):
        raise TypeError("subject must be a Subject")
    if not isinstance(producer, Producer):
        raise TypeError("producer must be a Producer")
    if not isinstance(evidence, tuple) or any(
        not isinstance(item, EvidenceArtifact) for item in evidence
    ):
        raise TypeError("evidence must be a tuple of EvidenceArtifact")
    evidence_ids = [item.id for item in evidence]
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("submitted evidence IDs must be unique")
    if profile is Profile.RELEASE and subject.worktree == "dirty":
        raise ValueError("release profile requires a clean subject worktree")
    result_ids = [item.id for item in results]
    if len(set(result_ids)) != len(result_ids):
        raise ValueError("submitted check IDs must be unique")
    expected_ids = {item.id for item in policy.checks}
    unexpected = sorted(set(result_ids) - expected_ids)
    if unexpected:
        raise ValueError(
            "results contain policy-unknown check IDs: " + ", ".join(unexpected)
        )
    referenced_artifacts = {
        entry["value"]
        for result in results
        for entry in result.evidence
        if entry["kind"] == "artifact"
    }
    missing_artifacts = sorted(referenced_artifacts - set(evidence_ids))
    if missing_artifacts:
        raise ValueError(
            "results reference missing evidence artifacts: "
            + ", ".join(missing_artifacts)
        )
    submitted = {item.id: item for item in results}
    assessed: list[AssessedCheck] = []
    for check_policy in policy.checks:
        result = submitted.get(check_policy.id)
        missing = result is None
        if result is None:
            result = CheckResult(
                id=check_policy.id,
                status=CheckStatus.UNKNOWN,
                score_bps=None,
                reason_code=StandardReason.POLICY_CHECK_MISSING.value,
            )
        if result.status is CheckStatus.NOT_APPLICABLE:
            if check_policy.applicability is None:
                raise ValueError(
                    f"{result.id} cannot be not_applicable without a policy rule"
                )
            if not result.evidence:
                raise ValueError(
                    f"{result.id} cannot be not_applicable without evidence"
                )
        assessed.append(
            AssessedCheck(
                id=result.id,
                dimension=check_policy.dimension,
                mode=check_policy.mode_for(profile),
                status=result.status,
                score_bps=result.score_bps,
                weight=check_policy.weight,
                score_eligible=check_policy.score_eligible,
                criterion=check_policy.criterion,
                reason_code=result.reason_code,
                numerator=result.numerator,
                denominator=result.denominator,
                exclusions=result.exclusions,
                evidence=result.evidence,
                missing=missing,
            )
        )
    assessed_checks = tuple(assessed)
    dimensions = tuple(
        DimensionAssessment(
            id=dimension.id,
            weight=dimension.weight,
            aggregate=_score_checks(
                tuple(
                    item for item in assessed_checks if item.dimension == dimension.id
                )
            ),
        )
        for dimension in policy.dimensions
    )
    scores = _score_dimensions(dimensions)
    return Assessment(
        schema_version=ASSESSMENT_SCHEMA_VERSION,
        profile=profile,
        subject=subject,
        producer=producer,
        policy_id=policy.id,
        policy_sha256=policy.digest(),
        checks=assessed_checks,
        dimensions=dimensions,
        aggregate=_gate(assessed_checks, scores),
        evidence=evidence,
    )


def decision_exit_code(decision: Decision) -> ExitCode:
    """Map a completed evaluation decision to its stable process exit."""
    if not isinstance(decision, Decision):
        raise TypeError("decision must be a Decision")
    if decision is Decision.PASS:
        return ExitCode.COMPLETE_PASS
    if decision is Decision.FAIL:
        return ExitCode.KNOWN_FAILURE
    return ExitCode.INDETERMINATE


def _require_exact_keys(raw: Mapping[str, object], keys: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing:
        raise ValueError(f"{name} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{name} contains unknown fields: {', '.join(extra)}")


def policy_from_dict(raw: object) -> Policy:
    """Strictly validate and construct a policy from decoded JSON."""
    if not isinstance(raw, Mapping):
        raise TypeError("policy must be an object")
    _require_exact_keys(
        raw,
        {"schema_version", "id", "dimensions", "checks", "waivers"},
        "policy",
    )
    dimensions_raw = raw["dimensions"]
    checks_raw = raw["checks"]
    waivers_raw = raw["waivers"]
    if not isinstance(dimensions_raw, list):
        raise TypeError("policy dimensions must be a list")
    if not isinstance(checks_raw, list):
        raise TypeError("policy checks must be a list")
    if not isinstance(waivers_raw, list):
        raise TypeError("policy waivers must be a list")
    dimensions: list[DimensionPolicy] = []
    for item in dimensions_raw:
        if not isinstance(item, Mapping):
            raise TypeError("dimension entries must be objects")
        _require_exact_keys(item, {"id", "weight"}, "dimension")
        dimensions.append(DimensionPolicy(id=item["id"], weight=item["weight"]))
    checks: list[CheckPolicy] = []
    for item in checks_raw:
        if not isinstance(item, Mapping):
            raise TypeError("check entries must be objects")
        _require_exact_keys(
            item,
            {
                "id",
                "dimension",
                "weight",
                "score_eligible",
                "criterion",
                "modes",
                "applicability",
            },
            "check",
        )
        criterion_raw = item["criterion"]
        modes_raw = item["modes"]
        applicability_raw = item["applicability"]
        if not isinstance(criterion_raw, Mapping):
            raise TypeError("check criterion must be an object")
        if not isinstance(modes_raw, Mapping):
            raise TypeError("check modes must be an object")
        _require_exact_keys(criterion_raw, {"op", "value"}, "criterion")
        _require_exact_keys(modes_raw, {"offline", "release"}, "modes")
        applicability = None
        if applicability_raw is not None:
            if not isinstance(applicability_raw, Mapping):
                raise TypeError("check applicability must be an object or null")
            _require_exact_keys(applicability_raw, {"rule"}, "applicability")
            applicability = ApplicabilityRule(rule=applicability_raw["rule"])
        try:
            offline_mode = CheckMode(modes_raw["offline"])
            release_mode = CheckMode(modes_raw["release"])
        except ValueError as exc:
            raise ValueError("policy check modes must be required or advisory") from exc
        checks.append(
            CheckPolicy(
                id=item["id"],
                dimension=item["dimension"],
                weight=item["weight"],
                score_eligible=item["score_eligible"],
                criterion=Criterion(
                    op=criterion_raw["op"], value=criterion_raw["value"]
                ),
                offline_mode=offline_mode,
                release_mode=release_mode,
                applicability=applicability,
            )
        )
    return Policy(
        schema_version=raw["schema_version"],
        id=raw["id"],
        dimensions=tuple(dimensions),
        checks=tuple(checks),
        waivers=tuple(waivers_raw),
    )


def load_policy(path: str | Path) -> Policy:
    """Load a local policy without importing or invoking any adapter."""
    if not isinstance(path, (str, Path)):
        raise TypeError("path must be text or Path")
    return policy_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


_ASSESSMENT_KEYS = {
    "schema_version",
    "profile",
    "subject",
    "producer",
    "policy",
    "checks",
    "evidence",
    "dimensions",
    "aggregate",
}
_SCORE_KEYS = {
    "score_bps",
    "observed_score_bps",
    "lower_bound_bps",
    "upper_bound_bps",
    "included_weight",
    "eligible_weight",
}


def _render_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise TypeError(f"{name} must be an object with text keys")
    return value


def _render_list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{name} must be a list")
    return value


def _validate_render_scores(raw: Mapping[str, object], name: str) -> None:
    for field_name in (
        "score_bps",
        "observed_score_bps",
        "lower_bound_bps",
        "upper_bound_bps",
    ):
        value = raw[field_name]
        if value is not None:
            _validate_score(value, f"{name} {field_name}")
    for field_name in ("included_weight", "eligible_weight"):
        _validate_non_negative_int(raw[field_name], f"{name} {field_name}")


def _assessment_render_mapping(
    assessment: Assessment | Mapping[str, object],
) -> Mapping[str, object]:
    """Validate the renderer-facing canonical shape without re-evaluating it.

    Rendering deliberately does not reconstruct a gate or a score.  The
    validation here protects the renderer from malformed input while leaving
    every policy judgment exactly as supplied by the canonical assessment.
    """
    if isinstance(assessment, Assessment):
        raw = assessment.to_dict()
    else:
        raw = _render_mapping(assessment, "assessment")
    _require_exact_keys(raw, _ASSESSMENT_KEYS, "assessment")
    if raw["schema_version"] != ASSESSMENT_SCHEMA_VERSION:
        raise ValueError(
            f"assessment schema_version must be {ASSESSMENT_SCHEMA_VERSION!r}"
        )
    try:
        Profile(raw["profile"])
    except (TypeError, ValueError) as exc:
        raise ValueError("assessment profile must be offline or release") from exc

    subject = _render_mapping(raw["subject"], "assessment subject")
    producer = _render_mapping(raw["producer"], "assessment producer")
    policy = _render_mapping(raw["policy"], "assessment policy")
    try:
        Subject(
            repository=subject["repository"],
            commit_sha=subject["commit_sha"],
            worktree=subject["worktree"],
            patch_sha256=subject.get("patch_sha256"),
            untracked_sha256=subject.get("untracked_sha256"),
        )
        Producer(
            name=producer["name"],
            version=producer["version"],
            commit_sha=producer["commit_sha"],
        )
    except KeyError as exc:
        raise ValueError("assessment identity is missing a required field") from exc
    expected_subject_keys = {"repository", "commit_sha", "worktree"}
    if subject["worktree"] == "dirty":
        expected_subject_keys.update({"patch_sha256", "untracked_sha256"})
    if set(subject) != expected_subject_keys:
        raise ValueError("assessment subject has an invalid field set")
    if set(producer) != {"name", "version", "commit_sha"}:
        raise ValueError("assessment producer has an invalid field set")
    if (
        set(policy) != {"id", "sha256"}
        or not isinstance(policy["id"], str)
        or not _POLICY_ID.fullmatch(policy["id"])
        or not isinstance(policy["sha256"], str)
        or not _SHA256.fullmatch(policy["sha256"])
    ):
        raise ValueError("assessment policy identity is invalid")

    checks = _render_list(raw["checks"], "assessment checks")
    check_ids: list[str] = []
    for index, item in enumerate(checks):
        check = _render_mapping(item, f"assessment check {index}")
        _require_exact_keys(
            check,
            {
                "id",
                "dimension",
                "mode",
                "status",
                "score_bps",
                "weight",
                "score_eligible",
                "criterion",
                "reason_code",
                "numerator",
                "denominator",
                "exclusions",
                "evidence",
                "missing",
            },
            f"assessment check {index}",
        )
        check_id = check["id"]
        if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
            raise ValueError("assessment check ID is invalid")
        check_ids.append(check_id)
        try:
            status = CheckStatus(check["status"])
            CheckMode(check["mode"])
        except (TypeError, ValueError) as exc:
            raise ValueError("assessment check status or mode is invalid") from exc
        if check["dimension"] not in DIMENSION_IDS:
            raise ValueError("assessment check dimension is invalid")
        _validate_positive_int(check["weight"], "assessment check weight")
        if not isinstance(check["score_eligible"], bool) or not isinstance(
            check["missing"], bool
        ):
            raise TypeError("assessment check flags must be bools")
        if status in {CheckStatus.PASS, CheckStatus.FAIL}:
            _validate_score(check["score_bps"], "assessment check score_bps")
        elif check["score_bps"] is not None:
            raise ValueError("unresolved assessment check score must be null")
        if not isinstance(check["reason_code"], str) or not _REASON_CODE.fullmatch(
            check["reason_code"]
        ):
            raise ValueError("assessment check reason_code is invalid")
        criterion = _render_mapping(check["criterion"], "assessment check criterion")
        _require_exact_keys(criterion, {"op", "value"}, "assessment criterion")
        Criterion(op=criterion["op"], value=criterion["value"])
        for field_name in ("numerator", "denominator"):
            value = check[field_name]
            if value is not None:
                _validate_non_negative_int(value, f"assessment check {field_name}")
        exclusions = _render_mapping(
            check["exclusions"], "assessment check exclusions"
        )
        for reason_code, count in exclusions.items():
            if not _REASON_CODE.fullmatch(reason_code):
                raise ValueError("assessment exclusion reason is invalid")
            _validate_non_negative_int(count, "assessment exclusion count")
        check_evidence = _render_list(check["evidence"], "assessment check evidence")
        for entry in check_evidence:
            evidence_entry = _render_mapping(entry, "assessment check evidence entry")
            if set(evidence_entry) != {"kind", "value"} or any(
                not isinstance(value, str) or not value
                for value in evidence_entry.values()
            ):
                raise ValueError("assessment check evidence entry is invalid")
    if check_ids != sorted(check_ids) or len(set(check_ids)) != len(check_ids):
        raise ValueError("assessment checks must have unique canonical ordering")

    dimensions = _render_list(raw["dimensions"], "assessment dimensions")
    if len(dimensions) != len(DIMENSION_IDS):
        raise ValueError("assessment must contain all six dimensions")
    for expected_id, item in zip(DIMENSION_IDS, dimensions, strict=True):
        dimension = _render_mapping(item, "assessment dimension")
        _require_exact_keys(
            dimension, {"id", "weight", *_SCORE_KEYS}, "assessment dimension"
        )
        if dimension["id"] != expected_id:
            raise ValueError("assessment dimensions are not canonically ordered")
        _validate_positive_int(dimension["weight"], "assessment dimension weight")
        _validate_render_scores(dimension, f"dimension {expected_id}")

    aggregate = _render_mapping(raw["aggregate"], "assessment aggregate")
    _require_exact_keys(
        aggregate,
        {"decision", "complete", "blockers", *_SCORE_KEYS},
        "assessment aggregate",
    )
    try:
        Decision(aggregate["decision"])
    except (TypeError, ValueError) as exc:
        raise ValueError("assessment decision is invalid") from exc
    if not isinstance(aggregate["complete"], bool):
        raise TypeError("assessment complete must be a bool")
    _validate_render_scores(aggregate, "assessment aggregate")
    blockers = _render_list(aggregate["blockers"], "assessment blockers")
    parsed_blockers: list[Blocker] = []
    for item in blockers:
        blocker = _render_mapping(item, "assessment blocker")
        _require_exact_keys(
            blocker,
            {"check_id", "kind", "status", "reason_code"},
            "assessment blocker",
        )
        try:
            parsed_blockers.append(
                Blocker(
                    check_id=blocker["check_id"],
                    kind=BlockerKind(blocker["kind"]),
                    status=CheckStatus(blocker["status"]),
                    reason_code=blocker["reason_code"],
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("assessment blocker is invalid") from exc
    if parsed_blockers != sorted(parsed_blockers, key=Blocker.sort_key):
        raise ValueError("assessment blockers are not canonically ordered")

    evidence = _render_list(raw["evidence"], "assessment evidence")
    evidence_keys: list[tuple[str, str, str]] = []
    for index, item in enumerate(evidence):
        artifact = _render_mapping(item, f"assessment evidence {index}")
        base_keys = {"id", "path", "sha256", "command", "sources"}
        artifact_keys = frozenset(artifact)
        allowed_keys = {
            frozenset(base_keys),
            frozenset({*base_keys, "normalization"}),
        }
        if artifact_keys not in allowed_keys:
            raise ValueError(f"assessment evidence {index} has an invalid field set")
        key = (artifact["id"], artifact["path"], artifact["sha256"])
        if (
            any(not isinstance(value, str) for value in key)
            or not _EVIDENCE_ID.fullmatch(key[0])
            or not _SHA256.fullmatch(key[2])
        ):
            raise ValueError("assessment evidence identity is invalid")
        normalization = artifact.get("normalization")
        if normalization is not None and (
            not isinstance(normalization, str)
            or not _NORMALIZATION_ID.fullmatch(normalization)
        ):
            raise ValueError("assessment evidence normalization is invalid")
        _validate_canonical_path(key[1], "assessment evidence path")
        command = artifact["command"]
        if command is not None:
            command_raw = _render_mapping(command, "assessment evidence command")
            _require_exact_keys(
                command_raw,
                {"argv", "process_exit", "collector_reason_code"},
                "assessment evidence command",
            )
            argv = _render_list(command_raw["argv"], "assessment evidence argv")
            CommandExecution(
                argv=tuple(argv),
                process_exit=command_raw["process_exit"],
                collector_reason_code=command_raw["collector_reason_code"],
            )
        sources = _render_list(artifact["sources"], "assessment evidence sources")
        for source_item in sources:
            source = _render_mapping(source_item, "assessment evidence source")
            _require_exact_keys(
                source,
                {"path", "blob_digest", "start_line", "end_line"},
                "assessment evidence source",
            )
            SourceSpan(
                path=source["path"],
                blob_digest=source["blob_digest"],
                start_line=source["start_line"],
                end_line=source["end_line"],
            )
        evidence_keys.append(key)
    if evidence_keys != sorted(evidence_keys) or len(set(evidence_keys)) != len(
        evidence_keys
    ):
        raise ValueError("assessment evidence must have unique canonical ordering")
    return raw


def _html(value: object) -> str:
    return _html_escape(str(value), quote=True)


def _json_cell(value: object) -> str:
    return _html(_canonical_json(value))


def _score_html(scores: Mapping[str, object]) -> str:
    exact = scores["score_bps"]
    if exact is None:
        return (
            '<span class="score score-unknown">unknown</span>'
            '<span class="bounds">'
            f'observed={_html(scores["observed_score_bps"] if scores["observed_score_bps"] is not None else "unknown")} '
            f'lower={_html(scores["lower_bound_bps"] if scores["lower_bound_bps"] is not None else "unknown")} '
            f'upper={_html(scores["upper_bound_bps"] if scores["upper_bound_bps"] is not None else "unknown")}'
            "</span>"
        )
    return (
        f'<span class="score score-exact">{_html(exact)}</span>'
        f'<span class="band" data-display-only="true">{_html(display_band(exact))}</span>'
    )


def render_assessment_html(
    assessment: Assessment | Mapping[str, object],
) -> bytes:
    """Render canonical assessment values to deterministic, escaped HTML bytes.

    The renderer reads existing decision and score fields.  It never evaluates
    a criterion, fills an unknown score, or uses a display band as a gate.
    """
    raw = _assessment_render_mapping(assessment)
    subject = _render_mapping(raw["subject"], "assessment subject")
    producer = _render_mapping(raw["producer"], "assessment producer")
    policy = _render_mapping(raw["policy"], "assessment policy")
    aggregate = _render_mapping(raw["aggregate"], "assessment aggregate")
    canonical = canonical_json_bytes(raw)
    digest = hashlib.sha256(canonical).hexdigest()

    dimension_rows = "".join(
        "<tr>"
        f'<th scope="row">{_html(item["id"])}</th>'
        f"<td>{_html(item['weight'])}</td>"
        f"<td>{_score_html(item)}</td>"
        f"<td>{_html(item['included_weight'])}/{_html(item['eligible_weight'])}</td>"
        "</tr>"
        for item in raw["dimensions"]
    )
    check_rows = "".join(
        "<tr>"
        f'<th scope="row">{_html(item["id"])}</th>'
        f"<td>{_html(item['dimension'])}</td>"
        f"<td>{_html(item['mode'])}</td>"
        f"<td>{_html(item['status'])}</td>"
        f"<td>{_html(item['score_bps']) if item['score_bps'] is not None else '<span class=\"score-unknown\">unknown</span>'}</td>"
        f"<td>{_html(item['reason_code'])}</td>"
        f"<td>{_json_cell(item['criterion'])}</td>"
        f"<td>{_json_cell(item['numerator'])}/{_json_cell(item['denominator'])}</td>"
        f"<td>{_json_cell(item['exclusions'])}</td>"
        f"<td>{_json_cell(item['evidence'])}</td>"
        "</tr>"
        for item in raw["checks"]
    )
    evidence_rows = "".join(
        "<tr>"
        f'<th scope="row">{_html(item["id"])}</th>'
        f"<td>{_html(item['path'])}</td>"
        f"<td>{_html(item['sha256'])}</td>"
        f"<td>{_html(item.get('normalization', 'none'))}</td>"
        f"<td>{_json_cell(item['command'])}</td>"
        f"<td>{_json_cell(item['sources'])}</td>"
        "</tr>"
        for item in raw["evidence"]
    )
    blocker_rows = "".join(
        "<li>"
        f"{_html(item['check_id'])}: {_html(item['kind'])} / "
        f"{_html(item['status'])} / {_html(item['reason_code'])}"
        "</li>"
        for item in aggregate["blockers"]
    ) or "<li>none</li>"
    subject_rows = "".join(
        f"<tr><th scope=\"row\">{_html(key)}</th><td>{_html(value)}</td></tr>"
        for key, value in sorted(subject.items())
    )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leitir assessment {_html(digest)}</title>
<style>
body{{font-family:system-ui,sans-serif;line-height:1.4;margin:2rem;max-width:100rem}}table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}th,td{{border:1px solid #bbb;padding:.4rem;text-align:left;vertical-align:top}}code,pre{{font-family:ui-monospace,monospace}}pre{{overflow:auto;white-space:pre-wrap}}.score{{font-weight:700}}.score-unknown{{font-weight:700;color:#6b4800}}.bounds,.band{{display:block;font-size:.9em}}.band::before{{content:"display band: "}}
</style>
</head>
<body>
<h1>Leitir canonical assessment</h1>
<p>profile=<code>{_html(raw['profile'])}</code> decision=<code>{_html(aggregate['decision'])}</code> complete=<code>{_html(str(aggregate['complete']).lower())}</code></p>
<p>policy=<code>{_html(policy['id'])}</code> policy_sha256=<code>{_html(policy['sha256'])}</code></p>
<p>producer=<code>{_html(producer['name'])}</code> version=<code>{_html(producer['version'])}</code> commit=<code>{_html(producer['commit_sha'])}</code></p>
<p>assessment_sha256=<code>{_html(digest)}</code></p>
<h2>Overall diagnostic</h2>
<div id="aggregate-score">{_score_html(aggregate)}</div>
<p>evidence weight={_html(aggregate['included_weight'])}/{_html(aggregate['eligible_weight'])}</p>
<h3>Blockers</h3><ul>{blocker_rows}</ul>
<h2>Subject</h2><table><tbody>{subject_rows}</tbody></table>
<h2>Dimensions</h2>
<table><thead><tr><th>dimension</th><th>weight</th><th>score (basis points)</th><th>evidence weight</th></tr></thead><tbody>{dimension_rows}</tbody></table>
<h2>Checks</h2>
<table><thead><tr><th>check</th><th>dimension</th><th>mode</th><th>status</th><th>score_bps</th><th>reason_code</th><th>criterion</th><th>counts</th><th>exclusions</th><th>evidence</th></tr></thead><tbody>{check_rows}</tbody></table>
<h2>Evidence artifacts</h2>
<table><thead><tr><th>id</th><th>path</th><th>canonical sha256</th><th>normalization</th><th>command</th><th>sources</th></tr></thead><tbody>{evidence_rows}</tbody></table>
<h2>Canonical JSON</h2>
<pre id="canonical-assessment">{_html(canonical.decode('utf-8'))}</pre>
</body>
</html>
"""
    return document.encode("utf-8")


def render_terminal_summary(
    assessment: Assessment | Mapping[str, object],
) -> str:
    """Return concise deterministic terminal text from canonical fields."""
    raw = _assessment_render_mapping(assessment)
    aggregate = _render_mapping(raw["aggregate"], "assessment aggregate")
    exact = (
        str(aggregate["score_bps"])
        if aggregate["score_bps"] is not None
        else "unknown"
    )
    observed = (
        str(aggregate["observed_score_bps"])
        if aggregate["observed_score_bps"] is not None
        else "unknown"
    )
    lower = (
        str(aggregate["lower_bound_bps"])
        if aggregate["lower_bound_bps"] is not None
        else "unknown"
    )
    upper = (
        str(aggregate["upper_bound_bps"])
        if aggregate["upper_bound_bps"] is not None
        else "unknown"
    )
    digest = hashlib.sha256(canonical_json_bytes(raw)).hexdigest()
    return (
        f"profile={raw['profile']} decision={aggregate['decision']} "
        f"complete={str(aggregate['complete']).lower()}\n"
        f"score_bps={exact} observed_score_bps={observed} "
        f"lower_bound_bps={lower} upper_bound_bps={upper}\n"
        f"assessment_sha256={digest}\n"
    )


def _run_envelope_for_assessment(
    assessment: Assessment,
    *,
    started_at_utc: str,
    finished_at_utc: str,
    duration_ns: int,
) -> RunEnvelope:
    import platform
    import socket

    raw_evidence = tuple(
        RawEvidenceProvenance(
            id=artifact.id,
            path=artifact.path,
            raw_sha256=str(artifact.raw_sha256),
            canonical_sha256=artifact.sha256,
            normalization=str(artifact.normalization),
        )
        for artifact in assessment.evidence
        if artifact.raw_sha256 is not None
    )
    return RunEnvelope(
        subject_sha256=assessment.digest(),
        started_at_utc=started_at_utc,
        finished_at_utc=finished_at_utc,
        duration_ns=duration_ns,
        host={
            "hostname": socket.gethostname(),
            "machine": platform.machine() or "unknown",
            "platform": platform.system() or "unknown",
            "python": platform.python_version(),
        },
        log_paths=(),
        raw_evidence=raw_evidence,
    )


def _github_slug(repository: str) -> str | None:
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        repository,
    )
    return None if match is None else match.group(1)


def _strict_json_for_normalization(content: bytes, name: str) -> object:
    def reject_constant(value: str) -> object:
        raise ValueError(f"{name} contains non-finite number {value}")

    try:
        return json.loads(content, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{name} is not strict JSON") from exc


def _canonicalize_coverage_json(content: bytes) -> bytes:
    """Remove coverage.py's report-generation timestamp, retaining measurements."""
    raw = _strict_json_for_normalization(content, "coverage evidence")
    if not isinstance(raw, dict) or not isinstance(raw.get("meta"), dict):
        raise ValueError("coverage evidence has no metadata object")
    meta = raw["meta"]
    if "timestamp" not in meta:
        raise ValueError("coverage evidence has no volatile timestamp")
    del meta["timestamp"]
    return canonical_json_bytes(raw)


def _canonicalize_asv_json(content: bytes) -> bytes:
    """Remove ASV orchestration timestamps/durations but retain benchmark samples."""
    raw = _strict_json_for_normalization(content, "ASV evidence")
    if not isinstance(raw, dict):
        raise ValueError("ASV evidence must be an object")
    columns = raw.get("result_columns")
    results = raw.get("results")
    if (
        raw.get("version") != _ASV_RESULT_SCHEMA_VERSION
        or not isinstance(columns, list)
        or not isinstance(results, dict)
        or "date" not in raw
        or "durations" not in raw
    ):
        raise ValueError("ASV evidence has no recognized volatile fields")
    try:
        volatile_indexes = tuple(
            columns.index(name) for name in ("started_at", "duration")
        )
    except ValueError as exc:
        raise ValueError("ASV result columns omit volatile fields") from exc
    raw["date"] = None
    raw["durations"] = {}
    for row in results.values():
        if not isinstance(row, list):
            raise ValueError("ASV result row must be a list")
        for index in volatile_indexes:
            if index < len(row):
                row[index] = None
    return canonical_json_bytes(raw)


def _local_evidence_artifact(
    evidence_dir: Path,
    filename: str,
    artifact_id: str,
) -> EvidenceArtifact | None:
    path = evidence_dir / filename
    if not path.is_file():
        return None
    content = path.read_bytes()
    normalized: tuple[bytes, str] | None = None
    try:
        if artifact_id == "test.coverage":
            normalized = (
                _canonicalize_coverage_json(content),
                "coverage-json-volatile-v1",
            )
        elif artifact_id in {"performance.baseline", "performance.candidate"}:
            normalized = (
                _canonicalize_asv_json(content),
                "asv-json-volatile-v1",
            )
    except ValueError:
        # Malformed bytes remain intact so the owning adapter can fail closed
        # with its established domain reason code.
        normalized = None
    if normalized is not None:
        canonical_content, normalization = normalized
        return _normalized_evidence_artifact(
            id=artifact_id,
            path=f"evidence/{filename}",
            raw_content=content,
            canonical_content=canonical_content,
            normalization=normalization,
        )
    return EvidenceArtifact(
        id=artifact_id,
        path=f"evidence/{filename}",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _complete_artifact_set(
    evidence_dir: Path,
    specifications: tuple[tuple[str, str], ...],
) -> tuple[EvidenceArtifact, ...] | None:
    artifacts = tuple(
        _local_evidence_artifact(evidence_dir, filename, artifact_id)
        for filename, artifact_id in specifications
    )
    if any(item is None for item in artifacts):
        return None
    return tuple(item for item in artifacts if item is not None)


def run_profile_assessment(
    *,
    root: str | Path,
    policy: Policy,
    profile: Profile,
    enable_live: bool = False,
    evidence_dir: str | Path | None = None,
) -> Assessment:
    """Collect the landed fixed collectors and evaluate one explicit profile."""
    repository_root = Path(root).resolve()
    if evidence_dir is None:
        local_evidence = repository_root / ".leitir-score" / "evidence"
    else:
        evidence_path = Path(evidence_dir)
        local_evidence = (
            evidence_path.resolve()
            if evidence_path.is_absolute()
            else (repository_root / evidence_path).resolve()
        )
    subject = subject_from_repository(repository_root)
    pytest_junit = collect_adr001_pytest_junit(repository_root)
    results: list[CheckResult] = [
        evaluate_pytest_junit(pytest_junit),
        evaluate_retired_surfaces_absent(repository_root),
    ]
    artifacts: list[EvidenceArtifact] = [pytest_junit]

    engine_artifacts = _complete_artifact_set(
        local_evidence,
        (
            ("benchmark-run.json", "engine.benchmark-run"),
            ("benchmark-run-repeat.json", "engine.benchmark-run-repeat"),
            ("benchmark-run-permuted.json", "engine.benchmark-run-permuted"),
            ("global-report.json", "engine.global-report"),
        ),
    )
    if engine_artifacts is not None:
        primary, repeated, permuted, global_report = engine_artifacts
        results = list(
            evaluate_engine_correctness_evidence(
                pytest_junit=pytest_junit,
                replay_artifacts=(primary, repeated, permuted),
                global_report=global_report,
                repository_root=repository_root,
            )
        )
        artifacts.extend(engine_artifacts)

        manifest_path = (
            repository_root
            / "src"
            / "leitir"
            / "benchmarks"
            / "search-v1"
            / "manifest.json"
        )
        qrels_path = manifest_path.with_name("qrels.json")
        if manifest_path.is_file() and qrels_path.is_file():
            manifest_content = manifest_path.read_bytes()
            qrels_content = qrels_path.read_bytes()
            manifest = EvidenceArtifact(
                id="output.benchmark-manifest",
                path="src/leitir/benchmarks/search-v1/manifest.json",
                sha256=hashlib.sha256(manifest_content).hexdigest(),
                content=manifest_content,
            )
            qrels = EvidenceArtifact(
                id="output.benchmark-qrels",
                path="src/leitir/benchmarks/search-v1/qrels.json",
                sha256=hashlib.sha256(qrels_content).hexdigest(),
                content=qrels_content,
            )
            results.extend(
                evaluate_output_effectiveness_evidence(
                    manifest=manifest,
                    qrels=qrels,
                    benchmark_run=primary,
                )
            )
            artifacts.extend((manifest, qrels))

    code_artifacts = _complete_artifact_set(
        local_evidence,
        (
            ("code-scope.json", "code.scope"),
            ("score-tool-versions.json", "code.tool-versions"),
            ("radon-cc.json", "code.radon-cc"),
            ("radon-mi.json", "code.radon-mi"),
        ),
    )
    if code_artifacts is not None:
        scope, tool_versions, radon_cc, radon_mi = code_artifacts
        results.extend(
            evaluate_code_health_evidence(
                policy=policy,
                scope_artifact=scope,
                tool_versions=tool_versions,
                radon_complexity=radon_cc,
                radon_mi=radon_mi,
            ).checks
        )
        artifacts.extend(code_artifacts)

    test_artifacts = _complete_artifact_set(
        local_evidence,
        (
            ("code-scope.json", "test.scope"),
            ("score-tool-versions.json", "test.tool-versions"),
            ("coverage.json", "test.coverage"),
            ("mutmut.json", "test.mutmut"),
        ),
    )
    if test_artifacts is not None:
        scope, tool_versions, coverage, mutmut = test_artifacts
        results.extend(
            evaluate_test_adequacy_evidence(
                policy=policy,
                scope_artifact=scope,
                tool_versions=tool_versions,
                coverage_json=coverage,
                mutmut_json=mutmut,
            ).checks
        )
        artifacts.extend(test_artifacts)

    performance_artifacts = _complete_artifact_set(
        local_evidence,
        (
            ("performance-runner.json", "performance.runner"),
            ("baseline-asv.json", "performance.baseline"),
            ("candidate-asv.json", "performance.candidate"),
        ),
    )
    if performance_artifacts is not None:
        runner, baseline, candidate = performance_artifacts
        results.extend(
            evaluate_performance_evidence(
                runner_output=runner,
                baseline_asv=baseline,
                candidate_asv=candidate,
            ).checks
        )
        artifacts.extend(performance_artifacts)

    latency = _local_evidence_artifact(
        local_evidence,
        "live-network-latency.json",
        "performance.live-network-latency",
    )
    if latency is not None:
        results.append(evaluate_live_network_latency(latency))
        artifacts.append(latency)

    if profile is Profile.RELEASE and enable_live:
        repository_slug = _github_slug(subject.repository)
        if repository_slug is None:
            raise ValueError("release live collection requires a GitHub repository URL")
        process_collection = collect_openssf_scorecard(repository_slug)
        process_evaluation = evaluate_process_supply_chain_collection(
            policy=policy,
            collection=process_collection,
        )
        results.extend(process_evaluation.checks)
        if process_collection.artifact is not None:
            artifacts.append(process_collection.artifact)

    return evaluate(
        policy,
        tuple(results),
        profile=profile,
        subject=subject,
        producer=Producer(
            name="leitir-score-engine",
            version=SCORE_ENGINE_VERSION,
            commit_sha=subject.commit_sha,
        ),
        evidence=tuple(artifacts),
    )


def _decoded_json(path: str | Path, name: str) -> object:
    def reject_constant(value: str) -> object:
        raise ValueError(f"{name} contains non-finite number {value}")

    try:
        content = Path(path).read_bytes()
        return json.loads(content, parse_constant=reject_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} is not readable strict JSON") from exc


def _write_output(path: str | Path, content: bytes) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="score_engine.py",
        description="Deterministic ADR-002 evidence scoring engine",
    )
    commands = parser.add_subparsers(dest="operation", required=True)
    run = commands.add_parser("run", help="collect, evaluate, and render")
    run.add_argument("--profile", choices=[item.value for item in Profile], required=True)
    run.add_argument("--root", default=".")
    run.add_argument("--policy", default="scorecard/policy-v1.json")
    run.add_argument("--evidence-dir")
    run.add_argument("--json-out", default=".leitir-score/assessment.json")
    run.add_argument("--html-out", default=".leitir-score/scorecard.html")
    run.add_argument(
        "--run-envelope-out", default=".leitir-score/run-envelope.json"
    )

    render = commands.add_parser("render", help="render a canonical assessment")
    render.add_argument("--assessment", required=True)
    render.add_argument("--html", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the standalone CLI and return the pinned ADR-002 process exit."""
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    parser = _build_cli_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        if args.operation == "render":
            raw = _assessment_render_mapping(
                _render_mapping(
                    _decoded_json(args.assessment, "assessment"), "assessment"
                )
            )
            _write_output(args.html, render_assessment_html(raw))
            output.write(render_terminal_summary(raw))
            return int(decision_exit_code(Decision(raw["aggregate"]["decision"])))

        profile = Profile(args.profile)
        policy_path = Path(args.policy)
        if not policy_path.is_absolute():
            policy_path = Path(args.root).resolve() / policy_path
        try:
            policy = load_policy(policy_path)
        except OSError as exc:
            raise ValueError("policy is not readable") from exc
        import time

        started_at_utc = _utc_now_text()
        started_ns = time.monotonic_ns()
        assessment = run_profile_assessment(
            root=args.root,
            policy=policy,
            profile=profile,
            enable_live=(
                profile is Profile.RELEASE
                and os.environ.get("LEITIR_ENABLE_SCORE_LIVE") == "1"
            ),
            evidence_dir=args.evidence_dir,
        )
        finished_ns = time.monotonic_ns()
        finished_at_utc = _utc_now_text()
        _write_output(args.json_out, assessment.to_bytes())
        _write_output(args.html_out, render_assessment_html(assessment))
        envelope_path = Path(args.run_envelope_out)
        if not envelope_path.is_absolute():
            envelope_path = Path(args.root).resolve() / envelope_path
        envelope = _run_envelope_for_assessment(
            assessment,
            started_at_utc=started_at_utc,
            finished_at_utc=finished_at_utc,
            duration_ns=finished_ns - started_ns,
        )
        _write_output(envelope_path, envelope.to_json().encode("utf-8"))
        output.write(render_terminal_summary(assessment))
        if profile is Profile.OFFLINE:
            output.write("release_readiness=not_claimed\n")
        return int(assessment.exit_code)
    except OSError as exc:
        errors.write(f"score_engine.py: infrastructure error: {exc}\n")
        return int(ExitCode.INDETERMINATE)
    except (TypeError, ValueError) as exc:
        errors.write(f"score_engine.py: {exc}\n")
        return int(ExitCode.INVALID_USAGE_OR_POLICY)


__all__ = [
    "ADR001_OFFLINE_GATE_ARGV",
    "ADR001_OFFLINE_GATE_TESTS",
    "ASSESSMENT_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "RUN_ENVELOPE_SCHEMA_VERSION",
    "SCORE_ENGINE_VERSION",
    "ApplicabilityRule",
    "Assessment",
    "AssessedCheck",
    "Blocker",
    "BlockerKind",
    "CheckMode",
    "CheckPolicy",
    "CheckResult",
    "CheckStatus",
    "CodeHealthEvaluation",
    "CommandExecution",
    "ComplexityReport",
    "Criterion",
    "Decision",
    "DimensionAssessment",
    "DimensionPolicy",
    "DeclaredCodeScope",
    "ExitCode",
    "EvidenceArtifact",
    "GateAggregate",
    "CoverageReport",
    "MaintainabilityIndexReport",
    "MutationReport",
    "MannWhitneyResult",
    "GitHubCapabilities",
    "OPENSSF_SCORECARD_API",
    "OPENSSF_SELECTED_CHECKS",
    "OpenSSFApplicability",
    "OpenSSFCollection",
    "OpenSSFCollectionState",
    "OpenSSFEvaluationError",
    "OpenSSFProvenance",
    "PINNED_SCORE_TOOL_VERSIONS",
    "PINNED_OPENSSF_SCORECARD_COMMIT",
    "PINNED_OPENSSF_SCORECARD_VERSION",
    "PINNED_ASV_VERSION",
    "Policy",
    "PerformanceBenchmarkComparison",
    "PerformanceEvaluation",
    "PerformanceEvaluationError",
    "PerformanceSampleSummary",
    "ProcessSupplyChainEvaluation",
    "Producer",
    "Profile",
    "RetrievalEvaluation",
    "RetrievalEvaluationError",
    "RetrievalCrossCheck",
    "RetrievalMetrics",
    "RetrievalStratum",
    "RetrievalTaskEvaluation",
    "RawEvidenceProvenance",
    "RunEnvelope",
    "ScoreAggregate",
    "SourceSpan",
    "ScopeApplicability",
    "Subject",
    "TestAdequacyEvaluation",
    "canonical_json_bytes",
    "canonical_patch_sha256",
    "collect_adr001_pytest_junit",
    "collect_openssf_scorecard",
    "compute_retrieval_metrics",
    "decision_exit_code",
    "display_band",
    "evaluate",
    "evaluate_deterministic_replay",
    "evaluate_engine_correctness_evidence",
    "evaluate_code_health_evidence",
    "evaluate_global_no_exhaustiveness",
    "evaluate_output_effectiveness_evidence",
    "evaluate_performance_evidence",
    "evaluate_live_network_latency",
    "evaluate_process_supply_chain_collection",
    "evaluate_process_supply_chain_evidence",
    "evaluate_pytest_junit",
    "evaluate_result_provenance",
    "evaluate_retired_surfaces_absent",
    "evaluate_scoped_coverage",
    "evaluate_retrieval",
    "evaluate_total_ordering",
    "evaluate_test_adequacy_evidence",
    "load_policy",
    "main",
    "mann_whitney_u_two_sided",
    "policy_from_dict",
    "proportional_score_bps",
    "render_assessment_html",
    "render_terminal_summary",
    "run_profile_assessment",
    "score_from_counts",
    "subject_from_repository",
    "untracked_inputs_sha256",
    "weighted_score_bps",
]


if __name__ == "__main__":
    raise SystemExit(main())
