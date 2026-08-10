"""Stable domain vocabulary for Leitir's deterministic code-search kernel.

These contracts define the harness boundary described in ADR-001: a caller
supplies a typed ``SearchSpec`` and Leitir returns a ``SearchReport`` with
immutable provenance and an honest coverage status. No model concepts live
here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")
_SPACE = re.compile(r"\s+")
_EXCLUSION_REASONS = frozenset(
    {
        "decode_failed",
        "deduplicated",
        "fetch_failed",
        "head_unresolved",
        "no_adapter",
        "path_mismatch",
        "provenance_mismatch",
        "pin_disagreement",
        "unpinned_hit",
    }
)


class SearchMode(StrEnum):
    """The two completeness regimes Leitir is allowed to claim."""

    SCOPED_EXHAUSTIVE = "scoped_exhaustive"
    GLOBAL_DISCOVERY = "global_discovery"


class CoverageStatus(StrEnum):
    """Honest, machine-checkable completeness states."""

    COMPLETE_FOR_DECLARED_UNIVERSE = "complete_for_declared_universe"
    PARTIAL = "partial"
    INDETERMINATE_GLOBAL = "indeterminate_global"


class ResolutionStrategy(StrEnum):
    """How immutable commit provenance was obtained for a search report."""

    INDEXED_COMMIT = "indexed_commit"
    DECLARED_SCOPE = "declared_scope"


class SearchSpecError(ValueError):
    """A typed search specification cannot be executed as requested."""


@dataclass(frozen=True, slots=True)
class Resolution:
    """Provenance resolution strategy and the UTC time it was recorded."""

    strategy: ResolutionStrategy
    as_of: str

    def __post_init__(self) -> None:
        if not isinstance(self.strategy, ResolutionStrategy):
            raise TypeError("strategy must be a ResolutionStrategy")
        if not isinstance(self.as_of, str) or not self.as_of:
            raise ValueError("as_of must be a non-empty RFC3339 UTC string")
        try:
            parsed = datetime.fromisoformat(self.as_of)
        except ValueError as exc:
            raise ValueError("as_of must be an RFC3339 UTC string") from exc
        if not self.as_of.endswith("Z") or parsed.utcoffset() is None:
            raise ValueError("as_of must be an RFC3339 UTC string")

    def to_dict(self) -> dict[str, str]:
        return {"strategy": self.strategy.value, "as_of": self.as_of}


class PredicateKind(StrEnum):
    """Typed search predicates; the harness chooses these, never prose."""

    EXACT_TEXT = "exact_text"
    TOKEN_SEQUENCE = "token_sequence"
    IDENTIFIER = "identifier"
    SYMBOL_DEFINITION = "symbol_definition"
    SYMBOL_REFERENCE = "symbol_reference"
    SIGNATURE = "signature"
    CALL = "call"
    IMPORT = "import"
    PATH = "path"
    REGEX = "regex"


@dataclass(frozen=True, slots=True)
class Predicate:
    """One deterministic match condition."""

    kind: PredicateKind
    value: str
    language: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PredicateKind):
            raise TypeError("kind must be a PredicateKind")
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("predicate value must be non-empty text")
        if self.language is not None and not self.language.strip():
            raise ValueError("language must be non-empty when provided")
        if self.kind is PredicateKind.REGEX:
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError("regex predicate must compile") from exc

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "kind": self.kind.value,
            "value": self.value,
        }
        if self.language is not None:
            result["language"] = self.language
        return result


@dataclass(frozen=True, slots=True)
class QueryTranslation:
    """Machine-readable disposition of one predicate during query planning."""

    clause: str
    predicate_index: int
    kind: PredicateKind
    strategy: str
    emitted_syntax: str | None = None

    def __post_init__(self) -> None:
        if self.clause not in {"must", "should", "must_not"}:
            raise ValueError("clause must be must, should, or must_not")
        if (
            isinstance(self.predicate_index, bool)
            or not isinstance(self.predicate_index, int)
            or self.predicate_index < 0
        ):
            raise ValueError("predicate_index must be a non-negative integer")
        if not isinstance(self.kind, PredicateKind):
            raise TypeError("kind must be a PredicateKind")
        if self.strategy not in {
            "github_query",
            "github_superset_local_filter",
            "local_filter",
        }:
            raise ValueError(
                "strategy must be github_query, github_superset_local_filter, or local_filter"
            )
        if self.strategy in {"github_query", "github_superset_local_filter"}:
            if not isinstance(self.emitted_syntax, str) or not self.emitted_syntax:
                raise ValueError("GitHub query translations require emitted syntax")
        elif self.emitted_syntax is not None:
            raise ValueError("local_filter translations cannot emit query syntax")

    def to_dict(self) -> dict[str, object]:
        return {
            "clause": self.clause,
            "predicate_index": self.predicate_index,
            "kind": self.kind.value,
            "strategy": self.strategy,
            "emitted_syntax": self.emitted_syntax,
        }


@dataclass(frozen=True, slots=True)
class RepoScope:
    """One explicitly declared repository pinned to an immutable commit."""

    slug: str
    commit_sha: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.slug, str)
            or not _REPO_SLUG.fullmatch(self.slug)
            or any(part in {".", ".."} for part in self.slug.split("/"))
        ):
            raise ValueError("slug must contain at least two safe repository path segments")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("commit_sha must be a 40-char git SHA")


@dataclass(frozen=True, slots=True)
class SearchSpec:
    """The harness-supplied, fully typed search intent."""

    mode: SearchMode
    must: tuple[Predicate, ...] = ()
    should: tuple[Predicate, ...] = ()
    must_not: tuple[Predicate, ...] = ()
    scopes: tuple[RepoScope, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.mode, SearchMode):
            raise TypeError("mode must be a SearchMode")
        for name in ("must", "should", "must_not"):
            value = getattr(self, name)
            if isinstance(value, (str, bytes)) or not isinstance(value, tuple):
                raise TypeError(f"{name} must be a tuple of Predicate")
            if any(not isinstance(item, Predicate) for item in value):
                raise TypeError(f"{name} must contain only Predicate values")
        if not isinstance(self.scopes, tuple) or any(
            not isinstance(item, RepoScope) for item in self.scopes
        ):
            raise TypeError("scopes must be a tuple of RepoScope")
        if not self.must:
            raise ValueError("a search requires at least one must predicate")
        if self.mode is SearchMode.SCOPED_EXHAUSTIVE and not self.scopes:
            raise ValueError("scoped_exhaustive requires at least one scope")
        from leitir.adapters.languages import canonicalize_language

        required_languages = {
            canonicalize_language(pred.language)
            for pred in self.must
            if pred.language is not None
        }
        if len(required_languages) > 1:
            raise SearchSpecError("conflicting required predicate languages")

    def digest(self) -> str:
        """Canonical identity of the spec; equal specs share a digest."""
        return hashlib.sha256(
            json.dumps(self._canonical(), sort_keys=True).encode("utf-8")
        ).hexdigest()

    def _canonical(self) -> dict[str, object]:
        def predicates(items: tuple[Predicate, ...]) -> list[dict[str, str]]:
            return [
                {
                    "kind": item.kind.value,
                    "value": item.value,
                    "language": item.language or "",
                }
                for item in items
            ]

        return {
            "mode": self.mode.value,
            "must": predicates(self.must),
            "should": predicates(self.should),
            "must_not": predicates(self.must_not),
            "scopes": [
                {"slug": scope.slug, "commit_sha": scope.commit_sha}
                for scope in self.scopes
            ],
        }


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Immutable identity of one matched source span."""

    slug: str
    commit_sha: str
    path: str
    blob_sha: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.slug, str)
            or not _REPO_SLUG.fullmatch(self.slug)
            or any(part in {".", ".."} for part in self.slug.split("/"))
        ):
            raise ValueError("slug must contain at least two safe repository path segments")
        if not isinstance(self.commit_sha, str) or not _SHA1.fullmatch(
            self.commit_sha
        ):
            raise ValueError("commit_sha must be a 40-char git SHA")
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("path must be non-empty")
        if not isinstance(self.blob_sha, str) or not _SHA1.fullmatch(self.blob_sha):
            raise ValueError("blob_sha must be a 40-char git SHA")
        if (
            isinstance(self.start_line, bool)
            or not isinstance(self.start_line, int)
            or self.start_line < 1
        ):
            raise ValueError("start_line must be a positive integer")
        if (
            isinstance(self.end_line, bool)
            or not isinstance(self.end_line, int)
            or self.end_line < self.start_line
        ):
            raise ValueError("end_line must be >= start_line")

    @property
    def permalink(self) -> str:
        return (
            f"https://github.com/{self.slug}/blob/{self.commit_sha}/"
            f"{self.path}#L{self.start_line}-L{self.end_line}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "slug": self.slug,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "blob_sha": self.blob_sha,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "permalink": self.permalink,
        }


@dataclass(frozen=True, slots=True)
class SourceMatch:
    """One ranked result with the predicates it satisfied."""

    source: SourceRef
    score: float
    matched_kinds: tuple[PredicateKind, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceRef):
            raise TypeError("source must be a SourceRef")
        if isinstance(self.score, bool) or not isinstance(self.score, (int, float)):
            raise TypeError("score must be a number")
        if not isinstance(self.matched_kinds, tuple):
            raise TypeError("matched_kinds must be a tuple")
        if any(not isinstance(item, PredicateKind) for item in self.matched_kinds):
            raise TypeError("matched_kinds must contain only PredicateKind")
        if not self.matched_kinds:
            raise ValueError("a match must record at least one matched predicate")

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source.to_dict(),
            "score": self.score,
            "matched_kinds": [k.value for k in self.matched_kinds],
        }


@dataclass(frozen=True, slots=True)
class Coverage:
    """The honest accounting of what was and was not searched."""

    status: CoverageStatus
    files_eligible: int
    files_indexed: int
    files_excluded: int
    incomplete_results: bool = False
    exclusions: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.status, CoverageStatus):
            raise TypeError("status must be a CoverageStatus")
        for name in ("files_eligible", "files_indexed", "files_excluded"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.files_indexed > self.files_eligible:
            raise ValueError("files_indexed cannot exceed files_eligible")
        if not isinstance(self.incomplete_results, bool):
            raise TypeError("incomplete_results must be a bool")
        if not isinstance(self.exclusions, dict):
            raise TypeError("exclusions must be a dict")
        for reason, count in self.exclusions.items():
            if not isinstance(reason, str):
                raise TypeError("exclusion reasons must be strings")
            if reason not in _EXCLUSION_REASONS:
                raise ValueError(f"unknown exclusion reason: {reason}")
            if isinstance(count, bool) or not isinstance(count, int):
                raise TypeError("exclusion counts must be integers")
            if count < 0:
                raise ValueError("exclusion counts must be non-negative")
        if sum(self.exclusions.values()) > self.files_excluded:
            raise ValueError("exclusion counts cannot exceed files_excluded")
        if (
            self.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
            and (self.incomplete_results or self.files_indexed != self.files_eligible)
        ):
            raise ValueError(
                "complete coverage requires full indexing and no partial results"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "files_eligible": self.files_eligible,
            "files_indexed": self.files_indexed,
            "files_excluded": self.files_excluded,
            "incomplete_results": self.incomplete_results,
            "exclusions": dict(sorted(self.exclusions.items())),
        }


@dataclass(frozen=True, slots=True)
class SearchReport:
    """The deterministic output returned to the harness."""

    spec_digest: str
    coverage: Coverage
    matches: tuple[SourceMatch, ...]
    resolution: Resolution
    query_translation: tuple[QueryTranslation, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.spec_digest, str) or not _SHA256.fullmatch(
            self.spec_digest
        ):
            raise ValueError("spec_digest must be a 64-char sha256 hex string")
        if not isinstance(self.coverage, Coverage):
            raise TypeError("coverage must be a Coverage")
        if not isinstance(self.matches, tuple):
            raise TypeError("matches must be a tuple")
        if any(not isinstance(item, SourceMatch) for item in self.matches):
            raise TypeError("matches must contain only SourceMatch values")
        if not isinstance(self.resolution, Resolution):
            raise TypeError("resolution must be a Resolution")
        if not isinstance(self.query_translation, tuple):
            raise TypeError("query_translation must be a tuple")
        if any(
            not isinstance(item, QueryTranslation) for item in self.query_translation
        ):
            raise TypeError("query_translation must contain only QueryTranslation values")

    def to_dict(self) -> dict[str, object]:
        return {
            "spec_digest": self.spec_digest,
            "coverage": self.coverage.to_dict(),
            "matches": [m.to_dict() for m in self.matches],
            "resolution": self.resolution.to_dict(),
            "query_translation": [item.to_dict() for item in self.query_translation],
        }

    def identity_digest(self) -> str:
        """Canonical report identity, excluding observation time/strategy metadata."""
        identity = {
            "spec_digest": self.spec_digest,
            "coverage": self.coverage.to_dict(),
            "matches": [match.to_dict() for match in self.matches],
            "query_translation": [item.to_dict() for item in self.query_translation],
        }
        encoded = json.dumps(
            identity,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
