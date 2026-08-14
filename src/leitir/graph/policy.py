"""Closed extraction-policy contracts for optional tree-sitter producers."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, fields
from pathlib import Path
from typing import NoReturn

from leitir.adapters.languages import canonicalize_language
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import SourceRef

GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION = "leitir-graph-extraction-policy-v1"
SOURCE_SELECTION_VERSION = "tree_sitter_source_selection_v1"
TREE_SITTER_PINS = {
    "tree-sitter": "0.25.2",
    "tree-sitter-javascript": "0.25.0",
    "tree-sitter-typescript": "0.23.2",
    "tree-sitter-rust": "0.24.2",
    "tree-sitter-go": "0.25.0",
}
_GRAMMAR_FACTORIES = {
    "javascript": "language",
    "typescript": "language_typescript",
    "rust": "language",
    "go": "language",
}
_LANGUAGES = frozenset({"javascript", "typescript", "rust", "go"})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REQUIREMENT = re.compile(r"^\s*([a-z0-9][a-z0-9._-]*)==([^\s\\]+)(?:\s|\\|$)", re.IGNORECASE)
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|\\|$)")
_HASH_LINE = re.compile(r"^\s*(?:--hash=sha256:[0-9a-f]{64}\s*)+\\?\s*$")
_INLINE_COMMENT = re.compile(r"(?:^|(?<=\s))#")


def _reject(reason: BTSRejectReason, message: str, detail_code: str) -> NoReturn:
    # Deliberately mirrors registry._typed: policy remains registry-independent.
    raise BTSError(reason, message, detail_code=detail_code)


def _require_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, f"{name} must be a non-empty string", "tree_sitter_policy_field_v1")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            f"{name} must be strict UTF-8",
            detail_code="tree_sitter_policy_field_v1",
            cause=exc,
        ) from exc


def _require_digest(value: object, name: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, f"{name} must be a lowercase SHA-256 digest", "tree_sitter_policy_digest_v1")


def _require_positive_int(value: object, name: str) -> None:
    if type(value) is not int or value <= 0:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, f"{name} must be a positive integer", "tree_sitter_policy_limit_v1")


def _policy_payload(policy: GraphExtractionPolicy) -> dict[str, object]:
    return {item.name: getattr(policy, item.name) for item in fields(policy) if item.name != "policy_digest"}


def compute_policy_digest(policy: GraphExtractionPolicy) -> str:
    """Hash every policy field other than its self-referential digest.

    The canonical representation is sorted-key, compact UTF-8 JSON with one
    terminating LF.  All policy values are scalar, so this deliberately has no
    implicit dataclass or platform-dependent serialization behavior.
    """

    encoded = (json.dumps(_policy_payload(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_requirements_lock_text(lock_text: str) -> str:
    """Return the canonical LF-terminated form used for lock identity."""

    if not isinstance(lock_text, str):
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "requirements lock text is invalid", "tree_sitter_lock_unavailable_v1")
    return lock_text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def requirements_lock_digest(lock_text: str) -> str:
    """Return the SHA-256 identity of canonical requirement-lock text."""

    return hashlib.sha256(canonical_requirements_lock_text(lock_text).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class GraphExtractionPolicy:
    schema_version: str
    authority: str
    policy_id: str
    language: str
    requirements_lock_digest: str
    runtime_distribution: str
    runtime_version: str
    grammar_distribution: str
    grammar_version: str
    grammar_factory: str
    grammar_abi_version: int
    query_id: str
    query_sha256: str
    producer_id: str
    producer_version: str
    resolution_rule_version: str
    source_selection_version: str
    max_files: int
    max_file_bytes: int
    max_tree_nodes_per_file: int
    max_query_matches: int
    max_symbols: int
    max_edges: int
    max_work_units: int
    policy_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "unknown graph extraction policy schema", "tree_sitter_policy_schema_v1")
        for name in (
            "authority", "policy_id", "language", "runtime_distribution", "runtime_version",
            "grammar_distribution", "grammar_version", "grammar_factory", "query_id", "producer_id",
            "producer_version", "resolution_rule_version", "source_selection_version",
        ):
            _require_text(getattr(self, name), name)
        if self.language not in _LANGUAGES or canonicalize_language(self.language) != self.language:
            _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unsupported graph extraction language", "tree_sitter_graph_language_unknown_v1")
        expected_runtime_version = TREE_SITTER_PINS["tree-sitter"]
        expected_runtime_distribution = "tree-sitter"
        expected_grammar_distribution = f"tree-sitter-{self.language}"
        expected_grammar_version = TREE_SITTER_PINS[f"tree-sitter-{self.language}"]
        expected_factory = _GRAMMAR_FACTORIES[self.language]
        if (
            self.runtime_distribution != expected_runtime_distribution
            or self.grammar_distribution != expected_grammar_distribution
        ):
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "graph extraction policy does not name the pinned tree-sitter distributions",
                "tree_sitter_policy_distribution_mismatch_v1",
            )
        if (
            self.runtime_version != expected_runtime_version
            or self.grammar_version != expected_grammar_version
            or self.grammar_factory != expected_factory
        ):
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "graph extraction policy does not match the pinned tree-sitter tuple",
                "tree_sitter_policy_tuple_mismatch_v1",
            )
        for name in ("requirements_lock_digest", "query_sha256", "policy_digest"):
            _require_digest(getattr(self, name), name)
        for name in (
            "grammar_abi_version", "max_files", "max_file_bytes", "max_tree_nodes_per_file",
            "max_query_matches", "max_symbols", "max_edges", "max_work_units",
        ):
            _require_positive_int(getattr(self, name), name)
        if compute_policy_digest(self) != self.policy_digest:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph extraction policy digest does not match its fields", "tree_sitter_policy_digest_mismatch_v1")


def build_graph_extraction_policy(**values: object) -> GraphExtractionPolicy:
    """Build a v1 policy and derive its mandatory canonical digest."""

    expected = {item.name for item in fields(GraphExtractionPolicy)} - {"policy_digest"}
    if set(values) != expected:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph extraction policy fields are not closed", "tree_sitter_policy_fields_v1")
    provisional = GraphExtractionPolicy.__new__(GraphExtractionPolicy)
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    object.__setattr__(provisional, "policy_digest", "0" * 64)
    return GraphExtractionPolicy(**values, policy_digest=compute_policy_digest(provisional))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class GraphExtractionRequest:
    language: str
    source_root: Path
    source_files: tuple[SourceRef, ...]
    policy: GraphExtractionPolicy

    def __post_init__(self) -> None:
        policy: object = self.policy
        if not isinstance(policy, GraphExtractionPolicy):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request policy is not a GraphExtractionPolicy", "tree_sitter_request_policy_v1")
        if not isinstance(self.language, str) or not self.language:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request language is invalid", "tree_sitter_request_language_v1")
        language = canonicalize_language(self.language)
        if language not in _LANGUAGES or language != policy.language:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request and policy languages differ", "tree_sitter_request_language_mismatch_v1")
        source_root: object = self.source_root
        if not isinstance(source_root, Path):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request source root is not a Path", "tree_sitter_request_root_v1")
        if not isinstance(self.source_files, tuple) or not self.source_files:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request source scope must be a non-empty tuple", "tree_sitter_request_scope_v1")
        if any(not isinstance(source, SourceRef) for source in self.source_files):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request source scope contains a non-SourceRef", "tree_sitter_request_scope_v1")
        paths = tuple(source.path for source in self.source_files)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "request source scope is not sorted and unique", "tree_sitter_request_scope_v1")


def assert_platform_wheel_coverage(lock_text: str, *, python_tag: str, platform_tags: Sequence[str]) -> None:
    """Fail closed unless a lock describes the complete pinned wheel tuple.

    Requirement hashes do not encode Python or platform tags.  Pip's
    ``--require-hashes --only-binary :all:`` resolver is consequently the
    install-time authority for the requested tuple.  This pure preflight checks
    that the supplied lock at least contains the exact reviewed tuple and one
    SHA-256 hash for every pin; malformed or incomplete locks cannot authorize
    production for any requested platform.
    """

    valid_request = isinstance(python_tag, str) and bool(python_tag) and not isinstance(platform_tags, str) and bool(platform_tags) and all(isinstance(tag, str) and tag for tag in platform_tags)
    pins: dict[str, tuple[str, int]] = {}
    current: str | None = None
    if isinstance(lock_text, str) and valid_request:
        for line in lock_text.splitlines():
            comment = _INLINE_COMMENT.search(line)
            effective_line = line[:comment.start()] if comment is not None else line
            if not effective_line.strip():
                # Pip ignores comments, so they cannot supply a pin's hash or
                # preserve a requirement's continuation context.
                current = None
                continue
            continued = effective_line.rstrip().endswith("\\")
            has_hash_option = "--hash=" in effective_line
            requirement = _REQUIREMENT.match(effective_line)
            if current is not None and requirement is not None:
                _reject(
                    BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                    "tree-sitter lock contains a requirement inside a hash continuation",
                    "tree_sitter_platform_hash_unavailable_v1",
                )
            if current is not None and has_hash_option:
                if _HASH_LINE.fullmatch(effective_line) is None:
                    _reject(
                        BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                        "tree-sitter lock contains a malformed hash continuation",
                        "tree_sitter_platform_hash_unavailable_v1",
                    )
                version, hash_count = pins[current]
                pins[current] = (version, hash_count + len(_HASH.findall(effective_line)))
                current = current if continued else None
                continue
            if requirement is not None:
                name = requirement.group(1).casefold()
                version = requirement.group(2)
                hash_count = len(_HASH.findall(effective_line))
                if has_hash_option and hash_count != effective_line.count("--hash="):
                    _reject(
                        BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                        "tree-sitter lock contains a malformed requirement hash",
                        "tree_sitter_platform_hash_unavailable_v1",
                    )
                if name in pins:
                    current = None
                    pins[name] = (version, -1)
                else:
                    pins[name] = (version, hash_count)
                    current = name if continued else None
            elif has_hash_option:
                _reject(
                    BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                    "tree-sitter lock contains an orphaned hash continuation",
                    "tree_sitter_platform_hash_unavailable_v1",
                )
            else:
                current = None
    complete = set(pins) == set(TREE_SITTER_PINS)
    if complete:
        for name, expected_version in TREE_SITTER_PINS.items():
            actual_version, hash_count = pins[name]
            if actual_version != expected_version or hash_count <= 0:
                complete = False
                break
    if not complete:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "tree-sitter lock has no accepted wheel hash for this resolution", "tree_sitter_platform_hash_unavailable_v1")


_GRAMMAR_MODULES = {
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "rust": "tree_sitter_rust",
    "go": "tree_sitter_go",
}


def require_tree_sitter_extra(language: str) -> None:
    """Import precisely the runtime and requested grammar, or reject typed."""

    normalized = canonicalize_language(language) if isinstance(language, str) else ""
    module = _GRAMMAR_MODULES.get(normalized)
    if module is None:
        _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unsupported graph extraction language", "tree_sitter_graph_language_unknown_v1")
    try:
        importlib.import_module("tree_sitter")
        importlib.import_module(module)
    except ImportError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_EXTRA,
            "tree-sitter optional extra is not installed for graph production",
            detail_code="tree_sitter_extra_missing_v1",
            cause=exc,
        ) from exc
    except Exception as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNSUPPORTED_EXTRA,
            "tree-sitter optional extra is broken for graph production",
            detail_code="tree_sitter_extra_broken_v1",
            cause=exc,
        ) from exc
