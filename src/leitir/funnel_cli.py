"""Pure input adapters for the future ``bts-funnel`` command.

The integrator should expose ``bts-funnel --spec PATH --recipient-manifest PATH
--stages PATH`` and ``capability-validate --spec PATH``.  This module owns no
argument parsing or I/O other than bounded input reads.

Recipient manifests are closed JSON objects with exactly ``schema_version``,
``project_root_identity``, and ``entries``.  ``schema_version`` is
``leitir-funnel-recipient-input-v1``.  Each entry has exactly ``path``,
``role``, and ``content_b64``; bytes are base64-decoded and bound by
``RecipientInputManifest.create``.  Every supplied entry is a required source
in the derived ``DependencyManifestPolicy``.  This is the pinned wrapper
policy: it prevents a caller from silently omitting an input from profiling.

Stages are a closed top-level array.  Each item has exactly ``search_spec_digest``,
``report``, ``symbols``, ``termination``, ``pages_recorded``, and
``blob_byte_lengths``.  ``report`` is the exact ``SearchReport.to_dict``
projection (including validated permalink fields); SearchReport has no parser.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, TypeVar

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.candidates import (
    PINNED_CANDIDATE_BUDGET_POLICY,
    CandidateBudget,
    CandidateRetrievalPlan,
    DiscoveryStageResult,
    EvidencePointer,
    FunnelTermination,
    SymbolStageEvidence,
    ValidationStatus,
    compile_search_specs,
    discover_candidates,
)
from leitir.capability import CapabilitySpec
from leitir.comparison import compare_and_select
from leitir.graph.model import SourceRef as GraphSourceRef
from leitir.lockfiles import DependencyManifestPolicy
from leitir.project_profile import (
    RecipientInputManifest,
    RecipientManifestEntry,
    RecipientProfile,
    profile_project,
)
from leitir.safeio import read_regular_file
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    QueryTranslation,
    Resolution,
    ResolutionStrategy,
    SearchReport,
    SourceMatch,
    SourceRef,
)
from leitir.suitability import build_survivor_set

_MAX_INPUT_BYTES = 64 * 1024 * 1024
_RECIPIENT_SCHEMA = "leitir-funnel-recipient-input-v1"
_T = TypeVar("_T")


@dataclass(slots=True)
class _ProfileDigest:
    """Mutable-protocol-compatible profile reference for C2's digest binding."""

    profile_digest: str


def _reject(reason: BTSRejectReason, message: str, code: str, cause: BaseException | None = None) -> NoReturn:
    raise BTSError(reason, message, detail_code=code, cause=cause)


def _input_error(family: str, message: str, cause: BaseException | None = None) -> NoReturn:
    _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, message, family, cause)


def _duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, family: str) -> object:
    try:
        if not isinstance(path, Path):
            raise TypeError("path must be pathlib.Path")
        data = read_regular_file(path, maximum_bytes=_MAX_INPUT_BYTES)
    except (OSError, TypeError, ValueError) as exc:
        _input_error(family, f"could not read {path}", exc)
    try:
        return json.loads(data, object_pairs_hook=_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        _input_error(family, f"{path} is not valid strict JSON", exc)


def _mapping(value: object, fields: frozenset[str], name: str, family: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        _input_error(family, f"{name} has missing or unknown fields")
    return value


def _text(value: object, name: str, family: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        _input_error(family, f"{name} must be bounded non-empty text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        _input_error(family, f"{name} must be strict UTF-8", exc)
    return value


def _integer(value: object, name: str, family: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _input_error(family, f"{name} must be an integer >= {minimum}")
    return value


def _enum(value: object, enum_type: type[_T], name: str, family: str) -> _T:
    try:
        return enum_type(value)  # type: ignore[call-arg]
    except (TypeError, ValueError) as exc:
        _input_error(family, f"{name} has an unsupported value", exc)


def _canonical_object(data: bytes) -> dict[str, object]:
    decoded = json.loads(data)
    if not isinstance(decoded, dict):  # pragma: no cover - owned serializers always produce objects
        raise AssertionError("owned serializer did not produce an object")
    return decoded


def validate_capability_spec(path: Path) -> dict[str, object]:
    """Load a canonical capability artifact, binding it to the pinned registry."""

    data = _read_json(path, "funnel_cli_spec_invalid_v1")
    try:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        spec = CapabilitySpec.from_json(canonical)
    except (BTSError, TypeError, ValueError) as exc:
        _input_error("funnel_cli_spec_invalid_v1", "capability spec is invalid or not canonical", exc)
    return {
        "schema_version": "leitir-funnel-capability-summary-v1",
        "spec": _canonical_object(spec.to_bytes()),
        "spec_digest": spec.spec_digest,
    }


def _load_spec(path: Path) -> CapabilitySpec:
    data = _read_json(path, "funnel_cli_spec_invalid_v1")
    try:
        return CapabilitySpec.from_json(
            json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        )
    except (BTSError, TypeError, ValueError) as exc:
        _input_error("funnel_cli_spec_invalid_v1", "capability spec is invalid or not canonical", exc)


def _load_recipient_manifest(path: Path) -> RecipientInputManifest:
    family = "funnel_cli_recipient_manifest_invalid_v1"
    data = _mapping(_read_json(path, family), frozenset({"schema_version", "project_root_identity", "entries"}), "recipient manifest", family)
    if data["schema_version"] != _RECIPIENT_SCHEMA:
        _input_error(family, "recipient manifest schema_version is unsupported")
    root = _text(data["project_root_identity"], "project_root_identity", family)
    raw_entries = data["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) > 10_000:
        _input_error(family, "entries must be a bounded array")
    entries: list[RecipientManifestEntry] = []
    for index, raw in enumerate(raw_entries):
        entry = _mapping(raw, frozenset({"path", "role", "content_b64"}), f"entries[{index}]", family)
        encoded = _text(entry["content_b64"], f"entries[{index}].content_b64", family)
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            _input_error(family, f"entries[{index}].content_b64 is not canonical base64", exc)
        if base64.b64encode(content).decode("ascii") != encoded:
            _input_error(family, f"entries[{index}].content_b64 is not canonical base64")
        entries.append(RecipientManifestEntry.from_bytes(_text(entry["path"], f"entries[{index}].path", family), _text(entry["role"], f"entries[{index}].role", family), content))
    try:
        return RecipientInputManifest.create(root, tuple(entries))
    except (BTSError, TypeError, ValueError) as exc:
        _input_error(family, "recipient manifest is invalid", exc)


def build_recipient_profile(manifest_path: Path) -> tuple[dict[str, object], RecipientProfile]:
    """Profile the closed manifest using the wrapper's all-inputs-required policy."""

    manifest = _load_recipient_manifest(manifest_path)
    policy = DependencyManifestPolicy(tuple(entry.path for entry in manifest.entries))
    try:
        profile = profile_project(manifest, policy)
    except (BTSError, TypeError, ValueError) as exc:
        _input_error("funnel_cli_recipient_manifest_invalid_v1", "recipient profile could not be built", exc)
    return (
        {
            "manifest_digest": manifest.manifest_digest,
            "profile": _canonical_object(profile.to_bytes()),
            "schema_version": "leitir-funnel-recipient-profile-summary-v1",
        },
        profile,
    )


def _source(value: object, name: str, family: str) -> SourceRef:
    fields = frozenset({"slug", "commit_sha", "path", "blob_sha", "start_line", "end_line", "permalink"})
    data = _mapping(value, fields, name, family)
    try:
        source = SourceRef(
            _text(data["slug"], f"{name}.slug", family), _text(data["commit_sha"], f"{name}.commit_sha", family),
            _text(data["path"], f"{name}.path", family), _text(data["blob_sha"], f"{name}.blob_sha", family),
            _integer(data["start_line"], f"{name}.start_line", family, minimum=1),
            _integer(data["end_line"], f"{name}.end_line", family, minimum=1),
        )
    except (TypeError, ValueError) as exc:
        _input_error(family, f"{name} is invalid", exc)
    if data["permalink"] != source.permalink:
        _input_error(family, f"{name}.permalink does not bind the source")
    return source


def _report(value: object, family: str) -> SearchReport:
    data = _mapping(value, frozenset({"spec_digest", "coverage", "matches", "resolution", "query_translation"}), "report", family)
    coverage_data = _mapping(data["coverage"], frozenset({"status", "files_eligible", "files_indexed", "files_excluded", "incomplete_results", "exclusions"}), "report.coverage", family)
    exclusions = coverage_data["exclusions"]
    if not isinstance(exclusions, dict) or any(not isinstance(key, str) for key in exclusions):
        _input_error(family, "report.coverage.exclusions must be an object")
    try:
        incomplete = coverage_data["incomplete_results"]
        if not isinstance(incomplete, bool):
            _input_error(family, "report.coverage.incomplete_results must be bool")
        coverage = Coverage(
            _enum(coverage_data["status"], CoverageStatus, "report.coverage.status", family),
            _integer(coverage_data["files_eligible"], "report.coverage.files_eligible", family),
            _integer(coverage_data["files_indexed"], "report.coverage.files_indexed", family),
            _integer(coverage_data["files_excluded"], "report.coverage.files_excluded", family),
            incomplete,
            {key: _integer(item, f"report.coverage.exclusions.{key}", family) for key, item in exclusions.items()},
        )
        raw_matches = data["matches"]
        if not isinstance(raw_matches, list):
            _input_error(family, "report.matches must be an array")
        matches = tuple(
            SourceMatch(
                _source(_mapping(item, frozenset({"source", "score", "matched_kinds"}), f"report.matches[{index}]", family)["source"], f"report.matches[{index}].source", family),
                item["score"],
                tuple(_enum(kind, PredicateKind, f"report.matches[{index}].matched_kinds", family) for kind in item["matched_kinds"]),
            )
            for index, item in enumerate(raw_matches)
            if isinstance(item, dict) and isinstance(item.get("matched_kinds"), list)
        )
        if len(matches) != len(raw_matches):
            _input_error(family, "report matches are malformed")
        resolution_data = _mapping(data["resolution"], frozenset({"strategy", "as_of"}), "report.resolution", family)
        resolution = Resolution(_enum(resolution_data["strategy"], ResolutionStrategy, "report.resolution.strategy", family), _text(resolution_data["as_of"], "report.resolution.as_of", family))
        raw_translations = data["query_translation"]
        if not isinstance(raw_translations, list):
            _input_error(family, "report.query_translation must be an array")
        translations = tuple(
            QueryTranslation(
                _text(item["clause"], f"report.query_translation[{index}].clause", family),
                _integer(item["predicate_index"], f"report.query_translation[{index}].predicate_index", family),
                _enum(item["kind"], PredicateKind, f"report.query_translation[{index}].kind", family),
                _text(item["strategy"], f"report.query_translation[{index}].strategy", family),
                item["emitted_syntax"],
            )
            for index, item in enumerate(raw_translations)
            if isinstance(item, dict) and set(item) == {"clause", "predicate_index", "kind", "strategy", "emitted_syntax"}
        )
        if len(translations) != len(raw_translations):
            _input_error(family, "report query translations are malformed")
        return SearchReport(_text(data["spec_digest"], "report.spec_digest", family), coverage, matches, resolution, translations)
    except (BTSError, TypeError, ValueError, KeyError) as exc:
        _input_error(family, "serialized search report is invalid", exc)


def _pointer(value: object, name: str, family: str) -> EvidencePointer:
    data = _mapping(value, frozenset({"evidence_kind", "collector_id", "collector_version", "evidence_digest"}), name, family)
    try:
        return EvidencePointer(_text(data["evidence_kind"], f"{name}.evidence_kind", family), _text(data["collector_id"], f"{name}.collector_id", family), _text(data["collector_version"], f"{name}.collector_version", family), _text(data["evidence_digest"], f"{name}.evidence_digest", family))
    except (BTSError, TypeError, ValueError) as exc:
        _input_error(family, f"{name} is invalid", exc)


def _symbol(value: object, index: int, family: str) -> SymbolStageEvidence:
    name = f"symbols[{index}]"
    fields = frozenset({"source", "symbol_kind", "qualified_name", "extraction_method", "extraction_version", "proposal_rule_id", "proposal_rule_version", "validation_status", "extraction_evidence", "context_evidence", "ast_nodes_visited"})
    data = _mapping(value, fields, name, family)
    source_data = _mapping(data["source"], frozenset({"slug", "commit_sha", "path", "blob_sha", "start_line", "start_col", "end_line", "end_col"}), f"{name}.source", family)
    extraction, context = data["extraction_evidence"], data["context_evidence"]
    if not isinstance(extraction, list) or not isinstance(context, list):
        _input_error(family, f"{name} evidence must be arrays")
    try:
        source = GraphSourceRef(
            _text(source_data["slug"], f"{name}.source.slug", family), _text(source_data["commit_sha"], f"{name}.source.commit_sha", family),
            _text(source_data["path"], f"{name}.source.path", family), _text(source_data["blob_sha"], f"{name}.source.blob_sha", family),
            _integer(source_data["start_line"], f"{name}.source.start_line", family, minimum=1), _integer(source_data["start_col"], f"{name}.source.start_col", family),
            _integer(source_data["end_line"], f"{name}.source.end_line", family, minimum=1), _integer(source_data["end_col"], f"{name}.source.end_col", family),
        )
        return SymbolStageEvidence(
            source, _text(data["symbol_kind"], f"{name}.symbol_kind", family), _text(data["qualified_name"], f"{name}.qualified_name", family),
            _text(data["extraction_method"], f"{name}.extraction_method", family), _text(data["extraction_version"], f"{name}.extraction_version", family),
            _text(data["proposal_rule_id"], f"{name}.proposal_rule_id", family), _text(data["proposal_rule_version"], f"{name}.proposal_rule_version", family),
            _enum(data["validation_status"], ValidationStatus, f"{name}.validation_status", family),
            tuple(_pointer(item, f"{name}.extraction_evidence[{item_index}]", family) for item_index, item in enumerate(extraction)),
            tuple(_pointer(item, f"{name}.context_evidence[{item_index}]", family) for item_index, item in enumerate(context)),
            _integer(data["ast_nodes_visited"], f"{name}.ast_nodes_visited", family, minimum=1),
        )
    except (BTSError, TypeError, ValueError) as exc:
        _input_error(family, f"{name} is invalid", exc)


def _load_plan(path: Path, spec: CapabilitySpec) -> CandidateRetrievalPlan:
    family = "funnel_cli_stages_invalid_v1"
    raw_stages = _read_json(path, family)
    if not isinstance(raw_stages, list) or not raw_stages:
        _input_error(family, "stages must be a non-empty array")
    searches = {search.digest(): search for search in compile_search_specs(spec)}
    stages: list[DiscoveryStageResult] = []
    fields = frozenset({"search_spec_digest", "report", "symbols", "termination", "pages_recorded", "blob_byte_lengths"})
    for index, raw in enumerate(raw_stages):
        data = _mapping(raw, fields, f"stages[{index}]", family)
        digest = _text(data["search_spec_digest"], f"stages[{index}].search_spec_digest", family)
        search = searches.get(digest)
        if search is None:
            _input_error(family, f"stages[{index}] does not name a capability search")
        report = _report(data["report"], family)
        symbols, lengths = data["symbols"], data["blob_byte_lengths"]
        if not isinstance(symbols, list) or not isinstance(lengths, list):
            _input_error(family, f"stages[{index}] symbols and blob_byte_lengths must be arrays")
        try:
            stages.append(DiscoveryStageResult(search, report, tuple(_symbol(item, item_index, family) for item_index, item in enumerate(symbols)), _enum(data["termination"], FunnelTermination, f"stages[{index}].termination", family), _integer(data["pages_recorded"], f"stages[{index}].pages_recorded", family, minimum=1), tuple(_integer(item, f"stages[{index}].blob_byte_lengths", family) for item in lengths)))
        except (BTSError, TypeError, ValueError) as exc:
            _input_error(family, f"stages[{index}] is invalid", exc)
    try:
        return CandidateRetrievalPlan(tuple(stages))
    except (BTSError, TypeError, ValueError) as exc:
        _input_error(family, "candidate retrieval plan is invalid", exc)


def _candidate_summary(candidates: object) -> dict[str, object]:
    return {"candidate_set": _canonical_object(candidates.to_bytes()), "schema_version": "leitir-funnel-discovery-summary-v1"}  # type: ignore[attr-defined]


def run_discovery(spec_path: Path, profile_manifest_path: Path, stages_path: Path) -> dict[str, object]:
    """Normalize recorded discovery reports using only the pinned candidate budget."""

    spec = _load_spec(spec_path)
    _, profile = build_recipient_profile(profile_manifest_path)
    plan = _load_plan(stages_path, spec)
    policy = PINNED_CANDIDATE_BUDGET_POLICY
    candidates = discover_candidates(spec, _ProfileDigest(profile.profile_digest), plan, CandidateBudget.from_policy(policy), policy)
    return _candidate_summary(candidates)


def run_funnel(spec_path: Path, profile_manifest_path: Path, stages_path: Path) -> dict[str, object]:
    """Run the pure capability → candidates → suitability → comparison funnel."""

    spec = _load_spec(spec_path)
    profile_summary, profile = build_recipient_profile(profile_manifest_path)
    plan = _load_plan(stages_path, spec)
    policy = PINNED_CANDIDATE_BUDGET_POLICY
    candidates = discover_candidates(spec, _ProfileDigest(profile.profile_digest), plan, CandidateBudget.from_policy(policy), policy)
    survivors = build_survivor_set(candidates.proposals, spec, profile)
    report = compare_and_select(survivors, spec, profile)
    return {
        "best3_report": _canonical_object(report.to_bytes()),
        "candidate_set": _canonical_object(candidates.to_bytes()),
        "recipient_profile": profile_summary,
        "schema_version": "leitir-funnel-summary-v1",
        "survivor_set": _canonical_object(survivors.to_bytes()),
    }


__all__ = ["build_recipient_profile", "run_discovery", "run_funnel", "validate_capability_spec"]
