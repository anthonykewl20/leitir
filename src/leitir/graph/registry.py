"""Explicit, lazy registry for optional polyglot graph producers."""

from __future__ import annotations

import hashlib
import importlib
import os
import stat
import sys
import sysconfig
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, TypeAlias, cast

from leitir.adapters.languages import canonicalize_language
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import Graph, SourceRef
from leitir.graph.policy import (
    SOURCE_SELECTION_VERSION,
    GraphExtractionPolicy,
    GraphExtractionRequest,
    assert_platform_wheel_coverage,
    require_tree_sitter_extra,
    requirements_lock_digest,
)
from leitir.treehash import TreeHashError, verify_materialized_tree_hash

if TYPE_CHECKING:
    from leitir.bts import DonorSnapshot

GraphExtractor: TypeAlias = Callable[[GraphExtractionRequest], Graph]

_EXTENSIONS = {
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs"}),
    "typescript": frozenset({".ts", ".tsx", ".mts", ".cts"}),
    "rust": frozenset({".rs"}),
    "go": frozenset({".go"}),
}
_EXTRACTORS: dict[str, GraphExtractor] = {}


def _typed(
    reason: BTSRejectReason, message: str, detail_code: str, *, cause: BaseException | None = None
) -> NoReturn:
    # Deliberately mirrors policy._reject while preserving an optional cause.
    raise BTSError(reason, message, detail_code=detail_code, cause=cause)


def register_graph_extractor(language: str, producer: GraphExtractor) -> GraphExtractor | None:
    """Register one explicit normalized-language producer and return its prior one."""

    if not isinstance(language, str) or not language:
        raise TypeError("language must be a non-empty string")
    if not callable(producer):
        raise TypeError("producer must be callable")
    normalized = canonicalize_language(language)
    previous = _EXTRACTORS.get(normalized)
    _EXTRACTORS[normalized] = producer
    return previous


def _lazy_builtin(language: str) -> GraphExtractor:
    """Create a thunk that imports no optional artifact until invocation."""

    def load_builtin_producer(request: GraphExtractionRequest) -> tuple[Any, GraphExtractor]:
        # Rechecking protects this boundary if an otherwise frozen request was
        # deliberately corrupted through object.__setattr__.
        GraphExtractionRequest(request.language, request.source_root, request.source_files, request.policy)
        if canonicalize_language(request.language) != language or request.policy.language != language:
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "producer received a different language", "tree_sitter_producer_language_mismatch_v1")
        module_name = f"leitir.graph.{language}"
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name == module_name:
                _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree-sitter language producer is not implemented in stage 1", "tree_sitter_producer_unimplemented_v1", cause=exc)
            raise
        producer = getattr(module, "extract_graph", None)
        if not callable(producer):
            _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree-sitter language producer is not implemented in stage 1", "tree_sitter_producer_unimplemented_v1")
        return module, producer

    def assert_builtin_identity(request: GraphExtractionRequest) -> None:
        """Import the stdlib-safe producer and check its identity before natives."""

        module, _producer = load_builtin_producer(request)
        identity = getattr(module, "assert_producer_identity", None)
        if not callable(identity):
            _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree-sitter language producer has no identity assertion", "tree_sitter_producer_unimplemented_v1")
        producer_id, producer_version, resolution_rule_version = (
            getattr(module, name, None)
            for name in ("PRODUCER_ID", "PRODUCER_VERSION", "RESOLUTION_RULE_VERSION")
        )
        if not all(isinstance(value, str) for value in (producer_id, producer_version, resolution_rule_version)):
            _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "tree-sitter language producer has invalid identity constants", "tree_sitter_producer_unimplemented_v1")
        identity(
            request.policy,
            producer_id=producer_id,
            producer_version=producer_version,
            resolution_rule_version=resolution_rule_version,
        )

    def extract_after_preflight(request: GraphExtractionRequest) -> Graph:
        """Invoke only after provider identity/extra/lock/coverage preflight."""

        _module, producer = load_builtin_producer(request)
        return producer(request)

    def produce(request: GraphExtractionRequest) -> Graph:
        assert_builtin_identity(request)
        require_tree_sitter_extra(language)
        return extract_after_preflight(request)

    # The provider invokes this preflight before importing native modules.  It
    # is intentionally private: registered third-party test/plugin producers
    # remain an explicit authority boundary rather than built-in producers.
    cast(Any, produce)._assert_builtin_identity = assert_builtin_identity
    cast(Any, produce)._extract_after_preflight = extract_after_preflight
    return produce


def _read_declared_file(path: Path, *, maximum: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "declared graph source is not a regular file", "tree_sitter_source_read_v1")
            if metadata.st_size > maximum:
                _typed(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "graph source exceeds max_file_bytes", "tree_sitter_max_file_bytes_v1")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                data = handle.read(maximum + 1)
        finally:
            if fd >= 0:
                os.close(fd)
    except BTSError:
        raise
    except OSError as exc:
        _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot safely read declared graph source", "tree_sitter_source_read_v1", cause=exc)
    if len(data) > maximum:
        _typed(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "graph source exceeds max_file_bytes", "tree_sitter_max_file_bytes_v1")
    return data


def _whole_file_source(source: bytes, *, snapshot: DonorSnapshot, path: str) -> SourceRef:
    lines = source.splitlines(keepends=True)
    if not lines:
        end_line, end_col = 1, 0
    else:
        end_line = len(lines)
        last = lines[-1]
        end_col = len(last.rstrip(b"\r\n"))
        if last.endswith((b"\n", b"\r")):
            end_line += 1
            end_col = 0
    blob_sha = hashlib.sha1(b"blob %d\x00" % len(source) + source).hexdigest()
    return SourceRef(snapshot.slug, snapshot.commit_sha, path, blob_sha, 1, 0, end_line, end_col)


def _build_request(snapshot: DonorSnapshot, language: str, policy: GraphExtractionPolicy) -> GraphExtractionRequest:
    """Build the complete declared scope; producers may only consume this scope."""

    if policy.source_selection_version != SOURCE_SELECTION_VERSION:
        _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unknown source selection rule", "tree_sitter_source_selection_unknown_v1")
    extensions = _EXTENSIONS[language]
    candidates: list[Path] = []

    def onerror(error: OSError) -> NoReturn:
        _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot enumerate declared graph scope", "tree_sitter_scope_enumeration_v1", cause=error)

    try:
        root_metadata = snapshot.source_root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode):
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph source root is a symlink", "tree_sitter_source_symlink_v1")
        for directory, dirnames, filenames in os.walk(snapshot.source_root, topdown=True, followlinks=False, onerror=onerror):
            dirnames.sort()
            filenames.sort()
            entries = sorted((*dirnames, *filenames))
            for name in entries:
                entry = Path(directory, name)
                if stat.S_ISLNK(entry.lstat().st_mode):
                    _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph source tree contains a symlink", "tree_sitter_source_symlink_v1")
            for name in filenames:
                candidate = Path(directory, name)
                if candidate.suffix in extensions:
                    candidates.append(candidate)
        candidates.sort(key=lambda path: path.relative_to(snapshot.source_root).as_posix())
    except (OSError, ValueError) as exc:
        _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot enumerate declared graph scope", "tree_sitter_scope_enumeration_v1", cause=exc)
    if len(candidates) > policy.max_files:
        _typed(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "graph scope exceeds max_files", "tree_sitter_max_files_v1")
    files: list[SourceRef] = []
    for candidate in candidates:
        try:
            relative = candidate.relative_to(snapshot.source_root).as_posix()
            metadata = candidate.lstat()
        except (OSError, ValueError) as exc:
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot inspect declared graph source", "tree_sitter_source_read_v1", cause=exc)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "declared graph source is not a regular file", "tree_sitter_source_read_v1")
        source = _read_declared_file(candidate, maximum=policy.max_file_bytes)
        files.append(_whole_file_source(source, snapshot=snapshot, path=relative))
    return GraphExtractionRequest(language, snapshot.source_root, tuple(files), policy)


def make_graph_provider(
    snapshot: DonorSnapshot,
    language: str,
    policy: GraphExtractionPolicy,
    *,
    requirements_lock_text: str | None = None,
) -> Callable[[Path], Graph]:
    """Bind one verified donor, language, and explicit producer as a GraphProvider.

    The composition adapter, not a producer, enumerates the verified snapshot
    root to declare the complete source scope.  A producer receives that scope
    and is forbidden from expanding it by filesystem discovery.
    """

    from leitir.bts import DonorSnapshot

    snapshot_value = cast(object, snapshot)
    if not isinstance(snapshot_value, DonorSnapshot):
        _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph provider requires a validated donor snapshot", "tree_sitter_snapshot_type_v1")
    validated_snapshot = snapshot_value
    if not isinstance(language, str) or not language:
        _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unknown graph extraction language", "tree_sitter_graph_language_unknown_v1")
    normalized = canonicalize_language(language)
    if normalized not in _EXTENSIONS:
        _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unknown graph extraction language", "tree_sitter_graph_language_unknown_v1")
    if not isinstance(policy, GraphExtractionPolicy) or policy.language != normalized:
        _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "policy does not match the selected graph producer language", "tree_sitter_producer_language_mismatch_v1")
    producer = _EXTRACTORS.get(normalized)
    if producer is None:
        _typed(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "no graph producer is registered for this language", "tree_sitter_graph_producer_missing_v1")

    def provider(source_root: Path) -> Graph:
        if not isinstance(source_root, Path) or source_root != validated_snapshot.source_root:
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph provider root does not match its donor snapshot", "tree_sitter_provider_root_v1")
        request = _build_request(validated_snapshot, normalized, policy)
        try:
            verify_materialized_tree_hash(
                validated_snapshot.source_root,
                validated_snapshot.materialized_tree_hash,
                algorithm=validated_snapshot.materialized_tree_hash_algorithm,
                scope=validated_snapshot.materialized_tree_hash_scope,
            )
        except TreeHashError as exc:
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor tree is no longer verified", "tree_sitter_snapshot_tree_v1", cause=exc)
        identity_check = getattr(producer, "_assert_builtin_identity", None)
        if callable(identity_check):
            identity_check(request)
        require_tree_sitter_extra(normalized)
        if requirements_lock_text is None:
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "tree-sitter requirements lock is unavailable", "tree_sitter_lock_unavailable_v1")
        if requirements_lock_digest(requirements_lock_text) != policy.requirements_lock_digest:
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "tree-sitter requirements lock digest does not match policy", "tree_sitter_lock_digest_mismatch_v1")
        assert_platform_wheel_coverage(
            requirements_lock_text,
            python_tag=f"cp{sys.version_info.major}{sys.version_info.minor}",
            platform_tags=(sysconfig.get_platform(),),
        )
        extract_after_preflight = getattr(producer, "_extract_after_preflight", None)
        result = extract_after_preflight(request) if callable(extract_after_preflight) else producer(request)
        if not isinstance(result, Graph):
            _typed(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "graph producer returned a non-Graph result", "tree_sitter_producer_result_v1")
        return result

    return provider


# Registration is explicit but only captures stdlib-only thunks.  The native
# bindings and the stage-2 producer modules are imported exclusively on invoke.
for _language in ("javascript", "typescript", "rust", "go"):
    register_graph_extractor(_language, _lazy_builtin(_language))
