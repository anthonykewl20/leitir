"""Fail-closed implementation helpers for the ``leitir bts-compute`` CLI.

Intended help text (the argparse wiring deliberately lives elsewhere)::

    leitir bts-compute OWNER/REPO@COMMIT --seed-module MODULE --seed-name NAME
        --out DIRECTORY [--language python|javascript|typescript|rust|go]
        [--root ROOT] [--policy POLICY.json] [--lock LOCK]

    Compute a Behavioral Transplant Set from a verified, exact Git-commit
    shelf.  The seed is an exact module plus qualified-name selector; Leitir
    never guesses a seed.  Existing output directories must be empty.

The Python producer merges the complete, sorted set of per-file static
extractions. Identical global evidence nodes are coalesced, while conflicting
records retain the graph model's typed duplicate rejection. Python extraction
resolves lexical bindings within each file only; imports remain
declared-external evidence, so cross-file import resolution is intentionally
not invented by this adapter.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from leitir.adapters.languages import canonicalize_language
from leitir.bts import (
    BTS_SCHEMA_VERSION,
    AdapterCatalog,
    AdapterCatalogEntry,
    AdaptRule,
    BTSBudget,
    BTSDisposition,
    BTSResult,
    DispositionRule,
    DonorSnapshot,
    ExternalRule,
    GraphProvider,
    ResolutionPolicy,
    StdlibIdentity,
    StdlibInterface,
    compute_bts,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph import go as go_graph
from leitir.graph import javascript as javascript_graph
from leitir.graph import rust as rust_graph
from leitir.graph import typescript as typescript_graph
from leitir.graph.model import (
    GRAPH_SCHEMA_VERSION,
    Edge,
    ExtractionBlocker,
    Graph,
    GraphCoverage,
    Node,
    NodeId,
    NodeKind,
    NodeOrigin,
    SourceRef,
    UnresolvedEdge,
)
from leitir.graph.policy import (
    GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
    SOURCE_SELECTION_VERSION,
    TREE_SITTER_PINS,
    GraphExtractionPolicy,
    build_graph_extraction_policy,
    requirements_lock_digest,
)
from leitir.graph.python import extract_static_edges
from leitir.graph.registry import make_graph_provider
from leitir.graph.ts_kernel import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_QUERY_MATCHES,
    DEFAULT_MAX_SYMBOLS,
    DEFAULT_MAX_TREE_NODES_PER_FILE,
    DEFAULT_MAX_WORK_UNITS,
)
from leitir.materialize import _target_lock, read_valid_manifest, target_path
from leitir.treehash import FULL, SAMPLED, TREE_HASH_ALGORITHM, TreeHashError, verify_materialized_tree_hash

CLI_SCHEMA_VERSION = "leitir-bts-cli-compute-v1"
DEFAULT_POLICY_ID = "leitir-bts-cli-default-policy-v1"
DEFAULT_POLICY_AUTHORITY = "leitir"
POLICY_SCHEMA_VERSION = "leitir-bts-cli-policy-v1"
_LOCK_MAX_BYTES = 4 * 1024 * 1024
# Python's non-tree-sitter producer applies the same per-file and file-count
# ceilings as the pinned tree-sitter policy.  This derived ceiling bounds the
# entire Python input set before any extraction is performed.
DEFAULT_MAX_INPUT_BYTES = DEFAULT_MAX_FILES * DEFAULT_MAX_FILE_BYTES
# Measured and pinned by the stage-2 producer tests (tests/test_graph_polyglot.py
# lines 67-71) against the grammar releases named in TREE_SITTER_PINS.
_GRAMMAR_ABI_VERSIONS = {
    "javascript": javascript_graph.GRAMMAR_ABI_VERSION,
    "typescript": typescript_graph.GRAMMAR_ABI_VERSION,
    "rust": rust_graph.GRAMMAR_ABI_VERSION,
    "go": go_graph.GRAMMAR_ABI_VERSION,
}
_GRAMMAR_FACTORIES = {"javascript": "language", "typescript": "language_typescript", "rust": "language", "go": "language"}


def _reject(reason: BTSRejectReason, message: str, detail_code: str, *, cause: BaseException | None = None) -> NoReturn:
    raise BTSError(reason, message, detail_code=detail_code, cause=cause)


@dataclass(frozen=True, slots=True)
class SeedSelector:
    """An exact caller-authorized seed identity, without a location guess."""

    module: str
    qualified_name: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (self.module, self.qualified_name)):
            raise ValueError("seed module and qualified_name must be non-empty strings")


@dataclass(frozen=True, slots=True)
class BTSComputeArtifacts:
    """The compute result plus canonical CLI artifacts ready for atomic output."""

    result: BTSResult
    graph_bytes: bytes
    summary: dict[str, object]


@dataclass(frozen=True, slots=True)
class _PolicySpec:
    """Closed-schema CLI policy data, before graph-specific rules are derived."""

    stdlib_modules: tuple[str, ...]
    adapters: tuple[tuple[str, str], ...]
    sibling_source_modules: tuple[str, ...] = ()


def load_donor_snapshot(root: Path, owner: str, repo: str, commit_sha: str, *, host: str = "github.com") -> DonorSnapshot:
    """Load only an exact, fully verified Git-commit shelf into a snapshot."""

    target = target_path(root, owner, repo, commit_sha, host=host)
    with _target_lock(target.parent, target, commit_sha):
        manifest = read_valid_manifest(target, owner, repo, commit_sha, host=host)
    if manifest is None:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor shelf is not verified", "bts_cli_shelf_unverified_v1")
    if manifest.get("source") != "git-commit":
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor source is not a Git commit", "bts_cli_source_unsupported_v1")
    if manifest.get("parity") != "exact":
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor parity is not exact", "bts_cli_parity_v1")
    if manifest.get("verified") is not True:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor verification is not complete", "bts_cli_verification_v1")
    tree_hash = manifest.get("materialized_tree_hash")
    algorithm = manifest.get("materialized_tree_hash_algorithm")
    scope = manifest.get("materialized_tree_hash_scope")
    if not isinstance(tree_hash, str) or not tree_hash or algorithm != TREE_HASH_ALGORITHM or scope != FULL:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor manifest integrity identity is invalid", "bts_cli_manifest_integrity_v1")
    return DonorSnapshot(
        f"{owner}/{repo}", commit_sha, "git-commit", "exact", tree_hash, algorithm, scope, target.parent, target,
    )


def load_donor_materialization(root: Path, owner: str, repo: str, commit_sha: str, *, host: str = "github.com") -> Path:
    """Open a structurally verified materialization without granting snapshot authority.

    Discovery may inspect a materialized candidate selected from the benchmark
    search space, but transplant construction must continue to use
    :func:`load_donor_snapshot`, which additionally requires exact Git parity.
    """

    target = target_path(root, owner, repo, commit_sha, host=host)
    with _target_lock(target.parent, target, commit_sha):
        manifest = read_valid_manifest(target, owner, repo, commit_sha, host=host)
    if manifest is None:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor shelf is not structurally verified", "bts_cli_shelf_unverified_v1")
    if manifest.get("source") != "git-commit":
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor source is not a Git commit", "bts_cli_source_unsupported_v1")
    if manifest.get("verified") not in (True, "sampled"):
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor materialization verification is incomplete", "bts_cli_verification_v1")
    tree_hash = manifest.get("materialized_tree_hash")
    if (
        not isinstance(tree_hash, str)
        or not tree_hash
        or manifest.get("materialized_tree_hash_algorithm") != TREE_HASH_ALGORITHM
        or manifest.get("materialized_tree_hash_scope") not in (FULL, SAMPLED)
    ):
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "donor manifest integrity identity is invalid", "bts_cli_manifest_integrity_v1")
    return target


def _read_regular(
    path: Path,
    *,
    maximum: int | None = None,
    maximum_detail_code: str = "bts_cli_input_bound_v1",
) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "source is not a regular file", "bts_cli_source_read_v1")
            if maximum is not None and metadata.st_size > maximum:
                _reject(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "input exceeds the configured bound", maximum_detail_code)
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                data = handle.read() if maximum is None else handle.read(maximum + 1)
        finally:
            if fd >= 0:
                os.close(fd)
    except BTSError:
        raise
    except OSError as exc:
        _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            f"cannot safely read input: {path}: {exc.strerror or str(exc)}",
            "bts_cli_source_read_v1",
            cause=exc,
        )
    if maximum is not None and len(data) > maximum:
        _reject(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "input exceeds the configured bound", maximum_detail_code)
    return data


def _python_candidates(snapshot: DonorSnapshot) -> tuple[Path, ...]:
    try:
        if stat.S_ISLNK(snapshot.source_root.lstat().st_mode):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "Python source root is a symlink", "bts_cli_source_symlink_v1")
        result: list[Path] = []
        for directory, dirnames, filenames in os.walk(snapshot.source_root, topdown=True, followlinks=False):
            dirnames.sort()
            filenames.sort()
            for name in sorted((*dirnames, *filenames)):
                entry = Path(directory, name)
                if stat.S_ISLNK(entry.lstat().st_mode):
                    _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "Python source tree contains a symlink", "bts_cli_source_symlink_v1")
            result.extend(Path(directory, name) for name in filenames if name.endswith(".py"))
        return tuple(sorted(result, key=lambda item: item.relative_to(snapshot.source_root).as_posix()))
    except BTSError:
        raise
    except OSError as exc:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot enumerate Python source scope", "bts_cli_python_scope_v1", cause=exc)


def python_graph_provider(snapshot: DonorSnapshot) -> GraphProvider:
    """Return a provider over every regular Python file in sorted donor order."""

    if not isinstance(snapshot, DonorSnapshot):
        raise TypeError("python graph provider requires a DonorSnapshot")

    def provider(source_root: Path) -> Graph:
        if source_root != snapshot.source_root:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "provider root differs from donor snapshot", "bts_cli_provider_root_v1")
        candidates = _python_candidates(snapshot)
        if not candidates:
            _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "donor has no Python sources", "bts_cli_empty_python_scope_v1")
        if len(candidates) > DEFAULT_MAX_FILES:
            _reject(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "Python source scope exceeds max_files", "bts_cli_max_files_v1")
        sources: list[tuple[str, bytes]] = []
        total_bytes = 0
        # Read and account for all inputs before extraction.  A later budget
        # failure consequently cannot yield a partially extracted graph.
        for candidate in candidates:
            relative = candidate.relative_to(snapshot.source_root).as_posix()
            data = _read_regular(
                candidate,
                maximum=DEFAULT_MAX_FILE_BYTES,
                maximum_detail_code="bts_cli_max_file_bytes_v1",
            )
            total_bytes += len(data)
            if total_bytes > DEFAULT_MAX_INPUT_BYTES:
                _reject(BTSRejectReason.REJECT_EXTRACTION_BUDGET, "Python source scope exceeds max_input_bytes", "bts_cli_max_input_bytes_v1")
            sources.append((relative, data))
        nodes_by_id: dict[NodeId, Node] = {}
        edges: list[Edge] = []
        unresolved: list[UnresolvedEdge] = []
        files: list[SourceRef] = []
        parsed_files: list[SourceRef] = []
        blockers: list[ExtractionBlocker] = []
        for relative, data in sources:
            extraction = extract_static_edges(
                data, slug=snapshot.slug, commit_sha=snapshot.commit_sha, path=relative,
                blob_sha=hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest(), package_root="",
            )
            for node in extraction.nodes:
                previous = nodes_by_id.get(node.id)
                if previous is None:
                    nodes_by_id[node.id] = node
                elif previous != node:
                    # Do not choose a source or producer method: that would
                    # erase contradictory extraction evidence. Mirror the
                    # canonical Graph duplicate failure instead.
                    _reject(
                        BTSRejectReason.REJECT_DUPLICATE_RESULT,
                        "duplicate node id",
                        "record_type=node id",
                    )
            edges.extend(extraction.edges)
            unresolved.extend(extraction.unresolved)
            files.extend(extraction.coverage.files)
            parsed_files.extend(extraction.coverage.parsed_files)
            blockers.extend(extraction.coverage.blockers)
        return Graph(
            GRAPH_SCHEMA_VERSION,
            tuple(nodes_by_id.values()),
            tuple(edges),
            tuple(unresolved),
            GraphCoverage(tuple(files), tuple(parsed_files), tuple(blockers)),
        )

    return provider


def _read_lock_text(lock_path: Path) -> str:
    data = _read_regular(lock_path, maximum=_LOCK_MAX_BYTES)
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "tree-sitter lock is not strict UTF-8", "bts_cli_lock_read_v1", cause=exc)


def _polyglot_policy(language: str, lock_text: str) -> GraphExtractionPolicy:
    if language not in _GRAMMAR_ABI_VERSIONS:
        _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "unsupported graph extraction language", "bts_cli_graph_language_v1")
    module = importlib.import_module(f"leitir.graph.{language}")
    values: dict[str, object] = {
        "schema_version": GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
        "authority": DEFAULT_POLICY_AUTHORITY,
        "policy_id": DEFAULT_POLICY_ID,
        "language": language,
        "requirements_lock_digest": requirements_lock_digest(lock_text),
        "runtime_distribution": "tree-sitter",
        "runtime_version": TREE_SITTER_PINS["tree-sitter"],
        "grammar_distribution": f"tree-sitter-{language}",
        "grammar_version": TREE_SITTER_PINS[f"tree-sitter-{language}"],
        "grammar_factory": _GRAMMAR_FACTORIES[language],
        "grammar_abi_version": _GRAMMAR_ABI_VERSIONS[language],
        "query_id": module.QUERY_ID,
        "query_sha256": hashlib.sha256(module.QUERY_TEXT.encode("utf-8", errors="strict")).hexdigest(),
        "producer_id": module.PRODUCER_ID,
        "producer_version": module.PRODUCER_VERSION,
        "resolution_rule_version": module.RESOLUTION_RULE_VERSION,
        "source_selection_version": SOURCE_SELECTION_VERSION,
        "max_files": DEFAULT_MAX_FILES,
        "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
        "max_tree_nodes_per_file": DEFAULT_MAX_TREE_NODES_PER_FILE,
        "max_query_matches": DEFAULT_MAX_QUERY_MATCHES,
        "max_symbols": DEFAULT_MAX_SYMBOLS,
        "max_edges": DEFAULT_MAX_EDGES,
        "max_work_units": DEFAULT_MAX_WORK_UNITS,
    }
    return build_graph_extraction_policy(**values)


def tree_sitter_graph_provider(snapshot: DonorSnapshot, language: str, *, lock_path: Path) -> GraphProvider:
    """Return the policy-pinned optional producer; native loading remains lazy."""

    normalized = canonicalize_language(language)
    lock_text = _read_lock_text(lock_path)
    policy = _polyglot_policy(normalized, lock_text)
    return make_graph_provider(snapshot, normalized, policy, requirements_lock_text=lock_text)


def _default_budget() -> BTSBudget:
    # Values are the reviewed E4a skeleton precedent (test_bts_skeleton.py:96-98);
    # max_donor_source_bps keeps BTSBudget's mandated default of 4,000.
    return BTSBudget(1_000_000, 1_000_000, 100_000, 20, 10_000, 10_000, 10_000, 100, 2_000_000, 10_000, 10_000, 100, 100)


def _sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _default_resolution_policy() -> ResolutionPolicy:
    # Empty stdlib and adapter catalogs mirror the conservative E4a precedent
    # (test_bts_skeleton.py:100-108); these hashes pin this CLI authority.
    return ResolutionPolicy(
        BTS_SCHEMA_VERSION, DEFAULT_POLICY_AUTHORITY, DEFAULT_POLICY_ID,
        _sha256_digest(b"leitir-bts-cli-resolution-policy-v1"),
        StdlibIdentity("cpython", ">=3.12,<3.13", "leitir-bts-cli-stdlib-v1", _sha256_digest(b"empty-stdlib-allowlist")),
        AdapterCatalog("empty", "leitir-bts-cli-adapters-v1", _sha256_digest(b"empty-adapter-catalog")),
    )


def _canonical_digest(value: object) -> str:
    """Return the BTS module's canonical JSON-line SHA-256 representation."""

    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8", errors="strict")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _required_policy_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    value.encode("utf-8", errors="strict")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_policy_spec(path: Path) -> _PolicySpec:
    """Load only the documented closed-schema policy JSON."""

    try:
        raw = _read_regular(path, maximum=_LOCK_MAX_BYTES)
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or set(value) not in (
            {"schema_version", "stdlib_modules", "adapters"},
            {"schema_version", "stdlib_modules", "adapters", "sibling_source_modules"},
        ):
            raise ValueError("policy has missing or unknown fields")
        if value["schema_version"] != POLICY_SCHEMA_VERSION:
            raise ValueError("policy schema_version is not pinned")
        stdlib_raw = value["stdlib_modules"]
        if not isinstance(stdlib_raw, list):
            raise ValueError("stdlib_modules must be a list")
        stdlib_modules = tuple(_required_policy_text(item, "stdlib_modules item") for item in stdlib_raw)
        if stdlib_modules != tuple(sorted(set(stdlib_modules))):
            raise ValueError("stdlib_modules must be sorted and unique")
        adapters_raw = value["adapters"]
        if not isinstance(adapters_raw, list):
            raise ValueError("adapters must be a list")
        adapters: list[tuple[str, str]] = []
        for item in adapters_raw:
            if not isinstance(item, dict) or set(item) != {"module", "disposition"}:
                raise ValueError("adapter has missing or unknown fields")
            module = _required_policy_text(item["module"], "adapter.module")
            disposition = _required_policy_text(item["disposition"], "adapter.disposition")
            if disposition not in {"adapter", "pinned-exact"}:
                raise ValueError("adapter.disposition is unsupported")
            adapters.append((module, disposition))
        ordered_adapters = tuple(sorted(adapters))
        if tuple(adapters) != ordered_adapters or len({module for module, _ in adapters}) != len(adapters):
            raise ValueError("adapters must be sorted and have unique modules")
        if set(stdlib_modules) & {module for module, _ in adapters}:
            raise ValueError("a module cannot have both stdlib and adapter policy")
        siblings_raw = value.get("sibling_source_modules", [])
        if not isinstance(siblings_raw, list):
            raise ValueError("sibling_source_modules must be a list")
        siblings = tuple(_required_policy_text(item, "sibling_source_modules item") for item in siblings_raw)
        if siblings != tuple(sorted(set(siblings))):
            raise ValueError("sibling_source_modules must be sorted and unique")
        if set(siblings) & set(stdlib_modules):
            raise ValueError("a sibling source cannot be stdlib")
        return _PolicySpec(stdlib_modules, ordered_adapters, siblings)
    except BTSError:
        raise
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        _reject(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "BTS CLI policy is malformed or violates its pinned schema",
            "bts_cli_policy_invalid_v1",
            cause=exc,
        )


def load_resolution_policy(path: Path, graph: Graph) -> ResolutionPolicy:
    """Derive graph-exact ResolutionPolicy rules from closed-schema policy JSON.

    ``stdlib_modules`` authorizes observed stdlib nodes and imported modules.
    Python's conservative producer represents imports as declared-external
    nodes, so its authorized modules receive exact EXTERNAL rules.
    ``pinned-exact`` keeps an external requirement; ``adapter`` produces a
    pinned zero-parameter adapter entry and exact ADAPT rule.
    """

    spec = _load_policy_spec(path)
    adapter_by_module = dict(spec.adapters)
    allowed_modules = set(spec.stdlib_modules) | set(adapter_by_module)
    stdlib_entries = tuple(
        StdlibInterface(node.id.module, node.id.qualified_name)
        for node in graph.nodes
        if node.id.origin.value == "stdlib" and node.id.module in spec.stdlib_modules
    )
    adapter_entries = tuple(
        AdapterCatalogEntry(
            f"leitir-bts-cli-adapter:{module}",
            f"module:{module}",
            _sha256_digest(f"module:{module}".encode("utf-8", errors="strict")),
        )
        for module, disposition in spec.adapters
        if disposition == "adapter"
    )
    catalog = AdapterCatalog(
        "leitir-bts-cli-policy-adapters",
        POLICY_SCHEMA_VERSION,
        _canonical_digest({"adapters": [entry.adapter_id for entry in adapter_entries], "schema_version": POLICY_SCHEMA_VERSION}),
        adapter_entries,
    )
    rules: list[DispositionRule] = []
    for node in graph.nodes:
        if node.id.origin.value != "declared_external" or node.id.module not in allowed_modules:
            continue
        disposition = adapter_by_module.get(node.id.module)
        payload: AdaptRule | ExternalRule
        if disposition == "adapter":
            payload = AdaptRule(f"leitir-bts-cli-adapter:{node.id.module}")
            rule_disposition = BTSDisposition.ADAPT
        else:
            payload = ExternalRule(node.id, node.id.module)
            rule_disposition = BTSDisposition.EXTERNAL
        evidence_payload = {
            "disposition": rule_disposition.value,
            "module": node.id.module,
            "source": {
                "kind": node.id.kind.value,
                "location_key": node.id.location_key,
                "module": node.id.module,
                "origin": node.id.origin.value,
                "qualified_name": node.id.qualified_name,
            },
        }
        rules.append(
            DispositionRule(
                f"leitir-bts-cli-policy:{rule_disposition.value}:{node.id.module}:{node.id.qualified_name}",
                node.id,
                rule_disposition,
                payload,
                _canonical_digest(evidence_payload),
            )
        )
    return ResolutionPolicy(
        BTS_SCHEMA_VERSION,
        DEFAULT_POLICY_AUTHORITY,
        POLICY_SCHEMA_VERSION,
        _canonical_digest(
            {
                "adapters": [{"disposition": disposition, "module": module} for module, disposition in spec.adapters],
                "schema_version": POLICY_SCHEMA_VERSION,
                "sibling_source_modules": list(spec.sibling_source_modules),
                "stdlib_modules": list(spec.stdlib_modules),
            }
        ),
        StdlibIdentity(
            "cpython",
            ">=3.12,<3.13",
            POLICY_SCHEMA_VERSION,
            _canonical_digest([
                {"module": entry.module, "qualified_name": entry.qualified_name}
                for entry in stdlib_entries
            ]),
            stdlib_entries,
        ),
        catalog,
        tuple(rules),
    )


def load_sibling_source_modules(path: Path) -> tuple[str, ...]:
    """Return the closed-policy donor modules authorized for sibling relocation."""

    return _load_policy_spec(path).sibling_source_modules


_SEED_KINDS = frozenset({
    NodeKind.FUNCTION,
    NodeKind.ASYNC_FUNCTION,
    NodeKind.METHOD,
    NodeKind.ASYNC_METHOD,
})
_SEED_CANDIDATE_LIMIT = 10


def list_seed_candidates(graph: Graph, module: str | None = None) -> tuple[NodeId, ...]:
    """Return deterministic, selectable donor definition seeds only."""

    return tuple(sorted(
        (
            node.id
            for node in graph.nodes
            if node.id.origin is NodeOrigin.DONOR
            and node.id.kind in _SEED_KINDS
            and (module is None or node.id.module == module)
        ),
        key=lambda node: (node.module, node.qualified_name, node.kind.value, node.location_key),
    ))


def _seed_evidence_candidates(candidates: tuple[NodeId, ...]) -> str:
    displayed = candidates[:_SEED_CANDIDATE_LIMIT]
    rendered = ", ".join(
        f"{candidate.qualified_name} ({candidate.origin.value})" for candidate in displayed
    )
    suffix = "" if len(candidates) <= _SEED_CANDIDATE_LIMIT else f", … (+{len(candidates) - _SEED_CANDIDATE_LIMIT} more)"
    return f"; candidates: {rendered or '(none)'}{suffix}"


def resolve_seed(graph: Graph, selector: SeedSelector) -> NodeId:
    """Resolve exactly one graph node, refusing absent or ambiguous selectors."""

    candidates = list_seed_candidates(graph, selector.module)
    matches = tuple(
        node for node in candidates
        if node.module == selector.module and node.qualified_name == selector.qualified_name
    )
    if not matches:
        _reject(
            BTSRejectReason.REJECT_UNRESOLVED_EDGE,
            "seed selector matched no donor definition" + _seed_evidence_candidates(candidates),
            "bts_cli_seed_not_found_v1",
        )
    if len(matches) != 1:
        _reject(
            BTSRejectReason.REJECT_DUPLICATE_RESULT,
            "seed selector matched multiple donor definitions" + _seed_evidence_candidates(matches),
            "bts_cli_seed_ambiguous_v1",
        )
    return matches[0]


def _summary(snapshot: DonorSnapshot, language: str, seed: NodeId, result: BTSResult, graph_bytes: bytes) -> dict[str, object]:
    blocker = next((item for item in result.report.blockers if getattr(item, "reason", None) is not None), None)
    reason = None if blocker is None else getattr(blocker, "reason", None)
    detail_code = None if blocker is None else getattr(blocker, "detail_code", None)
    return {
        "schema_version": CLI_SCHEMA_VERSION,
        "language": language,
        "slug": snapshot.slug,
        "commit": snapshot.commit_sha,
        "status": result.status.value.upper(),
        "reason": None if not isinstance(reason, BTSRejectReason) else reason.value,
        "detail_code": detail_code if isinstance(detail_code, str) else None,
        "seed": {"module": seed.module, "qualified_name": seed.qualified_name, "location_key": seed.location_key},
        "graph_sha256": "sha256:" + hashlib.sha256(graph_bytes).hexdigest(),
        "analysis_digest": result.report.analysis_digest,
        "bts_digest": None if result.bts is None else result.bts.bts_digest,
        "member_equivalence_digest": None if result.bts is None else result.bts.member_equivalence_digest,
    }


def run_bts_compute(
    root: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str = "github.com",
    language: str = "python",
    lock_path: Path | None = None,
    policy_path: Path | None = None,
    seed: SeedSelector,
) -> BTSComputeArtifacts:
    """Compute a BTS under the shelf lock using the exact caller-selected seed."""

    snapshot = load_donor_snapshot(root, owner, repo, commit_sha, host=host)
    normalized = canonicalize_language(language)
    if normalized == "python":
        provider = python_graph_provider(snapshot)
    else:
        if lock_path is None:
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "tree-sitter lock path is required for non-Python BTS computation",
                "bts_cli_lock_required_v1",
            )
        provider = tree_sitter_graph_provider(
            snapshot, normalized, lock_path=lock_path,
        )
    try:
        with _target_lock(snapshot.materialization_root, snapshot.source_root, snapshot.commit_sha):
            verify_materialized_tree_hash(snapshot.source_root, snapshot.materialized_tree_hash, algorithm=snapshot.materialized_tree_hash_algorithm, scope=snapshot.materialized_tree_hash_scope)
            if not callable(provider):
                raise TypeError("BTS CLI graph provider must be callable")
            graph = provider(snapshot.source_root)
            selected = resolve_seed(graph, seed)
            policy = _default_resolution_policy() if policy_path is None else load_resolution_policy(policy_path, graph)
            result = compute_bts(snapshot, selected, graph, _default_budget(), policy)
    except TreeHashError as exc:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "materialized donor tree integrity verification failed", "bts_materialized_tree_hash_v1", cause=exc)
    graph_bytes = graph.to_bytes()
    return BTSComputeArtifacts(result, graph_bytes, _summary(snapshot, normalized, selected, result, graph_bytes))


def list_bts_seeds(
    root: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    *,
    host: str = "github.com",
    language: str = "python",
    lock_path: Path | None = None,
) -> tuple[NodeId, ...]:
    """List callable donor definitions from a verified graph without computing a BTS."""

    snapshot = load_donor_snapshot(root, owner, repo, commit_sha, host=host)
    normalized = canonicalize_language(language)
    if normalized == "python":
        provider = python_graph_provider(snapshot)
    else:
        if lock_path is None:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "tree-sitter lock path is required for non-Python BTS computation", "bts_cli_lock_required_v1")
        provider = tree_sitter_graph_provider(snapshot, normalized, lock_path=lock_path)
    try:
        with _target_lock(snapshot.materialization_root, snapshot.source_root, snapshot.commit_sha):
            verify_materialized_tree_hash(snapshot.source_root, snapshot.materialized_tree_hash, algorithm=snapshot.materialized_tree_hash_algorithm, scope=snapshot.materialized_tree_hash_scope)
            if not callable(provider):
                raise TypeError("BTS CLI graph provider must be callable")
            graph = provider(snapshot.source_root)
    except TreeHashError as exc:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "materialized donor tree integrity verification failed", "bts_materialized_tree_hash_v1", cause=exc)
    return list_seed_candidates(graph)


def _atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as exc:
        _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot atomically write BTS artifact", "bts_cli_artifact_write_v1", cause=exc)
    finally:
        temporary.unlink(missing_ok=True)


def write_artifacts(result: BTSComputeArtifacts, out_dir: Path) -> None:
    """Atomically create graph and summary artifacts; non-empty output is refused."""

    if out_dir.exists() or out_dir.is_symlink():
        try:
            metadata = out_dir.lstat()
            has_entries = stat.S_ISDIR(metadata.st_mode) and any(out_dir.iterdir())
        except OSError as exc:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot inspect output directory", "bts_cli_artifact_write_v1", cause=exc)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or has_entries:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "output directory already contains artifacts", "bts_cli_output_conflict_v1")
    else:
        try:
            out_dir.mkdir(parents=True)
        except OSError as exc:
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "cannot create output directory", "bts_cli_artifact_write_v1", cause=exc)
    summary = (json.dumps(result.summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    _atomic_write(out_dir / "graph.json", result.graph_bytes)
    _atomic_write(out_dir / "summary.json", summary)


__all__ = [
    "CLI_SCHEMA_VERSION", "DEFAULT_MAX_INPUT_BYTES", "DEFAULT_POLICY_AUTHORITY", "DEFAULT_POLICY_ID", "POLICY_SCHEMA_VERSION", "BTSComputeArtifacts", "SeedSelector",
    "load_donor_materialization", "load_donor_snapshot", "load_resolution_policy", "python_graph_provider", "resolve_seed", "run_bts_compute", "tree_sitter_graph_provider", "write_artifacts",
]
