"""Validate pins for the ``leitir exit-gate-validate corpus.json`` CLI.

This module intentionally validates *pins only*: it records donor identity,
provenance, review receipts, and runnable-substrate-independent baseline
expectations.  It neither creates execution authority nor substitutes for the
authority chain in :mod:`leitir.bts_exit_gate`.  A publicly computable
self-hash is content binding only, never ratification.  External ratification
authority is deferred in v1, so validated output always reports
``ratified: false``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Never, TypeAlias, cast

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.bts_exit_gate import MINIMUM_EXIT_DONORS
from leitir.safeio import read_regular_file

EXIT_CORPUS_MANIFEST_SCHEMA_VERSION = "leitir-exit-corpus-manifest-v1.1"
_V1_SCHEMA_VERSION = "leitir-exit-corpus-manifest-v1"
MAX_MANIFEST_BYTES = 1 << 20

_HEX_40_RE = re.compile(r"[0-9a-f]{40}\Z")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_GATE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEBAB_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "corpus_id",
        "created_for_milestone",
        "cases",
        "ratified_manifest_digest",
        "ratified_runtime_digest",
        "notes",
        "runnable",
    }
)
_REQUIRED_TOP_LEVEL_KEYS = _TOP_LEVEL_KEYS - {"notes", "runnable", "ratified_runtime_digest"}
_CASE_KEYS = frozenset(
    {
        "case_id",
        "donor",
        "source_provenance",
        "review_receipt_digest",
        "baseline",
        "seed",
        "language",
    }
)
_DONOR_KEYS = frozenset({"host", "owner", "repo", "commit_sha"})
_BASELINE_KEYS = frozenset({"contract_test_count", "expected_pass", "expected_fail", "expected_skip"})
_SEED_KEYS = frozenset({"module", "qualified_name"})
_RUNNABLE_KEYS = frozenset({"substrate", "donors_dir_layout", "per_case"})
_SUBSTRATE_KEYS = frozenset({"nsjail_sha256", "nsjail_version", "nsjail_build_identity", "config_schema_digest", "rootfs_digest", "containment_template_version"})
_RUNNABLE_CASE_REQUIRED_KEYS = frozenset({"case_id", "contract_tests"})
_RUNNABLE_CASE_KEYS = _RUNNABLE_CASE_REQUIRED_KEYS | frozenset({"policy_path", "notes", "import_roots", "runtime_deps"})
_CONTRACT_TEST_KEYS = frozenset({"path", "module"})
_RUNTIME_DEP_KEYS = frozenset({"distribution", "version"})

JsonObject: TypeAlias = dict[str, object]


def _reject(message: str, detail_code: str) -> Never:
    raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, message, detail_code=detail_code)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            _reject("manifest contains a duplicate JSON key", "exit_corpus_schema_v1")
        result[key] = value
    return result


def _canonical_bytes(value: object) -> bytes:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "manifest cannot be encoded as canonical JSON",
            detail_code="exit_corpus_schema_v1",
            cause=exc,
        ) from exc
    return (payload + "\n").encode("utf-8")


def _object(value: object, field: str) -> JsonObject:
    if type(value) is not dict:
        _reject(f"{field} must be an object", "exit_corpus_schema_v1")
    return cast(JsonObject, value)


def _list(value: object, field: str) -> list[object]:
    if type(value) is not list:
        _reject(f"{field} must be an array", "exit_corpus_schema_v1")
    return cast(list[object], value)


def _text(value: object, field: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _reject(f"{field} must be nonempty text", "exit_corpus_schema_v1")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _reject(f"{field} must be valid UTF-8 text", "exit_corpus_schema_v1")
    if size > limit:
        _reject(f"{field} exceeds its byte limit", "exit_corpus_schema_v1")
    return value


def _integer(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        _reject(f"{field} must be a nonnegative integer", "exit_corpus_schema_v1")
    return value


def _exact_keys(value: JsonObject, expected: frozenset[str], field: str) -> None:
    if set(value) != expected:
        _reject(f"{field} has unknown or missing fields", "exit_corpus_schema_v1")


def _validate_case(raw_case: object) -> JsonObject:
    case = _object(raw_case, "case")
    _exact_keys(case, _CASE_KEYS, "case")

    case_id = _text(case["case_id"], "case.case_id")
    if _KEBAB_RE.fullmatch(case_id) is None:
        _reject("case.case_id must be lowercase kebab-case", "exit_corpus_schema_v1")

    donor = _object(case["donor"], "case.donor")
    _exact_keys(donor, _DONOR_KEYS, "case.donor")
    donor_host = _text(donor["host"], "case.donor.host")
    donor_owner = _text(donor["owner"], "case.donor.owner")
    donor_repo = _text(donor["repo"], "case.donor.repo")
    commit_sha = _text(donor["commit_sha"], "case.donor.commit_sha")
    if _HEX_40_RE.fullmatch(commit_sha) is None:
        _reject("case.donor.commit_sha must be 40 lowercase hexadecimal characters", "exit_corpus_schema_v1")

    provenance = _text(case["source_provenance"], "case.source_provenance")
    receipt = _text(case["review_receipt_digest"], "case.review_receipt_digest")
    if _HEX_64_RE.fullmatch(receipt) is None:
        _reject("case.review_receipt_digest must be 64 lowercase hexadecimal characters", "exit_corpus_schema_v1")

    baseline = _object(case["baseline"], "case.baseline")
    _exact_keys(baseline, _BASELINE_KEYS, "case.baseline")
    contract_test_count = _integer(baseline["contract_test_count"], "case.baseline.contract_test_count")
    expected_pass = _integer(baseline["expected_pass"], "case.baseline.expected_pass")
    expected_fail = _integer(baseline["expected_fail"], "case.baseline.expected_fail")
    expected_skip = _integer(baseline["expected_skip"], "case.baseline.expected_skip")
    if contract_test_count != expected_pass + expected_fail + expected_skip:
        _reject("case.baseline counts do not equal contract_test_count", "exit_corpus_schema_v1")

    seed = _object(case["seed"], "case.seed")
    _exact_keys(seed, _SEED_KEYS, "case.seed")
    seed_module = _text(seed["module"], "case.seed.module")
    qualified_name = _text(seed["qualified_name"], "case.seed.qualified_name")
    language = _text(case["language"], "case.language")
    return {
        "case_id": case_id,
        "donor": {"host": donor_host, "owner": donor_owner, "repo": donor_repo, "commit_sha": commit_sha},
        "source_provenance": provenance,
        "review_receipt_digest": receipt,
        "baseline": {
            "contract_test_count": contract_test_count,
            "expected_pass": expected_pass,
            "expected_fail": expected_fail,
            "expected_skip": expected_skip,
        },
        "seed": {"module": seed_module, "qualified_name": qualified_name},
        "language": language,
    }


def _relative_python_path(value: object, field: str) -> str:
    path = _text(value, field)
    candidate = PurePosixPath(path)
    if not path.endswith(".py") or candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != path:
        _reject(f"{field} must be a normalized relative Python path", "exit_corpus_schema_v1")
    return path


def _relative_json_path(value: object, field: str) -> str:
    path = _text(value, field)
    candidate = PurePosixPath(path)
    if not path.endswith(".json") or candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != path:
        _reject(f"{field} must be a normalized relative JSON path", "exit_corpus_schema_v1")
    return path


def _module_name(value: object, field: str) -> str:
    module = _text(value, field)
    if any(not part.isidentifier() for part in module.split(".")):
        _reject(f"{field} must be a Python module name", "exit_corpus_schema_v1")
    return module


def _validate_runnable(raw_runnable: object, case_ids: list[object]) -> JsonObject:
    runnable = _object(raw_runnable, "runnable")
    _exact_keys(runnable, _RUNNABLE_KEYS, "runnable")
    substrate = _object(runnable["substrate"], "runnable.substrate")
    if not {"nsjail_sha256", "rootfs_digest", "containment_template_version"} <= set(substrate) or not set(substrate) <= _SUBSTRATE_KEYS:
        _reject("runnable.substrate has unknown or missing fields", "exit_corpus_schema_v1")
    def substrate_pin(value: object, field: str) -> str | None:
        # A committed runnable corpus may deliberately defer a machine-specific
        # containment identity to an evidence run.  The runner then requires a
        # supplied pin; null never means "accept any substrate".
        if value is None:
            return None
        pin = _text(value, field)
        if _GATE_DIGEST_RE.fullmatch(pin) is None:
            _reject("runnable substrate pins must be sha256 digests or null", "exit_corpus_schema_v1")
        return pin

    nsjail_sha256 = substrate_pin(substrate["nsjail_sha256"], "runnable.substrate.nsjail_sha256")
    rootfs_digest = substrate_pin(substrate["rootfs_digest"], "runnable.substrate.rootfs_digest")
    nsjail_version = substrate.get("nsjail_version")
    nsjail_build_identity = substrate_pin(substrate.get("nsjail_build_identity"), "runnable.substrate.nsjail_build_identity")
    config_schema_digest = substrate_pin(substrate.get("config_schema_digest"), "runnable.substrate.config_schema_digest")
    if nsjail_version is not None:
        nsjail_version = _text(nsjail_version, "runnable.substrate.nsjail_version")
    template = _text(substrate["containment_template_version"], "runnable.substrate.containment_template_version")
    layout = _text(runnable["donors_dir_layout"], "runnable.donors_dir_layout", limit=4096)
    normalized_cases: list[JsonObject] = []
    for raw_case in _list(runnable["per_case"], "runnable.per_case"):
        case = _object(raw_case, "runnable.per_case item")
        if not _RUNNABLE_CASE_REQUIRED_KEYS <= set(case) or not set(case) <= _RUNNABLE_CASE_KEYS:
            _reject("runnable per_case item has unknown or missing fields", "exit_corpus_schema_v1")
        tests: list[JsonObject] = []
        for raw_test in _list(case["contract_tests"], "runnable.per_case.contract_tests"):
            test = _object(raw_test, "runnable contract test")
            _exact_keys(test, _CONTRACT_TEST_KEYS, "runnable contract test")
            tests.append({"path": _relative_python_path(test["path"], "runnable contract test.path"), "module": _module_name(test["module"], "runnable contract test.module")})
        if not tests or tests != sorted(tests, key=lambda item: (cast(str, item["path"]), cast(str, item["module"]))) or len({(item["path"], item["module"]) for item in tests}) != len(tests):
            _reject("runnable contract tests must be nonempty, sorted, and unique", "exit_corpus_schema_v1")
        normalized: JsonObject = {"case_id": _text(case["case_id"], "runnable.per_case.case_id"), "contract_tests": tests}
        if "policy_path" in case:
            normalized["policy_path"] = _relative_json_path(case["policy_path"], "runnable.per_case.policy_path")
        if "notes" in case:
            normalized["notes"] = _text(case["notes"], "runnable.per_case.notes", limit=4096)
        roots = case.get("import_roots", ["."])
        if not isinstance(roots, list) or not roots:
            _reject("runnable import_roots must be a nonempty array", "exit_corpus_schema_v1")
        normalized_roots: list[str] = []
        for root in roots:
            root_path = _text(root, "runnable.per_case.import_roots")
            candidate = PurePosixPath(root_path)
            if candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != root_path:
                _reject("runnable import root must be normalized and relative", "exit_corpus_schema_v1")
            normalized_roots.append(root_path)
        if normalized_roots != sorted(set(normalized_roots)):
            _reject("runnable import_roots must be sorted and unique", "exit_corpus_schema_v1")
        if "import_roots" in case:
            normalized["import_roots"] = normalized_roots
        deps = case.get("runtime_deps", [])
        if not isinstance(deps, list):
            _reject("runnable runtime_deps must be an array", "exit_corpus_schema_v1")
        normalized_deps: list[JsonObject] = []
        for dep in deps:
            item = _object(dep, "runnable runtime dependency")
            _exact_keys(item, _RUNTIME_DEP_KEYS, "runnable runtime dependency")
            distribution = _text(item["distribution"], "runnable runtime dependency.distribution")
            version = _text(item["version"], "runnable runtime dependency.version")
            if "==" in distribution or version.startswith("==") or any(character.isspace() for character in version):
                _reject("runtime dependencies require a distribution and exact plain version pin", "exit_corpus_schema_v1")
            normalized_deps.append({"distribution": distribution, "version": version})
        if normalized_deps != sorted(normalized_deps, key=lambda item: (cast(str, item["distribution"]), cast(str, item["version"]))):
            _reject("runnable runtime_deps must be sorted", "exit_corpus_schema_v1")
        if "runtime_deps" in case:
            normalized["runtime_deps"] = normalized_deps
        normalized_cases.append(normalized)
    expected = tuple(cast(str, item) for item in case_ids)
    actual = tuple(cast(str, item["case_id"]) for item in normalized_cases)
    if actual != tuple(sorted(actual)) or len(actual) != len(set(actual)) or set(actual) != set(expected):
        _reject("runnable per_case entries must be sorted and exactly align with corpus cases", "exit_corpus_runnable_case_alignment_v1")
    normalized_substrate: JsonObject = {"nsjail_sha256": nsjail_sha256, "rootfs_digest": rootfs_digest, "containment_template_version": template}
    for field, value in (("nsjail_version", nsjail_version), ("nsjail_build_identity", nsjail_build_identity), ("config_schema_digest", config_schema_digest)):
        if field in substrate:
            normalized_substrate[field] = value
    return {"substrate": normalized_substrate, "donors_dir_layout": layout, "per_case": normalized_cases}


def _validate_manifest(raw: object) -> JsonObject:
    manifest = _object(raw, "manifest")
    keys = set(manifest)
    if not _REQUIRED_TOP_LEVEL_KEYS <= keys or not keys <= _TOP_LEVEL_KEYS:
        _reject("manifest has unknown or missing fields", "exit_corpus_schema_v1")
    schema_version = _text(manifest["schema_version"], "schema_version")
    if schema_version not in {_V1_SCHEMA_VERSION, EXIT_CORPUS_MANIFEST_SCHEMA_VERSION}:
        _reject("manifest schema_version is unsupported", "exit_corpus_schema_v1")
    corpus_id = _text(manifest["corpus_id"], "corpus_id")
    milestone = _text(manifest["created_for_milestone"], "created_for_milestone")
    cases = [_validate_case(item) for item in _list(manifest["cases"], "cases")]

    case_ids = [case["case_id"] for case in cases]
    if len(set(case_ids)) != len(case_ids):
        _reject("manifest case_id values must be unique", "exit_corpus_duplicate_case_v1")
    provenances = [case["source_provenance"] for case in cases]
    if len(set(provenances)) != len(provenances):
        _reject("manifest source_provenance values must be distinct", "exit_corpus_provenance_not_distinct_v1")
    commit_shas = [_object(case["donor"], "case.donor")["commit_sha"] for case in cases]
    if len(set(commit_shas)) != len(commit_shas):
        _reject("manifest donor commit_sha values must be distinct", "exit_corpus_duplicate_donor_v1")
    if len(cases) < MINIMUM_EXIT_DONORS:
        _reject(f"manifest requires at least {MINIMUM_EXIT_DONORS} donors", "exit_corpus_min_donors_v1")

    ratified = manifest["ratified_manifest_digest"]
    if ratified is not None:
        ratified = _text(ratified, "ratified_manifest_digest")
        if _HEX_64_RE.fullmatch(ratified) is None:
            _reject("ratified_manifest_digest must be null or 64 lowercase hexadecimal characters", "exit_corpus_schema_v1")
    runtime = manifest.get("ratified_runtime_digest")
    if runtime is not None:
        runtime = _text(runtime, "ratified_runtime_digest")
        if _GATE_DIGEST_RE.fullmatch(runtime) is None:
            _reject("ratified_runtime_digest must be null or a sha256 digest", "exit_corpus_schema_v1")

    normalized: JsonObject = {
        "schema_version": schema_version,
        "corpus_id": corpus_id,
        "created_for_milestone": milestone,
        "cases": cases,
        "ratified_manifest_digest": ratified,
    }
    # v1.1 accepts an absent value as the canonical historical spelling of the
    # default null. New manifests should spell it explicitly to bind that choice.
    if "ratified_runtime_digest" in manifest:
        normalized["ratified_runtime_digest"] = runtime
    if "notes" in manifest:
        normalized["notes"] = _text(manifest["notes"], "notes", limit=4096)
    if "runnable" in manifest:
        if schema_version != EXIT_CORPUS_MANIFEST_SCHEMA_VERSION:
            _reject("runnable section requires the v1.1 manifest schema", "exit_corpus_schema_v1")
        normalized["runnable"] = _validate_runnable(manifest["runnable"], case_ids)
    return normalized


def content_digest(manifest_dict: Mapping[str, object]) -> str:
    """Return the SHA-256 content identity, deliberately excluding ratification."""

    content = dict(manifest_dict)
    content.pop("ratified_manifest_digest", None)
    return hashlib.sha256(_canonical_bytes(content)).hexdigest()


def _read_manifest(path: Path) -> bytes:
    try:
        # The canonical manifest's content digest binds these portable bytes;
        # ratification remains the separate no-follow trust-anchor read.
        data = read_regular_file(path, maximum_bytes=MAX_MANIFEST_BYTES, no_follow=False)
    except (OSError, ValueError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "cannot read exit corpus manifest",
            detail_code="exit_corpus_read_v1",
            cause=exc,
        ) from exc
    return data


def load_corpus_manifest(path: Path) -> JsonObject:
    """Load one bounded, canonical, closed-schema v1 corpus manifest."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    data = _read_manifest(path)
    try:
        source = data.decode("utf-8")
        raw = json.loads(source, object_pairs_hook=_reject_duplicate_json_keys)
    except BTSError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "exit corpus manifest is not valid JSON",
            detail_code="exit_corpus_schema_v1",
            cause=exc,
        ) from exc
    manifest = _validate_manifest(raw)
    if data != _canonical_bytes(manifest):
        _reject("exit corpus manifest is not canonical JSON", "exit_corpus_schema_v1")
    return manifest


def _expected_content_binding(content: str) -> str:
    return hashlib.sha256(("ratify:" + content).encode("utf-8")).hexdigest()


def validate_corpus_manifest(path: Path) -> JsonObject:
    """Validate corpus pins and v1 self-hash content binding, not ratification.

    External ratification authority is deferred, so ``ratified`` is always
    false even when ``ratified_manifest_digest`` has a valid content binding.
    """

    manifest = load_corpus_manifest(path)
    digest = content_digest(manifest)
    ratified = manifest["ratified_manifest_digest"]
    if ratified is None:
        content_binding = "absent"
    elif ratified == _expected_content_binding(digest):
        content_binding = "valid"
    else:
        _reject("ratified_manifest_digest does not bind the manifest content digest", "exit_corpus_digest_mismatch_v1")
    cases = _list(manifest["cases"], "cases")
    donors: list[str] = []
    for raw_case in cases:
        donor = _object(_object(raw_case, "case")["donor"], "case.donor")
        donors.append(
            "/".join(
                (
                    _text(donor["host"], "case.donor.host"),
                    _text(donor["owner"], "case.donor.owner"),
                    _text(donor["repo"], "case.donor.repo"),
                    _text(donor["commit_sha"], "case.donor.commit_sha"),
                )
            )
        )
    return {
        "schema_version": EXIT_CORPUS_MANIFEST_SCHEMA_VERSION,
        "corpus_id": manifest["corpus_id"],
        "case_count": len(cases),
        "donors": tuple(donors),
        "content_digest": digest,
        "content_binding": content_binding,
        "ratified": False,
    }


def cross_check_against_gate(corpus_manifest_path: Path) -> JsonObject:
    """Check standalone pins compatible with ``ExitCorpusCase``.

    A :class:`~leitir.bts_exit_gate.ExitCorpusCase` cannot be constructed here:
    it requires a ``BTSPipelineRequest`` from the future runnable substrate.
    This bridge consequently checks only its standalone pinning surface.  The
    manifest records raw SHA-256 hexadecimal values; its review receipt is
    converted to the ``sha256:`` form expected by ``ExitCorpusCase`` for this
    shape check.
    """

    manifest = load_corpus_manifest(corpus_manifest_path)
    checks: list[JsonObject] = []
    for raw_case in _list(manifest["cases"], "cases"):
        case = _object(raw_case, "case")
        case_id = _text(case["case_id"], "case.case_id")
        provenance = _text(case["source_provenance"], "case.source_provenance")
        receipt = _text(case["review_receipt_digest"], "case.review_receipt_digest")
        case_id_valid = len(case_id.encode("utf-8")) <= 512
        provenance_valid = len(provenance.encode("utf-8")) <= 512
        receipt_valid = _GATE_DIGEST_RE.fullmatch("sha256:" + receipt) is not None
        valid = case_id_valid and provenance_valid and receipt_valid
        checks.append(
            {
                "case_id": case_id,
                "case_id_valid": case_id_valid,
                "source_provenance_valid": provenance_valid,
                "review_receipt_digest_valid": receipt_valid,
                "valid": valid,
            }
        )
    return {
        "schema_version": EXIT_CORPUS_MANIFEST_SCHEMA_VERSION,
        "corpus_id": manifest["corpus_id"],
        "case_count": len(checks),
        "cases": tuple(checks),
        "valid": all(item["valid"] is True for item in checks),
    }


def add_runnable_section(manifest_dict: Mapping[str, object], runnable: Mapping[str, object]) -> JsonObject:
    """Convert a validated v1 pin manifest into a v1.1 runnable manifest.

    Ratification is intentionally cleared: runnable execution instructions are
    corpus content, but do not grant any new authority or inherit an old
    content binding.
    """

    if not isinstance(manifest_dict, Mapping) or not isinstance(runnable, Mapping):
        raise TypeError("manifest_dict and runnable must be mappings")
    candidate = dict(manifest_dict)
    candidate["schema_version"] = EXIT_CORPUS_MANIFEST_SCHEMA_VERSION
    candidate["runnable"] = dict(runnable)
    candidate["ratified_manifest_digest"] = None
    candidate["ratified_runtime_digest"] = None
    return _validate_manifest(candidate)


__all__ = [
    "EXIT_CORPUS_MANIFEST_SCHEMA_VERSION",
    "MAX_MANIFEST_BYTES",
    "add_runnable_section",
    "content_digest",
    "cross_check_against_gate",
    "load_corpus_manifest",
    "validate_corpus_manifest",
]
