"""Deterministic, manifest-bound recipient project profiling."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import asdict, dataclass, replace
from pathlib import PurePosixPath, PureWindowsPath

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.lockfiles import (
    DependencyManifestPolicy,
    ManifestDependencyDiagnostic,
    ManifestDependencySource,
    ManifestDiagnosticKind,
    VerifiedManifestBytes,
    dependency_closures_from_manifest,
)

RECIPIENT_MANIFEST_SCHEMA = "leitir-recipient-manifest-v1"
RECIPIENT_PROFILE_SCHEMA = "leitir-recipient-profile-v1"
PROFILE_RULE_VERSION = "recipient-profile-rules-v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical(value)).hexdigest()}"


def _valid_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    return (
        bool(path)
        and "\\" not in path
        and not candidate.is_absolute()
        and not PureWindowsPath(path).drive
        and candidate.as_posix() == path
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


@dataclass(frozen=True, slots=True)
class RecipientManifestEntry:
    """One exact byte capability in a recipient input manifest."""

    path: str
    role: str
    byte_length: int
    sha256: str
    content: bytes

    @classmethod
    def from_bytes(cls, path: str, role: str, content: bytes) -> RecipientManifestEntry:
        """Construct a content-bound entry without reading the filesystem."""

        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        return cls(path, role, len(content), f"sha256:{hashlib.sha256(content).hexdigest()}", content)


@dataclass(frozen=True, slots=True)
class RecipientInputManifest:
    """Bounded, content-addressed authority for recipient profiling."""

    schema_version: str
    manifest_version: str
    project_root_identity: str
    entries: tuple[RecipientManifestEntry, ...]
    manifest_digest: str

    @classmethod
    def create(
        cls,
        project_root_identity: str,
        entries: tuple[RecipientManifestEntry, ...],
        *,
        manifest_version: str = "recipient-manifest-v1",
    ) -> RecipientInputManifest:
        """Validate, canonically order, and digest an in-memory manifest."""

        ordered = tuple(sorted(entries, key=lambda item: item.path))
        draft = cls(RECIPIENT_MANIFEST_SCHEMA, manifest_version, project_root_identity, ordered, "")
        _validate_manifest(draft, check_digest=False)
        return replace(draft, manifest_digest=_manifest_digest(draft))


@dataclass(frozen=True, slots=True)
class RecipientProfilePolicy:
    """Pinned source scope for one recipient profile."""

    dependency_policy: DependencyManifestPolicy
    policy_id: str = "leitir-recipient-profile-policy"
    policy_version: str = "1"


@dataclass(frozen=True, slots=True, order=True)
class DeclaredDependency:
    """One normalized dependency and the source proving it."""

    ecosystem: str
    name: str
    version: str
    resolved_sha: str | None
    spec: str
    graph: str
    source_path: str
    source_digest: str
    parser_id: str
    parser_version: str


@dataclass(frozen=True, slots=True, order=True)
class RuntimeConstraint:
    """A declared language/runtime constraint with manifest evidence."""

    language: str
    runtime: str
    constraint: str
    source_path: str
    source_digest: str
    rule_id: str
    rule_version: str


@dataclass(frozen=True, slots=True, order=True)
class ManifestProvenance:
    """Manifest identity retained by the resulting profile."""

    path: str
    role: str
    byte_length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RecipientProfile:
    """Canonical recipient facts for downstream suitability gates."""

    schema_version: str
    rule_version: str
    policy_id: str
    policy_version: str
    project_root_identity: str
    recipient_manifest_version: str
    recipient_manifest_digest: str
    dependencies: tuple[DeclaredDependency, ...]
    dependency_sources: tuple[ManifestDependencySource, ...]
    runtime_constraints: tuple[RuntimeConstraint, ...]
    provenance: tuple[ManifestProvenance, ...]
    diagnostics: tuple[ManifestDependencyDiagnostic, ...]
    profile_digest: str

    def to_bytes(self) -> bytes:
        """Return canonical profile JSON, including one trailing LF."""

        return _canonical(_profile_payload(self, omit_digest=False))


# ADR-0010 uses ProjectProfile while C4's public issue names RecipientProfile.
ProjectProfile = RecipientProfile


def _entry_payload(entry: RecipientManifestEntry) -> dict[str, object]:
    return {
        "byte_length": entry.byte_length,
        "path": entry.path,
        "role": entry.role,
        "sha256": entry.sha256,
    }


def _manifest_payload(manifest: RecipientInputManifest) -> dict[str, object]:
    return {
        "entries": [_entry_payload(entry) for entry in manifest.entries],
        "manifest_version": manifest.manifest_version,
        "project_root_identity": manifest.project_root_identity,
        "schema_version": manifest.schema_version,
    }


def _manifest_digest(manifest: RecipientInputManifest) -> str:
    return _digest(_manifest_payload(manifest))


def _validate_manifest(manifest: RecipientInputManifest, *, check_digest: bool = True) -> None:
    if (
        manifest.schema_version != RECIPIENT_MANIFEST_SCHEMA
        or not manifest.manifest_version
        or not manifest.project_root_identity
        or not isinstance(manifest.entries, tuple)
    ):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "recipient manifest envelope is invalid",
            detail_code="recipient_manifest_bytes_mismatch_v1",
        )
    paths: list[str] = []
    for entry in manifest.entries:
        if not isinstance(entry, RecipientManifestEntry):
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "recipient manifest entry has an invalid type",
                detail_code="recipient_manifest_bytes_mismatch_v1",
            )
        expected = f"sha256:{hashlib.sha256(entry.content).hexdigest()}"
        if (
            not _valid_path(entry.path)
            or not entry.role
            or type(entry.byte_length) is not int
            or entry.byte_length != len(entry.content)
            or not _DIGEST.fullmatch(entry.sha256)
            or entry.sha256 != expected
        ):
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "recipient manifest entry bytes do not match",
                detail_code="recipient_manifest_bytes_mismatch_v1",
            )
        paths.append(entry.path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "recipient manifest paths are not canonical and unique",
            detail_code="recipient_manifest_bytes_mismatch_v1",
        )
    if check_digest and (not _DIGEST.fullmatch(manifest.manifest_digest) or manifest.manifest_digest != _manifest_digest(manifest)):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "recipient manifest digest does not match",
            detail_code="recipient_manifest_bytes_mismatch_v1",
        )


def _runtime_constraint(entry: RecipientManifestEntry) -> RuntimeConstraint | None:
    source_name = PurePosixPath(entry.path).name
    if source_name not in {"pyproject.toml", "package.json", "Cargo.toml", "go.mod"}:
        return None
    try:
        text = entry.content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNDER_COLLECTION,
            f"runtime source {entry.path} is not strict UTF-8",
            detail_code="dependency_source_parse_failed_v1",
            cause=exc,
        ) from exc
    language = ""
    runtime = ""
    constraint: object = None
    try:
        if source_name == "pyproject.toml":
            payload = tomllib.loads(text)
            project = payload.get("project")
            if isinstance(project, dict):
                constraint = project.get("requires-python")
            language, runtime = "python", "python"
        elif source_name == "package.json":
            payload = json.loads(text)
            if not isinstance(payload, dict):
                raise ValueError("package.json must be an object")
            engines = payload.get("engines")
            if engines is not None and not isinstance(engines, dict):
                raise ValueError("package.json engines must be an object")
            constraint = engines.get("node") if isinstance(engines, dict) else None
            language, runtime = "javascript", "node"
        elif source_name == "Cargo.toml":
            payload = tomllib.loads(text)
            package = payload.get("package")
            if package is not None and not isinstance(package, dict):
                raise ValueError("Cargo package must be a table")
            constraint = package.get("rust-version") if isinstance(package, dict) else None
            language, runtime = "rust", "rust"
        elif source_name == "go.mod":
            for raw in text.splitlines():
                parts = raw.split("//", 1)[0].split()
                if parts and parts[0] == "go":
                    if len(parts) != 2:
                        raise ValueError("malformed go runtime directive")
                    constraint = parts[1]
                    break
            language, runtime = "go", "go"
        else:
            return None
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNDER_COLLECTION,
            f"runtime source {entry.path} could not be parsed",
            detail_code="dependency_source_parse_failed_v1",
            cause=exc,
        ) from exc
    if constraint is None:
        return None
    if not isinstance(constraint, str) or not constraint.strip() or any(character in constraint for character in "\r\n\x00"):
        raise BTSError(
            BTSRejectReason.REJECT_COVERAGE_MISCOUNT,
            f"runtime constraint in {entry.path} is malformed",
            detail_code="dependency_record_malformed_v1",
        )
    return RuntimeConstraint(
        language,
        runtime,
        constraint.strip(),
        entry.path,
        entry.sha256,
        f"{runtime}-runtime-constraint",
        "1",
    )


def _profile_payload(profile: RecipientProfile, *, omit_digest: bool) -> dict[str, object]:
    payload = asdict(profile)
    if omit_digest:
        del payload["profile_digest"]
    return payload


def profile_project(
    manifest: RecipientInputManifest,
    policy: RecipientProfilePolicy | DependencyManifestPolicy,
) -> RecipientProfile:
    """Build a profile solely from verified manifest bytes; never probe a host path."""

    if not isinstance(manifest, RecipientInputManifest):
        raise TypeError("manifest must be a RecipientInputManifest")
    if isinstance(policy, DependencyManifestPolicy):
        policy = RecipientProfilePolicy(policy)
    if not isinstance(policy, RecipientProfilePolicy):
        raise TypeError("policy must be a RecipientProfilePolicy")
    _validate_manifest(manifest)
    verified = tuple(
        VerifiedManifestBytes(entry.path, entry.role, entry.byte_length, entry.sha256, entry.content)
        for entry in manifest.entries
    )
    dependency_result = dependency_closures_from_manifest(verified, policy.dependency_policy)
    required = frozenset(policy.dependency_policy.required_sources)
    for diagnostic in dependency_result.diagnostics:
        if diagnostic.kind is ManifestDiagnosticKind.ABSENT:
            if diagnostic.path in required:
                raise BTSError(
                    BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                    f"required recipient source is absent: {diagnostic.path}",
                    detail_code="recipient_manifest_source_absent_v1",
                )
            continue
        if diagnostic.detail_code == "dependency_source_parse_failed_v1":
            reason = BTSRejectReason.REJECT_UNDER_COLLECTION
        else:
            reason = BTSRejectReason.REJECT_COVERAGE_MISCOUNT
        raise BTSError(
            reason,
            f"dependency source did not account for {diagnostic.record} in {diagnostic.path}",
            detail_code=diagnostic.detail_code,
        )

    dependencies = tuple(
        sorted(
            DeclaredDependency(
                source.ecosystem,
                edge.name,
                edge.version,
                edge.resolved_sha,
                edge.spec,
                source.graph,
                source.path,
                source.source_digest,
                source.parser_id,
                source.parser_version,
            )
            for source in dependency_result.sources
            for edge in source.deps
        )
    )
    versions: dict[tuple[str, str], set[str]] = {}
    for dependency in dependencies:
        versions.setdefault((dependency.ecosystem, dependency.name), set()).add(dependency.version)
    if any(len(found) != 1 for found in versions.values()):
        raise BTSError(
            BTSRejectReason.REJECT_UNRESOLVED_EDGE,
            "recipient dependency sources conflict",
            detail_code="recipient_profile_conflict_v1",
        )

    runtime_constraints = tuple(
        sorted(constraint for entry in manifest.entries if (constraint := _runtime_constraint(entry)) is not None)
    )
    provenance = tuple(
        ManifestProvenance(entry.path, entry.role, entry.byte_length, entry.sha256)
        for entry in manifest.entries
    )
    draft = RecipientProfile(
        RECIPIENT_PROFILE_SCHEMA,
        PROFILE_RULE_VERSION,
        policy.policy_id,
        policy.policy_version,
        manifest.project_root_identity,
        manifest.manifest_version,
        manifest.manifest_digest,
        dependencies,
        dependency_result.sources,
        runtime_constraints,
        provenance,
        dependency_result.diagnostics,
        "",
    )
    return replace(draft, profile_digest=_digest(_profile_payload(draft, omit_digest=True)))


__all__ = [
    "DeclaredDependency",
    "DependencyManifestPolicy",
    "ManifestProvenance",
    "ProjectProfile",
    "RecipientInputManifest",
    "RecipientManifestEntry",
    "RecipientProfile",
    "RecipientProfilePolicy",
    "RuntimeConstraint",
    "profile_project",
]
