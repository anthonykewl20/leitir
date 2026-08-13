"""Canonical reference and reuse packets for validated Behavioral Transplant Sets.

V1 deliberately emits an uncompressed, byte-canonical USTAR stream.  A packet
provides receipt verification (and a reuse packet may support a separately
provisioned donor-absent rerun); it is not a self-contained ADR-0009 baseline
plus rerun revalidation artifact.  Its hashes establish integrity and subject
binding, not publisher identity or authenticity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass, fields
from enum import Enum
from itertools import pairwise
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TypeAlias

from leitir.bts import BTS, BTSResult, BTSStatus, MemberEvidence, _canonical_bytes, _digest
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.bts_pipeline import PIPELINE_SCHEMA_VERSION, PipelineValidationVerdict
from leitir.relocate import RELOCATION_SCHEMA_VERSION, FileRole, Relocation
from leitir.rerun import ValidationStatus

BUNDLE_SCHEMA_VERSION = "leitir-transplant-bundle-v1"
PACKET_INPUTS_SCHEMA_VERSION = "leitir-transplant-inputs-v1"
USTAR_WRITER_ID = "leitir-canonical-ustar-v1"
OBLIGATIONS_SLOT_SCHEMA_VERSION = "leitir-bts-obligations-slot-v1"
_ROOT = BUNDLE_SCHEMA_VERSION
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_TREE_HASH = re.compile(r"h1:[A-Za-z0-9+/]{43}=\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
_POINTER_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}\Z")
_BLOCK = 512
_ZERO_BLOCK = b"\0" * _BLOCK
_REQUIRED_METADATA = frozenset(
    {
        "ATTRIBUTION.md",
        "bts.json",
        "donor.json",
        "obligations.json",
        "packet-policy.json",
        "packet.json",
        "validation.json",
    }
)


class PacketKind(str, Enum):  # noqa: UP042 - normative ADR contract
    REFERENCE = "reference"
    REUSE = "reuse"


class PacketRole(str, Enum):  # noqa: UP042 - normative ADR contract
    METADATA = "metadata"
    MEMBER = "member"
    SOURCE = "source"
    ADAPTER = "adapter"
    TEST_ORIGINAL = "test_original"
    TEST_REWRITTEN = "test_rewritten"
    PROBE = "probe"
    HARNESS = "harness"
    LICENSE = "license"


class PacketOrigin(str, Enum):  # noqa: UP042 - normative ADR contract
    DONOR = "donor"
    LEITIR_CATALOG = "leitir_catalog"
    GENERATED = "generated"


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8", errors="strict"
    )


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase sha256 digest")
    return value


def _require_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a constrained ASCII identifier")
    return value


def _path(value: object, *, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8", errors="strict")) > maximum:
        raise ValueError("packet path is empty or exceeds the USTAR path bound")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or PureWindowsPath(value).drive
        or candidate.as_posix() != value
        or value == "."
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValueError("packet path must be a normalized relative POSIX path")
    return value


@dataclass(frozen=True, slots=True, order=True)
class DonorIdentity:
    slug: str
    commit_sha: str
    materialized_tree_hash: str
    source: str = "git-commit"

    def __post_init__(self) -> None:
        if _SLUG.fullmatch(self.slug) is None or any(part in {"", ".", ".."} for part in self.slug.split("/")):
            raise ValueError("donor.slug must be a constrained ASCII slug")
        if not isinstance(self.commit_sha, str) or _HEX40.fullmatch(self.commit_sha) is None:
            raise ValueError("donor.commit_sha must be an immutable 40-character SHA")
        if not isinstance(self.materialized_tree_hash, str) or _TREE_HASH.fullmatch(self.materialized_tree_hash) is None:
            raise ValueError("donor.materialized_tree_hash must be a canonical h1 tree hash")
        if self.source != "git-commit":
            raise ValueError("donor.source must be git-commit")


@dataclass(frozen=True, slots=True, order=True)
class PinnedSourcePointer:
    scheme: str
    authority: str
    repository_id: str
    commit_sha: str
    path: str
    blob_sha: str

    def __post_init__(self) -> None:
        if self.scheme != "git":
            raise ValueError("v1 supports only git source pointers")
        for name in ("authority", "repository_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or _POINTER_PART.fullmatch(value) is None or any(char in value for char in "%\r\n\0"):
                raise ValueError(f"pointer.{name} has an invalid ASCII grammar")
        _path(self.path)
        if _HEX40.fullmatch(self.commit_sha) is None or _HEX40.fullmatch(self.blob_sha) is None:
            raise ValueError("pointer Git identities must be lowercase 40-character SHAs")


@dataclass(frozen=True, slots=True, order=True)
class CatalogIdentity:
    catalog_id: str
    content_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.catalog_id, "catalog_id")
        _require_digest(self.content_digest, "catalog.content_digest")


@dataclass(frozen=True, slots=True)
class PacketInputs:
    schema_version: str
    kind: PacketKind
    selection_digest: str
    donor: DonorIdentity
    bts_digest: str
    member_equivalence_digest: str
    validation_digest: str
    recipient_license_policy_digest: str
    bundled_license_policy_digest: str
    packet_policy_digest: str
    source_pointers: tuple[PinnedSourcePointer, ...] = ()
    catalog_identities: tuple[CatalogIdentity, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != PACKET_INPUTS_SCHEMA_VERSION or not isinstance(self.kind, PacketKind):
            raise ValueError("unsupported packet inputs schema or kind")
        if not isinstance(self.donor, DonorIdentity):
            raise ValueError("donor must be a DonorIdentity")
        for item in fields(self):
            if item.name.endswith("_digest"):
                _require_digest(getattr(self, item.name), item.name)
        if not isinstance(self.source_pointers, tuple) or not all(isinstance(item, PinnedSourcePointer) for item in self.source_pointers):
            raise ValueError("source_pointers must contain only PinnedSourcePointer records")
        if not isinstance(self.catalog_identities, tuple) or not all(isinstance(item, CatalogIdentity) for item in self.catalog_identities):
            raise ValueError("catalog_identities must contain only CatalogIdentity records")
        pointers = tuple(sorted(self.source_pointers))
        catalogs = tuple(sorted(self.catalog_identities))
        if len(set(pointers)) != len(pointers) or len({item.catalog_id for item in catalogs}) != len(catalogs):
            raise ValueError("packet inputs contain duplicate pointers or catalog identities")
        object.__setattr__(self, "source_pointers", pointers)
        object.__setattr__(self, "catalog_identities", catalogs)


@dataclass(frozen=True, slots=True, order=True)
class PacketPayload:
    path: str
    role: PacketRole
    origin: PacketOrigin
    content: bytes

    def __post_init__(self) -> None:
        _path(self.path)
        if not isinstance(self.role, PacketRole) or self.role is PacketRole.METADATA:
            raise ValueError("payload role must be a source-bearing packet role")
        if not isinstance(self.origin, PacketOrigin) or not isinstance(self.content, bytes):
            raise ValueError("payload origin/content has an invalid type")
        expected = {
            PacketRole.MEMBER: "members/",
            PacketRole.SOURCE: "source/",
            PacketRole.ADAPTER: "adapters/",
            PacketRole.TEST_ORIGINAL: "tests/original/",
            PacketRole.TEST_REWRITTEN: "tests/rewritten/",
            PacketRole.PROBE: "probes/",
            PacketRole.HARNESS: "harness/",
            PacketRole.LICENSE: "licenses/",
        }[self.role]
        if not self.path.startswith(expected) or self.path == expected.rstrip("/"):
            raise ValueError(f"{self.role.value} payload must be below {expected}")


@dataclass(frozen=True, slots=True, order=True)
class PacketFile:
    path: str
    role: PacketRole
    origin: PacketOrigin
    mode: int
    size: int
    sha256: str

    def __post_init__(self) -> None:
        _path(self.path)
        if not isinstance(self.role, PacketRole) or not isinstance(self.origin, PacketOrigin):
            raise ValueError("packet file role/origin has an invalid type")
        if self.mode != 0o644 or isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("packet files require mode 0644 and a nonnegative size")
        _require_digest(self.sha256, "packet file digest")


@dataclass(frozen=True, slots=True)
class ReferencePacket:
    schema_version: str
    inputs: PacketInputs
    files: tuple[PacketFile, ...]
    obligations_digest: str
    bundle_digest: str
    bundle_json: bytes
    archive_bytes: bytes


@dataclass(frozen=True, slots=True)
class ReusePacket:
    schema_version: str
    inputs: PacketInputs
    files: tuple[PacketFile, ...]
    obligations_digest: str
    bundle_digest: str
    bundle_json: bytes
    archive_bytes: bytes


Packet: TypeAlias = ReferencePacket | ReusePacket


def member_payload_path(member: MemberEvidence) -> str:
    """Return the canonical, non-semantic archive key for an exact member span."""

    identity = _canonical_bytes((member.node, member.source))
    return f"members/{hashlib.sha256(identity).hexdigest()}.bin"


def _validated_bts(result: BTSResult) -> BTS:
    if not isinstance(result, BTSResult):
        raise TypeError("bts must be a BTSResult")
    if result.status is not BTSStatus.COMPLETE or result.report.status is not BTSStatus.COMPLETE or result.bts is None:
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "only a COMPLETE BTS may be packaged",
            detail_code="packet_non_complete_bts_v1",
        )
    artifact = result.bts
    # Frozen records are re-derived at this boundary; caller-set digest fields
    # are never accepted as assertions.
    result.report.from_json(result.report.to_bytes())
    equivalence = _digest(artifact, omit=frozenset({"bts_digest", "member_equivalence_digest"}))
    primary = _digest((result.report, artifact), omit=frozenset({"analysis_digest", "bts_digest", "member_equivalence_digest"}))
    if artifact.member_equivalence_digest != equivalence or artifact.bts_digest != primary:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "BTS identity does not match its canonical records",
            detail_code="packet_bts_digest_v1",
        )
    return artifact


def _receipt_bytes(receipt: PipelineValidationVerdict, bts_digest: str) -> bytes:
    if not isinstance(receipt, PipelineValidationVerdict):
        raise TypeError("validation_receipt must be a PipelineValidationVerdict")
    payload = {
        "bts_digest": receipt.bts_digest,
        "detail_categories": list(receipt.detail_categories),
        "probe_report_digest": receipt.probe_report_digest,
        "reason": None if receipt.reason is None else receipt.reason.value,
        "relocation_digest": receipt.relocation_digest,
        "rerun_report_digest": receipt.rerun_report_digest,
        "schema_version": receipt.schema_version,
        "status": receipt.status.value,
    }
    expected = _sha(_canonical(payload))
    if (
        receipt.schema_version != PIPELINE_SCHEMA_VERSION
        or receipt.status is not ValidationStatus.COMPLETE
        or receipt.reason is not None
        or receipt.detail_categories
        or receipt.bts_digest != bts_digest
        or receipt.rerun_report_digest is None
        or receipt.probe_report_digest is None
        or receipt.validation_digest != expected
    ):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "validation receipt is incomplete, malformed, or does not bind the BTS",
            detail_code="packet_validation_receipt_v1",
        )
    return _canonical({**payload, "validation_digest": receipt.validation_digest})


def _inputs_value(inputs: PacketInputs) -> dict[str, object]:
    return {
        "bts_digest": inputs.bts_digest,
        "bundled_license_policy_digest": inputs.bundled_license_policy_digest,
        "catalog_identities": [
            {"catalog_id": item.catalog_id, "content_digest": item.content_digest} for item in inputs.catalog_identities
        ],
        "donor": {
            "commit_sha": inputs.donor.commit_sha,
            "materialized_tree_hash": inputs.donor.materialized_tree_hash,
            "slug": inputs.donor.slug,
            "source": inputs.donor.source,
        },
        "kind": inputs.kind.value,
        "member_equivalence_digest": inputs.member_equivalence_digest,
        "packet_policy_digest": inputs.packet_policy_digest,
        "recipient_license_policy_digest": inputs.recipient_license_policy_digest,
        "schema_version": inputs.schema_version,
        "selection_digest": inputs.selection_digest,
        "source_pointers": [
            {
                "authority": item.authority,
                "blob_sha": item.blob_sha,
                "commit_sha": item.commit_sha,
                "path": item.path,
                "repository_id": item.repository_id,
                "scheme": item.scheme,
            }
            for item in inputs.source_pointers
        ],
        "validation_digest": inputs.validation_digest,
    }


def _member_value(member: MemberEvidence) -> dict[str, object]:
    source = member.source
    node = member.node
    return {
        "disposition": member.disposition.value,
        "member_path": member_payload_path(member),
        "node": {
            "kind": node.kind.value,
            "location_key": node.location_key,
            "module": node.module,
            "origin": node.origin.value,
            "qualified_name": node.qualified_name,
        },
        "source": {
            "blob_sha": source.blob_sha,
            "commit_sha": source.commit_sha,
            "end_col": source.end_col,
            "end_line": source.end_line,
            "path": source.path,
            "slug": source.slug,
            "start_col": source.start_col,
            "start_line": source.start_line,
        },
        "source_bytes_sha256": member.source_bytes_sha256,
    }


def _metadata(artifact: BTS, inputs: PacketInputs, receipt_bytes: bytes) -> dict[str, bytes]:
    obligations = _canonical(
        {
            "packet_kind": inputs.kind.value,
            "producer": "D1",
            "records": [],
            "schema_version": OBLIGATIONS_SLOT_SCHEMA_VERSION,
            "status": "not_provided",
        }
    )
    attribution = (
        b"# Attribution\n\nNo license or attribution claim is made by C5. "
        b"The authoritative obligations payload is produced by D1.\n"
    )
    return {
        "packet-policy.json": _canonical(
            {
                "content_digest": inputs.packet_policy_digest,
                "schema_version": "leitir-packet-policy-reference-v1",
            }
        ),
        "packet.json": _canonical(
            {
                "capability": "review_only" if inputs.kind is PacketKind.REFERENCE else "verified_payload_receipt",
                "inputs": _inputs_value(inputs),
                "schema_version": BUNDLE_SCHEMA_VERSION,
            }
        ),
        "donor.json": _canonical(
            {
                "commit_sha": inputs.donor.commit_sha,
                "materialized_tree_hash": inputs.donor.materialized_tree_hash,
                "slug": inputs.donor.slug,
                "source": inputs.donor.source,
            }
        ),
        "bts.json": _canonical(
            {
                "bts_digest": artifact.bts_digest,
                "member_equivalence_digest": artifact.member_equivalence_digest,
                "members": [_member_value(item) for item in artifact.members],
                "schema_version": artifact.schema_version,
            }
        ),
        "validation.json": receipt_bytes,
        "obligations.json": obligations,
        "ATTRIBUTION.md": attribution,
    }


def _packet_file(path: str, role: PacketRole, origin: PacketOrigin, content: bytes) -> PacketFile:
    return PacketFile(path, role, origin, 0o644, len(content), _sha(content))


def _files_value(files: tuple[PacketFile, ...]) -> list[dict[str, object]]:
    return [
        {
            "mode": item.mode,
            "origin": item.origin.value,
            "path": item.path,
            "role": item.role.value,
            "sha256": item.sha256,
            "size": item.size,
        }
        for item in files
    ]


def _logical(inputs: PacketInputs, files: tuple[PacketFile, ...], obligations_digest: str) -> dict[str, object]:
    return {
        "files": _files_value(files),
        "format": BUNDLE_SCHEMA_VERSION,
        "inputs": _inputs_value(inputs),
        "integrity_model": "integrity_not_authenticity",
        "obligations_digest": obligations_digest,
        "packet_kind": inputs.kind.value,
        "verification_claim": {
            "end_to_end_revalidation": False,
            "receipt_verification": True,
            "optional_relocated_rerun_requires_external_prerequisites": inputs.kind is PacketKind.REUSE,
        },
        "writer": USTAR_WRITER_ID,
    }


def _validate_inputs(inputs: PacketInputs, artifact: BTS, receipt: PipelineValidationVerdict, kind: PacketKind) -> None:
    if not isinstance(inputs, PacketInputs) or inputs.kind is not kind:
        raise ValueError(f"inputs.kind must be {kind.value}")
    report_inputs = artifact.members[0].source if artifact.members else None
    if (
        inputs.bts_digest != artifact.bts_digest
        or inputs.member_equivalence_digest != artifact.member_equivalence_digest
        or inputs.validation_digest != receipt.validation_digest
        or report_inputs is None
        or inputs.donor.slug != report_inputs.slug
        or inputs.donor.commit_sha != report_inputs.commit_sha
    ):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "packet inputs do not bind the supplied BTS, receipt, and donor",
            detail_code="packet_input_binding_v1",
        )


def _relocation_digest(relocation: Relocation) -> str:
    inventory = [
        {"mode": item.mode, "path": item.path, "role": item.role.value, "sha256": item.sha256, "size": len(item.content)}
        for item in sorted(relocation.files)
    ]
    identity = {
        "baseline_mounts": [
            (item.logical_path, item.read_only, item.donor_present) for item in relocation.baseline_mounts
        ],
        "bts_digest": relocation.bts_digest,
        "files": inventory,
        "module_map_digest": relocation.module_map.digest,
        "rerun_mounts": [(item.logical_path, item.read_only, item.donor_present) for item in relocation.rerun_mounts],
        "schema_version": relocation.schema_version,
    }
    return _sha(_canonical(identity))


def _public_relocation_files(relocation: Relocation) -> dict[tuple[PacketRole, str], bytes]:
    mapping = {
        FileRole.SOURCE: (PacketRole.SOURCE, "staging-v1/src/", "source/"),
        FileRole.TEST_ORIGINAL: (PacketRole.TEST_ORIGINAL, "staging-v1/tests/original/", "tests/original/"),
        FileRole.TEST_REWRITTEN: (PacketRole.TEST_REWRITTEN, "staging-v1/tests/rewritten/", "tests/rewritten/"),
        FileRole.PROBE: (PacketRole.PROBE, "staging-v1/probes/", "probes/"),
        FileRole.HARNESS: (PacketRole.HARNESS, "staging-v1/harness/", "harness/"),
    }
    result: dict[tuple[PacketRole, str], bytes] = {}
    for item in relocation.files:
        if item.role not in mapping:
            continue
        role, old, new = mapping[item.role]
        if not item.path.startswith(old):
            raise ValueError("relocation file is outside its canonical staging role")
        key = role, new + item.path.removeprefix(old)
        if key in result:
            raise ValueError("relocation has duplicate public packet paths")
        result[key] = item.content
    return result


def _validate_payloads(
    artifact: BTS,
    receipt: PipelineValidationVerdict,
    relocation: Relocation,
    payloads: tuple[PacketPayload, ...],
) -> tuple[PacketPayload, ...]:
    if not isinstance(relocation, Relocation):
        raise TypeError("relocation must be a Relocation")
    if (
        relocation.schema_version != RELOCATION_SCHEMA_VERSION
        or relocation.bts_digest != artifact.bts_digest
        or relocation.relocation_digest != receipt.relocation_digest
        or relocation.relocation_digest != _relocation_digest(relocation)
    ):
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "relocation does not match the BTS and validation receipt",
            detail_code="packet_relocation_binding_v1",
        )
    if not isinstance(payloads, tuple) or not all(isinstance(item, PacketPayload) for item in payloads):
        raise TypeError("payloads must be a tuple of PacketPayload records")
    ordered = tuple(sorted(payloads, key=lambda item: item.path.encode("utf-8")))
    paths = tuple(item.path for item in ordered)
    if len(set(paths)) != len(paths) or len({item.casefold() for item in paths}) != len(paths):
        raise BTSError(BTSRejectReason.REJECT_BUNDLE_INVALID, "payload paths collide", detail_code="packet_payload_path_collision_v1")
    for left, right in pairwise(paths):
        if right.startswith(left + "/"):
            raise BTSError(BTSRejectReason.REJECT_BUNDLE_INVALID, "payload path has a prefix conflict", detail_code="packet_payload_prefix_v1")
    expected_members = {member_payload_path(item): item.source_bytes_sha256 for item in artifact.members}
    actual_members = {item.path: _sha(item.content) for item in ordered if item.role is PacketRole.MEMBER}
    if actual_members != expected_members:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "reuse packet does not contain every exact BTS member span",
            detail_code="packet_member_payload_v1",
        )
    expected_relocation = _public_relocation_files(relocation)
    actual_relocation = {
        (item.role, item.path): item.content
        for item in ordered
        if item.role in {
            PacketRole.SOURCE,
            PacketRole.TEST_ORIGINAL,
            PacketRole.TEST_REWRITTEN,
            PacketRole.PROBE,
            PacketRole.HARNESS,
        }
    }
    if actual_relocation != expected_relocation:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "reuse packet relocated/test bytes do not match the validated staging tree",
            detail_code="packet_relocation_payload_v1",
        )
    if any(
        (item.role in {PacketRole.MEMBER, PacketRole.TEST_ORIGINAL} and item.origin is not PacketOrigin.DONOR)
        or (item.role in {PacketRole.SOURCE, PacketRole.TEST_REWRITTEN} and item.origin is not PacketOrigin.GENERATED)
        for item in ordered
    ):
        raise BTSError(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "reuse payload origin does not match its public role",
            detail_code="packet_payload_origin_v1",
        )
    roles = {item.role for item in ordered}
    required = {PacketRole.SOURCE, PacketRole.TEST_ORIGINAL, PacketRole.TEST_REWRITTEN}
    if not required <= roles:
        raise BTSError(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "reuse packet requires relocated source and exact original/rewritten tests",
            detail_code="packet_required_reuse_role_v1",
        )
    return ordered


def _build(
    bts: BTSResult,
    validation_receipt: PipelineValidationVerdict,
    inputs: PacketInputs,
    relocation: Relocation | None,
    payloads: tuple[PacketPayload, ...],
    kind: PacketKind,
) -> Packet:
    artifact = _validated_bts(bts)
    receipt_bytes = _receipt_bytes(validation_receipt, artifact.bts_digest)
    _validate_inputs(inputs, artifact, validation_receipt, kind)
    if kind is PacketKind.REFERENCE and payloads:
        raise BTSError(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "reference packets are metadata-only and cannot accept payload bytes",
            detail_code="packet_reference_payload_v1",
        )
    ordered_payloads: tuple[PacketPayload, ...]
    if kind is PacketKind.REFERENCE:
        ordered_payloads = ()
    else:
        if relocation is None:
            raise TypeError("reuse packet construction requires the validated Relocation")
        ordered_payloads = _validate_payloads(artifact, validation_receipt, relocation, payloads)
    contents = _metadata(artifact, inputs, receipt_bytes)
    for payload in ordered_payloads:
        contents[payload.path] = payload.content
    records = tuple(
        sorted(
            (
                _packet_file(path, PacketRole.METADATA, PacketOrigin.GENERATED, content)
                for path, content in contents.items()
                if path in _REQUIRED_METADATA
            ),
            key=lambda item: item.path.encode("utf-8"),
        )
    ) + tuple(_packet_file(item.path, item.role, item.origin, item.content) for item in ordered_payloads)
    records = tuple(sorted(records, key=lambda item: item.path.encode("utf-8")))
    obligations_digest = _sha(contents["obligations.json"])
    logical = _logical(inputs, records, obligations_digest)
    bundle_digest = _sha(_canonical(logical))
    bundle_json = _canonical({**logical, "bundle_digest": bundle_digest})
    contents["bundle.json"] = bundle_json
    archive = _write_ustar({f"{_ROOT}/{path}": data for path, data in contents.items()})
    cls = ReferencePacket if kind is PacketKind.REFERENCE else ReusePacket
    return cls(BUNDLE_SCHEMA_VERSION, inputs, records, obligations_digest, bundle_digest, bundle_json, archive)


def build_reference_packet(
    bts: BTSResult,
    validation_receipt: PipelineValidationVerdict,
    *,
    inputs: PacketInputs,
) -> ReferencePacket:
    """Build a closed metadata-only review/reacquisition packet."""

    packet = _build(bts, validation_receipt, inputs, None, (), PacketKind.REFERENCE)
    assert isinstance(packet, ReferencePacket)
    return packet


def build_reuse_packet(
    bts: BTSResult,
    validation_receipt: PipelineValidationVerdict,
    *,
    inputs: PacketInputs,
    relocation: Relocation,
    payloads: tuple[PacketPayload, ...],
) -> ReusePacket:
    """Build a source-bearing packet after COMPLETE BTS/receipt verification."""

    packet = _build(bts, validation_receipt, inputs, relocation, payloads, PacketKind.REUSE)
    assert isinstance(packet, ReusePacket)
    return packet


def _octal(value: int, width: int) -> bytes:
    rendered = f"{value:0{width - 1}o}".encode("ascii")
    if len(rendered) != width - 1:
        raise ValueError("USTAR numeric field overflow")
    return rendered + b"\0"


def _ustar_name(path: str, *, directory: bool) -> tuple[bytes, bytes]:
    rendered = path + ("/" if directory else "")
    encoded = rendered.encode("utf-8", errors="strict")
    if len(encoded) <= 100:
        return encoded, b""
    candidates: list[tuple[bytes, bytes]] = []
    for index, byte in enumerate(encoded):
        if byte == ord("/"):
            prefix, name = encoded[:index], encoded[index + 1 :]
            if prefix and name and len(prefix) <= 155 and len(name) <= 100:
                candidates.append((name, prefix))
    if not candidates:
        raise ValueError("USTAR path cannot be represented without an extension")
    return candidates[-1]


def _header(path: str, *, directory: bool, size: int) -> bytes:
    name, prefix = _ustar_name(path, directory=directory)
    header = bytearray(_BLOCK)
    header[: len(name)] = name
    header[100:108] = _octal(0o755 if directory else 0o644, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b" " * 8
    header[156:157] = b"5" if directory else b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    rendered = f"{checksum:06o}".encode("ascii")
    if len(rendered) != 6:
        raise ValueError("USTAR checksum overflow")
    header[148:156] = rendered + b"\0 "
    return bytes(header)


def _write_ustar(files: dict[str, bytes]) -> bytes:
    for path, content in files.items():
        _path(path)
        if not isinstance(content, bytes):
            raise TypeError("USTAR file content must be bytes")
    directories: set[str] = set()
    for path in files:
        parts = path.split("/")[:-1]
        directories.update("/".join(parts[:index]) for index in range(1, len(parts) + 1))
    entries: list[tuple[str, bool]] = [(path, True) for path in directories]
    entries.extend((path, False) for path in files)
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    output = bytearray()
    for path, directory in entries:
        data = b"" if directory else files[path]
        output.extend(_header(path, directory=directory, size=len(data)))
        if data:
            output.extend(data)
            output.extend(b"\0" * (-len(data) % _BLOCK))
    output.extend(_ZERO_BLOCK * 2)
    return bytes(output)


def _field(header: bytes, start: int, length: int) -> bytes:
    return header[start : start + length].split(b"\0", 1)[0]


def _read_octal(field: bytes, width: int) -> int:
    if len(field) != width or field[-1:] != b"\0" or any(byte not in b"01234567" for byte in field[:-1]):
        raise ValueError("noncanonical USTAR octal field")
    return int(field[:-1], 8)


def _read_ustar(archive: bytes) -> dict[str, bytes]:
    if not isinstance(archive, bytes) or len(archive) < 1024 or len(archive) % _BLOCK:
        raise ValueError("archive length is not a complete USTAR stream")
    offset = 0
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    while archive[offset : offset + _BLOCK] != _ZERO_BLOCK:
        if offset + _BLOCK > len(archive) - 1024:
            raise ValueError("USTAR trailer is missing")
        header = archive[offset : offset + _BLOCK]
        offset += _BLOCK
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise ValueError("unsupported USTAR identity")
        checksum = header[148:156]
        if len(checksum) != 8 or checksum[6:] != b"\0 ":
            raise ValueError("noncanonical USTAR checksum")
        checked = bytearray(header)
        checked[148:156] = b" " * 8
        if checksum[:6] != f"{sum(checked):06o}".encode("ascii"):
            raise ValueError("USTAR checksum mismatch")
        mode = _read_octal(header[100:108], 8)
        uid = _read_octal(header[108:116], 8)
        gid = _read_octal(header[116:124], 8)
        size = _read_octal(header[124:136], 12)
        mtime = _read_octal(header[136:148], 12)
        if uid or gid or mtime or _field(header, 157, 100) or _field(header, 265, 32) or _field(header, 297, 32):
            raise ValueError("USTAR host metadata is not zeroed")
        name = _field(header, 0, 100)
        prefix = _field(header, 345, 155)
        raw_path = (prefix + (b"/" if prefix else b"") + name).decode("utf-8", errors="strict")
        kind = header[156:157]
        directory = kind == b"5"
        if kind not in {b"0", b"5"} or mode != (0o755 if directory else 0o644):
            raise ValueError("unsupported USTAR member type or mode")
        logical = raw_path[:-1] if directory and raw_path.endswith("/") else raw_path
        _path(logical)
        if directory and (size != 0 or logical in directories):
            raise ValueError("invalid or duplicate USTAR directory")
        if not directory and logical in files:
            raise ValueError("duplicate USTAR file")
        data = archive[offset : offset + size]
        if len(data) != size:
            raise ValueError("truncated USTAR file")
        offset += size
        padding = -size % _BLOCK
        if archive[offset : offset + padding] != b"\0" * padding:
            raise ValueError("nonzero USTAR padding")
        offset += padding
        if directory:
            directories.add(logical)
        else:
            files[logical] = data
    if archive[offset:] != _ZERO_BLOCK * 2:
        raise ValueError("USTAR must end in exactly two zero blocks")
    if archive != _write_ustar(files):
        raise ValueError("USTAR stream is not in canonical member order or representation")
    return files


def _strict_json(data: bytes) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    decoded = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    if _canonical(decoded) != data:
        raise ValueError("JSON member is not canonical")
    return decoded


def _inputs_from_value(value: object) -> PacketInputs:
    if not isinstance(value, dict) or set(value) != {
        "bts_digest", "bundled_license_policy_digest", "catalog_identities", "donor", "kind",
        "member_equivalence_digest", "packet_policy_digest", "recipient_license_policy_digest", "schema_version",
        "selection_digest", "source_pointers", "validation_digest",
    }:
        raise ValueError("packet inputs have a missing or unknown field")
    donor = value["donor"]
    pointers = value["source_pointers"]
    catalogs = value["catalog_identities"]
    if not isinstance(donor, dict) or set(donor) != {"commit_sha", "materialized_tree_hash", "slug", "source"}:
        raise ValueError("donor identity is malformed")
    if not isinstance(pointers, list) or not isinstance(catalogs, list):
        raise ValueError("packet pointer/catalog collections are malformed")
    return PacketInputs(
        value["schema_version"],
        PacketKind(value["kind"]),
        value["selection_digest"],
        DonorIdentity(donor["slug"], donor["commit_sha"], donor["materialized_tree_hash"], donor["source"]),
        value["bts_digest"],
        value["member_equivalence_digest"],
        value["validation_digest"],
        value["recipient_license_policy_digest"],
        value["bundled_license_policy_digest"],
        value["packet_policy_digest"],
        tuple(PinnedSourcePointer(**item) for item in pointers),
        tuple(CatalogIdentity(**item) for item in catalogs),
    )


def load_packet(archive_bytes: bytes) -> Packet:
    """Load and fully verify a canonical packet; never extract or execute it."""

    try:
        members = _read_ustar(archive_bytes)
        prefix = f"{_ROOT}/"
        if not members or any(not path.startswith(prefix) for path in members):
            raise ValueError("packet has an invalid root")
        contents = {path.removeprefix(prefix): data for path, data in members.items()}
        bundle_data = contents.pop("bundle.json")
        bundle = _strict_json(bundle_data)
        if not isinstance(bundle, dict) or set(bundle) != {
            "bundle_digest", "files", "format", "inputs", "integrity_model", "obligations_digest", "packet_kind",
            "verification_claim", "writer",
        }:
            raise ValueError("bundle manifest has a missing or unknown field")
        raw_files = bundle["files"]
        if not isinstance(raw_files, list):
            raise ValueError("bundle file inventory is malformed")
        records = tuple(
            PacketFile(item["path"], PacketRole(item["role"]), PacketOrigin(item["origin"]), item["mode"], item["size"], item["sha256"])
            for item in raw_files
            if isinstance(item, dict) and set(item) == {"mode", "origin", "path", "role", "sha256", "size"}
        )
        if len(records) != len(raw_files) or records != tuple(sorted(records, key=lambda item: item.path.encode("utf-8"))):
            raise ValueError("bundle file inventory is incomplete or noncanonical")
        if set(contents) != {item.path for item in records}:
            raise ValueError("archive files do not exactly match the bundle inventory")
        metadata_paths = {item.path for item in records if item.role is PacketRole.METADATA}
        if metadata_paths != _REQUIRED_METADATA or any(
            item.origin is not PacketOrigin.GENERATED for item in records if item.role is PacketRole.METADATA
        ):
            raise ValueError("packet does not contain the exact required generated metadata set")
        for item in records:
            if len(contents[item.path]) != item.size or _sha(contents[item.path]) != item.sha256:
                raise ValueError("packet file digest mismatch")
        packet_json = _strict_json(contents["packet.json"])
        if not isinstance(packet_json, dict) or set(packet_json) != {"capability", "inputs", "schema_version"}:
            raise ValueError("packet.json is malformed")
        inputs = _inputs_from_value(packet_json["inputs"])
        expected_capability = "review_only" if inputs.kind is PacketKind.REFERENCE else "verified_payload_receipt"
        if packet_json["schema_version"] != BUNDLE_SCHEMA_VERSION or packet_json["capability"] != expected_capability:
            raise ValueError("packet capability or schema does not match its kind")
        obligations_digest = _require_digest(bundle["obligations_digest"], "obligations_digest")
        if obligations_digest != _sha(contents["obligations.json"]):
            raise ValueError("obligations digest mismatch")
        logical = _logical(inputs, records, obligations_digest)
        bundle_digest = _require_digest(bundle["bundle_digest"], "bundle_digest")
        if bundle != {**logical, "bundle_digest": bundle_digest} or bundle_digest != _sha(_canonical(logical)):
            raise ValueError("logical bundle digest mismatch")
        donor = _strict_json(contents["donor.json"])
        expected_donor = {
            "commit_sha": inputs.donor.commit_sha,
            "materialized_tree_hash": inputs.donor.materialized_tree_hash,
            "slug": inputs.donor.slug,
            "source": inputs.donor.source,
        }
        if donor != expected_donor:
            raise ValueError("donor metadata does not match packet inputs")
        bts_metadata = _strict_json(contents["bts.json"])
        if (
            not isinstance(bts_metadata, dict)
            or set(bts_metadata) != {"bts_digest", "member_equivalence_digest", "members", "schema_version"}
            or bts_metadata["bts_digest"] != inputs.bts_digest
            or bts_metadata["member_equivalence_digest"] != inputs.member_equivalence_digest
            or not isinstance(bts_metadata["members"], list)
        ):
            raise ValueError("BTS metadata does not match packet inputs")
        validation = _strict_json(contents["validation.json"])
        if (
            not isinstance(validation, dict)
            or set(validation) != {
                "bts_digest", "detail_categories", "probe_report_digest", "reason", "relocation_digest",
                "rerun_report_digest", "schema_version", "status", "validation_digest",
            }
            or validation.get("schema_version") != PIPELINE_SCHEMA_VERSION
            or validation.get("status") != "complete"
            or validation.get("reason") is not None
            or validation.get("detail_categories") != []
            or validation.get("bts_digest") != inputs.bts_digest
            or validation.get("validation_digest") != inputs.validation_digest
        ):
            raise ValueError("validation receipt subject or status mismatch")
        for name in ("probe_report_digest", "relocation_digest", "rerun_report_digest"):
            _require_digest(validation[name], name)
        receipt_without_digest = {key: value for key, value in validation.items() if key != "validation_digest"}
        if validation.get("validation_digest") != _sha(_canonical(receipt_without_digest)):
            raise ValueError("validation receipt digest mismatch")
        cls = ReferencePacket if inputs.kind is PacketKind.REFERENCE else ReusePacket
        if inputs.kind is PacketKind.REFERENCE and any(item.role is not PacketRole.METADATA for item in records):
            raise ValueError("reference packet contains source-bearing files")
        if inputs.kind is PacketKind.REUSE:
            roles = {item.role for item in records}
            if not {PacketRole.MEMBER, PacketRole.SOURCE, PacketRole.TEST_ORIGINAL, PacketRole.TEST_REWRITTEN} <= roles:
                raise ValueError("reuse packet is missing required source-bearing roles")
            member_paths: set[str] = set()
            for member in bts_metadata["members"]:
                if not isinstance(member, dict) or set(member) != {
                    "disposition", "member_path", "node", "source", "source_bytes_sha256"
                }:
                    raise ValueError("BTS member metadata is malformed")
                member_path = _path(member["member_path"])
                if not member_path.startswith("members/"):
                    raise ValueError("BTS member path is outside members/")
                _require_digest(member["source_bytes_sha256"], "member source digest")
                matching = next((item for item in records if item.path == member_path and item.role is PacketRole.MEMBER), None)
                if matching is None or matching.sha256 != member["source_bytes_sha256"] or member_path in member_paths:
                    raise ValueError("BTS member payload is missing, duplicate, or digest-mismatched")
                member_paths.add(member_path)
            if member_paths != {item.path for item in records if item.role is PacketRole.MEMBER}:
                raise ValueError("reuse packet contains a surplus member payload")
        return cls(BUNDLE_SCHEMA_VERSION, inputs, records, obligations_digest, bundle_digest, bundle_data, archive_bytes)
    except BTSError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "packet archive is malformed, noncanonical, or digest-mismatched",
            detail_code="packet_load_invalid_v1",
            cause=exc,
        ) from exc


def publish_packet(packet: Packet, target: Path) -> None:
    """Atomically publish an already-built packet and fsync its directory (directory fsync on POSIX)."""

    if not isinstance(packet, (ReferencePacket, ReusePacket)) or not isinstance(target, Path):
        raise TypeError("publish_packet requires a packet and pathlib.Path target")
    target = target.absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_file() and target.read_bytes() == packet.archive_bytes:
            return
        raise BTSError(
            BTSRejectReason.REJECT_BUNDLE_INVALID,
            "a different artifact already exists at the publication target",
            detail_code="packet_publish_conflict_v1",
        )
    fd, name = tempfile.mkstemp(prefix=f".{target.name}.tmp-", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(packet.archive_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        if os.name == "posix":
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "OBLIGATIONS_SLOT_SCHEMA_VERSION",
    "PACKET_INPUTS_SCHEMA_VERSION",
    "USTAR_WRITER_ID",
    "CatalogIdentity",
    "DonorIdentity",
    "Packet",
    "PacketFile",
    "PacketInputs",
    "PacketKind",
    "PacketOrigin",
    "PacketPayload",
    "PacketRole",
    "PinnedSourcePointer",
    "ReferencePacket",
    "ReusePacket",
    "build_reference_packet",
    "build_reuse_packet",
    "load_packet",
    "member_payload_path",
    "publish_packet",
]
