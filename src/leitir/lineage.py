"""Canonical source-lineage manifests and deterministic upstream drift checks.

Lineage observes a moving Git ref; it never changes the immutable BTS donor.
The resolver is deliberately injected.  This module performs no I/O, invokes no
subprocess, and treats unavailable evidence conservatively.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef

LINEAGE_SCHEMA_VERSION = "leitir-lineage-v1"
DRIFT_REPORT_SCHEMA_VERSION = "leitir-drift-report-v1"
LOCATOR_VERSION = "leitir-node-source-locator-v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _valid_ref_name(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split("/")
    if len(parts) < 3 or parts[0] != "refs" or parts[1] not in {"heads", "tags"}:
        return False
    return all(
        part and all(ord(char) > 0x20 and char not in "~^:?*\\" for char in part)
        for part in parts[2:]
    )


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8", errors="strict"
    )


def _sha(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical(value)).hexdigest()}"


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _hex40(value: object, name: str) -> str:
    if not isinstance(value, str) or _HEX40.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase 40-character Git SHA")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    value.encode("utf-8", errors="strict")
    return value


def _node_value(node: NodeId) -> dict[str, str]:
    return {
        "kind": node.kind.value,
        "location_key": node.location_key,
        "module": node.module,
        "origin": node.origin.value,
        "qualified_name": node.qualified_name,
    }


def _source_value(source: SourceRef) -> dict[str, str | int]:
    return {
        "blob_sha": source.blob_sha,
        "commit_sha": source.commit_sha,
        "end_col": source.end_col,
        "end_line": source.end_line,
        "path": source.path,
        "slug": source.slug,
        "start_col": source.start_col,
        "start_line": source.start_line,
    }


def _member_value(member: LineageMember) -> dict[str, object]:
    return {
        "locator_version": member.locator_version,
        "member_bytes_sha256": member.member_bytes_sha256,
        "node": _node_value(member.node),
        "source": _source_value(member.source),
        "swhid_cnt": member.swhid_cnt,
    }


def _member_key(member: LineageMember) -> bytes:
    return _canonical({"node": _node_value(member.node), "source": _source_value(member.source)})


@dataclass(frozen=True, slots=True)
class TrackedGitRef:
    repository_id: str
    ref_name: str
    observed_commit_sha: str
    resolver_id: str
    resolver_version: str

    def __post_init__(self) -> None:
        _text(self.repository_id, "tracked_ref.repository_id")
        if not _valid_ref_name(self.ref_name):
            raise ValueError("tracked_ref.ref_name must be a full refs/heads/... or refs/tags/... name")
        _hex40(self.observed_commit_sha, "tracked_ref.observed_commit_sha")
        _text(self.resolver_id, "tracked_ref.resolver_id")
        _text(self.resolver_version, "tracked_ref.resolver_version")


@dataclass(frozen=True, slots=True)
class LineageMember:
    node: NodeId
    source: SourceRef
    locator_version: str
    member_bytes_sha256: str
    swhid_cnt: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.node, NodeId) or not isinstance(self.source, SourceRef):
            raise ValueError("lineage member requires NodeId and SourceRef identities")
        _text(self.locator_version, "member.locator_version")
        _digest(self.member_bytes_sha256, "member.member_bytes_sha256")
        _hex40(self.source.commit_sha, "member.source.commit_sha")
        _hex40(self.source.blob_sha, "member.source.blob_sha")
        if self.swhid_cnt is not None and self.swhid_cnt != f"swh:1:cnt:{self.source.blob_sha}":
            raise ValueError("member.swhid_cnt must equal the source Git blob identity")

    @classmethod
    def create(
        cls,
        node: NodeId,
        source: SourceRef,
        member_bytes: bytes,
        *,
        locator_version: str = LOCATOR_VERSION,
        include_swhid: bool = True,
    ) -> LineageMember:
        if not isinstance(member_bytes, bytes):
            raise TypeError("member_bytes must be bytes")
        return cls(
            node,
            source,
            locator_version,
            f"sha256:{hashlib.sha256(member_bytes).hexdigest()}",
            f"swh:1:cnt:{source.blob_sha}" if include_swhid else None,
        )


@dataclass(frozen=True, slots=True)
class LineageManifest:
    schema_version: str
    bts_digest: str
    baseline_commit_sha: str
    tracked_ref: TrackedGitRef
    members: tuple[LineageMember, ...]
    predecessor_bundle_digests: tuple[str, ...]
    lineage_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != LINEAGE_SCHEMA_VERSION:
            raise ValueError("unsupported lineage schema version")
        _digest(self.bts_digest, "lineage.bts_digest")
        _hex40(self.baseline_commit_sha, "lineage.baseline_commit_sha")
        if not isinstance(self.tracked_ref, TrackedGitRef):
            raise ValueError("lineage.tracked_ref is malformed")
        if self.tracked_ref.observed_commit_sha != self.baseline_commit_sha:
            raise ValueError("tracked ref target must equal the immutable baseline at assembly")
        if not isinstance(self.members, tuple) or not all(isinstance(item, LineageMember) for item in self.members):
            raise ValueError("lineage.members must be a tuple of LineageMember records")
        ordered = tuple(sorted(self.members, key=_member_key))
        if self.members != ordered or len({_member_key(item) for item in ordered}) != len(ordered):
            raise ValueError("lineage members must be exhaustively sorted and unique")
        if not isinstance(self.predecessor_bundle_digests, tuple):
            raise ValueError("predecessor bundle digests must be a tuple")
        for item in self.predecessor_bundle_digests:
            _digest(item, "predecessor bundle digest")
        if self.predecessor_bundle_digests != tuple(sorted(set(self.predecessor_bundle_digests))):
            raise ValueError("predecessor bundle digests must be sorted and unique")
        _digest(self.lineage_digest, "lineage.lineage_digest")
        if self.lineage_digest != _sha(self._value(include_digest=False)):
            raise ValueError("lineage digest mismatch")

    @classmethod
    def create(
        cls,
        *,
        bts_digest: str,
        baseline_commit_sha: str,
        tracked_ref: TrackedGitRef,
        members: tuple[LineageMember, ...],
        predecessor_bundle_digests: tuple[str, ...] = (),
    ) -> LineageManifest:
        ordered = tuple(sorted(members, key=_member_key))
        predecessors = tuple(sorted(predecessor_bundle_digests))
        provisional = {
            "baseline_commit_sha": baseline_commit_sha,
            "bts_digest": bts_digest,
            "members": [_member_value(item) for item in ordered],
            "predecessor_bundle_digests": list(predecessors),
            "schema_version": LINEAGE_SCHEMA_VERSION,
            "tracked_ref": {
                "observed_commit_sha": tracked_ref.observed_commit_sha,
                "ref_name": tracked_ref.ref_name,
                "repository_id": tracked_ref.repository_id,
                "resolver_id": tracked_ref.resolver_id,
                "resolver_version": tracked_ref.resolver_version,
            },
        }
        return cls(LINEAGE_SCHEMA_VERSION, bts_digest, baseline_commit_sha, tracked_ref, ordered, predecessors, _sha(provisional))

    def _value(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "baseline_commit_sha": self.baseline_commit_sha,
            "bts_digest": self.bts_digest,
            "members": [_member_value(item) for item in self.members],
            "predecessor_bundle_digests": list(self.predecessor_bundle_digests),
            "schema_version": self.schema_version,
            "tracked_ref": {
                "observed_commit_sha": self.tracked_ref.observed_commit_sha,
                "ref_name": self.tracked_ref.ref_name,
                "repository_id": self.tracked_ref.repository_id,
                "resolver_id": self.tracked_ref.resolver_id,
                "resolver_version": self.tracked_ref.resolver_version,
            },
        }
        if include_digest:
            value["lineage_digest"] = self.lineage_digest
        return value

    def to_bytes(self) -> bytes:
        return _canonical(self._value())

    @classmethod
    def from_bytes(cls, data: bytes) -> LineageManifest:
        try:
            if not isinstance(data, bytes):
                raise TypeError("lineage input must be bytes")
            value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
            if _canonical(value) != data or not isinstance(value, dict) or set(value) != {
                "baseline_commit_sha", "bts_digest", "lineage_digest", "members", "predecessor_bundle_digests",
                "schema_version", "tracked_ref",
            }:
                raise ValueError("lineage manifest is noncanonical or has unknown fields")
            tracked = value["tracked_ref"]
            raw_members = value["members"]
            predecessors = value["predecessor_bundle_digests"]
            if not isinstance(tracked, dict) or set(tracked) != {
                "observed_commit_sha", "ref_name", "repository_id", "resolver_id", "resolver_version"
            } or not isinstance(raw_members, list) or not isinstance(predecessors, list):
                raise ValueError("lineage collections are malformed")
            members = tuple(_member_from_value(item) for item in raw_members)
            return cls(
                value["schema_version"], value["bts_digest"], value["baseline_commit_sha"], TrackedGitRef(**tracked),
                members, tuple(predecessors), value["lineage_digest"],
            )
        except BTSError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise BTSError(
                BTSRejectReason.REJECT_BUNDLE_INVALID,
                "lineage manifest is malformed, noncanonical, or digest-mismatched",
                detail_code="lineage_manifest_invalid_v1",
                cause=exc,
            ) from exc


class DriftAlertKind(str, Enum):  # noqa: UP042 - normative ADR contract
    SYMBOLS_CHANGED = "symbols_changed"
    BYTES_CHANGED = "bytes_changed"


@dataclass(frozen=True, slots=True)
class DriftAlert:
    kind: DriftAlertKind
    baseline_member: LineageMember
    observed_source: SourceRef | None
    observed_member_bytes_sha256: str | None
    detail_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DriftAlertKind) or not isinstance(self.baseline_member, LineageMember):
            raise ValueError("drift alert kind or baseline member is malformed")
        if self.observed_source is not None and not isinstance(self.observed_source, SourceRef):
            raise ValueError("drift alert observed source is malformed")
        if self.observed_member_bytes_sha256 is not None:
            _digest(self.observed_member_bytes_sha256, "alert observed member digest")
        _text(self.detail_code, "alert detail code")


@dataclass(frozen=True, slots=True)
class DriftReport:
    schema_version: str
    lineage_digest: str
    observed_commit_sha: str | None
    alerts: tuple[DriftAlert, ...]
    rejection_reason: BTSRejectReason | None
    detail_code: str | None
    report_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != DRIFT_REPORT_SCHEMA_VERSION:
            raise ValueError("unsupported drift report schema")
        _digest(self.lineage_digest, "report.lineage_digest")
        if self.observed_commit_sha is not None:
            _hex40(self.observed_commit_sha, "report.observed_commit_sha")
        if not isinstance(self.alerts, tuple) or not all(isinstance(item, DriftAlert) for item in self.alerts):
            raise ValueError("report alerts are malformed")
        if self.rejection_reason is not None and not isinstance(self.rejection_reason, BTSRejectReason):
            raise ValueError("report rejection reason is malformed")
        if (self.rejection_reason is None) != (self.detail_code is None):
            raise ValueError("report rejection reason and detail code must be jointly present or absent")
        if self.rejection_reason is not None and self.alerts:
            raise ValueError("a rejected drift check cannot contain alerts")
        _digest(self.report_digest, "report.report_digest")
        if self.report_digest != _sha(_report_value(self, include_digest=False)):
            raise ValueError("drift report digest mismatch")

    def to_bytes(self) -> bytes:
        return _canonical(_report_value(self))


@dataclass(frozen=True, slots=True)
class ObservedLineageMember:
    """One locator result returned from a verified materialized snapshot."""

    node: NodeId
    source: SourceRef
    member_bytes_sha256: str
    locator_version: str = LOCATOR_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.node, NodeId) or not isinstance(self.source, SourceRef):
            raise ValueError("observed member identities are malformed")
        _digest(self.member_bytes_sha256, "observed member digest")
        _text(self.locator_version, "observed locator version")


@dataclass(frozen=True, slots=True)
class DriftResolution:
    """Resolver output.  ``members`` are exact, versioned locator results."""

    baseline_commit_reachable: bool
    tracked_ref_reachable: bool
    observed_commit_sha: str | None
    members: tuple[ObservedLineageMember, ...] = ()
    repository_reachable: bool = True

    def __post_init__(self) -> None:
        if not all(type(item) is bool for item in (self.baseline_commit_reachable, self.tracked_ref_reachable, self.repository_reachable)):
            raise ValueError("resolution reachability fields must be bools")
        if self.observed_commit_sha is not None:
            _hex40(self.observed_commit_sha, "resolution.observed_commit_sha")
        if not isinstance(self.members, tuple) or not all(isinstance(item, ObservedLineageMember) for item in self.members):
            raise ValueError("resolution members are malformed")


LineageResolver = Callable[[LineageManifest], DriftResolution]


def check_drift(manifest: LineageManifest, resolver: LineageResolver) -> DriftReport:
    """Resolve and compare a tracked ref without mutating historical artifacts."""

    if not isinstance(manifest, LineageManifest) or not callable(resolver):
        raise TypeError("check_drift requires a verified manifest and callable resolver")
    try:
        resolution = resolver(manifest)
        if not isinstance(resolution, DriftResolution):
            raise TypeError("resolver returned an unsupported result")
    except Exception:
        return _report(manifest, None, (), BTSRejectReason.REJECT_FETCH_FAILED, "lineage_ref_resolution_unavailable_v1")
    if not resolution.repository_reachable or not resolution.baseline_commit_reachable:
        return _report(
            manifest, resolution.observed_commit_sha, (), BTSRejectReason.REJECT_MOVING_REFERENCE,
            "lineage_baseline_commit_unreachable_v1",
        )
    if not resolution.tracked_ref_reachable or resolution.observed_commit_sha is None:
        return _report(
            manifest, resolution.observed_commit_sha, (), BTSRejectReason.REJECT_MOVING_REFERENCE,
            "lineage_tracked_ref_unreachable_v1",
        )
    if resolution.observed_commit_sha == manifest.baseline_commit_sha:
        return _report(manifest, resolution.observed_commit_sha, (), None, None)

    alerts: list[DriftAlert] = []
    for baseline in manifest.members:
        # Complete NodeId equality plus a version-equal locator is the only proof
        # accepted here.  Name/regex/API-surface matches are intentionally absent.
        matches = tuple(
            item for item in resolution.members
            if item.node == baseline.node and item.locator_version == baseline.locator_version
        )
        if len(matches) != 1:
            alerts.append(DriftAlert(
                DriftAlertKind.SYMBOLS_CHANGED, baseline, None, None,
                "lineage_symbol_missing_v1" if not matches else "lineage_symbol_ambiguous_v1",
            ))
            continue
        observed = matches[0]
        source_changed = (
            observed.source.path != baseline.source.path
            or observed.source.blob_sha != baseline.source.blob_sha
            or (observed.source.start_line, observed.source.start_col, observed.source.end_line, observed.source.end_col)
            != (baseline.source.start_line, baseline.source.start_col, baseline.source.end_line, baseline.source.end_col)
        )
        if source_changed or observed.member_bytes_sha256 != baseline.member_bytes_sha256:
            alerts.append(DriftAlert(
                DriftAlertKind.BYTES_CHANGED, baseline, observed.source, observed.member_bytes_sha256,
                "lineage_member_bytes_changed_v1",
            ))
    alerts.sort(key=lambda item: (_member_key(item.baseline_member), item.kind.value, item.detail_code))
    return _report(manifest, resolution.observed_commit_sha, tuple(alerts), None, None)


def _report(
    manifest: LineageManifest,
    observed: str | None,
    alerts: tuple[DriftAlert, ...],
    rejection: BTSRejectReason | None,
    detail: str | None,
) -> DriftReport:
    provisional = DriftReport.__new__(DriftReport)
    object.__setattr__(provisional, "schema_version", DRIFT_REPORT_SCHEMA_VERSION)
    object.__setattr__(provisional, "lineage_digest", manifest.lineage_digest)
    object.__setattr__(provisional, "observed_commit_sha", observed)
    object.__setattr__(provisional, "alerts", alerts)
    object.__setattr__(provisional, "rejection_reason", rejection)
    object.__setattr__(provisional, "detail_code", detail)
    object.__setattr__(provisional, "report_digest", "")
    digest = _sha(_report_value(provisional, include_digest=False))
    return DriftReport(DRIFT_REPORT_SCHEMA_VERSION, manifest.lineage_digest, observed, alerts, rejection, detail, digest)


def _report_value(report: DriftReport, *, include_digest: bool = True) -> dict[str, object]:
    value: dict[str, object] = {
        "alerts": [
            {
                "baseline_member": _member_value(item.baseline_member),
                "detail_code": item.detail_code,
                "kind": item.kind.value,
                "observed_member_bytes_sha256": item.observed_member_bytes_sha256,
                "observed_source": None if item.observed_source is None else _source_value(item.observed_source),
            }
            for item in report.alerts
        ],
        "detail_code": report.detail_code,
        "lineage_digest": report.lineage_digest,
        "observed_commit_sha": report.observed_commit_sha,
        "rejection_reason": None if report.rejection_reason is None else report.rejection_reason.value,
        "schema_version": report.schema_version,
    }
    if include_digest:
        value["report_digest"] = report.report_digest
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _member_from_value(value: object) -> LineageMember:
    if not isinstance(value, dict) or set(value) != {"locator_version", "member_bytes_sha256", "node", "source", "swhid_cnt"}:
        raise ValueError("lineage member has missing or unknown fields")
    node = value["node"]
    source = value["source"]
    if not isinstance(node, dict) or set(node) != {"kind", "location_key", "module", "origin", "qualified_name"}:
        raise ValueError("lineage node is malformed")
    if not isinstance(source, dict) or set(source) != {
        "blob_sha", "commit_sha", "end_col", "end_line", "path", "slug", "start_col", "start_line"
    }:
        raise ValueError("lineage source is malformed")
    parsed_node = NodeId(NodeOrigin(node["origin"]), NodeKind(node["kind"]), node["module"], node["qualified_name"], node["location_key"])
    parsed_source = SourceRef(**source)
    return LineageMember(parsed_node, parsed_source, value["locator_version"], value["member_bytes_sha256"], value["swhid_cnt"])


__all__ = [
    "DRIFT_REPORT_SCHEMA_VERSION", "LINEAGE_SCHEMA_VERSION", "LOCATOR_VERSION", "DriftAlert", "DriftAlertKind",
    "DriftReport", "DriftResolution", "LineageManifest", "LineageMember", "LineageResolver",
    "ObservedLineageMember", "TrackedGitRef", "check_drift",
]
