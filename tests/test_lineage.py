from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from leitir.bts import _git_blob_sha
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.lineage import (
    LOCATOR_VERSION,
    DriftAlertKind,
    DriftResolution,
    LineageManifest,
    LineageMember,
    ObservedLineageMember,
    TrackedGitRef,
    check_drift,
)
from leitir.transplant import (
    BUNDLE_SCHEMA_VERSION,
    BUNDLE_V2_SCHEMA_VERSION,
    PacketKind,
    build_reference_packet,
    build_reference_packet_v2,
    load_packet,
)
from tests.test_bts_skeleton import FIXTURE, _run
from tests.test_transplant_packet import _inputs

BASE = "1" * 40
NEW = "2" * 40


def _fixture() -> tuple[LineageManifest, LineageMember]:
    data = b"def answer():\n    return 42\n"
    blob = _git_blob_sha(data)
    source = SourceRef("example/donor", BASE, "pkg/api.py", blob, 1, 0, 2, 13)
    node = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "pkg.api", "answer", "pkg/api.py:answer")
    member = LineageMember.create(node, source, data)
    tracked = TrackedGitRef("example/donor", "refs/heads/main", BASE, "fake-git", "1")
    manifest = LineageManifest.create(
        bts_digest="sha256:" + "a" * 64,
        baseline_commit_sha=BASE,
        tracked_ref=tracked,
        members=(member,),
        predecessor_bundle_digests=("sha256:" + "b" * 64,),
    )
    return manifest, member


def test_manifest_construction_serialization_round_trip_and_swhid() -> None:
    manifest, member = _fixture()

    assert LineageManifest.from_bytes(manifest.to_bytes()) == manifest
    assert member.swhid_cnt == f"swh:1:cnt:{member.source.blob_sha}"
    assert member.source.blob_sha == _git_blob_sha(b"def answer():\n    return 42\n")


def test_tracked_git_ref_rejects_pathological_invalid_ref_name() -> None:
    ref_name = "refs/tags/" + ")/" * 5000 + "*"

    with pytest.raises(ValueError, match="tracked_ref.ref_name"):
        TrackedGitRef("example/donor", ref_name, BASE, "fake-git", "1")


@pytest.mark.parametrize(
    ("resolution", "reason", "detail"),
    [
        (DriftResolution(False, True, NEW), BTSRejectReason.REJECT_MOVING_REFERENCE, "lineage_baseline_commit_unreachable_v1"),
        (DriftResolution(True, False, None), BTSRejectReason.REJECT_MOVING_REFERENCE, "lineage_tracked_ref_unreachable_v1"),
        (DriftResolution(False, False, None, repository_reachable=False), BTSRejectReason.REJECT_MOVING_REFERENCE, "lineage_baseline_commit_unreachable_v1"),
    ],
)
def test_unreachable_evidence_rejects_check(
    resolution: DriftResolution, reason: BTSRejectReason, detail: str
) -> None:
    manifest, _member = _fixture()
    report = check_drift(manifest, lambda _manifest: resolution)

    assert report.rejection_reason is reason
    assert report.detail_code == detail
    assert report.alerts == ()


def test_resolver_failure_rejects_fetch() -> None:
    manifest, _member = _fixture()

    def unavailable(_manifest: LineageManifest) -> DriftResolution:
        raise OSError("offline")

    report = check_drift(manifest, unavailable)
    assert report.rejection_reason is BTSRejectReason.REJECT_FETCH_FAILED
    assert report.detail_code == "lineage_ref_resolution_unavailable_v1"


def test_new_commit_missing_or_ambiguous_symbol_is_conservatively_changed() -> None:
    manifest, member = _fixture()
    missing = check_drift(manifest, lambda _: DriftResolution(True, True, NEW))
    duplicate = ObservedLineageMember(member.node, replace(member.source, commit_sha=NEW), member.member_bytes_sha256)
    ambiguous = check_drift(manifest, lambda _: DriftResolution(True, True, NEW, (duplicate, duplicate)))

    assert [item.kind for item in missing.alerts] == [DriftAlertKind.SYMBOLS_CHANGED]
    assert missing.alerts[0].detail_code == "lineage_symbol_missing_v1"
    assert ambiguous.alerts[0].detail_code == "lineage_symbol_ambiguous_v1"


def test_new_commit_member_span_bytes_path_or_blob_change_alerts() -> None:
    manifest, member = _fixture()
    observed_source = replace(member.source, commit_sha=NEW, path="pkg/moved.py", blob_sha="3" * 40)
    observed = ObservedLineageMember(member.node, observed_source, "sha256:" + "4" * 64)
    report = check_drift(manifest, lambda _: DriftResolution(True, True, NEW, (observed,)))

    assert [item.kind for item in report.alerts] == [DriftAlertKind.BYTES_CHANGED]
    assert report.alerts[0].observed_source == observed_source


def test_clean_drift_checks_for_stationary_and_identical_moved_ref() -> None:
    manifest, member = _fixture()
    stationary = check_drift(manifest, lambda _: DriftResolution(True, True, BASE))
    observed = ObservedLineageMember(member.node, replace(member.source, commit_sha=NEW), member.member_bytes_sha256)
    moved = check_drift(manifest, lambda _: DriftResolution(True, True, NEW, (observed,)))

    assert stationary.alerts == moved.alerts == ()
    assert stationary.rejection_reason is moved.rejection_reason is None


def test_rejected_check_does_not_mutate_or_invalidate_historical_manifest() -> None:
    manifest, _member = _fixture()
    before = manifest.to_bytes()
    report = check_drift(manifest, lambda _: DriftResolution(False, False, None, repository_reachable=False))

    assert report.rejection_reason is not None
    assert manifest.to_bytes() == before
    assert LineageManifest.from_bytes(before) == manifest


def test_forged_lineage_digest_rejects() -> None:
    manifest, _member = _fixture()
    value = json.loads(manifest.to_bytes())
    value["lineage_digest"] = "sha256:" + "0" * 64
    forged = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    with pytest.raises(BTSError) as failure:
        LineageManifest.from_bytes(forged)
    assert failure.value.reason is BTSRejectReason.REJECT_BUNDLE_INVALID


def test_lineage_digest_is_pythonhashseed_independent() -> None:
    script = "from tests.test_lineage import _fixture; import sys; sys.stdout.buffer.write(_fixture()[0].lineage_digest.encode(\"ascii\") + b\"\\n\")"
    outputs = []
    for seed in ("0", "1", "42"):
        env = dict(os.environ, PYTHONPATH="src", PYTHONHASHSEED=seed)
        outputs.append(subprocess.check_output([sys.executable, "-c", script], cwd=Path(__file__).parents[1], env=env, text=True))
    assert len(set(outputs)) == 1


def test_bundle_v2_requires_and_binds_lineage_while_v1_loads_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    shutil.copytree(FIXTURE, root)
    result, _ = _run(root)
    inputs = _inputs(result, PacketKind.REFERENCE)
    v1 = build_reference_packet(result.bts, result.verdict, inputs=inputs)
    assert load_packet(v1.archive_bytes) == v1
    assert v1.schema_version == BUNDLE_SCHEMA_VERSION

    assert result.bts.bts is not None
    artifact = result.bts.bts
    lineage_members = tuple(
        LineageMember(item.node, item.source, LOCATOR_VERSION, item.source_bytes_sha256, f"swh:1:cnt:{item.source.blob_sha}")
        for item in artifact.members
    )
    lineage = LineageManifest.create(
        bts_digest=artifact.bts_digest,
        baseline_commit_sha=inputs.donor.commit_sha,
        tracked_ref=TrackedGitRef("example/donor", "refs/heads/main", inputs.donor.commit_sha, "fake-git", "1"),
        members=lineage_members,
    )
    v2 = build_reference_packet_v2(result.bts, result.verdict, inputs=inputs, lineage=lineage)

    assert v2.schema_version == BUNDLE_V2_SCHEMA_VERSION
    assert any(item.path == "lineage.json" for item in v2.files)
    assert load_packet(v2.archive_bytes) == v2
    rejected_check = check_drift(
        lineage,
        lambda _: DriftResolution(False, False, None, repository_reachable=False),
    )
    assert rejected_check.rejection_reason is BTSRejectReason.REJECT_MOVING_REFERENCE
    assert load_packet(v2.archive_bytes) == v2

    wrong = LineageManifest.create(
        bts_digest="sha256:" + "9" * 64,
        baseline_commit_sha=inputs.donor.commit_sha,
        tracked_ref=lineage.tracked_ref,
        members=lineage.members,
    )
    with pytest.raises(BTSError) as failure:
        build_reference_packet_v2(result.bts, result.verdict, inputs=inputs, lineage=wrong)
    assert failure.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH


def test_bundle_v2_rejects_tampered_lineage_member(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    shutil.copytree(FIXTURE, root)
    result, _ = _run(root)
    inputs = _inputs(result, PacketKind.REFERENCE)
    assert result.bts.bts is not None
    artifact = result.bts.bts
    lineage = LineageManifest.create(
        bts_digest=artifact.bts_digest,
        baseline_commit_sha=inputs.donor.commit_sha,
        tracked_ref=TrackedGitRef("example/donor", "refs/heads/main", inputs.donor.commit_sha, "fake-git", "1"),
        members=tuple(
            LineageMember(item.node, item.source, LOCATOR_VERSION, item.source_bytes_sha256, f"swh:1:cnt:{item.source.blob_sha}")
            for item in artifact.members
        ),
    )
    packet = build_reference_packet_v2(result.bts, result.verdict, inputs=inputs, lineage=lineage)
    corrupted = bytearray(packet.archive_bytes)
    offset = packet.archive_bytes.index(lineage.to_bytes())
    corrupted[offset] ^= 1

    with pytest.raises(BTSError) as failure:
        load_packet(bytes(corrupted))
    assert failure.value.reason is BTSRejectReason.REJECT_BUNDLE_INVALID
