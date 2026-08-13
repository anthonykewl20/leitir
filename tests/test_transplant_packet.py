from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from leitir.bts import BTSStatus
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.relocate import FileRole
from leitir.transplant import (
    BUNDLE_SCHEMA_VERSION,
    PACKET_INPUTS_SCHEMA_VERSION,
    DonorIdentity,
    PacketInputs,
    PacketKind,
    PacketOrigin,
    PacketPayload,
    PacketRole,
    PinnedSourcePointer,
    ReferencePacket,
    ReusePacket,
    build_reference_packet,
    build_reuse_packet,
    load_packet,
    member_payload_path,
    publish_packet,
)
from tests.test_bts_skeleton import FIXTURE, REPO_ROOT, _digest, _run


def _span(data: bytes, start_line: int, start_col: int, end_line: int, end_col: int) -> bytes:
    starts = [0]
    for line in data.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    return data[starts[start_line - 1] + start_col : starts[end_line - 1] + end_col]


def _inputs(result: object, kind: PacketKind) -> PacketInputs:
    bts_result = result.bts  # type: ignore[attr-defined]
    verdict = result.verdict  # type: ignore[attr-defined]
    assert bts_result.bts is not None
    artifact = bts_result.bts
    report_inputs = bts_result.report.inputs
    pointers = tuple({
        PinnedSourcePointer(
            "git",
            "example.invalid",
            "leitir/fixture",
            report_inputs.donor_commit_sha,
            item.path,
            item.blob_sha,
        )
        for item in artifact.required_files
    })
    return PacketInputs(
        PACKET_INPUTS_SCHEMA_VERSION,
        kind,
        _digest(b"accepted-selection"),
        DonorIdentity(
            report_inputs.donor_slug,
            report_inputs.donor_commit_sha,
            report_inputs.materialized_tree_hash,
        ),
        artifact.bts_digest,
        artifact.member_equivalence_digest,
        verdict.validation_digest,
        _digest(b"recipient-license-policy"),
        _digest(b"bundled-license-policy-d1-slot"),
        _digest(b"packet-policy"),
        pointers,
    )


def _payloads(root: Path, result: object) -> tuple[PacketPayload, ...]:
    bts_result = result.bts  # type: ignore[attr-defined]
    relocation = result.relocation  # type: ignore[attr-defined]
    assert bts_result.bts is not None
    payloads: list[PacketPayload] = []
    for member in bts_result.bts.members:
        source = member.source
        data = (root / source.path).read_bytes()
        payloads.append(
            PacketPayload(
                member_payload_path(member),
                PacketRole.MEMBER,
                PacketOrigin.DONOR,
                _span(data, source.start_line, source.start_col, source.end_line, source.end_col),
            )
        )
    mapping = {
        FileRole.SOURCE: (PacketRole.SOURCE, "staging-v1/src/", "source/"),
        FileRole.TEST_ORIGINAL: (PacketRole.TEST_ORIGINAL, "staging-v1/tests/original/", "tests/original/"),
        FileRole.TEST_REWRITTEN: (PacketRole.TEST_REWRITTEN, "staging-v1/tests/rewritten/", "tests/rewritten/"),
        FileRole.PROBE: (PacketRole.PROBE, "staging-v1/probes/", "probes/"),
        FileRole.HARNESS: (PacketRole.HARNESS, "staging-v1/harness/", "harness/"),
    }
    for item in relocation.files:
        if item.role not in mapping:
            continue
        role, old, new = mapping[item.role]
        assert item.path.startswith(old)
        origin = PacketOrigin.DONOR if role is PacketRole.TEST_ORIGINAL else PacketOrigin.GENERATED
        payloads.append(PacketPayload(new + item.path.removeprefix(old), role, origin, item.content))
    return tuple(reversed(payloads))  # construction must not observe caller order


@pytest.fixture
def complete(tmp_path: Path) -> tuple[Path, object]:
    root = tmp_path / "fixture"
    shutil.copytree(FIXTURE, root)
    result, _ = _run(root)
    return root, result


@pytest.mark.skipif(sys.platform == "win32", reason="BTS contained rerun runner aborts on Windows; tracked in #128 (validated on Linux + macOS)")
def test_reuse_packet_is_canonical_uncompressed_ustar_and_round_trips(complete: tuple[Path, object], tmp_path: Path) -> None:
    root, result = complete
    packet = build_reuse_packet(result.bts, result.verdict, inputs=_inputs(result, PacketKind.REUSE), relocation=result.relocation, payloads=_payloads(root, result))  # type: ignore[attr-defined]

    assert isinstance(packet, ReusePacket)
    assert packet.schema_version == BUNDLE_SCHEMA_VERSION
    assert packet.archive_bytes[:2] != b"\x1f\x8b"
    assert packet.archive_bytes[-1024:] == b"\0" * 1024
    assert load_packet(packet.archive_bytes) == packet
    assert packet.bundle_digest == load_packet(packet.archive_bytes).bundle_digest

    with tarfile.open(fileobj=io.BytesIO(packet.archive_bytes), mode="r:") as archive:
        members = archive.getmembers()
    assert [item.name.removesuffix("/") for item in members] == sorted(item.name.removesuffix("/") for item in members)
    assert all(item.mtime == item.uid == item.gid == 0 for item in members)
    assert all(item.uname == item.gname == "" for item in members)
    assert all(item.mode == (0o755 if item.isdir() else 0o644) for item in members)
    assert any(item.name.startswith(f"{BUNDLE_SCHEMA_VERSION}/tests/original/") for item in members)

    target = tmp_path / f"{packet.bundle_digest[7:]}.leitir-bts.tar"
    publish_packet(packet, target)
    assert target.read_bytes() == packet.archive_bytes


@pytest.mark.skipif(sys.platform == "win32", reason="BTS contained rerun runner aborts on Windows; tracked in #128 (validated on Linux + macOS)")
def test_reference_packet_is_closed_metadata_only(complete: tuple[Path, object]) -> None:
    root, result = complete
    donor_bytes = (root / "skeleton_donor/policy.py").read_bytes()
    packet = build_reference_packet(result.bts, result.verdict, inputs=_inputs(result, PacketKind.REFERENCE))  # type: ignore[attr-defined]

    assert isinstance(packet, ReferencePacket)
    assert all(item.role is PacketRole.METADATA for item in packet.files)
    assert all(not item.path.startswith(("members/", "source/", "adapters/", "tests/", "probes/", "harness/", "licenses/")) for item in packet.files)
    assert donor_bytes not in packet.archive_bytes
    for payload in _payloads(root, result):
        if payload.content:
            assert payload.content not in packet.archive_bytes
    assert load_packet(packet.archive_bytes) == packet


@pytest.mark.parametrize("status", [BTSStatus.PARTIAL, BTSStatus.REJECT])
def test_non_complete_bts_is_refused(complete: tuple[Path, object], status: BTSStatus) -> None:
    _root, result = complete
    rejected = replace(result.bts, status=status)  # type: ignore[attr-defined]
    with pytest.raises(BTSError) as failure:
        build_reference_packet(rejected, result.verdict, inputs=_inputs(result, PacketKind.REFERENCE))  # type: ignore[attr-defined]
    assert failure.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED


@pytest.mark.skipif(sys.platform == "win32", reason="BTS contained rerun runner aborts on Windows; tracked in #128 (validated on Linux + macOS)")
def test_archive_tamper_fails_closed(complete: tuple[Path, object]) -> None:
    root, result = complete
    packet = build_reuse_packet(result.bts, result.verdict, inputs=_inputs(result, PacketKind.REUSE), relocation=result.relocation, payloads=_payloads(root, result))  # type: ignore[attr-defined]
    payload = next(item.content for item in _payloads(root, result) if item.role is PacketRole.TEST_ORIGINAL and item.content)
    offset = packet.archive_bytes.index(payload)
    corrupted = bytearray(packet.archive_bytes)
    corrupted[offset] ^= 1
    with pytest.raises(BTSError) as failure:
        load_packet(bytes(corrupted))
    assert failure.value.reason is BTSRejectReason.REJECT_BUNDLE_INVALID


@pytest.mark.skipif(sys.platform == "win32", reason="BTS contained rerun runner aborts on Windows; tracked in #128 (validated on Linux + macOS)")
def test_claim_is_receipt_verification_not_end_to_end_revalidation(complete: tuple[Path, object]) -> None:
    root, result = complete
    packet = build_reuse_packet(result.bts, result.verdict, inputs=_inputs(result, PacketKind.REUSE), relocation=result.relocation, payloads=_payloads(root, result))  # type: ignore[attr-defined]
    assert b'"receipt_verification":true' in packet.bundle_json
    assert b'"end_to_end_revalidation":false' in packet.bundle_json
    assert b'"integrity_model":"integrity_not_authenticity"' in packet.bundle_json


@pytest.mark.skipif(sys.platform == "win32", reason="BTS contained rerun runner aborts on Windows; tracked in #128 (validated on Linux + macOS)")
def test_archive_bytes_are_pythonhashseed_independent() -> None:
    script = r'''
import shutil, tempfile
from pathlib import Path
from leitir.transplant import PacketKind, build_reuse_packet
from tests.test_bts_skeleton import FIXTURE, _run
from tests.test_transplant_packet import _inputs, _payloads
with tempfile.TemporaryDirectory() as value:
    root=Path(value)/"fixture"; shutil.copytree(FIXTURE, root)
    result,_=_run(root)
    packet=build_reuse_packet(result.bts,result.verdict,inputs=_inputs(result,PacketKind.REUSE),relocation=result.relocation,payloads=_payloads(root,result))
    print(packet.bundle_digest, packet.archive_bytes.hex())
'''
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(
            os.environ,
            PYTHONHASHSEED=seed,
            PYTHONPATH=os.pathsep.join((str((REPO_ROOT / "src").resolve()), str(REPO_ROOT.resolve()))),
        )
        outputs.append(subprocess.check_output((sys.executable, "-c", script), env=environment))
    assert outputs[0] == outputs[1] == outputs[2]
