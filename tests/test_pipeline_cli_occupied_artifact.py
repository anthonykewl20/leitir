from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from enum import Enum

import pytest

from leitir.bts import BTSStatus, compute_bts
from leitir.bts_errors import BTSError
from leitir.composition import CompositionCandidateRef, compose
from leitir.lockfiles import DependencyManifestPolicy, VerifiedManifestBytes
from leitir.pipeline_cli import occupied_validate, occupied_validate_artifact
from leitir.project_profile import RecipientInputManifest, RecipientManifestEntry
from leitir.relocate import ModuleMap
from tests.test_bts_occupied import _baseline, _policy, _rerun
from tests.test_bts_walk import _budget, _fixture
from tests.test_bts_walk import _policy as bts_policy


def _digest(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def _artifact() -> dict[str, object]:
    snapshot, seed, graph = _fixture()
    result = compute_bts(snapshot, seed, graph, _budget(), bts_policy())
    assert result.status is BTSStatus.COMPLETE and result.bts is not None
    manifest = RecipientInputManifest.create("recipient", (RecipientManifestEntry.from_bytes("src/recipient.py", "source", b"recipient_only = 1\n"),))
    recipient = CompositionCandidateRef(("recipient",), _digest(b"recipient-bts"), _digest(b"recipient-manifest"), _digest(b"recipient-graph"))
    candidate = CompositionCandidateRef(("candidate",), result.bts.bts_digest, _digest(b"candidate-manifest"), _digest(b"candidate-graph"))
    lock = b'{"lockfileVersion":3,"packages":{"node_modules/shared":{"version":"1"}}}'
    dependency = (VerifiedManifestBytes("package-lock.json", "dependency", len(lock), _digest(lock), lock),)
    matrix, _ = compose("recipient-project", recipient, dependency, (candidate,), {candidate.candidate_key: dependency}, DependencyManifestPolicy(("package-lock.json",)), _digest(b"conflict-policy"))
    policy = _policy(conflict=matrix.policy_digest)
    baseline = _baseline(policy, manifest.manifest_digest)
    rerun = _rerun(policy, manifest.manifest_digest, baseline.outcomes, bts_digest=result.bts.bts_digest)
    mapping = ModuleMap.from_pairs(*((module, "relocated." + module) for module in sorted({member.node.module for member in result.bts.members})))
    return {
        "schema_version": "leitir-occupied-validate-input-v1",
        "policy": _json_value(policy),
        "recipient_manifest": {"project_root_identity": manifest.project_root_identity, "manifest_version": manifest.manifest_version, "entries": [{"path": entry.path, "role": entry.role, "content": entry.content.decode("utf-8")} for entry in manifest.entries]},
        "bts_report": result.report.to_bytes().decode("utf-8"),
        "module_map": [[entry.donor, entry.recipient] for entry in mapping.entries],
        "matrix": _json_value(matrix),
        "recipient_subject": "recipient-project",
        "candidate": _json_value(candidate),
        "baseline": _json_value(baseline),
        "occupied_rerun": _json_value(rerun),
        "test_set_digest": baseline.test_set_digest,
        "runner_closure_digest": baseline.runner_closure_digest,
        "config_closure_digest": baseline.config_closure_digest,
    }


def _bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_occupied_validate_artifact_happy_path_and_tamper_matrix() -> None:
    artifact = _artifact()
    summary = occupied_validate(_bytes(artifact))
    assert summary["status"] == "complete"

    matrix = artifact["matrix"]
    assert isinstance(matrix, dict)
    matrix["policy_digest"] = _digest(b"stale-policy")
    with pytest.raises(BTSError) as caught:
        occupied_validate_artifact(_bytes(artifact))
    assert caught.value.evidence.detail_code == "occupied_conflict_matrix_identity_v1"


def test_occupied_validate_artifact_rejects_stale_rerun_and_collision() -> None:
    stale = _artifact()
    rerun = stale["occupied_rerun"]
    assert isinstance(rerun, dict)
    rerun["bts_digest"] = _digest(b"stale")
    # The stale content digest is rejected by the receipt's own validator.
    with pytest.raises(BTSError) as caught:
        occupied_validate_artifact(_bytes(stale))
    assert caught.value.evidence.detail_code == "pipeline_cli_occupied_artifact_v1"

    collision = _artifact()
    mapping = collision["module_map"]
    assert isinstance(mapping, list) and mapping
    mapping[0][1] = "recipient"
    with pytest.raises(BTSError) as collision_caught:
        occupied_validate_artifact(_bytes(collision))
    assert collision_caught.value.evidence.detail_code in {"occupied_binding_collision_v1", "occupied_module_collision_v1"}
