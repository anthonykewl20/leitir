"""ADR-002 S2 canonical evidence and subject-provenance gates."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools.score_engine import (
    POLICY_SCHEMA_VERSION,
    CheckMode,
    CheckPolicy,
    CheckResult,
    CheckStatus,
    CommandExecution,
    Criterion,
    DimensionPolicy,
    EvidenceArtifact,
    Policy,
    Producer,
    Profile,
    RawEvidenceProvenance,
    RunEnvelope,
    SourceSpan,
    Subject,
    canonical_json_bytes,
    canonical_patch_sha256,
    evaluate,
    policy_from_dict,
    subject_from_repository,
    untracked_inputs_sha256,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "provenance"
DIMENSIONS = (
    "engine_correctness",
    "output_effectiveness",
    "code_health",
    "test_adequacy",
    "process_supply_chain",
    "performance_operability",
)


def _test_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "LC_ALL": "C",
        }
    )
    return environment


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ("git", *argv),
        cwd=root,
        env=_test_git_environment(),
        capture_output=True,
        check=True,
    )


def _initialize_repository(root: Path, content: str = "committed\n") -> str:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "config", "user.name", "Provenance Test")
    _git(root, "config", "user.email", "provenance@example.invalid")
    (root / "tracked.txt").write_text(content, encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-q", "-m", "fixture")
    return _git(root, "rev-parse", "HEAD").stdout.decode().strip()


def _check(check_id: str, dimension: str) -> CheckPolicy:
    return CheckPolicy(
        id=check_id,
        dimension=dimension,
        weight=1,
        score_eligible=True,
        criterion=Criterion(op="gte", value=0),
        offline_mode=CheckMode.REQUIRED,
        release_mode=CheckMode.REQUIRED,
    )


def _policy(*, reverse: bool = False) -> Policy:
    check_ids = (
        "engine.provenance",
        "output.provenance",
        "code.provenance",
        "test.provenance",
        "process.provenance",
        "performance.provenance",
    )
    checks = tuple(
        _check(check_id, dimension)
        for check_id, dimension in zip(check_ids, DIMENSIONS, strict=True)
    )
    return Policy(
        schema_version=POLICY_SCHEMA_VERSION,
        id="provenance-policy-v1",
        dimensions=tuple(DimensionPolicy(id=item, weight=1) for item in DIMENSIONS),
        checks=tuple(reversed(checks)) if reverse else checks,
    )


def _artifact(
    artifact_id: str,
    content: bytes,
    *,
    reverse_sources: bool = False,
) -> EvidenceArtifact:
    sources = (
        SourceSpan("src/z.py", "a" * 40, 8, 9),
        SourceSpan("src/a.py", "b" * 40, 1, 3),
    )
    return EvidenceArtifact(
        id=artifact_id,
        path=f"evidence/{artifact_id}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
        command=CommandExecution(
            argv=("python", "-m", "fixed_collector", "--format", "json"),
            process_exit=0,
            collector_reason_code="COLLECTOR_COMPLETE",
        ),
        sources=tuple(reversed(sources)) if reverse_sources else sources,
    )


def _assessment(*, reverse: bool = False):
    evidence_items = (
        _artifact("fixture.z", b"z\n", reverse_sources=reverse),
        _artifact("fixture.a", b"a\n", reverse_sources=reverse),
    )
    check_ids = (
        "engine.provenance",
        "output.provenance",
        "code.provenance",
        "test.provenance",
        "process.provenance",
        "performance.provenance",
    )
    results = tuple(
        CheckResult(
            id=check_id,
            status=(
                CheckStatus.FAIL
                if check_id == "engine.provenance"
                else (
                    CheckStatus.UNKNOWN
                    if check_id == "output.provenance"
                    else CheckStatus.PASS
                )
            ),
            score_bps=(
                0
                if check_id == "engine.provenance"
                else (None if check_id == "output.provenance" else 10000)
            ),
            reason_code=(
                "KNOWN_FAILURE"
                if check_id == "engine.provenance"
                else (
                    "EVIDENCE_UNKNOWN"
                    if check_id == "output.provenance"
                    else "CHECK_PASSED"
                )
            ),
            exclusions=(
                (("EXCLUDED_B", 2), ("EXCLUDED_A", 1))
                if reverse
                else (("EXCLUDED_A", 1), ("EXCLUDED_B", 2))
            ),
            evidence=(
                (
                    {"value": "z.py", "kind": "source"},
                    {"value": "fixture.a", "kind": "artifact"},
                )
                if reverse
                else (
                    {"kind": "artifact", "value": "fixture.a"},
                    {"kind": "source", "value": "z.py"},
                )
            ),
        )
        for check_id in check_ids
    )
    return evaluate(
        _policy(reverse=reverse),
        tuple(reversed(results)) if reverse else results,
        profile=Profile.OFFLINE,
        subject=Subject(
            repository="https://example.invalid/café",
            commit_sha="1" * 40,
            worktree="clean",
        ),
        producer=Producer(
            name="leitir-score-engine",
            version="2",
            commit_sha="2" * 40,
        ),
        evidence=tuple(reversed(evidence_items)) if reverse else evidence_items,
    )


def _dirty_subject() -> Subject:
    patch = (FIXTURES / "dirty.patch").read_bytes()
    inputs = {
        "untracked/alpha.txt": (FIXTURES / "untracked" / "alpha.txt").read_bytes(),
        "untracked/nested/beta.json": (
            FIXTURES / "untracked" / "nested" / "beta.json"
        ).read_bytes(),
    }
    return Subject(
        repository="https://example.invalid/leitir",
        commit_sha="1" * 40,
        worktree="dirty",
        patch_sha256=canonical_patch_sha256(patch),
        untracked_sha256=untracked_inputs_sha256(inputs),
    )


def test_permuted_maps_checks_evidence_and_sources_are_byte_identical():
    forward = _assessment()
    reverse = _assessment(reverse=True)
    assert forward == reverse
    assert hash(forward) == hash(reverse)
    assert forward.to_bytes() == reverse.to_bytes()
    assert forward.digest() == reverse.digest()


def test_every_serialized_unordered_collection_is_normalized_at_construction():
    assessment = _assessment(reverse=True)
    assert [item.id for item in assessment.checks] == sorted(
        item.id for item in assessment.checks
    )
    assert [item.id for item in assessment.evidence] == sorted(
        item.id for item in assessment.evidence
    )
    assert assessment.aggregate.blockers == tuple(
        sorted(assessment.aggregate.blockers, key=lambda item: item.sort_key())
    )
    for check in assessment.checks:
        assert check.exclusions == tuple(sorted(check.exclusions))
        evidence_keys = [
            (entry["kind"], entry["value"]) for entry in check.evidence
        ]
        assert evidence_keys == sorted(evidence_keys)
    for artifact in assessment.evidence:
        assert artifact.sources == tuple(
            sorted(artifact.sources, key=lambda item: item.sort_key())
        )
    forward_policy = _policy()
    reverse_policy = _policy(reverse=True)
    assert [item.id for item in reverse_policy.checks] == sorted(
        item.id for item in reverse_policy.checks
    )
    assert forward_policy == reverse_policy
    assert hash(forward_policy) == hash(reverse_policy)

    reversed_gate = replace(
        assessment.aggregate,
        blockers=tuple(reversed(assessment.aggregate.blockers)),
    )
    assert reversed_gate == assessment.aggregate
    assert hash(reversed_gate) == hash(assessment.aggregate)


def test_canonical_json_is_compact_unescaped_utf8_and_digest_is_exact_bytes():
    assessment = _assessment()
    payload = assessment.to_bytes()
    decoded = json.loads(payload)
    assert b"\n" not in payload
    assert b": " not in payload
    assert "café".encode() in payload
    assert assessment.to_json().encode("utf-8") == payload
    assert assessment.digest() == hashlib.sha256(payload).hexdigest()
    assert decoded["producer"] == {
        "name": "leitir-score-engine",
        "version": "2",
        "commit_sha": "2" * 40,
    }
    assert decoded["policy"] == {
        "id": "provenance-policy-v1",
        "sha256": _policy().digest(),
    }


def test_different_pythonhashseed_values_produce_identical_assessment_bytes():
    probe = FIXTURES / "hashseed_probe.py"
    outputs = []
    for seed in ("1", "8675309"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, (str(REPO_ROOT), env.get("PYTHONPATH", "")))
        )
        completed = subprocess.run(
            [sys.executable, str(probe)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append(json.loads(completed.stdout))
    assert outputs[0] == outputs[1]


def test_raw_evidence_digest_and_structured_provenance_are_canonical():
    raw_path = FIXTURES / "raw-evidence.json"
    golden = json.loads((FIXTURES / "golden-digests.json").read_text(encoding="utf-8"))
    expected = golden["raw_evidence_sha256"]
    artifact = EvidenceArtifact.from_path(
        id="fixture.raw",
        path=raw_path,
        canonical_path="fixtures/raw-evidence.json",
        sha256=expected,
        command=CommandExecution(
            argv=("python", "-m", "collector"),
            process_exit=7,
            collector_reason_code="COLLECTOR_FAILED",
        ),
        sources=(SourceSpan("src/leitir/search.py", "a" * 40, 10, 12),),
    )
    decoded = artifact.to_dict()
    assert decoded["sha256"] == expected
    assert decoded["command"] == {
        "argv": ["python", "-m", "collector"],
        "process_exit": 7,
        "collector_reason_code": "COLLECTOR_FAILED",
    }
    assert decoded["sources"] == [
        {
            "path": "src/leitir/search.py",
            "blob_digest": "a" * 40,
            "start_line": 10,
            "end_line": 12,
        }
    ]


def test_strict_assessment_schema_owns_s2_provenance_objects():
    schema = json.loads(
        (REPO_ROOT / "scorecard" / "assessment-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert "evidence" in schema["required"]
    assert schema["properties"]["evidence"]["items"] == {
        "$ref": "#/$defs/evidenceArtifact"
    }
    for definition in ("evidenceArtifact", "commandExecution", "sourceSpan"):
        assert schema["$defs"][definition]["additionalProperties"] is False


def test_tampered_raw_evidence_fails_closed():
    raw = (FIXTURES / "raw-evidence.json").read_bytes()
    golden = json.loads((FIXTURES / "golden-digests.json").read_text(encoding="utf-8"))
    pinned = golden["raw_evidence_sha256"]
    with pytest.raises(ValueError, match="does not match"):
        EvidenceArtifact(
            id="fixture.raw",
            path="fixtures/raw-evidence.json",
            sha256=pinned,
            content=raw + b"tampered",
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_canonical_values_fail_closed(value):
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_json_bytes({"score_bps": value})


def test_dirty_patch_and_untracked_manifest_digests_are_golden_and_order_stable():
    golden = json.loads((FIXTURES / "golden-digests.json").read_text(encoding="utf-8"))
    patch = (FIXTURES / "dirty.patch").read_bytes()
    inputs = {
        "untracked/alpha.txt": (FIXTURES / "untracked" / "alpha.txt").read_bytes(),
        "untracked/nested/beta.json": (
            FIXTURES / "untracked" / "nested" / "beta.json"
        ).read_bytes(),
    }
    assert canonical_patch_sha256(patch) == golden["patch_sha256"]
    assert untracked_inputs_sha256(inputs) == golden["untracked_sha256"]
    assert untracked_inputs_sha256(dict(reversed(tuple(inputs.items())))) == golden[
        "untracked_sha256"
    ]


def test_dirty_subject_requires_both_digests_and_clean_subject_forbids_them():
    with pytest.raises(ValueError, match="patch_sha256"):
        Subject(
            repository="https://example.invalid/leitir",
            commit_sha="1" * 40,
            worktree="dirty",
        )
    with pytest.raises(ValueError, match="clean subject"):
        Subject(
            repository="https://example.invalid/leitir",
            commit_sha="1" * 40,
            worktree="clean",
            patch_sha256="a" * 64,
            untracked_sha256="b" * 64,
        )


def test_release_profile_rejects_dirty_subject_while_offline_accepts_it():
    policy = _policy()
    results = tuple(
        CheckResult(
            id=item.id,
            status=CheckStatus.PASS,
            score_bps=10000,
            reason_code="CHECK_PASSED",
        )
        for item in policy.checks
    )
    producer = Producer("leitir-score-engine", "2", "2" * 40)
    offline = evaluate(
        policy,
        results,
        profile=Profile.OFFLINE,
        subject=_dirty_subject(),
        producer=producer,
    )
    assert offline.subject.worktree == "dirty"
    with pytest.raises(ValueError, match="release profile requires a clean"):
        evaluate(
            policy,
            results,
            profile=Profile.RELEASE,
            subject=_dirty_subject(),
            producer=producer,
        )


def test_policy_command_field_is_rejected_as_an_enforced_unknown_field():
    raw = json.loads(
        (REPO_ROOT / "scorecard" / "policy-v1.json").read_text(encoding="utf-8")
    )
    raw["checks"][0]["command"] = ["pytest", "-q"]
    with pytest.raises(ValueError, match="check contains unknown fields: command"):
        policy_from_dict(raw)


def test_subject_git_queries_use_only_fixed_argv_and_explicit_shell_false(
    monkeypatch,
):
    calls = []

    monkeypatch.setenv("GIT_DIR", "/poison/repository.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/poison/worktree")
    monkeypatch.setenv("GIT_INDEX_FILE", "/poison/index")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.autocrlf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "rev-parse" in argv:
            stdout = b"1" * 40 + b"\n"
        elif "status" in argv:
            stdout = b" M tracked.txt\0"
        elif "diff" in argv:
            stdout = b"canonical patch"
        elif "ls-files" in argv:
            stdout = b""
        else:  # pragma: no cover - demonstrates there is no caller argv path
            raise AssertionError(f"unexpected fixed command: {argv!r}")
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    subject = subject_from_repository(
        FIXTURES,
        repository="https://example.invalid/leitir",
    )
    assert subject.worktree == "dirty"
    assert len(calls) == 4
    assert all(isinstance(argv, tuple) for argv, _ in calls)
    assert all(kwargs["shell"] is False for _, kwargs in calls)
    assert all(kwargs["check"] is False for _, kwargs in calls)
    for _, kwargs in calls:
        environment = kwargs["env"]
        assert "GIT_DIR" not in environment
        assert "GIT_WORK_TREE" not in environment
        assert "GIT_INDEX_FILE" not in environment
        assert "GIT_CONFIG_COUNT" not in environment
        assert "GIT_CONFIG_KEY_0" not in environment
        assert "GIT_CONFIG_VALUE_0" not in environment
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
        assert environment["GIT_CONFIG_SYSTEM"] == os.devnull
        assert environment["GIT_ATTR_NOSYSTEM"] == "1"
        assert environment["LC_ALL"] == "C"
    patch_argv = next(argv for argv, _ in calls if "diff" in argv)
    for pinned_config in (
        "core.autocrlf=false",
        "core.safecrlf=false",
        "core.eol=lf",
        f"core.attributesFile={os.devnull}",
        "core.filemode=true",
        "filter.lfs.clean=",
        "filter.lfs.smudge=",
        "filter.lfs.process=",
        "filter.lfs.required=false",
    ):
        assert pinned_config in patch_argv


def test_poisoned_repository_environment_cannot_redirect_subject(tmp_path, monkeypatch):
    expected_root = tmp_path / "expected"
    poison_root = tmp_path / "poison"
    expected_commit = _initialize_repository(expected_root, "expected\n")
    _initialize_repository(poison_root, "poison\n")

    monkeypatch.setenv("GIT_DIR", str(poison_root / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(poison_root))
    monkeypatch.setenv("GIT_INDEX_FILE", str(poison_root / ".git" / "index"))
    subject = subject_from_repository(
        expected_root,
        repository="https://example.invalid/expected",
    )

    assert subject.commit_sha == expected_commit
    assert subject.worktree == "clean"


def test_patch_digest_is_stable_when_local_lfs_filter_would_transform_bytes(tmp_path):
    root = tmp_path / "filtered"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "config", "user.name", "Provenance Test")
    _git(root, "config", "user.email", "provenance@example.invalid")
    (root / ".gitattributes").write_text("*.txt filter=lfs\n", encoding="utf-8")
    (root / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(root, "add", ".gitattributes", "tracked.txt")
    _git(root, "commit", "-q", "-m", "fixture")
    (root / "tracked.txt").write_text("candidate\n", encoding="utf-8")

    _git(root, "config", "filter.lfs.clean", "sed s/candidate/baseline/")
    _git(root, "config", "filter.lfs.smudge", "cat")
    _git(root, "config", "filter.lfs.required", "true")
    transformed_a = _git(root, "diff", "HEAD", "--").stdout
    subject_a = subject_from_repository(
        root,
        repository="https://example.invalid/filtered",
    )

    _git(root, "config", "filter.lfs.clean", "sed s/candidate/poison-b/")
    transformed_b = _git(root, "diff", "HEAD", "--").stdout
    subject_b = subject_from_repository(
        root,
        repository="https://example.invalid/filtered",
    )

    assert transformed_a == b""
    assert b"poison-b" in transformed_b
    assert subject_a.worktree == subject_b.worktree == "dirty"
    assert subject_a.patch_sha256 == subject_b.patch_sha256


def test_missing_origin_names_repository_keyword_override(tmp_path):
    root = tmp_path / "local-only"
    _initialize_repository(root)
    with pytest.raises(ValueError, match=r"pass the repository= keyword"):
        subject_from_repository(root)


def test_volatile_run_envelope_never_changes_assessment_identity():
    assessment = _assessment()
    digest = assessment.digest()
    first = RunEnvelope(
        subject_sha256=digest,
        started_at_utc="2026-08-02T00:00:00Z",
        finished_at_utc="2026-08-02T00:00:01Z",
        duration_ns=1_000_000_000,
        host={"hostname": "builder-a", "platform": "linux"},
        log_paths=("logs/first.log",),
    )
    second = RunEnvelope(
        subject_sha256=digest,
        started_at_utc="2030-01-01T00:00:00Z",
        finished_at_utc="2030-01-01T00:10:00Z",
        duration_ns=600_000_000_000,
        host={"platform": "other", "hostname": "builder-z"},
        log_paths=("/volatile/elsewhere.log",),
    )
    assert first.to_json() != second.to_json()
    assert first.subject_sha256 == second.subject_sha256 == digest
    assert assessment.digest() == digest
    canonical = assessment.to_dict()
    assert "started_at_utc" not in canonical
    assert "duration_ns" not in canonical
    assert "log_paths" not in canonical


def test_run_envelope_copies_host_mapping_before_freezing():
    host = {"hostname": "builder-a", "platform": "linux"}
    envelope = RunEnvelope(
        subject_sha256="a" * 64,
        started_at_utc="2026-08-02T00:00:00Z",
        finished_at_utc="2026-08-02T00:00:01Z",
        duration_ns=1,
        host=host,
        log_paths=("logs/run.log",),
    )
    serialized = envelope.to_json()

    host["hostname"] = "mutated"
    host["new"] = "value"

    assert envelope.to_json() == serialized
    assert envelope.to_dict()["host"] == {
        "hostname": "builder-a",
        "platform": "linux",
    }


def test_raw_collector_digest_lives_in_run_envelope_not_assessment_identity():
    assessment = _assessment()
    raw = RawEvidenceProvenance(
        id="engine.pytest-junit",
        path=".leitir-score/evidence/adr001-offline-junit.xml",
        raw_sha256="b" * 64,
        canonical_sha256="c" * 64,
        normalization="pytest-junit-volatile-v1",
    )
    envelope = RunEnvelope(
        subject_sha256=assessment.digest(),
        started_at_utc="2026-08-02T00:00:00Z",
        finished_at_utc="2026-08-02T00:00:01Z",
        duration_ns=1,
        host={"hostname": "builder-a"},
        log_paths=(),
        raw_evidence=(raw,),
    )

    assert envelope.to_dict()["raw_evidence"] == [raw.to_dict()]
    assert raw.raw_sha256 in envelope.to_json()
    assert raw.raw_sha256 not in assessment.to_json()


def test_assessment_digest_is_pinned_by_real_fixture_bytes():
    golden = json.loads((FIXTURES / "golden-digests.json").read_text(encoding="utf-8"))
    assert _assessment().digest() == golden["assessment_sha256"]
