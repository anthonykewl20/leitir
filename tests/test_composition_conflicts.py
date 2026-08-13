"""Dependency-composition conflict matrix coverage."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import replace

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.composition import (
    CandidateDependencyEvidence,
    ClosureCompleteness,
    CompatibilityStatus,
    CompositionCandidateRef,
    CompositionEligibilityStatus,
    ConflictKind,
    compose,
    evaluate_eligibility,
)
from leitir.lockfiles import DependencyManifestPolicy, VerifiedManifestBytes

_DIGEST = "sha256:" + "1" * 64
_POLICY = DependencyManifestPolicy(("package-lock.json",))


def _key(name: str) -> tuple[str | int, ...]:
    return (name, "a" * 40, "x.py", "b" * 40, 1, 0, 1, 1, "schema", "function", name, "ast", "1", "rule", "1", _DIGEST)


def _ref(name: str) -> CompositionCandidateRef:
    return CompositionCandidateRef(_key(name), _DIGEST, _DIGEST, _DIGEST)


def _manifest(version: str, *, content: bytes | None = None) -> tuple[VerifiedManifestBytes, ...]:
    body = content or ('{"lockfileVersion":3,"packages":{"node_modules/shared":{"version":"' + version + '"}}}').encode()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    return (VerifiedManifestBytes("package-lock.json", "dependency", len(body), digest, body),)


def _compose(versions: tuple[str, str] = ("1.0.0", "1.0.0")):
    recipient, candidate = _ref("recipient"), _ref("candidate")
    return compose("recipient-project", recipient, _manifest(versions[0]), (candidate,), {candidate.candidate_key: _manifest(versions[1])}, _POLICY, _DIGEST)


def test_happy_path_matrix_and_equal_declarations_accept() -> None:
    matrix, eligibility = _compose()
    assert matrix.conflicts == ()
    assert len(matrix.dependencies) == 2
    assert eligibility.status is CompositionEligibilityStatus.ACCEPT


def test_version_clash_rejects() -> None:
    matrix, eligibility = _compose(("1.0.0", "2.0.0"))
    assert [(item.kind, item.status) for item in matrix.conflicts] == [(ConflictKind.VERSION_CLASH, CompatibilityStatus.INCOMPATIBLE)]
    assert eligibility.status is CompositionEligibilityStatus.REJECT


def test_direct_only_is_indeterminate_and_unknown_cell_is_not_pass() -> None:
    policy = DependencyManifestPolicy(("requirements.txt",))
    body = b"shared==1.0.0\n"
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    files = (VerifiedManifestBytes("requirements.txt", "dependency", len(body), digest, body),)
    recipient, candidate = _ref("recipient"), _ref("candidate")
    matrix, eligibility = compose("recipient-project", recipient, files, (candidate,), {candidate.candidate_key: files}, policy, _DIGEST)
    assert all(item.status is CompatibilityStatus.UNKNOWN for item in matrix.conflicts)
    assert eligibility.status is CompositionEligibilityStatus.INDETERMINATE


def test_tampered_manifest_fails_closed() -> None:
    recipient, candidate = _ref("recipient"), _ref("candidate")
    tampered = replace(_manifest("1.0.0")[0], content=b"tampered")
    with pytest.raises(BTSError) as caught:
        compose("recipient-project", recipient, (tampered,), (candidate,), {candidate.candidate_key: _manifest("1.0.0")}, _POLICY, _DIGEST)
    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert caught.value.evidence.detail_code == "composition_input_missing_v1"


def test_matrix_digest_is_deterministic_across_candidate_orderings() -> None:
    recipient, first, second = _ref("recipient"), _ref("a"), _ref("b")
    files = {first.candidate_key: _manifest("1.0.0"), second.candidate_key: _manifest("1.0.0")}
    one, _ = compose("recipient-project", recipient, _manifest("1.0.0"), (first, second), files, _POLICY, _DIGEST)
    two, _ = compose("recipient-project", recipient, _manifest("1.0.0"), (second, first), dict(reversed(tuple(files.items()))), _POLICY, _DIGEST)
    assert one.matrix_digest == two.matrix_digest
    assert one == two


def test_composition_digests_are_hash_seed_independent() -> None:
    script = (
        "from tests.test_composition_conflicts import _compose; "
        "matrix, eligibility = _compose(); "
        "import sys; sys.stdout.buffer.write((matrix.matrix_digest + '\\n' + eligibility.eligibility_digest + '\\n').encode('utf-8'))"
    )
    expected_matrix, expected_eligibility = _compose()
    expected = f"{expected_matrix.matrix_digest}\n{expected_eligibility.eligibility_digest}\n".encode("utf-8")
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = "src"
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
            env=environment,
            check=True,
            capture_output=True,
        )
        assert result.stdout == expected


def test_missing_candidate_closure_rejected() -> None:
    recipient, first, second = _ref("recipient"), _ref("a"), _ref("b")
    with pytest.raises(BTSError) as caught:
        compose(
            "recipient-project",
            recipient,
            _manifest("1.0.0"),
            (first, second),
            {first.candidate_key: _manifest("1.0.0")},
            _POLICY,
            _DIGEST,
        )
    assert caught.value.evidence.detail_code == "composition_input_missing_v1"


def test_unknown_completeness_is_indeterminate_not_accept(monkeypatch: pytest.MonkeyPatch) -> None:
    from leitir import composition

    recipient, candidate = _ref("recipient"), _ref("candidate")

    def unknown_closure(subject, files, policy):
        del files, policy
        evidence = CandidateDependencyEvidence(
            subject,
            "npm",
            "shared",
            "1.0.0",
            None,
            ClosureCompleteness.UNKNOWN,
            "package-lock.json",
            _DIGEST,
        )
        return (evidence,), ((evidence.ecosystem, evidence.source_path, evidence.source_digest),)

    monkeypatch.setattr(composition, "_closure_evidence", unknown_closure)
    matrix, eligibility = compose(
        "recipient-project",
        recipient,
        _manifest("1.0.0"),
        (candidate,),
        {candidate.candidate_key: _manifest("1.0.0")},
        _POLICY,
        _DIGEST,
    )
    assert eligibility.status is CompositionEligibilityStatus.INDETERMINATE
    assert eligibility.status is not CompositionEligibilityStatus.ACCEPT
    assert any(
        item.status is CompatibilityStatus.UNKNOWN
        and item.detail_code == "composition_transitive_closure_unknown_v1"
        for item in matrix.conflicts
    )


def test_duplicate_candidate_key_rejected() -> None:
    recipient, candidate = _ref("recipient"), _ref("candidate")
    with pytest.raises(BTSError, match="duplicated"):
        compose("recipient-project", recipient, _manifest("1.0.0"), (candidate, candidate), {candidate.candidate_key: _manifest("1.0.0")}, _POLICY, _DIGEST)


def test_mismatched_matrix_digest_rejected() -> None:
    matrix, _ = _compose()
    with pytest.raises(BTSError) as caught:
        evaluate_eligibility(replace(matrix, matrix_digest=_DIGEST))
    assert caught.value.evidence.detail_code == "composition_input_missing_v1"


def test_omitted_known_clash_rejected() -> None:
    matrix, _ = _compose(("1.0.0", "2.0.0"))
    without_clash = replace(matrix, conflicts=(), matrix_digest="")
    from leitir.composition import _digest

    without_clash = replace(without_clash, matrix_digest=_digest(without_clash, omit=frozenset({"matrix_digest"})))
    with pytest.raises(BTSError) as caught:
        evaluate_eligibility(without_clash)
    assert caught.value.evidence.detail_code == "composition_input_missing_v1"
