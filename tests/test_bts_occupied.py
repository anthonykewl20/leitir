"""ADR-0017 occupied-recipient validation gate coverage."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import replace

import pytest

from leitir.bts import BTS, BTSDisposition, MemberEvidence
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.composition import CompositionCandidateRef, compose
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.lockfiles import DependencyManifestPolicy, VerifiedManifestBytes
from leitir.occupied import (
    OccupiedAttachmentPolicy,
    OccupiedCorpus,
    OccupiedCorpusCase,
    OccupiedRecipientProfile,
    OccupiedRerunEvidence,
    RecipientBaselineEvidence,
    derive_recipient_binding_inventory,
    run_occupied_corpus_gate,
    validate_collisions,
    validate_conflict_matrix,
    validate_recipient_parity,
)
from leitir.project_profile import RECIPIENT_MANIFEST_SCHEMA, RecipientInputManifest, RecipientManifestEntry
from leitir.relocate import ModuleMap
from leitir.rerun import TestOutcome as Outcome
from leitir.rerun import TestOutcomeEvidence as OutcomeEvidence

_D = "sha256:" + "1" * 64


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _policy(*, conflict: str = _D, corpus: str = _D) -> OccupiedAttachmentPolicy:
    return OccupiedAttachmentPolicy.pin(
        "leitir-maintainers",
        "occupied-v1",
        "1",
        ("python",),
        RECIPIENT_MANIFEST_SCHEMA,
        "python-ast-exhaustive",
        "1",
        _D,
        conflict,
        _digest(b"baseline-mount"),
        _digest(b"occupied-mount"),
        _digest(b"baseline-policy"),
        _digest(b"occupied-policy"),
        corpus,
    )


def _manifest(*entries: tuple[str, str, bytes]) -> RecipientInputManifest:
    return RecipientInputManifest.create(
        "recipient",
        tuple(RecipientManifestEntry.from_bytes(path, role, content) for path, role, content in entries),
    )


def _bts(name: str = "occupied") -> BTS:
    source = SourceRef("donor/repo", "a" * 40, "donor/mod.py", "b" * 40, 1, 0, 2, 0)
    node = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "donor.mod", f"donor.mod.{name}", "location")
    member = MemberEvidence(node, source, _digest(b"def occupied():\n    pass\n"), BTSDisposition.INCLUDE)
    return BTS("leitir-bts-v1", node, (member,), (), (), (), _D, _D)


def _outcome(name: str = "test_ok", outcome: Outcome = Outcome.PASS) -> OutcomeEvidence:
    test_id = f"test_recipient.py::{name}::-"
    return OutcomeEvidence(test_id, outcome, "fixture_result_v1", _digest((test_id + outcome.value).encode()))


def _baseline(
    policy: OccupiedAttachmentPolicy,
    manifest_digest: str,
    execute=lambda: (_outcome(),),
) -> RecipientBaselineEvidence:
    return RecipientBaselineEvidence.qualify_fixture(
        recipient_manifest_digest=manifest_digest,
        test_set_digest=_digest(b"tests"),
        runner_closure_digest=_digest(b"runner"),
        config_closure_digest=_digest(b"config"),
        mount_plan_digest=policy.recipient_baseline_mount_plan_digest,
        execution_policy_digest=policy.recipient_baseline_execution_policy_digest,
        execute=execute,
    )


def _rerun(policy: OccupiedAttachmentPolicy, manifest_digest: str, outcomes: tuple[OutcomeEvidence, ...], *, bts_digest: str = _D) -> OccupiedRerunEvidence:
    return OccupiedRerunEvidence.record_fixture(
        recipient_manifest_digest=manifest_digest,
        bts_digest=bts_digest,
        test_set_digest=_digest(b"tests"),
        runner_closure_digest=_digest(b"runner"),
        config_closure_digest=_digest(b"config"),
        mount_plan_digest=policy.occupied_rerun_mount_plan_digest,
        execution_policy_digest=policy.occupied_rerun_execution_policy_digest,
        outcomes=outcomes,
    )


def _assert_detail(caught: pytest.ExceptionInfo[BTSError], reason: BTSRejectReason, detail: str) -> None:
    assert caught.value.reason is reason
    assert caught.value.evidence.detail_code == detail


def test_strict_inventory_extracts_unused_nested_and_module_bindings() -> None:
    manifest = _manifest(
        ("src/app/service.py", "source", b"UNUSED = 1\nclass Worker:\n    def hidden(self):\n        return 1\n"),
        ("tests/test_service.py", "test", b"def test_ok(): pass\n"),
    )
    inventory = derive_recipient_binding_inventory(manifest, _policy())
    assert [item.qualified_name for item in inventory.bindings] == [
        "app.service.UNUSED",
        "app.service.Worker",
        "app.service.Worker.hidden",
    ]
    assert inventory.module_paths == ("app/service.py",)


@pytest.mark.parametrize(
    ("entry", "detail"),
    [
        (("src/app.py", "source", b"def broken(:\n"), "occupied_inventory_parse_failed_v1"),
        (("src/app.js", "source", b"const value = 1;\n"), "occupied_inventory_unsupported_language_v1"),
    ],
)
def test_strict_inventory_rejects_parse_and_language_failures(entry: tuple[str, str, bytes], detail: str) -> None:
    with pytest.raises(BTSError) as caught:
        derive_recipient_binding_inventory(_manifest(entry), _policy())
    assert caught.value.evidence.detail_code == detail


def test_strict_inventory_rejects_omitted_source_and_duplicate_identity() -> None:
    with pytest.raises(BTSError) as absent:
        derive_recipient_binding_inventory(_manifest(("README.md", "documentation", b"x")), _policy())
    _assert_detail(absent, BTSRejectReason.REJECT_UNDER_COLLECTION, "occupied_inventory_source_omitted_v1")
    with pytest.raises(BTSError) as duplicate:
        derive_recipient_binding_inventory(_manifest(("src/app.py", "source", b"value = 1\nvalue = 2\n")), _policy())
    _assert_detail(duplicate, BTSRejectReason.REJECT_DUPLICATE_RESULT, "occupied_inventory_duplicate_binding_v1")


def test_strict_inventory_rejects_declared_bytes_mismatch() -> None:
    manifest = _manifest(("src/app.py", "source", b"value = 1\n"))
    entry = replace(manifest.entries[0], byte_length=0, sha256=_D)
    malformed = replace(manifest, entries=(entry,))
    with pytest.raises(BTSError) as caught:
        derive_recipient_binding_inventory(malformed, _policy())
    _assert_detail(caught, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "occupied_inventory_manifest_mismatch_v1")


def test_any_binding_overlap_rejects_even_when_symbol_is_unused() -> None:
    inventory = derive_recipient_binding_inventory(
        _manifest(("src/recipient/mod.py", "source", b"def occupied():\n    return 'unused'\n")),
        _policy(),
    )
    with pytest.raises(BTSError) as caught:
        validate_collisions(inventory, _bts(), ModuleMap.from_pairs(("donor.mod", "recipient.mod")), recipient_manifest_digest=inventory.recipient_manifest_digest, bts_digest=_D)
    _assert_detail(caught, BTSRejectReason.REJECT_UNRESOLVED_EDGE, "occupied_binding_collision_v1")


@pytest.mark.parametrize("recipient", [b"async def occupied(): pass\n", b"class occupied: pass\n"])
def test_cross_kind_same_name_collision_has_deterministic_first_module_detail(recipient: bytes) -> None:
    inventory = derive_recipient_binding_inventory(_manifest(("src/recipient/mod.py", "source", recipient)), _policy())
    with pytest.raises(BTSError) as caught:
        validate_collisions(inventory, _bts(), ModuleMap.from_pairs(("donor.mod", "recipient.mod")), recipient_manifest_digest=inventory.recipient_manifest_digest, bts_digest=_D)
    # Different kinds cannot share a collision key; the proven-superset module
    # check therefore supplies the first deterministic rejection.
    _assert_detail(caught, BTSRejectReason.REJECT_UNRESOLVED_EDGE, "occupied_module_collision_v1")


def test_module_path_collision_rejects_independently() -> None:
    inventory = derive_recipient_binding_inventory(
        _manifest(("src/recipient/mod.py", "source", b"recipient_only = 1\n")),
        _policy(),
    )
    with pytest.raises(BTSError) as caught:
        validate_collisions(inventory, _bts("donor_only"), ModuleMap.from_pairs(("donor.mod", "recipient.mod")), recipient_manifest_digest=inventory.recipient_manifest_digest, bts_digest=_D)
    _assert_detail(caught, BTSRejectReason.REJECT_UNRESOLVED_EDGE, "occupied_module_collision_v1")

    prefix_inventory = derive_recipient_binding_inventory(
        _manifest(("src/recipient.py", "source", b"recipient_only = 1\n")),
        _policy(),
    )
    with pytest.raises(BTSError) as prefix:
        validate_collisions(prefix_inventory, _bts("donor_only"), ModuleMap.from_pairs(("donor.mod", "recipient.child")), recipient_manifest_digest=prefix_inventory.recipient_manifest_digest, bts_digest=_D)
    _assert_detail(prefix, BTSRejectReason.REJECT_UNRESOLVED_EDGE, "occupied_module_collision_v1")


def _key(name: str) -> tuple[str | int, ...]:
    return (name, "a" * 40, "x.py", "b" * 40, 1, 0, 1, 1, "schema", "function", name, "ast", "1", "rule", "1", _D)


def _ref(name: str) -> CompositionCandidateRef:
    return CompositionCandidateRef(_key(name), _D, _D, _D)


def _dependency(version: str) -> tuple[VerifiedManifestBytes, ...]:
    body = ('{"lockfileVersion":3,"packages":{"node_modules/shared":{"version":"' + version + '"}}}').encode()
    return (VerifiedManifestBytes("package-lock.json", "dependency", len(body), _digest(body), body),)


def _matrix(versions: tuple[str, str] = ("1", "1")):
    recipient, candidate = _ref("recipient"), _ref("candidate")
    matrix, _ = compose(
        "recipient-project",
        recipient,
        _dependency(versions[0]),
        (candidate,),
        {candidate.candidate_key: _dependency(versions[1])},
        DependencyManifestPolicy(("package-lock.json",)),
        _digest(b"conflict-policy"),
    )
    return matrix, candidate


def test_conflict_matrix_absent_and_identity_mismatch_reject() -> None:
    matrix, candidate = _matrix()
    policy = _policy(conflict=matrix.policy_digest)
    with pytest.raises(BTSError) as absent:
        validate_conflict_matrix(None, policy=policy, recipient_subject="recipient-project", candidate=candidate)
    _assert_detail(absent, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_conflict_matrix_absent_v1")
    with pytest.raises(BTSError) as mismatch:
        validate_conflict_matrix(matrix, policy=policy, recipient_subject="other", candidate=candidate)
    _assert_detail(mismatch, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_conflict_matrix_identity_v1")
    with pytest.raises(BTSError) as policy_mismatch:
        validate_conflict_matrix(matrix, policy=_policy(conflict=_digest(b"wrong")), recipient_subject="recipient-project", candidate=candidate)
    _assert_detail(policy_mismatch, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_conflict_matrix_identity_v1")
    with pytest.raises(BTSError) as candidate_mismatch:
        validate_conflict_matrix(matrix, policy=policy, recipient_subject="recipient-project", candidate=_ref("other"))
    _assert_detail(candidate_mismatch, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_conflict_matrix_identity_v1")


def test_conflict_matrix_hard_row_rejects_before_attachment() -> None:
    matrix, candidate = _matrix(("1", "2"))
    with pytest.raises(BTSError) as caught:
        validate_conflict_matrix(
            matrix,
            policy=_policy(conflict=matrix.policy_digest),
            recipient_subject="recipient-project",
            candidate=candidate,
        )
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_conflict_matrix_blocked_v1")


def test_baseline_requires_zero_failures_and_two_identical_runs() -> None:
    policy = _policy()
    calls = 0

    def flaky() -> tuple[OutcomeEvidence, ...]:
        nonlocal calls
        calls += 1
        return (_outcome(f"test_{calls}"),)

    with pytest.raises(BTSError) as unstable:
        _baseline(policy, _D, flaky)
    _assert_detail(unstable, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_baseline_nondeterministic_v1")
    assert calls == 2
    with pytest.raises(BTSError) as failed:
        _baseline(policy, _D, lambda: (_outcome(outcome=Outcome.FAIL),))
    _assert_detail(failed, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_baseline_nonzero_failures_v1")


def test_fixture_baseline_is_qualified_and_missing_baseline_rejects() -> None:
    policy = _policy()
    baseline = _baseline(policy, _D)
    assert baseline.status == "qualified"
    with pytest.raises(BTSError) as missing:
        validate_recipient_parity(
            None,  # type: ignore[arg-type]
            _rerun(policy, _D, baseline.outcomes),
            policy=policy,
            recipient_manifest_digest=_D,
            bts_digest=_D,
            test_set_digest=_digest(b"tests"),
            runner_closure_digest=_digest(b"runner"),
            config_closure_digest=_digest(b"config"),
        )
    _assert_detail(missing, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_baseline_missing_v1")


def test_exact_occupied_parity_rejects_count_outcome_and_stale_deltas() -> None:
    policy = _policy()
    baseline = _baseline(policy, _D)
    common = dict(
        policy=policy,
        recipient_manifest_digest=_D,
        bts_digest=_D,
        test_set_digest=_digest(b"tests"),
        runner_closure_digest=_digest(b"runner"),
        config_closure_digest=_digest(b"config"),
    )
    validate_recipient_parity(baseline, _rerun(policy, _D, baseline.outcomes), **common)
    for changed in ((), (_outcome(outcome=Outcome.SKIP),)):
        with pytest.raises(BTSError) as delta:
            validate_recipient_parity(baseline, _rerun(policy, _D, changed), **common)
        _assert_detail(delta, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_exact_parity_failed_v1")
    with pytest.raises(BTSError) as stale:
        validate_recipient_parity(baseline, _rerun(policy, _D, baseline.outcomes), **{**common, "recipient_manifest_digest": _digest(b"new")})
    _assert_detail(stale, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_baseline_stale_v1")


def test_replayed_bare_parity_outcomes_reject() -> None:
    policy = _policy()
    baseline = _baseline(policy, _D)
    with pytest.raises(BTSError) as caught:
        validate_recipient_parity(
            baseline,
            baseline.outcomes,  # type: ignore[arg-type] -- a replayed legacy payload
            policy=policy,
            recipient_manifest_digest=_D,
            bts_digest=_D,
            test_set_digest=_digest(b"tests"),
            runner_closure_digest=_digest(b"runner"),
            config_closure_digest=_digest(b"config"),
        )
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_rerun_receipt_missing_v1")


def test_forged_baseline_and_inventory_digests_reject() -> None:
    policy = _policy()
    baseline = _baseline(policy, _D)
    forged_baseline = object.__new__(RecipientBaselineEvidence)
    for field in baseline.__dataclass_fields__:
        object.__setattr__(forged_baseline, field, getattr(baseline, field))
    object.__setattr__(forged_baseline, "evidence_digest", _D)
    with pytest.raises(BTSError) as caught:
        validate_recipient_parity(
            forged_baseline,
            _rerun(policy, _D, baseline.outcomes),
            policy=policy,
            recipient_manifest_digest=_D,
            bts_digest=_D,
            test_set_digest=_digest(b"tests"),
            runner_closure_digest=_digest(b"runner"),
            config_closure_digest=_digest(b"config"),
        )
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_baseline_malformed_v1")
    inventory = derive_recipient_binding_inventory(_manifest(("src/app.py", "source", b"value = 1\n")), policy)
    forged_inventory = object.__new__(type(inventory))
    for field in inventory.__dataclass_fields__:
        object.__setattr__(forged_inventory, field, getattr(inventory, field))
    object.__setattr__(forged_inventory, "inventory_digest", _D)
    with pytest.raises(BTSError) as inventory_error:
        validate_collisions(forged_inventory, _bts(), ModuleMap.from_pairs(("donor.mod", "new.mod")), recipient_manifest_digest=inventory.recipient_manifest_digest, bts_digest=_D)
    _assert_detail(inventory_error, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "occupied_inventory_digest_mismatch_v1")


def test_forged_rerun_evidence_digest_rejects() -> None:
    policy = _policy()
    baseline = _baseline(policy, _D)
    rerun = _rerun(policy, _D, baseline.outcomes)
    forged_rerun = object.__new__(OccupiedRerunEvidence)
    for field in rerun.__dataclass_fields__:
        object.__setattr__(forged_rerun, field, getattr(rerun, field))
    object.__setattr__(forged_rerun, "evidence_digest", _D)
    with pytest.raises(BTSError) as caught:
        validate_recipient_parity(
            baseline,
            forged_rerun,
            policy=policy,
            recipient_manifest_digest=_D,
            bts_digest=_D,
            test_set_digest=_digest(b"tests"),
            runner_closure_digest=_digest(b"runner"),
            config_closure_digest=_digest(b"config"),
        )
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_rerun_receipt_malformed_v1")


def test_rerun_receipt_binding_mismatch_rejects() -> None:
    policy = _policy()
    baseline = _baseline(policy, _D)
    with pytest.raises(BTSError) as caught:
        validate_recipient_parity(
            baseline,
            _rerun(policy, _D, baseline.outcomes, bts_digest=_digest(b"different-bts")),
            policy=policy,
            recipient_manifest_digest=_D,
            bts_digest=_D,
            test_set_digest=_digest(b"tests"),
            runner_closure_digest=_digest(b"runner"),
            config_closure_digest=_digest(b"config"),
        )
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_rerun_receipt_binding_mismatch_v1")


def test_collision_bts_digest_mismatch_rejects() -> None:
    inventory = derive_recipient_binding_inventory(_manifest(("src/app.py", "source", b"value = 1\n")), _policy())
    with pytest.raises(BTSError) as caught:
        validate_collisions(
            inventory,
            _bts(),
            ModuleMap.from_pairs(("donor.mod", "new.mod")),
            recipient_manifest_digest=inventory.recipient_manifest_digest,
            bts_digest=_digest(b"different-bts"),
        )
    _assert_detail(caught, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "occupied_collision_attachment_mismatch_v1")


def test_stale_manifest_inventory_rejects_before_collision_check() -> None:
    inventory = derive_recipient_binding_inventory(_manifest(("src/app.py", "source", b"value = 1\n")), _policy())
    with pytest.raises(BTSError) as caught:
        validate_collisions(
            inventory,
            _bts(),
            ModuleMap.from_pairs(("donor.mod", "new.mod")),
            recipient_manifest_digest=_digest(b"new-recipient"),
            bts_digest=_D,
        )
    _assert_detail(caught, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "occupied_collision_attachment_mismatch_v1")


def test_tampered_policy_content_digest_rejects() -> None:
    policy = _policy()
    with pytest.raises(BTSError) as caught:
        replace(policy, content_digest=_D)
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_policy_content_digest_mismatch_v1")


def _corpus(count: int = 5, predecessor: tuple[str, ...] = ()) -> OccupiedCorpus:
    cases = tuple(
        OccupiedCorpusCase.pin(
            f"case-{number}",
            f"donor://{number}",
            f"recipient://{number}",
            OccupiedRecipientProfile.ASYNC_WEB_API if number % 2 == 0 else OccupiedRecipientProfile.SYNC_CLI,
        )
        for number in range(count)
    )
    return OccupiedCorpus.pin("leitir-maintainers", "v0.1.3", cases, predecessor_case_ids=predecessor, ratified_manifest_digest=_D)


def test_corpus_noncompensating_and_runs_every_case() -> None:
    corpus = _corpus()
    ran: list[str] = []

    def run(case: OccupiedCorpusCase) -> bool:
        ran.append(case.case_id)
        return case.case_id != "case-2"

    report = run_occupied_corpus_gate(corpus, run, policy=_policy(corpus=corpus.corpus_manifest_digest))
    assert not report.accepted
    assert ran == [f"case-{number}" for number in range(5)]
    assert sum(not item.passed for item in report.cases) == 1


def test_policy_pinned_corpus_digest_rejects_after_running_every_case() -> None:
    corpus = _corpus()
    ran: list[str] = []
    report = run_occupied_corpus_gate(corpus, lambda case: ran.append(case.case_id) is None, policy=_policy(corpus=_digest(b"stale")))
    assert not report.accepted
    assert not report.authority_digest_matches
    assert ran == [f"case-{number}" for number in range(5)]
    assert all(case.passed for case in report.cases)


def test_corpus_manifest_digest_is_order_independent() -> None:
    corpus = _corpus()
    shuffled = (corpus.cases[3], corpus.cases[0], corpus.cases[4], corpus.cases[1], corpus.cases[2])
    repinned = OccupiedCorpus.pin("leitir-maintainers", "v0.1.3", shuffled, ratified_manifest_digest=_D)
    assert repinned.corpus_manifest_digest == corpus.corpus_manifest_digest


def test_corpus_minimum_profiles_and_monotonic_membership() -> None:
    with pytest.raises(ValueError, match="at least five"):
        _corpus(4)
    with pytest.raises(ValueError, match="monotonic"):
        _corpus(predecessor=("removed-case",))
    cases = tuple(
        OccupiedCorpusCase.pin(f"same-{number}", f"d://{number}", f"r://{number}", OccupiedRecipientProfile.SYNC_CLI)
        for number in range(5)
    )
    with pytest.raises(ValueError, match="required recipient profile"):
        OccupiedCorpus.pin("maintainers", "release", cases, ratified_manifest_digest=_D)


def test_self_ratified_corpus_rejects() -> None:
    corpus = _corpus()
    with pytest.raises(BTSError) as caught:
        replace(corpus, ratified_manifest_digest=corpus.corpus_manifest_digest)
    _assert_detail(caught, BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied_corpus_self_ratification_v1")


def test_every_occupied_digest_is_pythonhashseed_independent() -> None:
    script = """
from tests.test_bts_occupied import _corpus, _manifest, _policy, _rerun, _outcome
from leitir.occupied import derive_recipient_binding_inventory, run_occupied_corpus_gate
import sys
m=_manifest(('src/app.py','source',b'value = 1\\n'))
i=derive_recipient_binding_inventory(m,_policy())
c=_corpus()
r=_rerun(_policy(), i.recipient_manifest_digest, (_outcome(),))
g=run_occupied_corpus_gate(c,lambda case: True,policy=_policy(corpus=c.corpus_manifest_digest))
sys.stdout.buffer.write(
    "\\n".join((i.inventory_digest,_policy().content_digest,r.evidence_digest,c.ratified_manifest_digest,c.corpus_manifest_digest,g.report_digest)).encode("ascii") + b"\\n"
)
"""
    outputs = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = "src"
        outputs.append(
            subprocess.check_output(
                (sys.executable, "-c", script),
                cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
                env=environment,
                timeout=30,
            )
        )
    assert outputs[0] == outputs[1] == outputs[2]
