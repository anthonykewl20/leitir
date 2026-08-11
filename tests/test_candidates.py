from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, replace

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.candidates import (
    PINNED_CANDIDATE_BUDGET_POLICY,
    CandidateBudget,
    CandidateBudgetPolicy,
    CandidateProposal,
    CandidateRetrievalPlan,
    CandidateSetStatus,
    DiscoveryStageResult,
    EvidencePointer,
    FunnelTermination,
    SymbolStageEvidence,
    ValidationStatus,
    compile_search_specs,
    discover_candidates,
)
from leitir.graph.model import NodeId, SourceRef
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    Resolution,
    ResolutionStrategy,
    SearchReport,
    SourceMatch,
)
from leitir.search import SourceRef as SearchSourceRef
from tests.test_capability import _spec

_COMMIT = "1" * 40
_BLOB = "2" * 40
_EVIDENCE_DIGEST = "sha256:" + "3" * 64
_PROFILE_DIGEST = "sha256:" + "4" * 64


@dataclass(frozen=True)
class _Profile:
    profile_digest: str = _PROFILE_DIGEST


def _policy() -> CandidateBudgetPolicy:
    return PINNED_CANDIDATE_BUDGET_POLICY


def _bound_spec():
    policy = _policy()
    spec = replace(
        _spec(),
        required_behaviors=(replace(_spec().required_behaviors[0], evidence_terms=("parse",)),),
        max_candidate_budget_id=policy.policy_id,
        max_candidate_budget_version=policy.policy_version,
        max_candidate_budget_digest=policy.content_digest,
    )
    return spec, policy, CandidateBudget.from_policy(policy)


def _symbol(start_col: int, end_col: int, qualified_name: str = "pkg.parse") -> SymbolStageEvidence:
    return SymbolStageEvidence(
        source=SourceRef("owner/repo", _COMMIT, "pkg/api.py", _BLOB, 7, start_col, 7, end_col),
        symbol_kind="function",
        qualified_name=qualified_name,
        extraction_method="python_ast",
        extraction_version="v1",
        proposal_rule_id="python.symbol.exact",
        proposal_rule_version="v1",
        validation_status=ValidationStatus.VALIDATED,
        extraction_evidence=(EvidencePointer("ast", "leitir.python_ast", "v1", _EVIDENCE_DIGEST),),
    )


def _plan(
    symbols: tuple[SymbolStageEvidence, ...],
    termination: FunnelTermination = FunnelTermination.CLEAN_EOF,
    *,
    incomplete: bool = False,
) -> CandidateRetrievalPlan:
    spec, _, _ = _bound_spec()
    search_spec = compile_search_specs(spec)[0]
    source = SearchSourceRef("owner/repo", _COMMIT, "pkg/api.py", _BLOB, 7, 7)
    report = SearchReport(
        spec_digest=search_spec.digest(),
        coverage=Coverage(
            CoverageStatus.INDETERMINATE_GLOBAL,
            files_eligible=1,
            files_indexed=1,
            files_excluded=0,
            incomplete_results=incomplete,
        ),
        matches=(SourceMatch(source, 1.0, (PredicateKind.IDENTIFIER,)),),
        resolution=Resolution(ResolutionStrategy.INDEXED_COMMIT, "2026-08-11T00:00:00Z"),
    )
    return CandidateRetrievalPlan((DiscoveryStageResult(search_spec, report, symbols, termination, 1, (100,)),))


def _fixture_bytes() -> bytes:
    spec, policy, budget = _bound_spec()
    symbols = (_symbol(16, 21), _symbol(4, 9, "pkg.other"), _symbol(16, 21))
    return discover_candidates(spec, _Profile(), _plan(symbols), budget, policy).to_bytes()


def test_fixture_funnel_normalizes_deduplicates_and_accounts() -> None:
    spec, policy, budget = _bound_spec()
    result = discover_candidates(
        spec,
        _Profile(),
        _plan((_symbol(16, 21), _symbol(4, 9, "pkg.other"), _symbol(16, 21))),
        budget,
        policy,
    )
    assert len(result.proposals) == 2
    assert all(isinstance(item, CandidateProposal) for item in result.proposals)
    assert [item.start_col for item in result.proposals] == [4, 16]
    assert result.accounting[2].duplicates == 1
    assert tuple(item.stage for item in result.accounting) == (
        "repository_discovery",
        "file_discovery",
        "symbol_proposal",
        "local_structural_validation",
        "context_expansion",
    )


def test_same_line_distinct_utf8_byte_columns_remain_distinct() -> None:
    spec, policy, budget = _bound_spec()
    result = discover_candidates(spec, _Profile(), _plan((_symbol(4, 9), _symbol(16, 21))), budget, policy)
    assert {(item.start_line, item.start_col, item.end_col) for item in result.proposals} == {(7, 4, 9), (7, 16, 21)}


def test_clean_eof_below_three_is_complete_but_globally_indeterminate() -> None:
    spec, policy, budget = _bound_spec()
    result = discover_candidates(spec, _Profile(), _plan((_symbol(4, 9),)), budget, policy)
    assert result.complete_for_funnel is True
    assert result.status is CandidateSetStatus.INDETERMINATE_GLOBAL
    assert result.comparison_authorized is False


def test_page_ceiling_rejects_as_under_collection() -> None:
    spec, policy, budget = _bound_spec()
    with pytest.raises(BTSError) as caught:
        discover_candidates(
            spec,
            _Profile(),
            _plan((_symbol(4, 9),), FunnelTermination.PAGE_CEILING, incomplete=True),
            budget,
            policy,
        )
    assert caught.value.reason is BTSRejectReason.REJECT_UNDER_COLLECTION
    assert caught.value.evidence.detail_code == "candidate_funnel_under_collection_v1"


def test_proposals_are_non_authorizing_and_produce_no_graph_identity() -> None:
    spec, policy, budget = _bound_spec()
    proposal = discover_candidates(spec, _Profile(), _plan((_symbol(4, 9),)), budget, policy).proposals[0]
    assert isinstance(proposal, CandidateProposal)
    assert not isinstance(proposal, NodeId)
    assert not hasattr(proposal, "edges")
    assert not hasattr(proposal, "bts")


def test_budget_must_match_spec_pinned_policy_digest() -> None:
    spec, policy, budget = _bound_spec()
    mismatched = replace(spec, max_candidate_budget_digest="sha256:" + "f" * 64)
    with pytest.raises(BTSError) as caught:
        discover_candidates(mismatched, _Profile(), _plan((_symbol(4, 9),)), budget, policy)
    assert caught.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert caught.value.evidence.detail_code == "candidate_budget_policy_mismatch_v1"


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_candidate_set_is_hash_seed_independent(seed: str) -> None:
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-c", "from tests.test_candidates import _fixture_bytes; import sys; sys.stdout.buffer.write(_fixture_bytes())"],
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        env=environment,
        check=True,
        capture_output=True,
    )
    assert result.stdout == _fixture_bytes()
