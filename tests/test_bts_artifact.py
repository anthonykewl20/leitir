from __future__ import annotations

import pytest

from leitir.bts import BTSStatus, compute_bts, load_bts_artifact
from leitir.bts_errors import BTSError
from tests.test_bts_walk import _budget, _fixture, _policy


def test_complete_canonical_report_rehydrates_the_occupied_bts_surface() -> None:
    snapshot, seed, graph = _fixture()
    result = compute_bts(snapshot, seed, graph, _budget(), _policy())
    assert result.status is BTSStatus.COMPLETE and result.bts is not None

    loaded = load_bts_artifact(result.report.to_bytes())

    assert loaded.seed == result.bts.seed
    assert loaded.members == result.bts.members
    assert loaded.bts_digest == result.bts.bts_digest


def test_artifact_loader_maps_noncanonical_or_tampered_report_to_its_typed_error() -> None:
    snapshot, seed, graph = _fixture()
    result = compute_bts(snapshot, seed, graph, _budget(), _policy())
    with pytest.raises(BTSError) as caught:
        load_bts_artifact(result.report.to_bytes().rstrip())
    assert caught.value.evidence.detail_code == "bts_artifact_invalid_v1"
