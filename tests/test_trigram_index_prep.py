"""S8 #95 fixture contracts and red public-workflow intent tests."""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from leitir.engine import ScopedSearcher
from tests.trigram._reference import (
    EXPECTED_SCHEMA_VERSION,
    atomic_write_json,
    build_reference_postings,
    intersect_sorted,
    iter_trigrams,
    refuse_unknown_schema,
    sound_required_literal_runs,
)

FIXTURES = Path(__file__).parent / "fixtures" / "trigram"
SHELF = FIXTURES / "shelf-a"
S8_REASON = "S8 #95 IndexedSearcher not yet implemented; blocked by S9 #94 + S5/S6 #92/#93 + S2a"
s8_red = pytest.mark.xfail(strict=True, reason=S8_REASON)


def _json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _ordered_contents() -> tuple[str, ...]:
    documents = _json(SHELF / "documents.json")["documents"]
    identities = [
        (
            item["host"],
            item["owner"],
            item["repo"],
            item["commit"],
            item["path"],
            item["blob_sha"],
        )
        for item in documents
    ]
    assert identities == sorted(identities)
    return tuple((SHELF / item["path"]).read_text(encoding="utf-8") for item in documents)


def test_golden_postings_equal_reference_regeneration(tmp_path: Path) -> None:
    golden = _json(SHELF / "golden-postings.json")
    regenerated = {
        "postings": build_reference_postings(_ordered_contents()),
        "schema_version": EXPECTED_SCHEMA_VERSION,
    }
    assert regenerated == golden

    regenerated_path = tmp_path / "golden-postings.json"
    atomic_write_json(regenerated_path, regenerated)
    assert regenerated_path.read_bytes() == (SHELF / "golden-postings.json").read_bytes()


def test_reference_intersection_matches_hand_computed_cases() -> None:
    postings = _json(SHELF / "golden-postings.json")["postings"]
    assert intersect_sorted(postings["ban"], postings["nan"]) == (0,)
    assert intersect_sorted(postings["ban"], postings["and"], postings["nda"]) == (1,)
    assert intersect_sorted(postings["ban"], postings["cab"]) == (2,)
    assert intersect_sorted(postings["nan"], postings["cab"]) == ()


def test_reference_trigrams_and_literal_runs_match_hand_derived_cases() -> None:
    cases = _json(FIXTURES / "literal-cases.json")
    for case in cases["sound"]:
        runs = sound_required_literal_runs(case["pattern"])
        grams = tuple(sorted({gram for run in runs for gram in iter_trigrams(run)}))
        assert runs == tuple(case["runs"])
        assert grams == tuple(case["grams"])
    for pattern in cases["no_sound_literal"]:
        assert sound_required_literal_runs(pattern) == ()
    assert iter_trigrams("banana") == ("ana", "ban", "nan")


def test_reference_refuses_unknown_schema_without_rewriting_fixture() -> None:
    unknown = _json(FIXTURES / "tamper-cases.json")["cases"][2]["schema_version"]
    before = (SHELF / "golden-postings.json").read_bytes()
    with pytest.raises(ValueError, match="unsupported trigram index schema"):
        refuse_unknown_schema(unknown)
    assert (SHELF / "golden-postings.json").read_bytes() == before


@s8_red
def test_candidates_match_literal_goldens_and_none_marks_bounded_partial_fallback() -> None:
    # Public S8 surface named in #95; deliberately absent until the final slice.
    from leitir.index.query import candidates  # type: ignore[attr-defined]

    cases = _json(FIXTURES / "literal-cases.json")
    postings = _json(SHELF / "golden-postings.json")["postings"]
    for case in cases["sound"]:
        assert candidates(case["pattern"], postings) == tuple(case["candidate_doc_ids"])
    for pattern in cases["no_sound_literal"]:
        assert candidates(pattern, postings) is None


@s8_red
def test_built_index_and_manifest_are_byte_identical_across_hash_seeds(tmp_path: Path) -> None:
    script = """
from pathlib import Path
from leitir.index.builder import build_fixture_shelf_index
build_fixture_shelf_index(Path(__import__('sys').argv[1]), Path(__import__('sys').argv[2]))
"""
    artifacts: list[tuple[bytes, bytes]] = []
    for seed in ("0", "1", "42"):
        output = tmp_path / seed
        environment = {**os.environ, "PYTHONHASHSEED": seed}
        subprocess.run(
            [sys.executable, "-c", script, str(SHELF), str(output)],
            check=True,
            env=environment,
            capture_output=True,
            text=True,
        )
        artifacts.append(((output / "index.json").read_bytes(), (output / "manifest.json").read_bytes()))
    assert artifacts[0] == artifacts[1] == artifacts[2]


@s8_red
def test_indexed_searcher_search_mirrors_scoped_searcher_public_shape() -> None:
    from leitir.index.query import IndexedSearcher

    assert inspect.signature(IndexedSearcher.search) == inspect.signature(ScopedSearcher.search)
    # The final fixture constructor must be usable without private implementation objects.
    searcher = IndexedSearcher.from_fixture(SHELF)  # type: ignore[attr-defined]
    assert callable(searcher.search)


@s8_red
def test_ineligible_stale_tampered_and_unknown_schema_fallback_or_require_index_reject() -> None:
    from leitir.index.verify import evaluate_fixture_shelf  # type: ignore[attr-defined]

    eligibility = _json(FIXTURES / "eligibility.json")["cases"]
    tamper = _json(FIXTURES / "tamper-cases.json")["cases"]
    for case in eligibility:
        result = evaluate_fixture_shelf(case["manifest"], require_index=False)
        assert result.eligible is case["eligible"]
        if not case["eligible"]:
            assert result.coverage == "partial"
            assert result.fallback == "ScopedSearcher"
            assert evaluate_fixture_shelf(case["manifest"], require_index=True).exit_code != 0
    for case in tamper:
        assert evaluate_fixture_shelf(case, require_index=False).coverage == "partial"
        assert evaluate_fixture_shelf(case, require_index=True).exit_code != 0


@s8_red
def test_trigram_candidates_are_full_regex_verified_before_becoming_matches() -> None:
    from leitir.index.query import search_fixture_shelf  # type: ignore[attr-defined]

    # "banana(cab)" has an empty posting intersection; "ban.*na" candidates
    # include bandana, but the original regex must decide the actual matches.
    report = search_fixture_shelf(SHELF, pattern=r"ban.*na", verify_full_regex=True)
    assert report.candidate_doc_ids == (0, 1, 2)
    assert report.match_doc_ids == (0, 1)
    assert report.full_regex_verified_doc_ids == report.candidate_doc_ids


@s8_red
def test_index_only_coverage_denominators_equal_exhaustive_scan() -> None:
    from leitir.index.query import compare_fixture_coverage  # type: ignore[attr-defined]

    indexed, exhaustive = compare_fixture_coverage(SHELF, pattern="banana")
    assert indexed.files_eligible == exhaustive.files_eligible == 3
    assert indexed.files_indexed == exhaustive.files_indexed == 3
    assert indexed.files_excluded == exhaustive.files_excluded == 0


@s8_red
def test_index_build_and_verified_reads_hold_the_materialization_lock() -> None:
    from leitir.index.verify import probe_fixture_lock_lifetime  # type: ignore[attr-defined]

    observation = probe_fixture_lock_lifetime(SHELF)
    assert observation.lock_held_during_manifest_verification
    assert observation.lock_held_during_index_read
    assert observation.lock_held_during_source_read_and_full_regex_verification
