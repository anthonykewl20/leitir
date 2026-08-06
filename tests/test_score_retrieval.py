"""ADR-002 S4 ranked-output effectiveness adapter gates."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path

import pytest

from tools.score_engine import (
    CheckStatus,
    EvidenceArtifact,
    RetrievalEvaluationError,
    canonical_json_bytes,
    compute_retrieval_metrics,
    evaluate_output_effectiveness_evidence,
    evaluate_retrieval,
    load_policy,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "retrieval"
SEARCH_V1 = REPO_ROOT / "src" / "leitir" / "benchmarks" / "search-v1"
# Pinned contract values. These are deliberately hard-coded rather than
# recomputed from the data under test: a test that derives its expectation from
# the same source it checks would pass no matter what that source became.
#
# They therefore fail whenever search-v1 or the policy changes, which is the
# point. To regenerate after an intended change:
#
#   MANIFEST_SHA256 — the canonical manifest digest, matching
#     BenchmarkManifest.digest() in src/leitir/bench.py:
#       PYTHONPATH=src python -c "from leitir.bench import load_manifest; \
#         print(load_manifest().digest())"
#   task and check counts — `jq '.tasks | length'` over
#     src/leitir/benchmarks/search-v1/{manifest,qrels}.json, and
#     `jq '.checks | length'` over scorecard/policy-v1.json.
#
# Update these only when the underlying change is itself intended and reviewed.
# Never edit one to make a failing test green — that inverts what it is for.
MANIFEST_SHA256 = "58e23654abc2d999548b7b36e9ca014637f1268503e8456c175c50d626a042bc"


def _identity(name: str) -> tuple[str, str, str, str, int, int]:
    number = sum(name.encode("utf-8"))
    return (
        "example/repository",
        "1" * 40,
        f"src/{name}.py",
        f"{number:040x}"[-40:],
        1,
        1,
    )


def _source(identity, *, permalink: bool = False):
    slug, commit_sha, path, blob_sha, start_line, end_line = identity
    result = {
        "slug": slug,
        "commit_sha": commit_sha,
        "path": path,
        "blob_sha": blob_sha,
        "start_line": start_line,
        "end_line": end_line,
    }
    if permalink:
        result["permalink"] = (
            f"https://github.com/{slug}/blob/{commit_sha}/{path}"
            f"#L{start_line}-L{end_line}"
        )
    return result


def _artifact(artifact_id: str, value: object) -> EvidenceArtifact:
    content = canonical_json_bytes(value)
    return EvidenceArtifact(
        id=artifact_id,
        path=f"tests/fixtures_score/retrieval/{artifact_id}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _p6_manifest_digest(manifest: dict[str, object]) -> str:
    normalized = deepcopy(manifest)
    normalized["tasks"] = sorted(normalized["tasks"], key=lambda item: item["id"])
    for task in normalized["tasks"]:
        expected = []
        for source in task["expected_results"]:
            item = dict(source)
            item["permalink"] = (
                f"https://github.com/{item['slug']}/blob/{item['commit_sha']}/"
                f"{item['path']}#L{item['start_line']}-L{item['end_line']}"
            )
            expected.append(item)
        task["expected_results"] = sorted(
            expected,
            key=lambda item: (
                item["slug"], item["commit_sha"], item["path"], item["blob_sha"],
                item["start_line"], item["end_line"],
            ),
        )
    return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()


def _scenario():
    manifest_tasks = []
    qrel_tasks = []
    run_tasks = []
    for language in ("go", "python", "rust"):
        for index in range(4):
            task_id = f"{language}-fixture-task-{index}"
            target = _identity(f"{language}-target-{index}")
            manifest_tasks.append(
                {
                    "id": task_id,
                    "language": language,
                    "scope": {"slug": target[0], "commit_sha": target[1]},
                    "must": [
                        {"kind": "path", "value": target[2], "language": language},
                        {"kind": "symbol_definition", "value": f"target_{index}", "language": language},
                    ],
                    "should": [],
                    "must_not": [],
                    "expected_results": [_source(target)],
                    "pin_source": "committed synthetic artifact-contract fixture",
                }
            )
            qrel_tasks.append(
                {
                    "task_id": task_id,
                    "judgments_complete": False,
                    "judgments": [{"grade": 2, "source": _source(target)}],
                }
            )
            run_tasks.append(
                {
                    "task_id": task_id,
                    "language": language,
                    "spec_digest": f"{index + 1:064x}",
                    "coverage": {
                        "status": "complete_for_declared_universe",
                        "files_eligible": 1,
                        "files_indexed": 1,
                        "files_excluded": 0,
                        "incomplete_results": False,
                        "exclusions": {},
                    },
                    "results": [
                        {
                            "source": _source(target, permalink=True),
                            "score": 1.0,
                            "normalized_score": 1.0,
                            "rank": 1,
                            "rank_score": 1,
                            "matched_kinds": ["symbol_definition"],
                        }
                    ],
                }
            )
    manifest = {
        "schema_version": "leitir-benchmark-manifest-v1",
        "benchmark_id": "fixture-v1",
        "tasks": manifest_tasks,
    }
    manifest_sha256 = _p6_manifest_digest(manifest)
    qrels = {
        "schema_version": "leitir-benchmark-qrels-v1",
        "benchmark": {"id": "fixture-v1", "manifest_sha256": manifest_sha256},
        "tasks": qrel_tasks,
    }
    run = {
        "schema_version": "leitir-benchmark-run-v1",
        "benchmark": {"id": "fixture-v1", "manifest_sha256": manifest_sha256},
        "tasks": run_tasks,
    }
    return manifest, qrels, run


def _evaluation(manifest, qrels, run):
    return evaluate_retrieval(
        manifest=_artifact("manifest", manifest),
        qrels=_artifact("qrels", qrels),
        benchmark_run=_artifact("run", run),
    )


def _metric_dict(metrics):
    return {
        "ndcg_at_10": metrics.ndcg_at_10,
        "reciprocal_rank_at_10": metrics.reciprocal_rank_at_10,
        "success_at_1": metrics.success_at_1,
        "success_at_5": metrics.success_at_5,
        "success_at_10": metrics.success_at_10,
        "recall_at_10": metrics.recall_at_10,
        "precision_at_5": metrics.precision_at_5,
        "precision_at_10": metrics.precision_at_10,
        "average_precision_at_10": metrics.average_precision_at_10,
    }


def test_shipped_qrels_are_exactly_the_twelve_manifest_pins():
    manifest = json.loads((SEARCH_V1 / "manifest.json").read_text(encoding="utf-8"))
    qrels = json.loads((SEARCH_V1 / "qrels.json").read_text(encoding="utf-8"))

    assert _p6_manifest_digest(manifest) == MANIFEST_SHA256
    assert qrels["benchmark"] == {
        "id": "search-v1",
        "manifest_sha256": MANIFEST_SHA256,
    }
    assert {task["task_id"] for task in qrels["tasks"]} == {
        task["id"] for task in manifest["tasks"]
    }
    assert len(qrels["tasks"]) == 12
    by_id = {task["id"]: task for task in manifest["tasks"]}
    counts = {"python": 0, "rust": 0, "go": 0}
    for task in qrels["tasks"]:
        judgments = task["judgments"]
        assert task["judgments_complete"] is False
        assert [item["grade"] for item in judgments] == [2]
        assert [item["source"] for item in judgments] == by_id[task["task_id"]]["expected_results"]
        counts[by_id[task["task_id"]]["language"]] += 1
    assert counts == {"python": 4, "rust": 4, "go": 4}


@pytest.mark.parametrize("vector_name", ["rank1", "rank3", "missing", "unjudged_first"])
def test_hand_calculated_vectors_match_pinned_trec_golden(vector_name):
    golden = json.loads((FIXTURES / "trec-golden.json").read_text(encoding="utf-8"))
    vector = golden["vectors"][vector_name]
    identities = {name: _identity(name) for name in {"exact", "support", "wrong", "unjudged"}}
    metrics = compute_retrieval_metrics(
        tuple(identities[name] for name in vector["ranking"]),
        {identities[name]: grade for name, grade in golden["qrels"].items()},
        judgments_complete=True,
    )

    for name, expected in vector["expected"].items():
        assert getattr(metrics, name) == pytest.approx(expected, abs=1e-15)


def test_rank_three_linear_gain_ndcg_is_hand_calculated():
    exact, support, wrong = (_identity(name) for name in ("exact", "support", "wrong"))
    metrics = compute_retrieval_metrics(
        (support, wrong, exact),
        {exact: 2, support: 1, wrong: 0},
        judgments_complete=True,
    )
    expected = (1 / math.log2(2) + 2 / math.log2(4)) / (
        2 / math.log2(2) + 1 / math.log2(3)
    )
    assert metrics.ndcg_at_10 == pytest.approx(expected, abs=1e-15)


def test_incomplete_qrels_suppress_only_precision_and_ap():
    exact, support = _identity("exact"), _identity("support")
    metrics = compute_retrieval_metrics(
        (support, exact),
        {exact: 2, support: 1},
        judgments_complete=False,
    )
    assert metrics.ndcg_at_10 > 0
    assert metrics.recall_at_10 == 1
    assert metrics.precision_at_5 is None
    assert metrics.precision_at_10 is None
    assert metrics.average_precision_at_10 is None


def test_present_task_with_empty_results_is_valid_and_scores_zero():
    manifest, qrels, run = _scenario()
    run["tasks"][0]["results"] = []
    evaluation = _evaluation(manifest, qrels, run)
    empty = next(item for item in evaluation.tasks if item.task_id == run["tasks"][0]["task_id"])

    assert empty.result_count == 0
    assert empty.metrics.ndcg_at_10 == 0
    assert empty.metrics.reciprocal_rank_at_10 == 0
    exact_check = next(item for item in evaluation.checks if item.id == "output.exact_target_at_10")
    assert exact_check.status is CheckStatus.FAIL
    assert exact_check.numerator == 11
    assert exact_check.denominator == 12


@pytest.mark.parametrize("missing_from", ["run", "qrels"])
def test_missing_task_is_an_evaluation_error(missing_from):
    manifest, qrels, run = _scenario()
    target = run if missing_from == "run" else qrels
    target["tasks"].pop()

    with pytest.raises(RetrievalEvaluationError) as caught:
        _evaluation(manifest, qrels, run)
    assert caught.value.reason_code == "TASK_SET_MISMATCH"

    checks = evaluate_output_effectiveness_evidence(
        manifest=_artifact("manifest", manifest),
        qrels=_artifact("qrels", qrels),
        benchmark_run=_artifact("run", run),
    )
    assert checks
    assert all(item.status is CheckStatus.ERROR for item in checks)
    assert {item.reason_code for item in checks} == {"TASK_SET_MISMATCH"}


def test_duplicate_result_identity_is_rejected():
    manifest, qrels, run = _scenario()
    duplicate = deepcopy(run["tasks"][0]["results"][0])
    duplicate["rank"] = 2
    duplicate["rank_score"] = 1
    run["tasks"][0]["results"][0]["rank_score"] = 2
    run["tasks"][0]["results"].append(duplicate)

    with pytest.raises(RetrievalEvaluationError) as caught:
        _evaluation(manifest, qrels, run)
    assert caught.value.reason_code == "DUPLICATE_RESULT_ID"


def test_equal_rank_scores_are_rejected_as_a_tie():
    manifest, qrels, run = _scenario()
    first = run["tasks"][0]
    decoy_identity = _identity("zz-decoy")
    first["results"].append(
        {
            "source": _source(decoy_identity, permalink=True),
            "score": 0.0,
            "normalized_score": 0.0,
            "rank": 2,
            "rank_score": 1,
            "matched_kinds": ["path"],
        }
    )

    with pytest.raises(RetrievalEvaluationError) as caught:
        _evaluation(manifest, qrels, run)
    assert caught.value.reason_code == "RANKED_RUN_TOTAL_ORDER_INVALID"


def test_normalized_score_ties_require_canonical_source_order():
    manifest, qrels, run = _scenario()
    first = run["tasks"][0]
    target = first["results"][0]
    decoy_identity = _identity("aa-decoy")
    target["rank"] = 2
    target["rank_score"] = 1
    first["results"] = [
        {
            "source": _source(decoy_identity, permalink=True),
            "score": 1.0,
            "normalized_score": 1.0,
            "rank": 1,
            "rank_score": 2,
            "matched_kinds": ["path"],
        },
        target,
    ]
    # Equal normalized scores are resolved by the full SourceRef tuple.  The
    # aa-decoy path sorts before the go-target path.
    evaluation = _evaluation(manifest, qrels, run)
    assert evaluation.tasks[0].result_count == 2

    first["results"].reverse()
    for rank, result in enumerate(first["results"], start=1):
        result["rank"] = rank
        result["rank_score"] = 3 - rank
    with pytest.raises(RetrievalEvaluationError) as caught:
        _evaluation(manifest, qrels, run)
    assert caught.value.reason_code == "RANKED_RUN_TOTAL_ORDER_INVALID"


def test_language_and_predicate_strata_are_never_silently_omitted():
    manifest, qrels, run = _scenario()
    for task in run["tasks"]:
        task["results"] = []
    evaluation = _evaluation(manifest, qrels, run)

    assert [item.value for item in evaluation.language_strata] == ["go", "python", "rust"]
    assert [len(item.task_ids) for item in evaluation.language_strata] == [4, 4, 4]
    assert [item.value for item in evaluation.predicate_strata] == ["path", "symbol_definition"]
    assert [len(item.task_ids) for item in evaluation.predicate_strata] == [12, 12]
    rendered = evaluation.to_dict()
    assert len(rendered["strata"]["language"]) == 3
    assert len(rendered["strata"]["predicate"]) == 2


def test_future_authoritative_adapter_receives_unique_rank_scores():
    manifest, qrels, run = _scenario()
    evaluation = _evaluation(manifest, qrels, run)
    for task_run in evaluation.authoritative_run.values():
        scores = list(task_run.values())
        assert len(scores) == len(set(scores))
        assert scores == sorted(scores, reverse=True)


def test_shipped_policy_has_contract_checks_but_no_metric_floor():
    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    checks = [item for item in policy.checks if item.dimension == "output_effectiveness"]
    assert len(checks) == 15
    metric_ids = {
        "output.ndcg_at_10",
        "output.reciprocal_rank_at_10",
        "output.success_at_1",
        "output.success_at_5",
        "output.success_at_10",
        "output.recall_at_10",
        "output.precision_at_5",
        "output.precision_at_10",
        "output.average_precision_at_10",
    }
    for check in checks:
        if check.id in metric_ids:
            assert (check.criterion.op, check.criterion.value) == ("gte", 0)
    conditional = {"output.precision_at_5", "output.precision_at_10", "output.average_precision_at_10"}
    assert {item.id for item in checks if item.applicability is not None} == conditional


def test_trec_golden_fixture_is_committed_real_data():
    fixture = FIXTURES / "trec-golden.json"
    assert fixture.is_file()
    golden = json.loads(fixture.read_text(encoding="utf-8"))
    assert golden["scorers"] == {
        "ir_measures": "0.4.3",
        "pytrec_eval_terrier": "0.5.10",
    }


def test_optional_authoritative_cross_check_is_explicit_when_absent_or_agrees():
    manifest, qrels, run = _scenario()
    for qrel_task, run_task in zip(qrels["tasks"], run["tasks"], strict=True):
        support = _identity(f"{qrel_task['task_id']}-support")
        qrel_task["judgments"].append({"grade": 1, "source": _source(support)})
        target = run_task["results"][0]
        target["rank"] = 2
        target["rank_score"] = 1
        run_task["results"] = [
            {
                "source": _source(support, permalink=True),
                "score": 1.0,
                "normalized_score": 1.0,
                "rank": 1,
                "rank_score": 2,
                "matched_kinds": ["path"],
            },
            target,
        ]
    cross_check = _evaluation(manifest, qrels, run).cross_check

    # Three outcomes are legitimate, and each must fail with its own diagnostic.
    # Collapsing the non-skipped cases into one else branch reported a mismatched
    # local install as "error != agree", which reads like a metric disagreement
    # when it is really an environment problem.
    if cross_check.status == "skipped":
        assert cross_check.reason_code == "SCORING_LOCK_NOT_INSTALLED"
        assert cross_check.authoritative_bps == ()
    elif cross_check.status == "error":
        assert cross_check.reason_code in {
            "RETRIEVAL_TOOL_VERSION_MISMATCH",
            "AUTHORITATIVE_RETRIEVAL_CROSS_CHECK_ERROR",
        }, (
            "cross-check errored unexpectedly: install the pinned scoring lock "
            f"(requirements-score.txt) or none at all; got {cross_check.reason_code} "
            f"with versions {cross_check.installed_versions}"
        )
    else:
        assert cross_check.status == "agree", (
            "authoritative scorer disagreed with the standard-library kernel: "
            f"{cross_check.disagreements}"
        )
        assert cross_check.reason_code == "AUTHORITATIVE_RETRIEVAL_AGREEMENT"
        assert cross_check.installed_versions == (
            ("ir_measures", "0.4.3"),
            ("pytrec-eval-terrier", "0.5.10"),
        )
        assert cross_check.disagreements == ()
        assert cross_check.standard_library_bps == cross_check.authoritative_bps
