from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from leitir.exit_corpus import content_digest, load_corpus_manifest, validate_corpus_manifest

_REPO_ROOT = Path(__file__).parents[1]
_CORPUS_ROOT = _REPO_ROOT / "benchmarks" / "exit-corpus"
_MANIFEST_PATH = _CORPUS_ROOT / "corpus-v1.1.json"
_REVIEW_RECORD_PATH = _CORPUS_ROOT / "review-record-v1.md"
_EXPECTED_CONTENT_DIGEST = "2839d7afc3551dd06366e8b7b112ffad9c5b05327ad53a395e1247c42a38c386"
_EXPECTED_OUTCOMES: dict[str, tuple[int, int, int, int]] = {
    "backoff-full-jitter": (2, 2, 0, 0),
    "cognee-calculate-backoff": (2, 2, 0, 0),
    "luhn-checksum": (2, 2, 0, 0),
    "url-normalize-fragment": (2, 2, 0, 0),
    "webcolors-rgb-to-hex": (2, 2, 0, 0),
}
_EXPECTED_IMPORTS = {
    "backoff-full-jitter": "backoff._jitter",
    "cognee-calculate-backoff": "cognee.infrastructure.utils.calculate_backoff",
    "luhn-checksum": "luhn",
    "url-normalize-fragment": "url_normalize.normalize_fragment",
    "webcolors-rgb-to-hex": "webcolors._conversion",
}
_META_KEYS = {
    "case_id",
    "commit_sha",
    "license",
    "module_path",
    "repo",
    "schema_version",
    "seed",
    "test_pythonpath",
}


def _manifest() -> dict[str, object]:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _case_by_id(manifest: dict[str, object]) -> dict[str, object]:
    cases = manifest["cases"]
    assert isinstance(cases, list)
    return {str(case["case_id"]): case for case in cases if isinstance(case, dict)}


def _lint_contract_test(path: Path, expected_import: str) -> int:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    imports: list[str] = []
    test_count = 0
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            assert len(statement.names) == 1
            imported = statement.names[0]
            assert imported.name == expected_import
            assert imported.asname == "donor"
            imports.append(imported.name)
            continue
        assert isinstance(statement, ast.FunctionDef)
        assert statement.name.startswith("test_")
        assert not statement.decorator_list
        assert not statement.args.posonlyargs
        assert not statement.args.args
        assert statement.args.vararg is None
        assert not statement.args.kwonlyargs
        assert statement.args.kwarg is None
        assert statement.returns is None
        assert statement.body
        assert all(isinstance(child, ast.Assert) for child in statement.body)
        test_count += 1
    assert imports == [expected_import]
    return test_count


def test_real_exit_corpus_manifest_is_structurally_valid_and_content_bound() -> None:
    summary = validate_corpus_manifest(_MANIFEST_PATH)
    manifest = _manifest()
    cases = _case_by_id(manifest)

    assert summary["case_count"] == 5
    assert set(cases) == set(_EXPECTED_OUTCOMES)
    assert len({case["source_provenance"] for case in cases.values()}) == 5
    assert len({case["donor"]["commit_sha"] for case in cases.values()}) == 5
    assert summary["content_digest"] == _EXPECTED_CONTENT_DIGEST
    assert content_digest(load_corpus_manifest(_MANIFEST_PATH)) == _EXPECTED_CONTENT_DIGEST
    assert manifest["ratified_runtime_digest"] is None
    runnable = manifest["runnable"]
    assert isinstance(runnable, dict)
    assert runnable["substrate"] == {
        "config_schema_digest": None,
        "containment_template_version": "leitir-containment-policy-v1",
        "nsjail_build_identity": None,
        "nsjail_sha256": None,
        "nsjail_version": None,
        "rootfs_digest": None,
    }
    runnable_cases = {item["case_id"]: item for item in runnable["per_case"]}
    assert {case_id: item["import_roots"] for case_id, item in runnable_cases.items()} == {
        "luhn-checksum": ["."], "backoff-full-jitter": ["."],
        "url-normalize-fragment": ["."], "webcolors-rgb-to-hex": ["src"],
        "cognee-calculate-backoff": ["cognee/infrastructure/utils"],
    }
    assert {case_id: item["policy_path"] for case_id, item in runnable_cases.items()} == {
        case_id: f"policies/{case_id}.json" for case_id in sorted(_EXPECTED_OUTCOMES)
    }
    assert all((_CORPUS_ROOT / item["policy_path"]).is_file() for item in runnable_cases.values())
    assert runnable_cases["url-normalize-fragment"]["runtime_deps"] == [{"distribution": "idna", "version": "3.18"}]
    assert all(item["runtime_deps"] == [] for case_id, item in runnable_cases.items() if case_id != "url-normalize-fragment")


def test_committed_donor_metadata_and_contract_tests_match_the_manifest() -> None:
    cases = _case_by_id(_manifest())
    for case_id in sorted(_EXPECTED_OUTCOMES):
        case = cases[case_id]
        metadata_path = _CORPUS_ROOT / "donors" / case_id / "donor-meta.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        assert set(metadata) == _META_KEYS
        assert metadata["schema_version"] == "leitir-exit-corpus-donor-meta-v1"
        assert metadata["case_id"] == case_id
        assert metadata["commit_sha"] == case["donor"]["commit_sha"]
        assert metadata["repo"] == "/".join((case["donor"]["owner"], case["donor"]["repo"]))
        assert metadata["seed"] == case["seed"]
        assert isinstance(metadata["module_path"], str) and metadata["module_path"]
        assert isinstance(metadata["test_pythonpath"], str) and metadata["test_pythonpath"]

        license_record = metadata["license"]
        assert set(license_record) == {"file", "sha256", "spdx"}
        assert license_record["file"] == "LICENSE"
        assert len(license_record["sha256"]) == 64
        assert all(character in "0123456789abcdef" for character in license_record["sha256"])
        assert license_record["spdx"] in {"Apache-2.0", "BSD-3-Clause", "MIT"}

        test_paths = sorted((metadata_path.parent / "contract_tests").glob("test_*.py"))
        assert len(test_paths) == 1
        test_count = _lint_contract_test(test_paths[0], _EXPECTED_IMPORTS[case_id])
        expected = _EXPECTED_OUTCOMES[case_id]
        assert test_count == expected[0]
        assert case["baseline"] == {
            "contract_test_count": expected[0],
            "expected_pass": expected[1],
            "expected_fail": expected[2],
            "expected_skip": expected[3],
        }


def test_review_record_receipt_matches_every_case() -> None:
    expected_receipt = hashlib.sha256(_REVIEW_RECORD_PATH.read_bytes()).hexdigest()
    cases = _case_by_id(_manifest())

    assert expected_receipt == "933ad4b1906a5033be2147ef4b5903de52cf38bf59631a2f1a4cb873fb1ca061"
    assert {case["review_receipt_digest"] for case in cases.values()} == {expected_receipt}


def test_real_corpus_content_digest_is_pythonhashseed_independent() -> None:
    script = """
from pathlib import Path
from leitir.exit_corpus import content_digest, load_corpus_manifest
print(content_digest(load_corpus_manifest(Path('benchmarks/exit-corpus/corpus-v1.1.json'))))
"""
    outputs: list[bytes] = []
    for seed in ("0", "1", "42"):
        environment = os.environ | {"PYTHONHASHSEED": seed, "PYTHONPATH": str(_REPO_ROOT / "src")}
        outputs.append(subprocess.check_output([sys.executable, "-c", script], cwd=_REPO_ROOT, env=environment).replace(b"\r\n", b"\n"))

    assert outputs == [_EXPECTED_CONTENT_DIGEST.encode() + b"\n"] * 3
