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
_EXPECTED_CONTENT_DIGEST = "a969398a87266a85051006ee776607e456a951f2422e34b13431b71d7e4caea5"
_EXPECTED_RATIFIED_RUNTIME_DIGEST = "sha256:901bf7ac3cdfc5e7fcb59a9f6c153d24724c7525d7398174478d3d1322b40f69"
_EXPECTED_OUTCOMES: dict[str, tuple[int, int, int, int]] = {
    "backoff-full-jitter": (2, 2, 0, 0),
    "haversine-avg-earth-radius": (2, 2, 0, 0),
    "luhn-checksum": (2, 2, 0, 0),
    "url-normalize-fragment": (2, 2, 0, 0),
    "webcolors-rgb-to-hex": (2, 2, 0, 0),
}
_EXPECTED_IMPORTS = {
    "backoff-full-jitter": "backoff._jitter",
    "haversine-avg-earth-radius": "haversine.haversine",
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
        if isinstance(statement, ast.ImportFrom):
            assert statement.level == 0
            assert statement.module == expected_import
            assert statement.names
            assert all(item.asname is None for item in statement.names)
            imports.append(statement.module)
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
    assert manifest["ratified_runtime_digest"] == _EXPECTED_RATIFIED_RUNTIME_DIGEST
    assert load_corpus_manifest(_MANIFEST_PATH)["ratified_runtime_digest"] == _EXPECTED_RATIFIED_RUNTIME_DIGEST
    runnable = manifest["runnable"]
    assert isinstance(runnable, dict)
    assert runnable["substrate"] == {
        "config_schema_digest": "sha256:39803af3291a1f08860ec1ec4b028aba5d000df53d2f0f73781718f75ff16c80",
        "containment_template_version": "leitir-containment-policy-v1",
        "nsjail_build_identity": "sha256:9fc7783e8fee63cf059bb5e48053f3ac77e80fda34128917bae956bda90c0c4b",
        "nsjail_sha256": "sha256:2a740ac196d27176216788f6213d585cd5b5933f83f2c9bff31ce95cd64939d4",
        "nsjail_version": "nsjail@f78475530b46d0186111a9096b30725f816b55fe",
        "rootfs_digest": "sha256:ec28886a5e448e9d6b088470c85ee2e0d170e16002bd78ecc835e9d4161155ac",
    }
    runnable_cases = {item["case_id"]: item for item in runnable["per_case"]}
    assert {case_id: item["import_roots"] for case_id, item in runnable_cases.items()} == {
        "luhn-checksum": ["."], "backoff-full-jitter": ["."],
        "url-normalize-fragment": ["."], "webcolors-rgb-to-hex": ["src"],
        "haversine-avg-earth-radius": ["."],
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
        expected_seed = case["seed"]
        if case_id == "url-normalize-fragment":
            assert metadata["seed"] == {
                **expected_seed,
                "start_line": 1,
                "end_line": 27,
            }
        else:
            assert metadata["seed"] == expected_seed
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

    assert expected_receipt == "d7015d94598225050c0e712c0580b56d946ed1938823c61ec37e6b0d991f3b41"
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
