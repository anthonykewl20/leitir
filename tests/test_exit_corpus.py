from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from leitir.bts_errors import BTSError
from leitir.exit_corpus import (
    EXIT_CORPUS_MANIFEST_SCHEMA_VERSION,
    content_digest,
    cross_check_against_gate,
    load_corpus_manifest,
    validate_corpus_manifest,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "exit_corpus"


def _fixture(name: str = "corpus-valid.json") -> Path:
    return _FIXTURES / name


def _write_canonical(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")


def _manifest() -> dict[str, object]:
    return json.loads(_fixture().read_text(encoding="utf-8"))


def _detail_code(operation: Callable[[Path], object], path: Path) -> str:
    with pytest.raises(BTSError) as caught:
        operation(path)
    assert caught.value.evidence.detail_code is not None
    return caught.value.evidence.detail_code


def test_valid_five_donor_corpus_has_an_absent_content_binding_and_no_ratification() -> None:
    summary = validate_corpus_manifest(_fixture())

    assert summary == {
        "schema_version": EXIT_CORPUS_MANIFEST_SCHEMA_VERSION,
        "corpus_id": "bts-exit-v0-1-2",
        "case_count": 5,
        "donors": (
            "github.com/acme/alpha/1111111111111111111111111111111111111111",
            "github.com/acme/bravo/2222222222222222222222222222222222222222",
            "github.com/acme/charlie/3333333333333333333333333333333333333333",
            "github.com/acme/delta/4444444444444444444444444444444444444444",
            "github.com/acme/echo/5555555555555555555555555555555555555555",
        ),
        "content_digest": content_digest(load_corpus_manifest(_fixture())),
        "content_binding": "absent",
        "ratified": False,
    }


def test_valid_self_hash_is_content_binding_not_external_ratification() -> None:
    summary = validate_corpus_manifest(_fixture("corpus-ratified.json"))
    assert summary["content_binding"] == "valid"
    assert summary["ratified"] is False


@pytest.mark.parametrize(
    ("mutate", "detail_code"),
    [
        (lambda manifest: manifest.__setitem__("cases", manifest["cases"][:4]), "exit_corpus_min_donors_v1"),
        (
            lambda manifest: manifest["cases"][1].__setitem__("case_id", manifest["cases"][0]["case_id"]),
            "exit_corpus_duplicate_case_v1",
        ),
        (
            lambda manifest: manifest["cases"][1]["donor"].__setitem__(
                "commit_sha", manifest["cases"][0]["donor"]["commit_sha"]
            ),
            "exit_corpus_duplicate_donor_v1",
        ),
        (
            lambda manifest: manifest["cases"][1].__setitem__(
                "source_provenance", manifest["cases"][0]["source_provenance"]
            ),
            "exit_corpus_provenance_not_distinct_v1",
        ),
        (lambda manifest: manifest.__setitem__("unexpected", True), "exit_corpus_schema_v1"),
        (
            lambda manifest: manifest["cases"][0].__setitem__("review_receipt_digest", "not-hex"),
            "exit_corpus_schema_v1",
        ),
        (lambda manifest: manifest.__setitem__("ratified_manifest_digest", "0" * 64), "exit_corpus_digest_mismatch_v1"),
    ],
)
def test_tampered_manifest_fails_closed_with_the_expected_detail_code(
    tmp_path: Path, mutate: Callable[[dict[str, object]], None], detail_code: str
) -> None:
    manifest = _manifest()
    mutate(manifest)
    target = tmp_path / "tampered.json"
    _write_canonical(target, manifest)

    assert _detail_code(validate_corpus_manifest, target) == detail_code


def test_loader_round_trips_the_source_fields() -> None:
    source = _manifest()
    loaded = load_corpus_manifest(_fixture())

    assert loaded == source


def test_content_digest_is_pythonhashseed_independent() -> None:
    script = """
from pathlib import Path
from leitir.exit_corpus import content_digest, load_corpus_manifest
print(content_digest(load_corpus_manifest(Path('tests/fixtures/exit_corpus/corpus-valid.json'))))
"""
    outputs: list[bytes] = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script], cwd=Path(__file__).parents[1], env=environment
            )
        )

    assert outputs[0] == outputs[1] == outputs[2]


def test_cross_check_reports_every_standalone_gate_pin_as_valid() -> None:
    report = cross_check_against_gate(_fixture())

    assert report["valid"] is True
    assert report["case_count"] == 5
    assert all(case["valid"] is True for case in report["cases"])
