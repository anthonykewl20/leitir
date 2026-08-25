from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.examples import (
    CLASSIFICATION_DETAIL_CODE,
    CLASSIFICATION_METHOD,
    EXAMPLES_SCHEMA_VERSION,
    ExampleClass,
    ExampleClassification,
    classify_example,
    extract_examples,
    valid_serialized_classification,
)


def _record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "path": "docs/usage.md",
        "line": 7,
        "language": "python",
        "code": "try:\n    configure(option=True)\nexcept Error:\n    pass",
        "symbols": ["configure"],
    }
    record.update(changes)
    return record


def test_concrete_classification_is_sorted_unique_multilabel_and_evidence_backed() -> None:
    record = _record()

    result = classify_example(record)

    assert result.labels == (
        ExampleClass.MINIMAL_USAGE,
        ExampleClass.ERROR_HANDLING,
        ExampleClass.CONFIGURATION,
    )
    assert result.method == CLASSIFICATION_METHOD
    assert result.confidence_bps == 8500
    assert tuple(item.label for item in result.evidence) == result.labels
    assert all(item.path == record["path"] and item.line == record["line"] for item in result.evidence)
    assert all(item.symbols == ("configure",) for item in result.evidence)
    assert len({item.code_sha256 for item in result.evidence}) == 1


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_client.py", (ExampleClass.ERROR_HANDLING, ExampleClass.CONFIGURATION, ExampleClass.UNIT_TEST)),
        (
            "tests/integration/test_client.py",
            (ExampleClass.ERROR_HANDLING, ExampleClass.CONFIGURATION, ExampleClass.INTEGRATION_TEST),
        ),
        (
            "examples/production/client.py",
            (ExampleClass.PRODUCTION_USAGE, ExampleClass.ERROR_HANDLING, ExampleClass.CONFIGURATION),
        ),
    ],
)
def test_exact_path_rules_classify_without_calling_tests_production(
    path: str, expected: tuple[ExampleClass, ...]
) -> None:
    assert classify_example(_record(path=path)).labels == expected


@pytest.mark.parametrize("alias", ["pycon", "python2", "python3", "py", "ipython", "doctest"])
def test_python_fence_aliases_classify_as_python_usage(alias: str) -> None:
    record = _record(
        language=alias,
        code=">>> from tabulate import tabulate\n>>> print(tabulate([[1, 2]]))\n",
        symbols=["tabulate"],
    )

    result = classify_example(record)

    assert ExampleClass.MINIMAL_USAGE in result.labels
    assert ExampleClass.UNKNOWN not in result.labels
    assert all(item.language == "python" for item in result.evidence)


def test_pip_install_only_shell_snippet_classifies_as_unknown_not_usage() -> None:
    # This exercises classify_example() in isolation; ranking (extract_examples
    # sorting install-only snippets below real usage) is covered separately by
    # test_install_only_snippets_rank_below_real_usage_regardless_of_symbol_count
    # in tests/test_examples.py.
    record = _record(
        path="README.md",
        language="shell",
        code="pip install tabulate",
        symbols=["tabulate"],
    )

    result = classify_example(record)

    assert ExampleClass.MINIMAL_USAGE not in result.labels
    assert result.labels == (ExampleClass.UNKNOWN,)


def test_shell_snippet_with_more_than_install_still_classifies_as_usage() -> None:
    record = _record(
        path="README.md",
        language="shell",
        code="pip install tabulate\ntabulate --help",
        symbols=["tabulate"],
    )

    result = classify_example(record)

    assert ExampleClass.MINIMAL_USAGE in result.labels


def test_unsupported_language_is_unknown_and_unknown_is_exclusive() -> None:
    result = classify_example(_record(language="brainfuck"))

    assert result.labels == (ExampleClass.UNKNOWN,)
    assert result.confidence_bps is None
    assert tuple(item.label for item in result.evidence) == (ExampleClass.UNKNOWN,)


def test_unrecognized_label_rejects_with_registered_bts_reason() -> None:
    with pytest.raises(BTSError) as caught:
        ExampleClassification(
            labels=("future_label",),  # type: ignore[arg-type]
            method=CLASSIFICATION_METHOD,
            confidence_bps=9000,
            evidence=(),
        )

    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert caught.value.evidence.detail_code == CLASSIFICATION_DETAIL_CODE


def test_unknown_cannot_be_mixed_with_concrete_labels() -> None:
    unknown = classify_example(_record(language="unsupported"))
    with pytest.raises(BTSError):
        ExampleClassification(
            labels=(ExampleClass.MINIMAL_USAGE, ExampleClass.UNKNOWN),
            method=CLASSIFICATION_METHOD,
            confidence_bps=None,
            evidence=unknown.evidence,
        )


def test_serialized_classification_rejects_tampered_test_as_production() -> None:
    record = _record(path="tests/test_client.py")
    record["classification"] = classify_example(record).as_dict()
    assert valid_serialized_classification(record)

    tampered = json.loads(json.dumps(record))
    tampered["classification"]["labels"] = ["production_usage"]
    assert not valid_serialized_classification(tampered)


def test_extract_examples_adds_classification_without_removing_existing_fields(tmp_path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "use.py").write_text("connect()\n", encoding="utf-8")
    api = {"schema_version": 1, "symbols": [{"name": "connect", "qualified_name": "pkg.connect"}]}

    index = extract_examples(tmp_path, api)

    assert index["schema_version"] == EXAMPLES_SCHEMA_VERSION
    snippet = index["snippets"][0]
    assert {"path", "line", "language", "code", "symbols"} <= set(snippet)
    assert snippet["classification"]["labels"] == ["minimal_usage"]
    assert valid_serialized_classification(snippet)


def test_classification_is_identical_across_python_hash_seeds() -> None:
    script = """
import json
from leitir.examples import classify_example
record = {
    "path": "docs/usage.md", "line": 7, "language": "python",
    "code": "try:\\n    configure(option=True)\\nexcept Error:\\n    pass",
    "symbols": ["configure"],
}
print(json.dumps(classify_example(record).as_dict(), sort_keys=True, separators=(",", ":")))
"""
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(os.environ, PYTHONHASHSEED=seed)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(completed.stdout)

    assert outputs[0] == outputs[1] == outputs[2]
