from __future__ import annotations

import json

from leitir.corpus import examples_index_path, read_examples_index, write_examples_index
from leitir.examples import extract_examples, extract_snippets, match_symbols


def _api(*names):
    return {
        "schema_version": 1,
        "symbols": [
            {"name": name, "qualified_name": f"pkg.{name}"} for name in names
        ],
    }


def test_extracts_markdown_fences_and_whole_code_files_with_provenance(tmp_path):
    (tmp_path / "README.md").write_text(
        "intro\n```python\nfrom pkg import alpha\nalpha()\n```\n", encoding="utf-8"
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_demo.py").write_text("def test_it():\n    alpha()\n", encoding="utf-8")
    (tmp_path / "src.py").write_text("alpha()\n", encoding="utf-8")

    snippets = extract_snippets(tmp_path)

    assert [(item["path"], item["line"], item["language"]) for item in snippets] == [
        ("README.md", 3, "python"),
        ("tests/test_demo.py", 1, "python"),
    ]


def test_pycon_fence_is_normalized_to_python_language(tmp_path):
    (tmp_path / "README.md").write_text(
        "```pycon\n>>> from pkg import alpha\n>>> alpha()\n```\n", encoding="utf-8"
    )

    snippets = extract_snippets(tmp_path)

    assert [(item["path"], item["language"]) for item in snippets] == [("README.md", "python")]


def test_ranking_drops_zero_matches_is_deterministic_and_capped(tmp_path):
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "a.py").write_text("alpha(); beta()\n", encoding="utf-8")
    (examples / "b.py").write_text("alpha()\n", encoding="utf-8")
    (examples / "c.py").write_text("unrelated()\n", encoding="utf-8")

    first = extract_examples(tmp_path, _api("alpha", "beta"), limit=1)
    second = extract_examples(tmp_path, _api("alpha", "beta"), limit=1)

    assert first == second
    assert first["symbols_source"] == "api_index"
    assert [item["path"] for item in first["snippets"]] == ["examples/a.py"]
    assert first["snippets"][0]["symbols"] == ["alpha", "beta"]


def test_ties_use_path_then_line_before_length(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text(
        "```py\nalpha()\n```\n```py\nalpha() # much longer\n```\n", encoding="utf-8"
    )
    index = extract_examples(tmp_path, _api("alpha"))
    assert [(item["line"], item["code"]) for item in index["snippets"]] == [
        (2, "alpha()"),
        (5, "alpha() # much longer"),
    ]


def test_install_only_snippets_rank_below_real_usage_regardless_of_symbol_count(tmp_path):
    # A pure "pip install tabulate" block matches the "tabulate" symbol just
    # like real usage does, and by symbol-count alone would tie or even beat
    # a real usage example with fewer matched symbols. Ranking must consult
    # classification so the install-only snippet is demoted below genuine
    # usage instead of only being relabeled UNKNOWN in isolation.
    readme = tmp_path / "README.md"
    readme.write_text(
        "```shell\npip install tabulate\n```\n"
        "```python\nfrom tabulate import tabulate\ntabulate([[1, 2]])\n```\n",
        encoding="utf-8",
    )

    index = extract_examples(tmp_path, _api("tabulate"))

    assert [item["classification"]["labels"] for item in index["snippets"]] == [
        ["minimal_usage"],
        ["unknown"],
    ]
    assert index["snippets"][0]["language"] == "python"
    assert index["snippets"][1]["language"] == "shell"


def test_matching_uses_identifier_boundaries():
    assert match_symbols("alpha(); pkg.beta()", ("alpha", "pkg.beta", "bet")) == [
        "alpha",
        "pkg.beta",
    ]


def test_empty_missing_and_unreadable_trees_are_safe(tmp_path):
    assert extract_examples(tmp_path / "missing", _api("alpha"))["snippets"] == []
    assert extract_examples(tmp_path, _api("alpha"))["snippets"] == []


def test_examples_cache_path_and_round_trip(tmp_path):
    entry = {"name": "demo", "host": "github.com", "commit_sha": "a" * 40}
    manifest = {"ecosystem": "pypi", "version": "1.2.3"}
    index = {"schema_version": 1, "symbols_source": "api_index", "snippets": []}
    path = write_examples_index(tmp_path, entry, manifest, index)
    assert path == tmp_path / "examples/pypi/demo/1.2.3/index.json"
    assert examples_index_path(tmp_path, entry, manifest) == path
    assert read_examples_index(tmp_path, entry, manifest) == index
    assert json.loads(path.read_text(encoding="utf-8")) == index
