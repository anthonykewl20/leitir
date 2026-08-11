from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

import leitir.tree as tree_module
from leitir.adapters import PythonAdapter
from leitir.engine import ScopedSearcher
from leitir.search import CoverageStatus, Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
from leitir.tree import (
    GitHubTreeSource,
    TreeEnumerationError,
    TreeTruncatedError,
    TreeWalkBudgetError,
)

ROOT = "a" * 40
BLOB_A = "1" * 40
BLOB_B = "2" * 40
TREE_A = "b" * 40
TREE_B = "c" * 40
TREE_C = "d" * 40


def item(path: str, kind: str, sha: str, size: int = 1) -> dict[str, object]:
    value: dict[str, object] = {"path": path, "type": kind, "sha": sha, "mode": "100644"}
    if kind == "blob":
        value["size"] = size
    return value


class FakeTreeSource(GitHubTreeSource):
    def __init__(
        self,
        recursive: dict[str, object],
        trees: dict[str, dict[str, object]] | None = None,
        contents: dict[str, bytes] | None = None,
    ) -> None:
        super().__init__(base_url="https://api.example")
        self.recursive = recursive
        self.trees = trees or {}
        self.contents = contents or {}
        self.requests: list[str] = []

    def _get_json(self, url: str, headers: dict[str, str]) -> dict[str, object]:
        self.requests.append(url)
        if url.endswith("?recursive=1"):
            return self.recursive
        return self.trees[url.rsplit("/", 1)[-1]]

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self.contents[blob_sha]


def truncated_source(
    trees: dict[str, dict[str, object]],
    contents: dict[str, bytes] | None = None,
) -> FakeTreeSource:
    return FakeTreeSource({"truncated": True, "tree": [item("ignored", "blob", BLOB_A)]}, trees, contents)


def test_non_truncated_recursive_response_is_sorted_and_compatible():
    source = FakeTreeSource(
        {"truncated": False, "tree": [item("z.py", "blob", BLOB_B), item("a.py", "blob", BLOB_A)]}
    )

    blobs, recovered = source.list_blobs_ex("owner/repo", ROOT)

    assert [blob.path for blob in blobs] == ["a.py", "z.py"]
    assert recovered is False
    assert source.list_blobs("owner/repo", ROOT) == blobs


def test_truncated_recursive_response_recovers_all_blobs():
    source = truncated_source(
        {
            ROOT: {"tree": [item("root.py", "blob", BLOB_A), item("src", "tree", TREE_A)]},
            TREE_A: {"tree": [item("nested.py", "blob", BLOB_B)]},
        }
    )

    blobs, recovered = source.list_blobs_ex("owner/repo", ROOT)

    assert [blob.path for blob in blobs] == ["root.py", "src/nested.py"]
    assert recovered is True


def test_compat_wrapper_truncation_raises_after_one_request():
    source = truncated_source(
        {
            ROOT: {"tree": [item("root.py", "blob", BLOB_A), item("src", "tree", TREE_A)]},
            TREE_A: {"tree": [item("nested.py", "blob", BLOB_B)]},
        }
    )

    with pytest.raises(TreeTruncatedError) as error:
        source.list_blobs("owner/repo", ROOT)
    assert error.value.partial_blobs == ()
    assert len(source.requests) == 1


def test_repeated_tree_sha_at_distinct_prefixes_uses_cache():
    source = truncated_source(
        {
            ROOT: {"tree": [item("left", "tree", TREE_A), item("right", "tree", TREE_A)]},
            TREE_A: {"tree": [item("same.py", "blob", BLOB_A)]},
        }
    )

    blobs, recovered = source.list_blobs_ex("owner/repo", ROOT)

    assert recovered is True
    assert [blob.path for blob in blobs] == ["left/same.py", "right/same.py"]
    assert sum(url.endswith(TREE_A) for url in source.requests) == 1


def test_repeated_tree_sha_and_prefix_is_visited_once():
    source = truncated_source(
        {
            ROOT: {"tree": [item("same", "tree", TREE_A), item("same", "tree", TREE_A)]},
            TREE_A: {"tree": [item("leaf.py", "blob", BLOB_A)]},
        }
    )

    blobs, recovered = source.list_blobs_ex("owner/repo", ROOT)

    assert recovered is True
    assert [blob.path for blob in blobs] == ["same/leaf.py"]


def test_nested_truncation_fails_with_validated_partial_blobs():
    source = truncated_source(
        {
            ROOT: {"tree": [item("root.py", "blob", BLOB_A), item("src", "tree", TREE_A)]},
            TREE_A: {"truncated": True, "tree": [item("lost.py", "blob", BLOB_B)]},
        }
    )

    with pytest.raises(TreeTruncatedError) as error:
        source.list_blobs_ex("owner/repo", ROOT)

    assert [blob.path for blob in error.value.partial_blobs] == ["root.py"]


@pytest.mark.parametrize(
    "payload",
    [
        {"tree": [item("", "blob", BLOB_A)]},
        {"tree": [item("x", "blob", "bad")]},
        {},
        {"tree": [item("x", "blob", BLOB_A, -1)]},
    ],
)
def test_malformed_tree_responses_fail_closed(payload: dict[str, object]):
    source = FakeTreeSource(payload)
    with pytest.raises(TreeEnumerationError):
        source.list_blobs_ex("owner/repo", ROOT)


def test_non_dict_recursive_payload_fails_closed():
    source = FakeTreeSource(["not", "an", "object"])  # type: ignore[arg-type]
    with pytest.raises(TreeEnumerationError):
        source.list_blobs_ex("owner/repo", ROOT)


def test_non_dict_subtree_payload_fails_closed_with_partial_blobs():
    source = truncated_source({ROOT: ["not", "an", "object"]})  # type: ignore[dict-item]
    with pytest.raises(TreeEnumerationError):
        source.list_blobs_ex("owner/repo", ROOT)


def test_commit_entries_are_skipped_in_recursive_and_walk_paths():
    recursive = FakeTreeSource({"tree": [item("vendor", "commit", BLOB_A)]})
    assert recursive.list_blobs_ex("owner/repo", ROOT) == ((), False)

    walked = truncated_source(
        {ROOT: {"tree": [item("vendor", "commit", BLOB_A)]}}
    )
    assert walked.list_blobs_ex("owner/repo", ROOT) == ((), True)


def test_empty_tree_is_valid():
    source = FakeTreeSource({"tree": [], "truncated": False})
    assert source.list_blobs_ex("owner/repo", ROOT) == ((), False)


def test_mid_walk_malformed_item_preserves_partial_blobs():
    malformed = item("z.py", "unknown", TREE_A)
    source = truncated_source(
        {
            ROOT: {
                "tree": [
                    item("a.py", "blob", BLOB_A),
                    item("b.py", "blob", BLOB_B),
                    malformed,
                ]
            }
        }
    )

    with pytest.raises(TreeEnumerationError) as error:
        source.list_blobs_ex("owner/repo", ROOT)
    assert [blob.path for blob in error.value.partial_blobs] == ["a.py", "b.py"]


def test_depth_budget_exhaustion_preserves_partial_blobs(monkeypatch):
    monkeypatch.setattr(tree_module, "MAX_TREE_DEPTH", 0)
    source = truncated_source(
        {
            ROOT: {"tree": [item("root.py", "blob", BLOB_A), item("one", "tree", TREE_A)]},
            TREE_A: {"tree": [item("two", "tree", TREE_B)]},
            TREE_B: {"tree": [item("lost.py", "blob", BLOB_B)]},
        }
    )

    with pytest.raises(TreeWalkBudgetError) as error:
        source.list_blobs_ex("owner/repo", ROOT)
    assert [blob.path for blob in error.value.partial_blobs] == ["root.py"]


def test_request_budget_exhaustion_preserves_partial_blobs(monkeypatch):
    monkeypatch.setattr(tree_module, "MAX_TREE_REQUESTS", 1)
    source = truncated_source(
        {ROOT: {"tree": [item("root.py", "blob", BLOB_A), item("src", "tree", TREE_A)]}}
    )

    with pytest.raises(TreeWalkBudgetError) as error:
        source.list_blobs_ex("owner/repo", ROOT)
    assert [blob.path for blob in error.value.partial_blobs] == ["root.py"]


def test_entry_budget_exhaustion_preserves_partial_blobs(monkeypatch):
    monkeypatch.setattr(tree_module, "MAX_TREE_ENTRIES", 1)
    source = truncated_source(
        {ROOT: {"tree": [item("a.py", "blob", BLOB_A), item("z.py", "blob", BLOB_B)]}}
    )

    with pytest.raises(TreeWalkBudgetError) as error:
        source.list_blobs_ex("owner/repo", ROOT)
    assert [blob.path for blob in error.value.partial_blobs] == ["a.py"]


def test_enumeration_exception_hierarchy_keeps_budget_and_truncation_siblings():
    assert issubclass(TreeTruncatedError, TreeEnumerationError)
    assert issubclass(TreeWalkBudgetError, TreeEnumerationError)
    assert not issubclass(TreeWalkBudgetError, TreeTruncatedError)
    caught = False
    try:
        raise TreeWalkBudgetError("budget")
    except TreeTruncatedError:
        caught = True
    except TreeEnumerationError:
        pass
    assert caught is False


def test_tree_walk_path_collision_fails_closed():
    source = truncated_source(
        {
            ROOT: {"tree": [item("same", "tree", TREE_A), item("same", "tree", TREE_B)]},
            TREE_A: {"tree": [item("leaf.py", "blob", BLOB_A)]},
            TREE_B: {"tree": [item("leaf.py", "blob", BLOB_B)]},
        }
    )

    with pytest.raises(TreeEnumerationError, match="duplicate path"):
        source.list_blobs_ex("owner/repo", ROOT)


def search_spec() -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.IDENTIFIER, "target"),),
        scopes=(RepoScope("owner/repo", ROOT),),
    )


def test_scoped_search_reports_recovered_enumeration_as_partial_with_real_matches():
    data = b"def target():\n    pass\n"
    source = truncated_source(
        {ROOT: {"tree": [item("target.py", "blob", BLOB_A, len(data))]}},
        {BLOB_A: data},
    )

    report = ScopedSearcher(source, (PythonAdapter(),)).search(search_spec())

    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.coverage.incomplete_results is True
    assert report.coverage.files_excluded >= 1
    assert [match.source.path for match in report.matches] == ["target.py"]


def test_scoped_search_reports_non_truncated_enumeration_as_complete():
    data = b"def target():\n    pass\n"
    source = FakeTreeSource(
        {"tree": [item("target.py", "blob", BLOB_A, len(data))]}, contents={BLOB_A: data}
    )

    report = ScopedSearcher(source, (PythonAdapter(),)).search(search_spec())

    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
    assert report.coverage.incomplete_results is False
    assert report.coverage.files_excluded == 0


def test_recovered_scoped_search_is_hash_seed_independent():
    script = textwrap.dedent(
        """
        import json
        import leitir.engine
        from leitir.adapters import PythonAdapter
        from leitir.engine import ScopedSearcher
        from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
        from leitir.tree import GitHubTreeSource

        root, tree, blob_a, blob_b = "a" * 40, "b" * 40, "1" * 40, "2" * 40
        data = {blob_a: b"def target():\\n    pass\\n", blob_b: b"target = True\\n"}
        class Source(GitHubTreeSource):
            def __init__(self):
                super().__init__(base_url="https://api.example")
            def _get_json(self, url, headers):
                if url.endswith("?recursive=1"):
                    return {"truncated": True, "tree": [{"path": "ignored", "type": "blob", "sha": blob_a}]}
                sha = url.rsplit("/", 1)[-1]
                if sha == root:
                    return {"tree": [{"path": "z.py", "type": "blob", "sha": blob_b, "size": len(data[blob_b])}, {"path": "src", "type": "tree", "sha": tree}]}
                return {"tree": [{"path": "a.py", "type": "blob", "sha": blob_a, "size": len(data[blob_a])}]}
            def read_blob(self, slug, blob_sha):
                return data[blob_sha]

        leitir.engine._utc_now = lambda: "2026-08-10T00:00:00Z"
        source = Source()
        blobs, recovered = source.list_blobs_ex("owner/repo", root)
        spec = SearchSpec(mode=SearchMode.SCOPED_EXHAUSTIVE, must=(Predicate(PredicateKind.IDENTIFIER, "target"),), scopes=(RepoScope("owner/repo", root),))
        report = ScopedSearcher(source, (PythonAdapter(),)).search(spec)
        print(json.dumps({"blobs": [blob.path for blob in blobs], "recovered": recovered, "matches": [match.source.path for match in report.matches], "coverage": report.coverage.to_dict()}, sort_keys=True))
        """
    )
    outputs = []
    for seed in ("0", "1", "42"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = "src"
        outputs.append(subprocess.check_output([sys.executable, "-c", script], env=env))
    assert outputs[0] == outputs[1] == outputs[2]
    assert json.loads(outputs[0])["blobs"] == ["src/a.py", "z.py"]
