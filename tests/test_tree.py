from __future__ import annotations

import base64
import io
import json
import os
from urllib.error import HTTPError, URLError

import pytest

from leitir.adapters import PythonAdapter
from leitir.engine import ScopedSearcher
from leitir.search import CoverageStatus, Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
from leitir.tree import (
    BlobEntry,
    GitHubTreeSource,
    TreeEnumerationError,
    TreeReadError,
)


@pytest.mark.parametrize("token", ["bad\x00token", "bad\x7ftoken"])
def test_tree_token_control_character_is_rejected_without_disclosure(token):
    with pytest.raises(ValueError) as error:
        GitHubTreeSource(token=token)._headers()
    assert token not in str(error.value)


@pytest.mark.parametrize(
    "base_url", ["http://api.github.com", "https://github-mirror.example"]
)
def test_tree_token_is_not_attached_to_untrusted_api_endpoint(base_url):
    token = "sentinel-tree-token"
    headers = GitHubTreeSource(token=token, base_url=base_url)._headers()

    assert "Authorization" not in headers
    from leitir.logging import redact

    assert token not in redact(f"request failed with {token}")


def test_read_blob_by_path_quotes_slug_and_path(monkeypatch):
    captured = {}

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return Response(b"content")

    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    source = GitHubTreeSource(raw_base_url="https://raw.example", max_attempts=1)

    assert source.read_blob_by_path("owner/re#po", "a" * 40, "dir/a#b%25") == b"content"
    assert captured["url"] == (
        f"https://raw.example/owner/re%23po/{'a' * 40}/dir/a%23b%2525"
    )


def _assert_tampered_blob_is_excluded(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, object], blob_sha: str, size: int
) -> None:
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    class Source(GitHubTreeSource):
        def list_blobs_ex(self, slug: str, commit_sha: str):
            return (BlobEntry("target.py", blob_sha, size),), False

    monkeypatch.setattr(
        "leitir._http.safe_urlopen",
        lambda request, timeout: Response(json.dumps(payload).encode()),
    )
    spec = SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.IDENTIFIER, "target"),),
        scopes=(RepoScope("owner/repo", "a" * 40),),
    )

    report = ScopedSearcher(Source(max_attempts=1), (PythonAdapter(),)).search(spec)

    assert report.matches == ()
    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.coverage.files_excluded == 1


def test_same_size_one_byte_flip_is_excluded_and_partial(monkeypatch):
    original = b"def target():\n    pass\n"
    tampered = original[:-2] + b"x\n"
    blob_sha = GitHubTreeSource.git_blob_sha(original)
    _assert_tampered_blob_is_excluded(
        monkeypatch,
        {
            "content": base64.b64encode(tampered).decode(),
            "sha": blob_sha,
            "size": len(tampered),
        },
        blob_sha,
        len(original),
    )


def test_blob_size_mismatch_is_excluded_and_partial(monkeypatch):
    data = b"def target():\n    pass\n"
    blob_sha = GitHubTreeSource.git_blob_sha(data)
    _assert_tampered_blob_is_excluded(
        monkeypatch,
        {
            "content": base64.b64encode(data).decode(),
            "sha": blob_sha,
            "size": len(data) + 1,
        },
        blob_sha,
        len(data),
    )


def test_wrong_blob_response_sha_is_excluded_and_partial(monkeypatch):
    data = b"def target():\n    pass\n"
    blob_sha = GitHubTreeSource.git_blob_sha(data)
    _assert_tampered_blob_is_excluded(
        monkeypatch,
        {
            "content": base64.b64encode(data).decode(),
            "sha": "b" * 40,
            "size": len(data),
        },
        blob_sha,
        len(data),
    )


# --- Truncated-tree fallback for GitHubTreeSource.list_blobs (issue #187) ---

ROOT_SHA = "a" * 40
SUBTREE_SHA = "b" * 40
NESTED_SHA = "c" * 40
BLOB_ROOT_SHA = "1" * 40
BLOB_SUB_SHA = "2" * 40
BLOB_NESTED_SHA = "3" * 40

TRUNCATED_RECURSIVE_PAGE = {
    "sha": ROOT_SHA,
    "truncated": True,
    "tree": [{"path": "ignored", "type": "blob", "sha": BLOB_ROOT_SHA, "mode": "100644", "size": 1}],
}


def _tree_item(path: str, kind: str, sha: str, size: int = 1) -> dict[str, object]:
    value: dict[str, object] = {"path": path, "type": kind, "sha": sha, "mode": "100644"}
    if kind == "blob":
        value["size"] = size
    return value


class _ScriptedTreeSource(GitHubTreeSource):
    """GitHubTreeSource answering from scripted tree pages, recording requests."""

    def __init__(
        self,
        recursive: dict[str, object],
        trees: dict[str, object],
    ) -> None:
        super().__init__(base_url="https://api.example")
        self._scripted_recursive = recursive
        self._scripted_trees = trees
        self.requests: list[str] = []

    def _get_json(self, url: str, headers: dict[str, str]) -> dict:
        self.requests.append(url)
        if url.endswith("?recursive=1"):
            return self._scripted_recursive
        return self._scripted_trees[url.rsplit("/", 1)[-1]]


def _consistent_walk_pages() -> dict[str, object]:
    return {
        ROOT_SHA: {
            "sha": ROOT_SHA,
            "truncated": False,
            "tree": [
                _tree_item("root.py", "blob", BLOB_ROOT_SHA),
                _tree_item("src", "tree", SUBTREE_SHA),
            ],
        },
        SUBTREE_SHA: {
            "sha": SUBTREE_SHA,
            "truncated": False,
            "tree": [
                _tree_item("nested.py", "blob", BLOB_SUB_SHA),
                _tree_item("deep", "tree", NESTED_SHA),
            ],
        },
        NESTED_SHA: {
            "sha": NESTED_SHA,
            "truncated": False,
            "tree": [_tree_item("leaf.py", "blob", BLOB_NESTED_SHA)],
        },
    }


def test_list_blobs_truncated_recursive_listing_completes_via_walk():
    source = _ScriptedTreeSource(TRUNCATED_RECURSIVE_PAGE, _consistent_walk_pages())

    blobs = source.list_blobs("owner/repo", ROOT_SHA)

    assert [blob.path for blob in blobs] == [
        "root.py",
        "src/deep/leaf.py",
        "src/nested.py",
    ]
    assert [blob.blob_sha for blob in blobs] == [
        BLOB_ROOT_SHA,
        BLOB_NESTED_SHA,
        BLOB_SUB_SHA,
    ]
    # One recursive probe plus one non-recursive page per distinct subtree.
    assert len(source.requests) == 4
    assert source.requests[0].endswith("?recursive=1")
    assert [url.rsplit("/", 1)[-1] for url in source.requests[1:]] == [
        ROOT_SHA,
        SUBTREE_SHA,
        NESTED_SHA,
    ]
    # The wrapper's universe equals the recovery-aware API's universe.
    assert blobs == source.list_blobs_ex("owner/repo", ROOT_SHA)[0]


def test_list_blobs_inconsistent_pagination_fails_closed_with_partial_blobs():
    # The subtree page answers under a SHA other than the one requested:
    # enumeration must reject the whole result — never a silent partial list
    # or a "sampled" downgrade.
    source = _ScriptedTreeSource(
        TRUNCATED_RECURSIVE_PAGE,
        {
            ROOT_SHA: _consistent_walk_pages()[ROOT_SHA],
            SUBTREE_SHA: {
                "sha": NESTED_SHA,
                "truncated": False,
                "tree": [_tree_item("nested.py", "blob", BLOB_SUB_SHA)],
            },
        },
    )

    with pytest.raises(TreeEnumerationError) as error:
        source.list_blobs("owner/repo", ROOT_SHA)

    assert "does not match requested tree" in str(error.value)
    assert [blob.path for blob in error.value.partial_blobs] == ["root.py"]


@pytest.mark.parametrize(
    "bad_page",
    [
        ["not", "a", "dict"],
        {"sha": SUBTREE_SHA, "truncated": False},
        {"sha": SUBTREE_SHA, "truncated": False, "tree": "not-a-list"},
        {
            "sha": SUBTREE_SHA,
            "truncated": False,
            "tree": [_tree_item("nested.py", "blob", "not-a-sha")],
        },
    ],
)
def test_list_blobs_malformed_subtree_page_fails_typed(bad_page: object):
    source = _ScriptedTreeSource(
        TRUNCATED_RECURSIVE_PAGE,
        {
            ROOT_SHA: _consistent_walk_pages()[ROOT_SHA],
            SUBTREE_SHA: bad_page,
        },
    )

    with pytest.raises(TreeEnumerationError):
        source.list_blobs("owner/repo", ROOT_SHA)


class _JsonResponse(io.BytesIO):
    def __enter__(self) -> _JsonResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _json_response(payload: dict[str, object]) -> _JsonResponse:
    return _JsonResponse(json.dumps(payload).encode())


def test_list_blobs_mid_walk_network_failure_raises_typed_error(monkeypatch):
    pages = {
        f"https://api.example/repos/owner/repo/git/trees/{ROOT_SHA}?recursive=1": TRUNCATED_RECURSIVE_PAGE,
        f"https://api.example/repos/owner/repo/git/trees/{ROOT_SHA}": _consistent_walk_pages()[ROOT_SHA],
    }

    def fake_urlopen(request, timeout):
        if request.full_url not in pages:
            raise URLError("connection reset mid-walk")
        return _json_response(pages[request.full_url])

    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    source = GitHubTreeSource(
        base_url="https://api.example",
        max_attempts=2,
        base_delay=0.0,
        sleeper=lambda _seconds: None,
    )

    with pytest.raises(TreeReadError, match="connection reset mid-walk"):
        source.list_blobs("owner/repo", ROOT_SHA)


def test_list_blobs_rate_limit_exhaustion_retries_then_raises_typed_error(monkeypatch):
    from email.message import Message

    calls = {"subtree": 0}

    def fake_urlopen(request, timeout):
        url = request.full_url
        if url.endswith("?recursive=1"):
            return _json_response(TRUNCATED_RECURSIVE_PAGE)
        calls["subtree"] += 1
        headers = Message()
        headers["Retry-After"] = "0"
        raise HTTPError(url, 429, "Too Many Requests", headers, None)

    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    source = GitHubTreeSource(
        base_url="https://api.example",
        max_attempts=3,
        base_delay=0.0,
        sleeper=lambda _seconds: None,
    )

    with pytest.raises(TreeReadError, match="HTTP 429"):
        source.list_blobs("owner/repo", ROOT_SHA)

    # Existing per-page make_retry semantics: the rate-limited page was
    # retried through the full attempt budget before the typed failure.
    assert calls["subtree"] == 3


live_gate = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)

TYPESCRIPT_SLUG = "microsoft/TypeScript"
TYPESCRIPT_COMMIT = "b465fdbfe175304d9b977da137b2c178ae1091d3"
# The truncated recursive listing at this pinned commit returned 53,309 blob
# entries (55,311 total, truncated=true; OBSERVED 2026-08-18), so a completed
# enumeration must exceed it.
TYPESCRIPT_TRUNCATED_BLOB_COUNT = 53_309


@live_gate
def test_live_list_blobs_truncated_tree_fallback():
    class _CountingSource(GitHubTreeSource):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)  # type: ignore[arg-type]
            self.api_calls = 0

        def _get_json(self, url: str, headers: dict[str, str]) -> dict:
            self.api_calls += 1
            return super()._get_json(url, headers)

    source = _CountingSource(
        token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    )

    # Must not raise TreeTruncatedError and must not downgrade to a sample.
    blobs = source.list_blobs(TYPESCRIPT_SLUG, TYPESCRIPT_COMMIT)

    paths = [blob.path for blob in blobs]
    assert paths == sorted(paths)
    assert len(set(paths)) == len(paths)
    assert len(blobs) > TYPESCRIPT_TRUNCATED_BLOB_COUNT
    print(
        f"typescript fallback walk: blobs={len(blobs)} api_calls={source.api_calls}"
    )
