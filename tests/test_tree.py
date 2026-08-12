from __future__ import annotations

import base64
import io
import json

import pytest

from leitir.adapters import PythonAdapter
from leitir.engine import ScopedSearcher
from leitir.search import CoverageStatus, Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
from leitir.tree import BlobEntry, GitHubTreeSource


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
