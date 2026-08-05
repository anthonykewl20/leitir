from __future__ import annotations

import io

import pytest

from leitir.tree import GitHubTreeSource


@pytest.mark.parametrize("token", ["bad\x00token", "bad\x7ftoken"])
def test_tree_token_control_character_is_rejected_without_disclosure(token):
    with pytest.raises(ValueError) as error:
        GitHubTreeSource(token=token)._headers()
    assert token not in str(error.value)


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
