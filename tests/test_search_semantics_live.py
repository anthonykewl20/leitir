"""Actual Linux and Requests bytes, live transport and public query replay."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="real upstream search probes require LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_live_linux_stream_exclusions_match_buffered_scoring() -> None:
    from leitir.adapters.registry import build_adapters
    from leitir.engine import _score_content_ex
    from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
    from leitir.streaming import score_blob_stream
    from leitir.tree import BlobEntry, GitHubTreeSource

    slug, commit = "torvalds/linux", "d58772d8520c7ef247c4b95c9bd76d3a25da9ff5"
    path = "drivers/accel/habanalabs/include/gaudi2/asic_reg/gaudi2_blocks_linux_driver.h"
    sha, size = "3caee4515ad62aa7b8031b93bccb4e69b9ed0e64", 2456864
    source = GitHubTreeSource(token=os.environ.get("GITHUB_TOKEN"))
    data = b"".join(source.read_blob_stream(slug, sha))
    with urlopen(f"https://raw.githubusercontent.com/{slug}/{commit}/{path}", timeout=60) as response:
        assert response.read() == data
    assert hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() == sha
    content = data.decode()
    names = re.findall(r"^#define\s+(\w+)", content, re.M)
    adapter = build_adapters(("c",))[0]
    for excluded in ((), (Predicate(PredicateKind.IDENTIFIER, names[-1]),)):
        spec = SearchSpec(SearchMode.SCOPED_EXHAUSTIVE, must=(Predicate(PredicateKind.IDENTIFIER, names[0]),), must_not=excluded, scopes=(RepoScope(slug, commit),))
        regular, unavailable = _score_content_ex(content, adapter, slug, commit, path, sha, spec.must, spec.should, spec.must_not)
        streamed, unsupported, parser = score_blob_stream(source, BlobEntry(path, sha, size), slug=slug, commit_sha=commit, path=path, adapter=adapter, spec=spec, retry=lambda operation: operation())
        assert streamed == regular
        assert not (unavailable or unsupported or parser)
        assert len(regular) == (0 if excluded else 2)


@pytest.mark.live
def test_real_requests_query_replay_boosts_and_ast_labels(tmp_path: Path) -> None:
    from leitir.ask import rerun_search_command
    from leitir.search import Predicate, PredicateKind

    pin = "0e322af87745eff34caffe4df68456ebc20d9068"
    def invoke(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "leitir.cli", *args, "--root", str(tmp_path), "--json"], capture_output=True, text=True, timeout=240, check=False)
    fetched = invoke("get", "github:psf/requests@" + pin)
    assert fetched.returncode == 0, fetched.stderr
    args = ("search", "--repo", "psf/requests", "--commit", pin)
    regex = invoke(*args, "--must", "regex:(?:Session|Request)")
    assert regex.returncode == 0, regex.stderr
    assert json.loads(regex.stdout)["matches"]
    baseline = invoke(*args, "--must", "identifier:get", "--must", "path:src/requests/api.py")
    boosted = invoke(*args, "--must", "identifier:get", "--must", "path:src/requests/api.py", "--should", "identifier:params", "--should", "identifier:AAADoesNotExist")
    assert baseline.returncode == boosted.returncode == 0
    original = {m["source"]["start_line"]: m["score"] for m in json.loads(baseline.stdout)["matches"]}
    assert any(m["score"] > original[m["source"]["start_line"]] for m in json.loads(boosted.stdout)["matches"])
    ast = invoke(*args, "--must", "symbol_definition:Session", "--ast")
    assert ast.returncode == 0, ast.stderr
    assert any(m["method"] == "ast" for m in json.loads(ast.stdout)["matches"])
    predicate = Predicate(PredicateKind.EXACT_TEXT, "https://httpbin.org/get")
    command = rerun_search_command(package="requests", version="2.32.3", ecosystem="pypi", predicates=(predicate,))
    tokens = shlex.split(command)
    replay = invoke(*tokens[1:])
    assert replay.returncode == 0, replay.stderr
