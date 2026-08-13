from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from _http_server import json_body, routed_server

from leitir.bench import load_manifest
from leitir.cli import ExitCode, main
from leitir.corpus_bench import (
    CorpusBenchmarkManifest,
    CorpusBenchmarkRun,
    CorpusBenchmarkRunner,
    CorpusBenchmarkTask,
    CorpusBenchmarkTaskRun,
    CorpusExpectedFile,
    manifest_from_dict,
)
from leitir.materialize import MANIFEST_NAME
from leitir.tree import GitHubTreeSource

SHA = "d" * 40


def _tarball() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        content = b"offline benchmark proof\n"
        member = tarfile.TarInfo(f"demo-{SHA}/proof.txt")
        member.size = len(content)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _benchmark_manifest(
    *, expected_sha: str = SHA, expected_line: str = "offline benchmark proof"
) -> CorpusBenchmarkManifest:
    tasks = tuple(
        CorpusBenchmarkTask(
            task_id=f"offline-{number}",
            spec=f"acme/demo@{SHA}",
            expected_owner="acme",
            expected_repo="demo",
            expected_commit_sha=expected_sha,
            expected_files=(CorpusExpectedFile("proof.txt", expected_line),),
            pin_source="deterministic local fixture",
        )
        for number in range(4)
    )
    return CorpusBenchmarkManifest(
        "leitir-corpus-benchmark-manifest-v1", "corpus-v1", tasks
    )


def _routes() -> dict[str, tuple[int, dict[str, str], bytes]]:
    content = b"offline benchmark proof\n"
    tree = json_body(
        {
            "sha": SHA,
            "truncated": False,
            "tree": [
                {
                    "path": "proof.txt",
                    "type": "blob",
                    "size": len(content),
                    "mode": "100644",
                    "sha": GitHubTreeSource.git_blob_sha(content),
                }
            ]
        }
    )
    return {
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball()),
        f"/repos/acme/demo/git/trees/{SHA}": (200, {}, tree),
    }


def test_packaged_corpus_manifest_is_valid_and_pinned():
    manifest = load_manifest("corpus-v1")
    assert isinstance(manifest, CorpusBenchmarkManifest)
    assert len(manifest.tasks) == 4
    assert {task.spec.split(":", 1)[0] for task in manifest.tasks} >= {"npm", "pypi", "crates"}
    assert any(task.spec == "octocat/Hello-World" for task in manifest.tasks)
    for task in manifest.tasks:
        assert len(task.expected_commit_sha) == 40
        assert task.expected_files
        assert task.pin_source


def test_corpus_manifest_can_be_loaded_by_explicit_path():
    path = Path(__file__).parents[1] / "src/leitir/benchmarks/corpus-v1/manifest.json"
    assert load_manifest(path).digest() == load_manifest("corpus-v1").digest()


def test_corpus_manifest_rejects_missing_expected_files():
    raw = load_manifest("corpus-v1").to_dict()
    raw["tasks"][0]["expected_files"] = []
    with pytest.raises(ValueError, match="expected file"):
        manifest_from_dict(raw)


def test_corpus_manifest_round_trip_is_canonical():
    manifest = load_manifest("corpus-v1")
    assert json.loads(manifest.to_json()) == manifest.to_dict()


def test_cli_discovers_and_runs_packaged_corpus_manifest(monkeypatch):
    manifest = load_manifest("corpus-v1")

    def fake_run(self, received):
        assert received.digest() == manifest.digest()
        task = received.tasks[0]
        return CorpusBenchmarkRun(
            received.benchmark_id,
            received.digest(),
            (
                CorpusBenchmarkTaskRun(
                    task.task_id,
                    task.expected_owner,
                    task.expected_repo,
                    task.expected_commit_sha,
                    task.expected_files,
                ),
            ),
        )

    monkeypatch.setattr(CorpusBenchmarkRunner, "run", fake_run)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["bench", "--manifest", "corpus-v1"],
        resolver_factory=lambda _token: object(),
        code_search_factory=lambda _token: object(),
        tree_source_factory=lambda _token: pytest.fail("search runner was selected"),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out.getvalue())["benchmark"]["id"] == "corpus-v1"
    assert "benchmark=corpus-v1" in err.getvalue()


def test_runner_resolves_materializes_and_verifies_offline(monkeypatch):
    with routed_server(_routes()) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        run = CorpusBenchmarkRunner(object(), object()).run(_benchmark_manifest())

    assert [task.task_id for task in run.tasks] == [f"offline-{number}" for number in range(4)]
    assert all(task.resolved_commit_sha == SHA for task in run.tasks)
    assert server.state.request_paths == [
        f"/acme/demo/tar.gz/{SHA}",
        f"/repos/acme/demo/git/trees/{SHA}",
    ]


def test_runner_rejects_commit_mismatch():
    with pytest.raises(ValueError, match="resolved .* expected"):
        CorpusBenchmarkRunner(object(), object()).run(
            _benchmark_manifest(expected_sha="e" * 40)
        )


def test_runner_rejects_missing_expected_line(monkeypatch):
    with routed_server(_routes()) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        with pytest.raises(ValueError, match="expected line absent"):
            CorpusBenchmarkRunner(object(), object()).run(
                _benchmark_manifest(expected_line="not present")
            )


def test_runner_rejects_unverified_extraction(monkeypatch):
    import leitir.corpus

    real_materialize = leitir.corpus.materialize_source

    def mark_unverified(*args: object, **kwargs: object) -> Path:
        target = real_materialize(*args, **kwargs)  # type: ignore[arg-type]
        manifest_path = target / MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["verified"] = False
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return target

    with routed_server(_routes()) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setattr(leitir.corpus, "materialize_source", mark_unverified)
        with pytest.raises(ValueError, match="extraction was not verified"):
            CorpusBenchmarkRunner(object(), object()).run(_benchmark_manifest())
