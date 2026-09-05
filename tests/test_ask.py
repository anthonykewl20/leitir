"""Offline user-level intent tests for ``leitir ask`` (issue #266 A3).

``leitir ask`` answers "how do I do X with Y" in one call: it resolves the
exact package version from the caller's own project lockfile (never a
registry "latest" fallback, never ambient filesystem discovery), compiles
the free-text task into deterministic search predicates, and returns
ranked examples, verified signatures, and a citation line -- all offline
against an already-shelved, verified source, exactly like the existing
local-first ``get``/``info``/``lock`` offline contract.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

from test_offline_cached_resolution import SHA_A, _DeadRegistryResolver

from leitir.cli import ExitCode, main
from leitir.corpus import write_sources
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

DEMO_CODE = '''\
def connect(value: str, timeout: int = 30):
    """Open a connection and return it."""
    return value


def close(conn):
    return None


result = connect('ok')
'''


def _shelve_pypi_demo(
    tmp_path: Path, *, sha: str, version: str, code: str = DEMO_CODE
) -> tuple[Path, dict]:
    relative = f"repos/github.com/acme/demo/{sha}"
    source = tmp_path / relative
    source.mkdir(parents=True)
    (source / "demo.py").write_text(code, encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(source)
    manifest: dict[str, object] = {
        "spec": "pypi:demo",
        "ecosystem": "pypi",
        "name": "demo",
        "version": version,
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": sha,
        # Offline Git citations require a Git-bound shelf. An artifact
        # checksum alone cannot establish these repository/blob identities.
        "fetch_method": "codeload-tarball",
        "source": "git-commit",
        "parity": "exact",
        "repo_url": "https://github.com/acme/demo",
        "registry_url": f"https://pypi.org/project/demo/{version}/",
        "fetched_at": "2026-08-23T00:00:00Z",
        "verified": True,
        "verified_at": "2026-08-23T00:00:00Z",
        "tag": "v" + version,
        **manifest_digest_fields(digest, scope=scope),
    }
    (source / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    entry = {
        "name": "demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": sha,
        "path": relative,
        "fetched_at": "2026-08-23T00:00:00Z",
    }
    return source, entry


def _invoke(argv, resolver=None):
    out, err = io.StringIO(), io.StringIO()
    kwargs = {"stdout": out, "stderr": err}
    if resolver is not None:
        kwargs["resolver_factory"] = lambda _token: resolver
    code = main(argv, **kwargs)
    return code, out.getvalue(), err.getvalue()


def _pinned_project(tmp_path: Path, requirement: str) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text(requirement + "\n", encoding="utf-8")
    return project


def test_ask_resolves_pinned_version_and_answers_in_one_call(tmp_path):
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    project = _pinned_project(tmp_path, "demo==1.0.0")

    code, out, err = _invoke(
        [
            "ask",
            "how do I connect(value) to demo",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(project),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    document = json.loads(out)

    # Version resolved from the project's own lockfile, not from the agent.
    assert document["package"]["version"] == "1.0.0"
    assert document["package"]["version_source"] == "lockfile"
    assert document["package"]["lockfile"] == "requirements.txt"
    assert document["package"]["spec"] == "pypi:demo@1.0.0"

    # Provenance, signatures, examples, citation reused from info's machinery.
    assert document["provenance"]["commit_sha"] == SHA_A
    assert document["citation"].startswith("# Per ")
    assert isinstance(document["signatures"], list) and document["signatures"]
    assert isinstance(document["trust"], int)

    # The compiled predicates are transparent and re-runnable.
    compilation = document["query_compilation"]
    assert compilation["compiled"] is True
    assert {"kind": "call", "value": "connect", "language": ""} in compilation["predicates"]
    assert compilation["rerun_command"].startswith("leitir search")
    assert "--must call:connect" in compilation["rerun_command"]

    # Ranked real examples in the same call.
    assert document["matches"]
    for match in document["matches"]:
        assert match["source"]["commit_sha"] == SHA_A
        assert "permalink" in match["source"]


class _PinnedResolver:
    """Resolves exactly one known pypi pin; anything else is an error.

    ``leitir search --package`` (unlike ``get``/``info``/``lock``) always
    resolves live -- it has no local-first cached-shelf path -- so this
    test proves the compiled predicates are re-runnable through it, not
    that the re-run itself stays offline.
    """

    def resolve(self, ref):
        from leitir.resolver import Ecosystem, ResolutionError, ResolvedPackage
        from leitir.search import RepoScope

        if (
            ref.ecosystem is Ecosystem.PYPI
            and ref.name == "demo"
            and ref.version == "1.0.0"
        ):
            return ResolvedPackage(
                ref=ref,
                scope=RepoScope("acme/demo", SHA_A),
                tag="v1.0.0",
                registry_url="https://pypi.org/project/demo/1.0.0/",
            )
        raise ResolutionError(f"unknown {ref.name}=={ref.version}")


def test_ask_predicates_are_rerunnable_via_leitir_search(tmp_path):
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    project = _pinned_project(tmp_path, "demo==1.0.0")

    code, out, _err = _invoke(
        [
            "ask",
            "how do I connect(value) to demo",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(project),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )
    assert code == ExitCode.SUCCESS
    document = json.loads(out)
    matches_from_ask = document["matches"]

    code2, out2, err2 = _invoke(
        [
            "search",
            "--package", "demo",
            "--version", "1.0.0",
            "--ecosystem", "pypi",
            "--must", "call:connect",
            "--root", str(tmp_path),
        ],
        resolver=_PinnedResolver(),
    )
    assert code2 == ExitCode.SUCCESS, err2
    replayed = json.loads(out2)
    assert [m["source"]["path"] for m in matches_from_ask] == [
        m["source"]["path"] for m in replayed["matches"]
    ]


def test_ask_degrades_honestly_when_task_cannot_be_compiled(tmp_path):
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    project = _pinned_project(tmp_path, "demo==1.0.0")

    code, out, _err = _invoke(
        [
            "ask",
            "how do I do this with it",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(project),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, out
    document = json.loads(out)
    assert document["query_compilation"]["compiled"] is False
    assert document["query_compilation"]["predicates"] == []
    assert document["query_compilation"]["rerun_command"] is None
    assert document["matches"] is None
    # It still returns the honest package-level answer instead of nothing.
    assert document["package"]["version"] == "1.0.0"
    assert document["citation"].startswith("# Per ")


def test_ask_rejects_absent_lockfile(tmp_path):
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    empty_project = tmp_path / "empty-project"
    empty_project.mkdir()

    code, out, err = _invoke(
        [
            "ask",
            "how do I connect(value)",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(empty_project),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS
    assert out == ""
    assert "lockfile" in err
    assert "never falls back" in err


def test_ask_rejects_malformed_lockfile_rather_than_falling_back(tmp_path):
    """A present-but-malformed lockfile must reject, not silently fall
    back to the registry 'latest' version (ambient discovery)."""
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    project = tmp_path / "malformed-project"
    project.mkdir()
    # pyproject.toml with an unparseable [project.dependencies] table --
    # detect_installed_version_with_source returns None for "demo" here,
    # never "latest" from a live registry (which _DeadRegistryResolver
    # would raise on, proving no live call is attempted).
    (project / "pyproject.toml").write_text("not valid toml [[[", encoding="utf-8")

    code, out, err = _invoke(
        [
            "ask",
            "how do I connect(value)",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(project),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS
    assert out == ""
    assert "lockfile" in err


def test_ask_rejects_absent_pin_directory(tmp_path):
    code, out, err = _invoke(
        [
            "ask",
            "how do I connect(value)",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(tmp_path / "does-not-exist"),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )
    assert code == ExitCode.MALFORMED_USAGE
    assert out == ""
    assert "--pin directory not found" in err


def test_ask_accepts_a_lockfile_file_path_for_pin(tmp_path):
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    project = _pinned_project(tmp_path, "demo==1.0.0")

    code, out, err = _invoke(
        [
            "ask",
            "how do I connect(value)",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(project / "requirements.txt"),
            "--root", str(tmp_path),
            "--json",
        ],
        resolver=_DeadRegistryResolver(),
    )
    assert code == ExitCode.SUCCESS, err
    document = json.loads(out)
    assert document["package"]["version"] == "1.0.0"


def _run_ask_subprocess(tmp_path: Path, seed: str) -> subprocess.CompletedProcess:
    import os

    env = dict(**os.environ)
    env["PYTHONHASHSEED"] = seed
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent / "src")
    env["LEITIR_HOME"] = str(tmp_path / "home")
    return subprocess.run(
        [
            sys.executable, "-m", "leitir.cli",
            "ask", "how do I connect(value) to demo",
            "--package", "demo",
            "--ecosystem", "pypi",
            "--pin", str(tmp_path / "project"),
            "--root", str(tmp_path / "corpus"),
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_ask_is_deterministic_across_hash_seeds(tmp_path):
    corpus_root = tmp_path / "corpus"
    _shelve_pypi_demo(corpus_root, sha=SHA_A, version="1.0.0")
    write_sources(
        corpus_root,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    _pinned_project(tmp_path, "demo==1.0.0")

    outputs = []
    for seed in ("0", "1", "42", "12345"):
        result = _run_ask_subprocess(tmp_path, seed)
        assert result.returncode == 0, result.stderr
        outputs.append(result.stdout)

    assert len(set(outputs)) == 1, "ask output must be byte-identical across seeds"
    document = json.loads(outputs[0])
    assert document["package"]["version"] == "1.0.0"


def test_ask_second_call_after_first_is_still_offline_and_stable(tmp_path):
    """Regression: two ask calls in a row must not diverge or drift the
    shelf on disk (a repeat of the offline determinism/idempotency
    contract the rest of the corpus commands already carry)."""
    _shelve_pypi_demo(tmp_path, sha=SHA_A, version="1.0.0")
    write_sources(
        tmp_path,
        [
            {
                "name": "demo",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "path": f"repos/github.com/acme/demo/{SHA_A}",
                "fetched_at": "2026-08-23T00:00:00Z",
            }
        ],
    )
    project = _pinned_project(tmp_path, "demo==1.0.0")
    argv = [
        "ask", "how do I connect(value) to demo",
        "--package", "demo",
        "--ecosystem", "pypi",
        "--pin", str(project),
        "--root", str(tmp_path),
        "--json",
    ]

    code1, out1, err1 = _invoke(argv, resolver=_DeadRegistryResolver())
    code2, out2, err2 = _invoke(argv, resolver=_DeadRegistryResolver())

    assert code1 == ExitCode.SUCCESS, err1
    assert code2 == ExitCode.SUCCESS, err2
    assert out1 == out2
