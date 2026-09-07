"""Real user journeys through an installed wheel, with retained command evidence.

No Leitir imports, fake transports, generated source repositories, or principal
operation mocks. Pins identify upstream inputs; assertions derive results from
those downloaded bytes and independent GitHub tree metadata.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, TypeAlias
from urllib.request import Request, urlopen

import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.real_user,
    pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
                       reason="installed real-provider journeys require LEITIR_ENABLE_LIVE_E2E=1"),
]

REPO = Path(__file__).resolve().parents[1]
PIN = "85442b8032cb7bae72866dfd7782234a98dd2fb7"
NEXT_PIN = "d8e3b31b734926ebbcaff654279f6855a73e052f"
SPEC = f"github:pypa/packaging@{PIN}"
Journey: TypeAlias = tuple["Journal", Path, Path]


class Journal:
    def __init__(self, directory: Path, env: dict[str, str]) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=False)
        self.env = env
        self.records: list[dict[str, object]] = []

    def run(self, argv: list[str], *, cwd: Path | None = None,
            expected: int = 0, timeout: int = 300) -> subprocess.CompletedProcess[str]:
        number = len(self.records) + 1
        start = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=cwd or self.directory, env=self.env,
                                    capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            for stream in ("stdout", "stderr"):
                partial = getattr(exc, stream, None) or ""
                if isinstance(partial, bytes):
                    partial = partial.decode("utf-8", errors="replace")
                (self.directory / f"{number:03d}.{stream}").write_text(partial, encoding="utf-8")
            self.records.append({"argv": argv, "cwd": str(cwd or self.directory),
                                 "status": "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "launch_error",
                                 "timeout": timeout, "error": str(exc),
                                 "stdout": f"{number:03d}.stdout", "stderr": f"{number:03d}.stderr"})
            self._save()
            raise AssertionError(f"real command did not complete: {argv}") from exc
        stdout = f"{number:03d}.stdout"
        stderr = f"{number:03d}.stderr"
        (self.directory / stdout).write_text(result.stdout, encoding="utf-8")
        (self.directory / stderr).write_text(result.stderr, encoding="utf-8")
        self.records.append({"argv": argv, "cwd": str(cwd or self.directory),
                             "exit_code": result.returncode, "expected_exit": expected,
                             "elapsed_seconds": round(time.monotonic() - start, 3),
                             "stdout": stdout, "stderr": stderr,
                             "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                             "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()})
        self._save()
        assert result.returncode == expected, f"{argv}\n{result.stdout}\n{result.stderr}"
        assert "Traceback (most recent call last)" not in result.stderr
        return result

    def _save(self) -> None:
        (self.directory / "commands.json").write_text(
            json.dumps(self.records, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, str], Path]:
    work = tmp_path_factory.mktemp("installed-real-journeys")
    evidence = Path(os.environ.get("LEITIR_JOURNEY_EVIDENCE_DIR", str(work / "evidence")))
    evidence.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "LEITIR_HOME"):
        env.pop(key, None)
    # Real-provider tests must never inherit a developer's fixture endpoint.
    for key in sorted(env):
        if key.startswith("LEITIR_") and ("BASE_URL" in key or "ENDPOINT" in key):
            env.pop(key)
    env["LEITIR_NO_UPDATE_CHECK"] = "1"
    journal = Journal(evidence / "installation", env)
    dist = work / "dist"
    journal.run(["uv", "run", "--no-project", "--with-requirements", str(REPO / "requirements.txt"),
                 "python", "-m", "build", "--wheel", "--outdir", str(dist)], cwd=REPO)
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1
    venv = work / "venv"
    journal.run(["uv", "venv", "--python", sys.executable, str(venv)])
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    cli = bindir / ("leitir.exe" if os.name == "nt" else "leitir")
    journal.run(["uv", "pip", "install", "--python", str(python), "--no-deps", str(wheels[0])])
    provenance = journal.run([str(python), "-c",
        "import importlib.metadata,json,leitir; print(json.dumps({'module':leitir.__file__,"
        "'distributions': sorted(d.metadata['Name'] for d in importlib.metadata.distributions())}))"])
    details = json.loads(provenance.stdout)
    assert Path(details["module"]).is_relative_to(venv)
    assert details["distributions"] == ["leitir"]
    (evidence / "artifact.json").write_text(json.dumps({
        "wheel": wheels[0].name, "wheel_sha256": hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
        "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "git_diff": subprocess.check_output(["git", "diff", "HEAD", "--", "src", "pyproject.toml"], cwd=REPO, text=True),
        "installed_module": details["module"], "python": sys.version,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    journal.run([str(cli), "--version"])
    return cli, env, evidence


@pytest.fixture
def journey(installed: tuple[Path, dict[str, str], Path], request: pytest.FixtureRequest) -> tuple[Journal, Path, Path]:
    cli, env, evidence = installed
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.name)
    journal = Journal(evidence / name, dict(env))
    (journal.directory / "test-nodeid.txt").write_text(request.node.nodeid + "\n", encoding="utf-8")
    corpus = journal.directory / "corpus"
    return journal, cli, corpus


def invoke(journey: tuple[Journal, Path, Path], *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    journal, cli, root = journey
    return journal.run([str(cli), *args, "--root", str(root)], expected=expected)


def fetch(journey: tuple[Journal, Path, Path], spec: str = SPEC) -> tuple[Path, dict[str, Any]]:
    payload = json.loads(invoke(journey, "get", spec, "--json").stdout)
    assert len(payload["results"]) == 1
    result = payload["results"][0]
    assert result["verified"] is True
    shelf = Path(result["path"])
    manifest = json.loads((shelf / "leitir-manifest.json").read_text(encoding="utf-8"))
    assert manifest["verified"] is True
    assert manifest["materialized_tree_hash_scope"] == "full"
    return shelf, manifest


def test_installed_analysis_search_and_index_match_real_source(journey: Journey) -> None:
    journal, _cli, _root = journey
    shelf, manifest = fetch(journey)
    assert manifest["commit_sha"] == PIN
    assert manifest["parity"] == "exact"
    before = (shelf / "leitir-manifest.json").read_bytes()
    fetch(journey)
    assert (shelf / "leitir-manifest.json").read_bytes() == before

    # Independent provider metadata, not Leitir's own source enumeration.
    headers = {"User-Agent": "leitir-real-user-validation"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    url = f"https://api.github.com/repos/pypa/packaging/git/trees/{PIN}?recursive=1"
    with urlopen(Request(url, headers=headers), timeout=60) as response:
        upstream = json.load(response)
    (journal.directory / "upstream-tree.json").write_text(json.dumps(upstream, indent=2, sort_keys=True) + "\n")
    assert upstream["truncated"] is False
    blobs = {item["path"]: item["sha"] for item in upstream["tree"] if item["type"] == "blob"}
    for relative, expected_sha in sorted(blobs.items()):
        data = (shelf / relative).read_bytes()
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == expected_sha

    info = json.loads(invoke(journey, "info", SPEC, "--json").stdout)
    api = json.loads(invoke(journey, "api", SPEC, "--json").stdout)
    assert api["symbols"] > 0
    assert info["api"]["symbols"] == api["symbols"]
    index_symbols = json.loads(Path(api["index_path"]).read_text(encoding="utf-8"))["symbols"]
    assert len(index_symbols) == api["symbols"]
    definitions: dict[str, set[tuple[str, int]]] = {}
    for symbol in index_symbols:
        path = symbol["path"]
        if path not in definitions:
            definitions[path] = {(node.name, node.lineno) for node in ast.walk(ast.parse((shelf / path).read_text(encoding="utf-8")))
                                 if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))}
        assert (symbol["name"], symbol["line"]) in definitions[path]
    examples = json.loads(invoke(journey, "examples", SPEC, "--json").stdout)
    assert examples["count"] > 0
    for snippet in examples["snippets"]:
        lines = (shelf / snippet["path"]).read_text(encoding="utf-8").splitlines()
        extracted = snippet["code"].splitlines()
        assert extracted
        assert lines[snippet["line"] - 1:snippet["line"] - 1 + len(extracted)] == extracted
    trust = json.loads(invoke(journey, "trust", SPEC, "--json").stdout)
    assert 0 <= trust["trust_score"] <= 100
    assert trust["trust_breakdown"]

    needle = "class Version"
    oracle = {(path, line) for path in sorted(blobs) if path.endswith(".py")
              for line, text in enumerate((shelf / path).read_text(encoding="utf-8").splitlines(), 1) if needle in text}
    assert oracle
    scan = json.loads(invoke(journey, "search", "--corpus", "--must", "exact_text:" + needle).stdout)
    assert scan["corpus_status"] == "complete_for_declared_universe"
    assert {(m["source"]["path"], m["source"]["start_line"]) for m in scan["matches"]} == oracle
    for match in scan["matches"]:
        source = match["source"]
        assert source["commit_sha"] == PIN
        assert source["blob_sha"] == blobs[source["path"]]
    built = json.loads(invoke(journey, "index").stdout)
    assert built["count"] == 1 and not built["hard_errors"]
    for seed in ("0", "1", "42"):
        journal.env["PYTHONHASHSEED"] = seed
        indexed = json.loads(invoke(journey, "search", "--corpus", "--must", "exact_text:" + needle, "--require-index").stdout)
        assert indexed["corpus_status"] == scan["corpus_status"]
        assert indexed["matches"] == scan["matches"]
    index = Path(built["indexes"][0])
    index.write_bytes(b"broken index\n")
    rejected = invoke(journey, "search", "--corpus", "--must", "exact_text:" + needle, "--require-index")
    payload = json.loads(rejected.stdout)
    assert payload["corpus_status"] == "partial"
    assert payload["matches"] == [] and payload["shelves_searched"] == []
    assert payload["shelves_excluded"][0]["reason"] == "unindexed"
    assert "corpus_status=partial" in rejected.stderr


@pytest.mark.parametrize("tamper", ["source_bytes", "legacy_scope", "missing_digest"])
def test_installed_cache_rejects_tampering_and_recovers(journey: Journey, tamper: str) -> None:
    shelf, manifest = fetch(journey)
    path = shelf / "leitir-manifest.json"
    original = (shelf / "src/packaging/version.py").read_bytes()
    assert len(json.loads(invoke(journey, "list", "--json").stdout)) == 1
    if tamper == "source_bytes":
        (shelf / "src/packaging/version.py").write_bytes(original + b"\n# deliberately tampered\n")
    elif tamper == "missing_digest":
        manifest.pop("materialized_tree_hash")
        path.write_text(json.dumps(manifest, sort_keys=True))
    else:
        manifest.pop("materialized_file_digests")
        manifest.pop("materialized_file_digests_algorithm")
        path.write_text(json.dumps(manifest, sort_keys=True))
        assert len(json.loads(invoke(journey, "list", "--json").stdout)) == 1
        manifest["materialized_tree_hash_scope"] = "sampled"
        path.write_text(json.dumps(manifest, sort_keys=True))
    listed = invoke(journey, "list", "--json")
    assert json.loads(listed.stdout) == []
    assert "excluded" in listed.stderr
    fetch(journey)
    assert (shelf / "src/packaging/version.py").read_bytes() == original
    assert len(json.loads(invoke(journey, "list", "--json").stdout)) == 1


def test_installed_snapshot_roundtrip_rejects_tampering(journey: Journey) -> None:
    journal, cli, root = journey
    shelf, _manifest = fetch(journey)
    lock = journal.directory / "snapshot.lock"
    exported = json.loads(invoke(journey, "export", "-o", str(lock)).stdout)
    assert hashlib.sha256(lock.read_bytes()).hexdigest() == exported["lock_sha256"]
    imported_root = journal.directory / "imported"
    imported = (journal, cli, imported_root)
    invoke(imported, "import", str(lock), "--lock-sha256", exported["lock_sha256"])
    entries = json.loads(invoke(imported, "list", "--json").stdout)
    assert len(entries) == 1 and entries[0]["commit_sha"] == PIN
    imported_shelf = imported_root / entries[0]["path"]
    for path in sorted(shelf.rglob("*.py")):
        assert (imported_shelf / path.relative_to(shelf)).read_bytes() == path.read_bytes()
    tarball = Path(exported["tarball"])
    tarball.write_bytes(tarball.read_bytes() + b"tamper")
    rejected_root = journal.directory / "rejected"
    invoke((journal, cli, rejected_root), "import", str(lock), "--lock-sha256", exported["lock_sha256"], expected=1)
    assert json.loads(invoke((journal, cli, rejected_root), "list", "--json").stdout) == []
    invoke(imported, "remove", SPEC)
    assert json.loads(invoke(imported, "list", "--json").stdout) == []
    journal.env["LEITIR_HOME"] = str(root)
    doctor = journal.run([str(cli), "doctor", "--no-network", "--json"])
    checks = {item["name"]: item for item in json.loads(doctor.stdout)["checks"]}
    for name in ("install.location", "install.entry_point", "cache.registered_shelves", "selftest.integrity"):
        assert checks[name]["status"] == "pass"
    invoke(journey, "gc")
    invoke(journey, "clean", "--repos")
    assert json.loads(invoke(journey, "list", "--json").stdout) == []


def test_installed_version_diff_and_sbom_use_real_identities(journey: Journey) -> None:
    fetch(journey)
    after_spec = f"github:pypa/packaging@{NEXT_PIN}"
    fetch(journey, after_spec)
    same = json.loads(invoke(journey, "diff", SPEC, SPEC, "--json").stdout)
    assert not same["api"]["added"] and not same["api"]["removed"] and not same["api"]["changed"]
    diff = json.loads(invoke(journey, "diff", SPEC, after_spec, "--json").stdout)
    assert diff["before"]["commit_sha"] == PIN
    assert diff["after"]["commit_sha"] == NEXT_PIN
    assert diff["api"]["added"] or diff["api"]["removed"] or diff["api"]["changed"]
    spdx = json.loads(invoke(journey, "sbom", "--format", "spdx").stdout)
    assert {p["versionInfo"] for p in spdx["packages"]} == {PIN, NEXT_PIN}
    cyclone = json.loads(invoke(journey, "sbom", "--format", "cyclonedx").stdout)
    assert {p["version"] for p in cyclone["components"]} == {PIN, NEXT_PIN}


@pytest.mark.parametrize("spec", ["npm:is-number@7.0.0", "pypi:requests@2.32.3",
                                  "crates:itoa@1.0.10", "go:github.com/BurntSushi/toml@v1.2.0"])
def test_installed_registry_acquisition_and_analysis(journey: Journey, spec: str) -> None:
    shelf, manifest = fetch(journey, spec)
    assert any(path.is_file() for path in shelf.rglob("*"))
    info = json.loads(invoke(journey, "info", spec, "--json").stdout)
    if spec.startswith("crates:"):
        # Acquisition is supported; Rust API extraction is not. Do not label
        # this as successful Rust analysis merely because info exits zero.
        assert info["api"]["symbols"] == 0 and info["api"]["method"] is None
    else:
        assert info["api"]["symbols"] > 0
    if spec.startswith("npm:"):
        exported = next(s for s in info["api"]["top_symbols"] if s["name"] == "module.exports")
        assert exported["signature"] == "(num)"
        cache = Path(info["api"]["index_path"])
        poisoned = json.loads(cache.read_text(encoding="utf-8"))
        poisoned["symbols"][0]["name"] = "fabricated_export"
        poisoned["symbols"][0]["qualified_name"] = "index.fabricated_export"
        cache.write_text(json.dumps(poisoned, sort_keys=True))
        recovered = invoke(journey, "info", spec, "--json")
        assert "fabricated_export" not in recovered.stdout
        assert any(s["name"] == "module.exports" for s in json.loads(recovered.stdout)["api"]["top_symbols"])
        assert "module.exports = function(num)" in (shelf / exported["path"]).read_text(encoding="utf-8").splitlines()[exported["line"] - 1]
    if spec.startswith("pypi:"):
        # Unmodified upstream consumer; no execution of its own test doubles.
        consumer = shelf / "tests/test_help.py"
        checked = json.loads(invoke(journey, "check", str(consumer), "--against", spec, "--json").stdout)
        tree = ast.parse(consumer.read_text(encoding="utf-8"))
        calls = sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "info" for n in ast.walk(tree))
        assert calls > 0 and checked["counts"]["sites_ok"] == calls
        assert checked["status"] == "clean" and checked["counts"]["sites_violation"] == 0
    entries = json.loads(invoke(journey, "list", "--json").stdout)
    assert len(entries) == 1 and entries[0]["verified"] is True
    assert manifest["materialized_tree_hash"].startswith("h1:")


def test_installed_lock_uses_unmodified_upstream_manifest(journey: Journey) -> None:
    journal, cli, _root = journey
    spec = "github:rsc/quote@c4d4236f92427c64bfbcf1cc3f8142ab18f30b22"
    shelf, _manifest = fetch(journey, spec)
    original = (shelf / "go.mod").read_bytes()
    # The real Go command provides an independent grammar/identity oracle.
    journal.run(["go", "version"])
    parsed = journal.run(["go", "mod", "edit", "-json"], cwd=shelf)
    requires = json.loads(parsed.stdout)["Require"]
    assert requires
    locked_root = journal.directory / "locked"
    locked = (journal, cli, locked_root)
    invoke(locked, "lock", "--cwd", str(shelf))
    assert (shelf / "go.mod").read_bytes() == original
    records = json.loads((locked_root / "sources.json").read_text(encoding="utf-8"))
    versions = {(record["name"], json.loads((locked_root / record["path"] / "leitir-manifest.json").read_text(encoding="utf-8"))["version"]) for record in records}
    assert {(item["Path"], item["Version"]) for item in requires} <= versions
    assert json.loads(invoke(locked, "list", "--json").stdout)
    asked = invoke(locked, "ask", "Hello", "--package", "rsc.io/sampler", "--ecosystem", "go",
                   "--pin", str(shelf / "go.mod"), "--json", expected=1)
    payload = json.loads(asked.stdout)
    assert "GitHub" in payload["query_compilation"]["search_error"]
    assert payload["matches"] is None and payload["coverage"] is None
