"""Task source: reads (never writes) ``benchmarks/exit-corpus/``.

This module is the one place in the harness that touches contract-test
bytes. It immediately splits every task into two disjoint objects:

* :class:`PublicTask` -- provenance metadata only (case id, seed module/
  qualified name, language, donor pin, import roots). This is what the
  README for ``benchmarks/exit-corpus`` says the manifest contains: pinned
  donor identities, *not* vendor source code. It is safe to hand to a
  prompt builder.
* :class:`EvaluatorAssets` -- the contract-test path, its raw bytes, and the
  recorded baseline. This is the evaluator seam boundary: nothing in this
  package's ``prompt`` module accepts an ``EvaluatorAssets`` (or a bare
  ``bytes``/``Path`` sourced from one) as an argument, so a generation or
  repair prompt builder has no reference through which it could leak these
  bytes. See ``check_leak`` in ``prompt.py`` for the runtime backstop.

Nothing here mutates ``benchmarks/exit-corpus/``. ``manifest_digest``
recomputes the manifest's content digest so callers can assert it is
unchanged after a harness run (see ``tests/test_differential_eval.py``).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from leitir.exit_corpus import content_digest, load_corpus_manifest
from leitir.safeio import read_regular_file

EXIT_CORPUS_ROOT = Path(__file__).resolve().parents[1] / "exit-corpus"
MANIFEST_PATH = EXIT_CORPUS_ROOT / "corpus-v1.1.json"

_MAX_CONTRACT_TEST_BYTES = 1 << 20


class TaskSourceError(Exception):
    """Raised when the exit-corpus manifest or a contract test is unreadable."""


@dataclass(frozen=True)
class PublicTask:
    """Everything a generation or repair prompt is allowed to see.

    Every field here comes from manifest sections the exit-corpus README
    describes as non-evaluator content (donor pin, seed identity, layout).
    None of it is contract-test path, source, assertions, or output.
    """

    case_id: str
    language: str
    seed_module: str
    seed_qualified_name: str
    donor_host: str
    donor_owner: str
    donor_repo: str
    donor_commit_sha: str
    import_roots: tuple[str, ...]

    @property
    def source_provenance(self) -> str:
        return f"github:{self.donor_owner}/{self.donor_repo}@{self.donor_commit_sha}"


@dataclass(frozen=True)
class EvaluatorAssets:
    """Hidden evaluator-only assets.

    Never pass this object, or any field pulled from it, into
    ``benchmarks.differential.prompt`` or any runner's ``generate``/
    ``repair`` call. It exists only for
    ``benchmarks.differential.contract_exec`` to run the contract tests
    against a candidate, in a subprocess whose own stdout/stderr is never
    copied into a prompt.
    """

    case_id: str
    contract_test_path: Path
    contract_test_bytes: bytes
    contract_test_module: str
    expected_pass: int
    expected_fail: int
    expected_skip: int


@dataclass(frozen=True)
class DifferentialTask:
    public: PublicTask
    evaluator: EvaluatorAssets


def manifest_digest(manifest_path: Path = MANIFEST_PATH) -> str:
    """Return the exit-corpus manifest's content digest (read-only)."""

    manifest = load_corpus_manifest(manifest_path)
    return content_digest(manifest)


def load_tasks(
    *,
    manifest_path: Path = MANIFEST_PATH,
    corpus_root: Path = EXIT_CORPUS_ROOT,
) -> tuple[DifferentialTask, ...]:
    """Load every case in the exit-corpus manifest as a differential task.

    Reads ``manifest_path`` and each case's contract-test file. Writes
    nothing. Raises :class:`TaskSourceError` on any structural problem
    (rather than silently skipping a task).
    """

    manifest = load_corpus_manifest(manifest_path)
    cases_raw = manifest["cases"]
    assert isinstance(cases_raw, list)
    cases_by_id: dict[str, dict[str, object]] = {}
    for raw_case in cases_raw:
        assert isinstance(raw_case, dict)
        cases_by_id[str(raw_case["case_id"])] = raw_case

    runnable = manifest.get("runnable")
    if not isinstance(runnable, dict):
        raise TaskSourceError("manifest has no 'runnable' section (need v1.1 schema)")
    per_case = runnable["per_case"]
    assert isinstance(per_case, list)

    tasks: list[DifferentialTask] = []
    for entry in sorted(per_case, key=lambda e: str(e["case_id"])):
        assert isinstance(entry, dict)
        case_id = entry["case_id"]
        assert isinstance(case_id, str)
        case = cases_by_id.get(case_id)
        if case is None:
            raise TaskSourceError(f"runnable.per_case references unknown case_id {case_id!r}")

        donor = case["donor"]
        assert isinstance(donor, dict)
        seed = case["seed"]
        assert isinstance(seed, dict)
        baseline = case["baseline"]
        assert isinstance(baseline, dict)

        import_roots_raw = entry["import_roots"]
        assert isinstance(import_roots_raw, list)
        import_roots = tuple(str(r) for r in import_roots_raw)

        public = PublicTask(
            case_id=case_id,
            language=str(case["language"]),
            seed_module=str(seed["module"]),
            seed_qualified_name=str(seed["qualified_name"]),
            donor_host=str(donor["host"]),
            donor_owner=str(donor["owner"]),
            donor_repo=str(donor["repo"]),
            donor_commit_sha=str(donor["commit_sha"]),
            import_roots=import_roots,
        )

        contract_tests = entry["contract_tests"]
        assert isinstance(contract_tests, list) and len(contract_tests) == 1
        contract_test_entry = contract_tests[0]
        assert isinstance(contract_test_entry, dict)
        rel_path = str(contract_test_entry["path"])
        contract_test_path = (corpus_root / rel_path).resolve()
        if corpus_root.resolve() not in contract_test_path.parents:
            raise TaskSourceError(f"contract test path escapes corpus root: {rel_path}")
        try:
            contract_test_bytes = read_regular_file(
                contract_test_path, maximum_bytes=_MAX_CONTRACT_TEST_BYTES, no_follow=False
            )
        except OSError as exc:
            raise TaskSourceError(f"cannot read contract test for {case_id}: {exc}") from exc

        evaluator = EvaluatorAssets(
            case_id=case_id,
            contract_test_path=contract_test_path,
            contract_test_bytes=contract_test_bytes,
            contract_test_module=str(contract_test_entry["module"]),
            expected_pass=int(baseline["expected_pass"]),
            expected_fail=int(baseline["expected_fail"]),
            expected_skip=int(baseline["expected_skip"]),
        )
        tasks.append(DifferentialTask(public=public, evaluator=evaluator))

    return tuple(tasks)


__all__ = [
    "EXIT_CORPUS_ROOT",
    "MANIFEST_PATH",
    "DifferentialTask",
    "EvaluatorAssets",
    "PublicTask",
    "TaskSourceError",
    "load_tasks",
    "manifest_digest",
]
