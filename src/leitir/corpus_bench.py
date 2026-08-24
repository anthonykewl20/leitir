"""Pinned fetch-correctness benchmark contracts and runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from leitir.resolver import ResolvedPackage
from leitir.search import RepoScope

_TASK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SCHEMA = "leitir-corpus-benchmark-manifest-v1"
_RUN_SCHEMA = "leitir-corpus-benchmark-run-v1"


class _MaterializeOptions(TypedDict, total=False):
    verify: bool
    token: str
    base_url: str
    tree_base_url: str


def _canonical_json(value: object) -> str:
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True, slots=True)
class CorpusExpectedFile:
    path: str
    content_line: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not isinstance(self.content_line, str):
            raise TypeError("expected file path and content line must be text")
        candidate = Path(self.path)
        if (
            not self.path
            or candidate.is_absolute()
            or ".." in candidate.parts
            or not self.content_line
            or "\n" in self.content_line
        ):
            raise ValueError("expected file requires a safe path and one non-empty content line")

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "content_line": self.content_line}


@dataclass(frozen=True, slots=True)
class CorpusBenchmarkTask:
    task_id: str
    spec: str
    expected_owner: str
    expected_repo: str
    expected_commit_sha: str
    expected_files: tuple[CorpusExpectedFile, ...]
    pin_source: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID.fullmatch(self.task_id):
            raise ValueError("task id must be lowercase kebab-case")
        if not all(
            isinstance(value, str) and value
            for value in (self.spec, self.expected_owner, self.expected_repo)
        ):
            raise ValueError("spec and expected repository identity must be non-empty")
        if not isinstance(self.expected_commit_sha, str) or not _SHA1.fullmatch(
            self.expected_commit_sha
        ):
            raise ValueError("expected_commit_sha must be a lowercase 40-character SHA")
        if not isinstance(self.expected_files, tuple) or not self.expected_files or any(
            not isinstance(item, CorpusExpectedFile) for item in self.expected_files
        ):
            raise ValueError("task requires at least one expected file")
        if not isinstance(self.pin_source, str) or not self.pin_source:
            raise ValueError("pin_source must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.task_id,
            "spec": self.spec,
            "expected_owner": self.expected_owner,
            "expected_repo": self.expected_repo,
            "expected_commit_sha": self.expected_commit_sha,
            "expected_files": [item.to_dict() for item in self.expected_files],
            "pin_source": self.pin_source,
        }


@dataclass(frozen=True, slots=True)
class CorpusBenchmarkManifest:
    schema_version: str
    benchmark_id: str
    tasks: tuple[CorpusBenchmarkTask, ...]

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA:
            raise ValueError(f"schema_version must be {_SCHEMA!r}")
        if self.benchmark_id != "corpus-v1":
            raise ValueError("corpus benchmark id must be 'corpus-v1'")
        if not isinstance(self.tasks, tuple) or any(
            not isinstance(task, CorpusBenchmarkTask) for task in self.tasks
        ):
            raise TypeError("corpus benchmark tasks must be a tuple of tasks")
        if not 4 <= len(self.tasks) <= 6:
            raise ValueError("corpus-v1 requires four to six tasks")
        ids = [task.task_id for task in self.tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("corpus benchmark task IDs must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark_id": self.benchmark_id,
            "tasks": [task.to_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class CorpusBenchmarkTaskRun:
    task_id: str
    resolved_owner: str
    resolved_repo: str
    resolved_commit_sha: str
    results: tuple[CorpusExpectedFile, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "resolved_owner": self.resolved_owner,
            "resolved_repo": self.resolved_repo,
            "resolved_commit_sha": self.resolved_commit_sha,
            "verified_files": [item.to_dict() for item in self.results],
        }


@dataclass(frozen=True, slots=True)
class CorpusBenchmarkRun:
    benchmark_id: str
    manifest_sha256: str
    tasks: tuple[CorpusBenchmarkTaskRun, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _RUN_SCHEMA,
            "benchmark": {"id": self.benchmark_id, "manifest_sha256": self.manifest_sha256},
            "tasks": [task.to_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()


def manifest_from_dict(raw: object) -> CorpusBenchmarkManifest:
    if not isinstance(raw, dict):
        raise TypeError("corpus benchmark manifest must be an object")
    tasks_raw = raw.get("tasks")
    if not isinstance(tasks_raw, list):
        raise TypeError("corpus benchmark tasks must be a list")
    tasks = []
    for value in tasks_raw:
        if not isinstance(value, dict):
            raise TypeError("corpus benchmark task must be an object")
        files_raw = value.get("expected_files")
        if not isinstance(files_raw, list):
            raise TypeError("expected_files must be a list")
        try:
            files = tuple(
                CorpusExpectedFile(path=item["path"], content_line=item["content_line"])
                for item in files_raw
            )
            tasks.append(
                CorpusBenchmarkTask(
                    task_id=value["id"],
                    spec=value["spec"],
                    expected_owner=value["expected_owner"],
                    expected_repo=value["expected_repo"],
                    expected_commit_sha=value["expected_commit_sha"],
                    expected_files=files,
                    pin_source=value["pin_source"],
                )
            )
        except KeyError as exc:
            raise ValueError(f"corpus benchmark task is missing {exc.args[0]!r}") from exc
    try:
        return CorpusBenchmarkManifest(raw["schema_version"], raw["benchmark_id"], tuple(tasks))
    except KeyError as exc:
        raise ValueError(f"corpus benchmark manifest is missing {exc.args[0]!r}") from exc


class CorpusBenchmarkRunner:
    """Resolve and verify every task in a disposable corpus root."""

    def __init__(
        self,
        resolver: object,
        heads: object,
        token: str | None = None,
    ) -> None:
        self._resolver = resolver
        self._heads = heads
        self._token = token

    def _resolve(self, spec: str) -> tuple[ResolvedPackage | RepoScope, str, str]:
        from leitir.cli import _resolve_corpus_spec
        from leitir.spec import parse_corpus_spec

        parsed = parse_corpus_spec(spec)
        # announce=sys.stderr keeps the registry-only degraded-provenance
        # warning visible on the benchmark path too (reviewer-qwen
        # 2026-08-23); the announce stream is write-only.
        import sys

        resolved_raw, _tag, _source, _detection = _resolve_corpus_spec(
            parsed, self._resolver, self._heads, Path.cwd(), sys.stderr
        )
        resolved = resolved_raw
        scope = resolved.scope if isinstance(resolved, ResolvedPackage) else resolved
        return resolved, parsed.name, scope.slug

    def run(self, manifest: CorpusBenchmarkManifest) -> CorpusBenchmarkRun:
        from leitir.corpus import materialize_source
        from leitir.materialize import MANIFEST_NAME

        if not isinstance(manifest, CorpusBenchmarkManifest):
            raise TypeError("manifest must be a CorpusBenchmarkManifest")
        runs = []
        with tempfile.TemporaryDirectory(prefix="leitir-corpus-bench-") as temporary:
            root = Path(temporary)
            for task in sorted(manifest.tasks, key=lambda item: item.task_id):
                resolved, name, slug = self._resolve(task.spec)
                scope = resolved.scope if isinstance(resolved, ResolvedPackage) else resolved
                owner, repo = slug.split("/", 1)
                actual = (owner, repo, scope.commit_sha)
                expected = (task.expected_owner, task.expected_repo, task.expected_commit_sha)
                if actual != expected:
                    raise ValueError(f"{task.task_id}: resolved {actual!r}, expected {expected!r}")
                options = _MaterializeOptions(verify=True)
                if self._token is not None:
                    options["token"] = self._token
                if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                    options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
                if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                    options["tree_base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
                target = materialize_source(
                    task.spec,
                    resolved,
                    root=root,
                    name=name,
                    version_source="explicit",
                    **options,
                )
                source_manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
                if source_manifest.get("verified") not in (True, "sampled"):
                    raise ValueError(f"{task.task_id}: extraction was not verified")
                for expected_file in task.expected_files:
                    lines = (target / expected_file.path).read_text(encoding="utf-8").splitlines()
                    if expected_file.content_line not in lines:
                        raise ValueError(
                            f"{task.task_id}: expected line absent from {expected_file.path}"
                        )
                runs.append(CorpusBenchmarkTaskRun(task.task_id, owner, repo, scope.commit_sha, task.expected_files))
        return CorpusBenchmarkRun(manifest.benchmark_id, manifest.digest(), tuple(runs))


__all__ = [
    "CorpusBenchmarkManifest",
    "CorpusBenchmarkRunner",
    "CorpusExpectedFile",
    "manifest_from_dict",
]
