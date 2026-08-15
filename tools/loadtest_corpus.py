"""Materialize and exercise a pinned, real-world load-test corpus.

The harness deliberately runs entries serially in source order.  It is intended
to create evidence, not to maximize network throughput: per-source timings are
therefore attributable and retry/rate-limit behaviour is not hidden by
concurrent clients.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Never, cast

from leitir.adapters.registry import build_adapters
from leitir.engine import ScopedSearcher
from leitir.index.builder import ShelfRef, build_shelf_index
from leitir.index.verify import require_eligible
from leitir.materialize import read_valid_manifest
from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
from leitir.tree import BlobEntry

SCHEMA_VERSION = "leitir-loadtest-run-v1"
CORPUS_SCHEMA_VERSION = "leitir-loadtest-corpus-v1"
MAX_CORPUS_BYTES = 5 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
# These are deliberately absent literals.  Each query still exhaustively reads every
# supported source file, while avoiding unbounded result fan-out from commonplace
# comments such as TODO or copyright notices.
QUERY_NEEDLES = (
    "__leitir_loadtest_needle_a4f8__",
    "__leitir_loadtest_needle_b7c2__",
    "__leitir_loadtest_needle_d9e6__",
)


class CorpusValidationError(ValueError):
    """Raised when the pinned corpus list is not safe and exact."""


class _OfflineShelfTree:
    """Enumerate a validated local GitHub shelf without any network access."""

    def __init__(self, target: Path) -> None:
        self._target = target

    def list_blobs_ex(
        self, _slug: str, _commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return self.list_blobs(_slug, _commit_sha), False

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        blobs: list[BlobEntry] = []
        for path in sorted(self._target.rglob("*"), key=lambda item: item.relative_to(self._target).as_posix()):
            relative = path.relative_to(self._target).as_posix()
            if relative == "leitir-manifest.json":
                continue
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                if path.is_symlink():
                    raise ValueError(f"shelf contains symbolic-link directory: {relative}")
                continue
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(os.fsencode(path))
                data = target if isinstance(target, bytes) else os.fsencode(target)
                blobs.append(BlobEntry(relative, _git_blob_sha_bytes(data), len(data), "120000"))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"shelf contains unsafe source entry: {relative}")
            mode = "100755" if metadata.st_mode & stat.S_IXUSR else "100644"
            blobs.append(BlobEntry(relative, _git_blob_sha_path(path, metadata.st_size), metadata.st_size, mode))
        return tuple(blobs)

    def read_blob(self, _slug: str, _blob_sha: str) -> Never:
        raise AssertionError("ScopedSearcher must use its validated local shelf reader")

    def read_blob_stream(self, _slug: str, _blob_sha: str) -> Iterator[bytes]:
        raise AssertionError("ScopedSearcher must use its validated local shelf reader")


def _git_blob_sha_bytes(data: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(data)}\0".encode("ascii"), usedforsecurity=False)
    digest.update(data)
    return digest.hexdigest()


def _git_blob_sha_path(path: Path, size: int) -> str:
    digest = hashlib.sha1(f"blob {size}\0".encode("ascii"), usedforsecurity=False)
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _read_bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise CorpusValidationError(f"{path} exceeds the {maximum}-byte input limit")
    return data


def _source_parts(source: str) -> tuple[str, str, str]:
    prefix = "github:"
    if not source.startswith(prefix):
        raise CorpusValidationError("corpus source must be a github:owner/repo@40-hex-sha pin")
    try:
        slug, commit = source[len(prefix) :].rsplit("@", 1)
        owner, repo = slug.split("/", 1)
    except ValueError as error:
        raise CorpusValidationError(f"invalid GitHub source pin: {source!r}") from error
    if (
        not owner
        or not repo
        or "/" in repo
        or len(commit) != 40
        or any(char not in "0123456789abcdef" for char in commit)
    ):
        raise CorpusValidationError(f"invalid GitHub source pin: {source!r}")
    return owner, repo, commit


def load_corpus(path: Path) -> tuple[dict[str, str], ...]:
    """Read a bounded, closed-schema, deterministically ordered corpus list."""

    try:
        raw = json.loads(_read_bounded(path, MAX_CORPUS_BYTES).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CorpusValidationError(f"cannot read corpus list {path}") from error
    if not isinstance(raw, dict) or set(raw) != {"entries", "schema_version"}:
        raise CorpusValidationError("corpus list must have exactly entries and schema_version")
    if raw["schema_version"] != CORPUS_SCHEMA_VERSION or not isinstance(raw["entries"], list):
        raise CorpusValidationError("corpus list has an unsupported schema")
    entries: list[dict[str, str]] = []
    for item in raw["entries"]:
        if not isinstance(item, dict) or set(item) != {"note", "source"}:
            raise CorpusValidationError("each corpus entry must have exactly note and source")
        source, note = item.get("source"), item.get("note")
        if not isinstance(source, str) or not isinstance(note, str) or not note.strip():
            raise CorpusValidationError("each corpus source and note must be non-empty text")
        _source_parts(source)
        entries.append({"note": note, "source": source})
    if len(entries) < 110:
        raise CorpusValidationError("corpus list must contain at least 110 entries")
    sources = [item["source"] for item in entries]
    if len(set(sources)) != len(sources):
        raise CorpusValidationError("corpus sources must be unique")
    # Keep the authored grouping readable while making every run order explicit.
    return tuple(sorted(entries, key=lambda item: item["source"]))


def percentile(values: Sequence[float | int], fraction: float) -> float | int:
    """Return the deterministic nearest-rank percentile of non-empty samples."""

    if not values or not 0 < fraction <= 1:
        raise ValueError("percentile requires values and a fraction in (0, 1]")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in values):
        raise ValueError("percentile values must be numeric")
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * fraction) - 1]


def classify_failure(error: str) -> str:
    """Classify a subprocess or phase failure without treating it as success."""

    value = error.casefold()
    if "rate limit" in value or "http 429" in value:
        return "rate_limit"
    if "timed out" in value or "timeout" in value:
        return "timeout"
    if "http 404" in value or "not found" in value or "no commit found" in value:
        return "not_found"
    if any(marker in value for marker in ("checksum", "manifest", "verification", "tree hash", "integrity")):
        return "integrity"
    if "resolve" in value or "invalid github source" in value:
        return "resolution"
    if "materializ" in value or "codeload" in value or "download" in value:
        return "materialization"
    return "unexpected"


def aggregate_entries(entries: Sequence[dict[str, object]]) -> dict[str, object]:
    """Aggregate completed phases and failure categories from entry records."""

    phase_names = ("materialize", "search", "index", "integrity")
    phases: dict[str, dict[str, object]] = {}
    for name in phase_names:
        values = [
            cast(float | int, cast(dict[str, object], entry[name])["duration_ms"])
            for entry in entries
            if isinstance(entry.get(name), dict)
            and cast(dict[str, object], entry[name]).get("status") == "completed"
        ]
        phases[name] = {
            "completed": len(values),
            "max_ms": max(values) if values else None,
            "p50_ms": percentile(values, 0.50) if values else None,
            "p95_ms": percentile(values, 0.95) if values else None,
            "total_ms": sum(values),
        }
    failure_categories: dict[str, int] = {}
    for entry in entries:
        failure = entry.get("failure")
        if isinstance(failure, dict) and isinstance(failure.get("category"), str):
            category = failure["category"]
            failure_categories[category] = failure_categories.get(category, 0) + 1
    successful = sum(entry.get("status") == "success" for entry in entries)
    shelf_sizes = [
        cast(int, entry["bytes"])
        for entry in entries
        if entry.get("status") == "success"
        and isinstance(entry.get("bytes"), int)
        and not isinstance(entry.get("bytes"), bool)
    ]
    shelf_files = [
        cast(int, entry["files"])
        for entry in entries
        if entry.get("status") == "success"
        and isinstance(entry.get("files"), int)
        and not isinstance(entry.get("files"), bool)
    ]
    shelf_bytes = sum(shelf_sizes)
    return {
        "entries_requested": len(entries),
        "entries_successful": successful,
        "failures_by_category": dict(sorted(failure_categories.items())),
        "phases": phases,
        "shelf_bytes": shelf_bytes,
        "shelf_size_bytes": {
            "count": len(shelf_sizes),
            "max": max(shelf_sizes) if shelf_sizes else None,
            "p50": percentile(shelf_sizes, 0.50) if shelf_sizes else None,
            "p95": percentile(shelf_sizes, 0.95) if shelf_sizes else None,
            "total": shelf_bytes,
        },
        "shelf_files": {
            "count": len(shelf_files),
            "max": max(shelf_files) if shelf_files else None,
            "p50": percentile(shelf_files, 0.50) if shelf_files else None,
            "p95": percentile(shelf_files, 0.95) if shelf_files else None,
            "total": sum(shelf_files),
        },
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _run_get(source: str, root: Path) -> tuple[dict[str, object], int]:
    environment = dict(os.environ)
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONPATH"] = source_root + os.pathsep + environment.get("PYTHONPATH", "")
    started = time.perf_counter_ns()
    completed = subprocess.run(
        [sys.executable, "-m", "leitir.cli", "get", "--json", "--root", str(root), source],
        capture_output=True,
        env=environment,
        timeout=300,
        check=False,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES or len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise RuntimeError("get command output exceeded bounded capture")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"get exited {completed.returncode}: {detail}")
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("get did not emit valid JSON") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("results"), list):
        raise RuntimeError("get emitted an unexpected JSON schema")
    results = payload["results"]
    if len(results) != 1 or not isinstance(results[0], dict):
        raise RuntimeError("get did not return exactly one result")
    return cast(dict[str, object], results[0]), round(elapsed_ms)


def _validated_shelf(source: str, root: Path, result: dict[str, object]) -> tuple[Path, dict[str, object], str, str, str]:
    owner, repo, commit = _source_parts(source)
    reported_path = result.get("path")
    if not isinstance(reported_path, str):
        raise RuntimeError("get result did not provide a path")
    target = (root / "repos" / "github.com" / owner / repo / commit).absolute()
    if Path(reported_path).absolute() != target or not target.is_relative_to(root.absolute()):
        raise RuntimeError("get returned a shelf outside its expected pinned location")
    manifest = read_valid_manifest(target, owner, repo, commit, host="github.com")
    if manifest is None:
        raise RuntimeError("materialized shelf failed load-time manifest validation")
    return target, manifest, owner, repo, commit


def _shelf_metrics(target: Path) -> tuple[int, int]:
    files = 0
    total_bytes = 0
    for path in sorted(target.rglob("*"), key=lambda item: item.relative_to(target).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if path.is_symlink():
                raise RuntimeError("shelf contains a symbolic-link directory")
            continue
        if stat.S_ISREG(metadata.st_mode):
            files += 1
            total_bytes += metadata.st_size
            continue
        if stat.S_ISLNK(metadata.st_mode):
            link = os.readlink(os.fsencode(path))
            files += 1
            total_bytes += len(link if isinstance(link, bytes) else os.fsencode(link))
            continue
        raise RuntimeError("shelf contains an unsafe non-file entry")
    return files, total_bytes


def _search(target: Path, owner: str, repo: str, commit: str, root: Path) -> tuple[dict[str, object], int]:
    searcher = ScopedSearcher(_OfflineShelfTree(target), build_adapters(), corpus_root=root)
    query_results: list[dict[str, object]] = []
    started = time.perf_counter_ns()
    for needle in QUERY_NEEDLES:
        report = searcher.search(
            SearchSpec(
                SearchMode.SCOPED_EXHAUSTIVE,
                must=(Predicate(PredicateKind.EXACT_TEXT, needle),),
                scopes=(RepoScope(f"{owner}/{repo}", commit),),
            )
        )
        query_results.append({"hits": len(report.matches), "needle": needle})
    elapsed_ms = round((time.perf_counter_ns() - started) / 1_000_000)
    total_hits = sum(cast(int, item["hits"]) for item in query_results)
    return {"queries": query_results, "status": "completed", "total_hits": total_hits}, elapsed_ms


def _index(target: Path, owner: str, repo: str, commit: str, manifest: dict[str, object], root: Path) -> tuple[dict[str, object], int]:
    try:
        require_eligible(manifest)
    except Exception as error:
        return {"reason": str(error), "status": "skipped_ineligible"}, 0
    started = time.perf_counter_ns()
    path = build_shelf_index(root, ShelfRef("github.com", owner, repo, commit))
    elapsed_ms = round((time.perf_counter_ns() - started) / 1_000_000)
    if not path.is_file():
        raise RuntimeError("index builder did not publish an index file")
    return {"path": str(path.relative_to(root)), "status": "completed"}, elapsed_ms


def run(corpus_path: Path, root: Path, *, allow_existing: bool) -> dict[str, object]:
    """Run every corpus source and return canonical, timestamp-free evidence."""

    corpus_bytes = _read_bounded(corpus_path, MAX_CORPUS_BYTES)
    entries = load_corpus(corpus_path)
    root = root.expanduser().absolute()
    if root.is_symlink():
        raise ValueError("load-test root must not be a symbolic link")
    if root.exists() and any(root.iterdir()) and not allow_existing:
        raise ValueError("load-test root is non-empty; use a fresh root or --allow-existing")
    root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    for item in entries:
        source = item["source"]
        record: dict[str, object] = {"note": item["note"], "source": source, "status": "failure"}
        try:
            get_result, elapsed_ms = _run_get(source, root)
            target, manifest, owner, repo, commit = _validated_shelf(source, root, get_result)
            files, shelf_bytes = _shelf_metrics(target)
            record.update(
                bytes=shelf_bytes,
                files=files,
                manifest_sha256=hashlib.sha256((target / "leitir-manifest.json").read_bytes()).hexdigest(),
                materialize={"duration_ms": elapsed_ms, "status": "completed"},
                verified=manifest.get("verified"),
            )
            search, search_ms = _search(target, owner, repo, commit, root)
            search["duration_ms"] = search_ms
            record["search"] = search
            index, index_ms = _index(target, owner, repo, commit, manifest, root)
            if index["status"] == "completed":
                index["duration_ms"] = index_ms
            record["index"] = index
            started = time.perf_counter_ns()
            if read_valid_manifest(target, owner, repo, commit, host="github.com") is None:
                raise RuntimeError("integrity re-check rejected the shelf")
            record["integrity"] = {"duration_ms": round((time.perf_counter_ns() - started) / 1_000_000), "status": "completed"}
            record["status"] = "success"
        except subprocess.TimeoutExpired:
            record["failure"] = {"category": "timeout", "phase": "materialize"}
        except Exception as error:
            text = str(error)
            phase = "materialize" if "materialize" not in record else "post_materialize"
            record["failure"] = {"category": classify_failure(text), "detail": text, "phase": phase}
        results.append(record)
    aggregate = aggregate_entries(results)
    return {
        "aggregate": aggregate,
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "entries": results,
        "query_needles": list(QUERY_NEEDLES),
        "root_mode": "allow_existing" if allow_existing else "fresh",
        "schema_version": SCHEMA_VERSION,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("tools/loadtest-corpus-v1.json"))
    parser.add_argument("--root", type=Path, required=True, help="fresh scratch corpus root")
    parser.add_argument("--output", type=Path, default=None, help="canonical result JSON path (stdout remains available)")
    parser.add_argument("--allow-existing", action="store_true", help="allow a non-empty root (warm-cache run)")
    parser.add_argument("--minimum-successes", type=int, default=100)
    args = parser.parse_args(argv)
    if args.minimum_successes < 100:
        parser.error("--minimum-successes must be at least 100 for the operational gate")
    try:
        result = run(args.corpus, args.root, allow_existing=args.allow_existing)
    except (OSError, ValueError, CorpusValidationError) as error:
        print(f"load test failed before completion: {error}", file=sys.stderr)
        return 2
    payload = _canonical(result)
    if args.output is not None:
        _atomic_write(args.output, payload)
    sys.stdout.buffer.write(payload)
    successful = cast(int, cast(dict[str, object], result["aggregate"])["entries_successful"])
    return 0 if successful >= args.minimum_successes else 1


if __name__ == "__main__":
    raise SystemExit(main())
