"""Seeded, offline fuzzing of Leitir's pure kernels with explicit oracles.

Each target declares which exceptions are *by design* (the error taxonomy it
documents).  Anything else that escapes is a crash.  Every input is also run
twice to detect nondeterminism, timed to detect algorithmic blow-ups, and
checked against metamorphic properties (permutation invariance, tamper
detection, idempotence) that the product's contracts promise.

Inputs are reproducible from ``(target, seed, index)`` alone, so a finding's
reproducer is three values, not a corpus file.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import random
import re
import shutil
import signal
import string
import sys
import tempfile
import time
import traceback
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SLOW_SECONDS = 2.0
HANG_SECONDS = 8.0


class InputHang(Exception):
    """Raised by the alarm when one input exceeds ``HANG_SECONDS``."""


def _is_main_thread() -> bool:
    import threading

    return threading.current_thread() is threading.main_thread()


class _deadline:
    """Hard per-input deadline (main thread, POSIX).  A hang is a finding, not a stalled harness."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.active = hasattr(signal, "setitimer") and _is_main_thread()

    def __enter__(self) -> None:
        if self.active:
            signal.signal(signal.SIGALRM, self._raise)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)

    def __exit__(self, *exc: object) -> None:
        if self.active:
            signal.setitimer(signal.ITIMER_REAL, 0)

    @staticmethod
    def _raise(signum: int, frame: object) -> None:
        raise InputHang()

_SHA1_A = "a" * 40


# --------------------------------------------------------------------------
# canonicalisation
# --------------------------------------------------------------------------


_TMP_ROOTS: list[str] = []


def _normalize_text(value: str) -> str:
    for root in _TMP_ROOTS:
        if root and root in value:
            value = value.replace(root, "<tmp>")
    return value


def canon(value: Any) -> Any:
    """Convert arbitrary Leitir return values into JSON-comparable structures.

    Scratch-directory paths are rewritten to ``<tmp>`` so two processes with
    different temporary roots produce comparable digests.
    """
    if isinstance(value, str):
        return _normalize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {"__bytes__": hashlib.sha256(value).hexdigest()}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Path):
        return _normalize_text(str(value))
    if isinstance(value, dict):
        return {str(key): canon(item) for key, item in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [canon(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(canon(item) for item in value)
    for method in ("to_dict", "as_dict"):
        function = getattr(value, method, None)
        if callable(function):
            return canon(function())
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: canon(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, BaseException):
        return {"__exception__": type(value).__name__}
    return repr(value)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(canon(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# generators
# --------------------------------------------------------------------------

_ALPHABET = string.ascii_letters + string.digits + "-_./@:~+"
_WEIRD = ["", " ", "\t", "\n", "\x00", "..", ".", "/", "//", "\\", "%2e%2e", "é", "\u2028", "\ud800", "🙂", "\r\n", "'", '"', "`", "$", "*", "?", "[", "]"]


def rand_text(rng: random.Random, max_len: int = 24, alphabet: str = _ALPHABET) -> str:
    if rng.random() < 0.08:
        return rng.choice(_WEIRD)
    length = rng.randint(0, max_len)
    parts = []
    for _ in range(length):
        roll = rng.random()
        if roll < 0.04:
            parts.append(rng.choice(_WEIRD))
        elif roll < 0.06:
            parts.append(chr(rng.randint(0x20, 0x2FF)))
        else:
            parts.append(rng.choice(alphabet))
    return "".join(parts)


def rand_bytes(rng: random.Random, max_len: int = 200) -> bytes:
    length = rng.randint(0, max_len)
    if rng.random() < 0.5:
        return "".join(rng.choice(string.printable) for _ in range(length)).encode("utf-8")
    return bytes(rng.randint(0, 255) for _ in range(length))


def rand_json(rng: random.Random, depth: int = 0) -> Any:
    roll = rng.random()
    if depth > 2 or roll < 0.3:
        return rng.choice([None, True, False, 0, 1, -1, 2**63, 1.5, float("nan"), "", "x", rand_text(rng)])
    if roll < 0.6:
        return [rand_json(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {rand_text(rng, 8): rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))}


# --------------------------------------------------------------------------
# targets
# --------------------------------------------------------------------------


@dataclass
class Target:
    name: str
    generate: Callable[[random.Random], Any]
    run: Callable[[Any, Path], Any]
    allowed: Callable[[], tuple[type[BaseException], ...]]
    properties: tuple[Callable[[Any, Any, Path], str | None], ...] = ()
    description: str = ""


def _spec_generate(rng: random.Random) -> str:
    prefixes = ["npm:", "pypi:", "crates:", "go:", "github:", "gitlab:", "bitbucket:", "codeberg:", "srht:", "https://github.com/", "https://gitlab.com/", "http://github.com/", "", "@", "git+", "file:"]
    body = rand_text(rng, 30)
    if rng.random() < 0.5:
        body = f"{rand_text(rng, 10, string.ascii_lowercase)}/{rand_text(rng, 10, string.ascii_lowercase + '-_.')}"
    version = rng.choice(["", "@1.2.3", "@latest", "@", "@@", "@1", "@v1.0", "==1.0", "@1.0.0-beta+build", "@" + rand_text(rng, 6)])
    return rng.choice(prefixes) + body + version


def _spec_run(value: str, _tmp: Path) -> Any:
    from leitir.spec import parse_corpus_spec

    return parse_corpus_spec(value)


def _spec_allowed() -> tuple[type[BaseException], ...]:
    from leitir.spec import SpecParseError

    return (SpecParseError,)


def _spec_prop_raw(value: Any, output: Any, _tmp: Path) -> str | None:
    if output is not None and getattr(output, "raw", value) != value:
        return "parsed spec does not preserve raw input"
    return None


def _confined_generate(rng: random.Random) -> str:
    parts = [rand_text(rng, 8, string.ascii_lowercase + "._-") for _ in range(rng.randint(0, 4))]
    joiner = rng.choice(["/", "/", "//", "\\", "/./", "/../"])
    text = joiner.join(parts)
    if rng.random() < 0.2:
        text = rng.choice(["/", "/etc/passwd", "../", "..", "a/..", "./a", "a/./b", "a//b", "a/b/", "", "\x00", "~", "C:\\x"]) + text
    return text


def _confined_run(value: str, tmp: Path) -> Any:
    from leitir.safeio import confined_path

    return str(confined_path(tmp, value))


def _confined_allowed() -> tuple[type[BaseException], ...]:
    from leitir.safeio import SafeIOError

    return (SafeIOError, ValueError)


def _confined_prop_inside(value: Any, output: Any, tmp: Path) -> str | None:
    if output is None:
        return None
    root = tmp.resolve()
    try:
        Path(output).relative_to(root)
    except ValueError:
        return f"confined_path escaped its root: {output!r}"
    return None


def _tree_generate(rng: random.Random) -> dict[str, Any]:
    files: dict[str, str] = {}
    for _ in range(rng.randint(0, 6)):
        depth = rng.randint(0, 2)
        name = "/".join(rand_text(rng, 6, string.ascii_lowercase + "._-") or "f" for _ in range(depth + 1))
        files[name] = rand_bytes(rng, 64).hex()
    return {"files": files, "symlink": rng.random() < 0.1, "manifest": rng.random() < 0.3}


def _tree_materialize(spec: dict[str, Any], tmp: Path) -> Path:
    root = tmp / "tree"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    for name, hex_content in spec["files"].items():
        if any(part in {"", ".", ".."} for part in name.split("/")):
            continue
        try:
            target = root / PurePosixPath(name)
            if not str(target.resolve()).startswith(str(root.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bytes.fromhex(hex_content))
        except (OSError, ValueError, UnicodeError):
            continue
    if spec["manifest"]:
        (root / "leitir-manifest.json").write_text("{}", encoding="utf-8")
    if spec["symlink"]:
        try:
            (root / "link").symlink_to("nowhere")
        except OSError:
            pass
    return root


def _tree_run(spec: dict[str, Any], tmp: Path) -> Any:
    from leitir.treehash import compute_materialized_tree_hash

    root = _tree_materialize(spec, tmp)
    return compute_materialized_tree_hash(root)


def _tree_allowed() -> tuple[type[BaseException], ...]:
    from leitir.treehash import TreeHashError

    return (TreeHashError,)


def _tree_prop_verify_and_tamper(spec: Any, output: Any, tmp: Path) -> str | None:
    if output is None:
        return None
    from leitir.treehash import TreeHashError, verify_materialized_tree_hash

    root = tmp / "tree"
    digest_value, scope = output
    try:
        verify_materialized_tree_hash(root, digest_value, scope=scope)
    except TreeHashError as exc:
        return f"freshly computed tree hash failed verification: {type(exc).__name__}"
    regular = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "leitir-manifest.json" and not path.is_symlink())
    if not regular:
        return None
    victim = regular[0]
    original = victim.read_bytes()
    victim.write_bytes(original + b"\x01")
    try:
        verify_materialized_tree_hash(root, digest_value, scope=scope)
    except TreeHashError:
        return None
    finally:
        victim.write_bytes(original)
    return f"tamper of {victim.relative_to(root)} was not detected"


_REGEX_FRAGMENTS = ["a", "b", ".", "\\w", "\\s", "\\d", "[a-z]", "[^x]", "(", ")", "(?:", "(?=", "(?!", "*", "+", "?", "{2}", "{1,3}", "{,5}", "|", "^", "$", "\\b", "(a+)+", "(a|aa)+", "(.*a){8}", "\\", "[", "]", "(?P<n>x)", "(?P=n)", "\\1", "x*y*z*", "\\.", "é", "\u00ff"]


def _regex_generate(rng: random.Random) -> dict[str, Any]:
    pattern = "".join(rng.choice(_REGEX_FRAGMENTS) for _ in range(rng.randint(1, 10)))
    lines = [rand_text(rng, 80, "ab xyz.\t") for _ in range(rng.randint(0, 8))]
    if rng.random() < 0.3:
        lines.append("a" * rng.randint(100, 5000))
    return {"pattern": pattern, "lines": lines}


def _regex_run(value: dict[str, Any], _tmp: Path) -> Any:
    from leitir._regex_budget import bounded_matching_lines, has_catastrophic_shape

    catastrophic = has_catastrophic_shape(value["pattern"])
    compiled = re.compile(value["pattern"])
    matched = bounded_matching_lines(list(value["lines"]), compiled)
    return {"catastrophic": catastrophic, "matched": sorted(matched)}


def _regex_allowed() -> tuple[type[BaseException], ...]:
    from leitir._regex_budget import RegexBudgetExceeded, RegexRejectedError

    return (re.error, RegexRejectedError, RegexBudgetExceeded)


def _search_generate(rng: random.Random) -> dict[str, Any]:
    from leitir.search import PredicateKind

    kinds = [kind.value for kind in PredicateKind]
    predicates = []
    for index in range(rng.randint(1, 4)):
        predicates.append(
            {
                "kind": rng.choice(kinds) if rng.random() < 0.95 else "bogus",
                "value": rng.choice(["defaultdict", "stable search phrase", "encode_value_3", "value", "def", rand_text(rng, 12), "(a+)+$", "*.py", ""]),
                "language": rng.choice([None, None, None, "python", "Python", "py", "rust", "", rand_text(rng, 5)]),
                "bucket": "must" if index == 0 else rng.choice(["must", "should", "must_not"]),
            }
        )
    files = []
    for index in range(rng.randint(0, 6)):
        files.append(
            {
                "path": rng.choice([f"pkg/m{index}.py", f"pkg/m{index}.rs", f"docs/{index}.md", rand_text(rng, 10, string.ascii_lowercase + "/._") + ".py"]),
                "content": rng.choice(
                    [
                        "from collections import defaultdict\n\ndef encode_value_3(value):\n    marker = 'stable search phrase'\n    return defaultdict(list), value\n",
                        rand_text(rng, 200, string.printable),
                        "",
                        "\x00\xff binary",
                        "def " + rand_text(rng, 8, string.ascii_lowercase) + "():\n    pass\n",
                    ]
                ),
            }
        )
    return {"predicates": predicates, "files": files, "whole_file": rng.random() < 0.2, "shuffle_seed": rng.randint(0, 10**6)}


class _MemoryTree:
    def __init__(self, files: list[tuple[str, bytes]]) -> None:
        from leitir.tree import BlobEntry

        self._entries = tuple(
            (BlobEntry(path, hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest(), len(content)), content)
            for path, content in files
        )
        self._content = {entry.blob_sha: content for entry, content in self._entries}

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[Any, ...]:
        del slug, commit_sha
        return tuple(entry for entry, _content in self._entries)

    def list_blobs_ex(self, slug: str, commit_sha: str) -> tuple[tuple[Any, ...], bool]:
        return (self.list_blobs(slug, commit_sha), False)

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        del slug
        return self._content[blob_sha]


def _search_build(value: dict[str, Any], files: list[tuple[str, bytes]]) -> Any:
    from leitir.adapters import PythonAdapter
    from leitir.engine import ScopedSearcher
    from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec

    buckets: dict[str, list[Any]] = {"must": [], "should": [], "must_not": []}
    for item in value["predicates"]:
        kind = PredicateKind(item["kind"])
        buckets[item["bucket"]].append(Predicate(kind, item["value"], item["language"]))
    spec = SearchSpec(
        SearchMode.SCOPED_EXHAUSTIVE,
        must=tuple(buckets["must"]),
        should=tuple(buckets["should"]),
        must_not=tuple(buckets["must_not"]),
        scopes=(RepoScope("example/corpus", _SHA1_A),),
        whole_file_must=value["whole_file"],
    )
    searcher = ScopedSearcher(_MemoryTree(files), (PythonAdapter(),))  # type: ignore[arg-type]
    return searcher.search(spec)


def _search_files(value: dict[str, Any]) -> list[tuple[str, bytes]]:
    return [(item["path"], item["content"].encode("utf-8", errors="surrogatepass")) for item in value["files"]]


def _search_run(value: dict[str, Any], _tmp: Path) -> Any:
    return _search_build(value, _search_files(value))


def _search_allowed() -> tuple[type[BaseException], ...]:
    from leitir.search import SearchSpecError

    return (ValueError, TypeError, SearchSpecError)


def _search_prop_permutation(value: Any, output: Any, _tmp: Path) -> str | None:
    """Search reports must not depend on the order files are listed."""
    if output is None:
        return None
    files = _search_files(value)
    random.Random(value["shuffle_seed"]).shuffle(files)
    try:
        permuted = _search_build(value, files)
    except Exception as exc:  # pragma: no cover - surfaced as crash by the runner
        return f"permuted run raised {type(exc).__name__}"
    if stable_digest(output) != stable_digest(permuted):
        return "search report changed when tree listing order was permuted"
    return None


_VOLATILE_KEYS = frozenset({"as_of", "elapsed", "elapsed_seconds", "duration", "wall_clock", "timing", "generated_at", "fetched_at", "started_at", "finished_at"})


def _strip_volatile(report: Any) -> Any:
    """Drop wall-clock fields (``resolution.as_of`` and friends) before comparing two runs."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: strip(item) for key, item in value.items() if key not in _VOLATILE_KEYS}
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    return strip(canon(report))


def stable_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(_strip_volatile(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _rank_generate(rng: random.Random) -> dict[str, Any]:
    matches = []
    for _ in range(rng.randint(0, 40)):
        matches.append(
            {
                "slug": f"ex/r{rng.randint(0, 4)}",
                "sha": rng.choice("0123456789abcdef") * 40,
                "path": rng.choice([f"pkg/m{rng.randint(0, 9)}.py", "a.py", "z/z.py"]),
                "blob": hashlib.sha1(str(rng.randint(0, 50)).encode()).hexdigest(),
                "line": rng.randint(1, 30),
                "score": rng.choice([0.0, 1.0, 2.5, float(rng.randint(0, 10)), rng.random() * 10]),
                "kinds": rng.choice([["identifier"], ["exact_text"], ["identifier", "regex"]]),
            }
        )
    return {"matches": matches, "shuffle_seed": rng.randint(0, 10**6)}


def _rank_build(items: list[dict[str, Any]]) -> Any:
    from leitir.ranking import rank_matches
    from leitir.search import PredicateKind, SourceMatch, SourceRef

    matches = tuple(
        SourceMatch(
            source=SourceRef(slug=item["slug"], commit_sha=item["sha"], path=item["path"], blob_sha=item["blob"], start_line=item["line"], end_line=item["line"]),
            score=item["score"],
            matched_kinds=tuple(PredicateKind(kind) for kind in item["kinds"]),
        )
        for item in items
    )
    return rank_matches(matches)


def _rank_run(value: dict[str, Any], _tmp: Path) -> Any:
    return _rank_build(value["matches"])


def _rank_allowed() -> tuple[type[BaseException], ...]:
    return (ValueError,)


def _rank_prop_permutation(value: Any, output: Any, _tmp: Path) -> str | None:
    if output is None:
        return None
    items = list(value["matches"])
    random.Random(value["shuffle_seed"]).shuffle(items)
    try:
        permuted = _rank_build(items)
    except Exception as exc:
        return f"permuted ranking raised {type(exc).__name__}"
    if digest(output) != digest(permuted):
        return "ranking changed under input permutation (total order violated)"
    scores = [getattr(item, "rank_score", None) for item in output]
    numeric = [float(score) for score in scores if isinstance(score, (int, float))]
    if len(numeric) != len(scores):
        return None
    if numeric != sorted(numeric, reverse=True) or len(set(numeric)) != len(numeric) or any(score <= 0 for score in numeric):
        return "rank scores are not unique, positive, and strictly decreasing"
    return None


def _trust_generate(rng: random.Random) -> dict[str, Any]:
    good = {
        "verified": True,
        "parity": "exact",
        "license_confidence": "high",
        "license_method": "manifest",
        "docs_urls": ["https://invalid.example/docs"],
        "entry_points": ["leitir"],
        "has_tests": True,
        "artifact_checksum": "sha256:" + "b" * 64,
        "artifact_kind": "sdist",
        "published_at": "2025-01-01T00:00:00+00:00",
        "fetched_at": "2025-06-01T00:00:00+00:00",
        "source": "git-commit",
    }
    manifest: dict[str, Any] = {}
    for key, value in good.items():
        roll = rng.random()
        if roll < 0.25:
            continue
        if roll < 0.5:
            manifest[key] = rand_json(rng)
        elif roll < 0.6 and isinstance(value, str):
            manifest[key] = rand_text(rng, 40)
        else:
            manifest[key] = value
    if rng.random() < 0.3:
        manifest["published_at"] = rng.choice(["2025-13-01T00:00:00+00:00", "2025-01-01", "2025-01-01T00:00:00", "1969-12-31T23:59:59+00:00", "9999-12-31T23:59:59+00:00", "2025-01-01T00:00:00+14:00", 0, ""])
    return manifest


def _trust_run(value: dict[str, Any], tmp: Path) -> Any:
    from leitir.trust import compute_trust

    return compute_trust(value, tmp)


def _trust_allowed() -> tuple[type[BaseException], ...]:
    return ()


def _trust_prop_bounds(_value: Any, output: Any, _tmp: Path) -> str | None:
    if output is None:
        return None
    score = getattr(output, "score", None)
    if not isinstance(score, int) or not 0 <= score <= 100:
        return f"trust score out of bounds: {score!r}"
    return None


_SPDX_FRAGMENTS = ["MIT", "Apache-2.0", "GPL-3.0-only", "GPL-2.0-or-later", "BSD-3-Clause", "LicenseRef-x", "AND", "OR", "WITH", "(", ")", " ", "and", "or", "+", "MIT ", "Classpath-exception-2.0", "NOASSERTION", "NONE", "-", "é"]


def _spdx_generate(rng: random.Random) -> str:
    if rng.random() < 0.15:
        return rand_text(rng, 30)
    return " ".join(rng.choice(_SPDX_FRAGMENTS) for _ in range(rng.randint(1, 8)))


def _spdx_run(value: str, _tmp: Path) -> Any:
    from leitir.license_policy import canonicalize_spdx_expression

    return canonicalize_spdx_expression(value)


def _spdx_allowed() -> tuple[type[BaseException], ...]:
    return (ValueError,)


def _spdx_prop_idempotent(_value: Any, output: Any, _tmp: Path) -> str | None:
    if output is None:
        return None
    from leitir.license_policy import canonicalize_spdx_expression

    try:
        again = canonicalize_spdx_expression(output)
    except ValueError:
        return f"canonical SPDX expression is not itself accepted: {output!r}"
    if again != output:
        return f"canonicalization is not idempotent: {output!r} -> {again!r}"
    return None


def _lockfile_generate(rng: random.Random) -> dict[str, Any]:
    names = ["package-lock.json", "package.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "Cargo.toml", "go.mod", "go.sum", "uv.lock", "poetry.lock", "requirements.txt", "Pipfile.lock", "pyproject.toml"]
    files: dict[str, str] = {}
    for name in rng.sample(names, rng.randint(0, 4)):
        roll = rng.random()
        if roll < 0.4:
            files[name] = json.dumps(rand_json(rng))
        elif roll < 0.7:
            files[name] = rand_text(rng, 300, string.printable)
        else:
            files[name] = rng.choice(
                [
                    '{"name":"x","lockfileVersion":3,"packages":{"node_modules/zod":{"version":"3.22.0"},"":{"dependencies":{"zod":"^3"}}}}',
                    'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
                    "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n",
                    "zod@^3:\n  version \"3.22.0\"\n",
                    "requests==2.31.0\nzod\n--index-url http://x\n",
                    'version = 1\n[[package]]\nname = "requests"\nversion = "2.31.0"\n',
                ]
            )
    return {"files": files, "ecosystem": rng.choice(["npm", "pypi", "crates", "go", "bogus", ""]), "package": rng.choice(["zod", "serde", "requests", "github.com/a/b", "@scope/pkg", rand_text(rng, 12), ""])}


def _lockfile_run(value: dict[str, Any], tmp: Path) -> Any:
    from leitir.lockfiles import dependency_closures, detect_installed_version_with_source

    root = tmp / "proj"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    for name, content in value["files"].items():
        (root / name).write_text(content, encoding="utf-8", errors="surrogatepass")
    detected = detect_installed_version_with_source(value["ecosystem"], value["package"], root)
    closures = dependency_closures(root)
    return {"detected": detected, "closures": closures}


def _lockfile_allowed() -> tuple[type[BaseException], ...]:
    return ()


def _sbom_generate(rng: random.Random) -> dict[str, Any]:
    texts = [
        "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy",
        "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/",
        "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007",
        "Redistribution and use in source and binary forms, with or without modification, are permitted",
        "SPDX-License-Identifier: MIT\n",
        "SPDX-License-Identifier: MIT OR Apache-2.0\n",
        "",
        rand_text(rng, 400, string.printable),
    ]
    files = {}
    for name in rng.sample(["LICENSE", "LICENSE.md", "COPYING", "LICENSE.txt", "license", "LICENSES/MIT.txt", "package.json", "pyproject.toml", "Cargo.toml", "README.md"], rng.randint(0, 4)):
        if name == "package.json":
            files[name] = json.dumps({"license": rng.choice(["MIT", "(MIT OR Apache-2.0)", rand_text(rng, 8), None, 5, {"type": "MIT"}])})
        elif name in {"pyproject.toml", "Cargo.toml"}:
            files[name] = f'[project]\nlicense = "{rng.choice(["MIT", "Apache-2.0", rand_text(rng, 8)])}"\n'
        else:
            files[name] = rng.choice(texts)
    manifest = {"license_hint": rng.choice([None, "MIT", "", rand_text(rng, 8)])} if rng.random() < 0.5 else {}
    return {"files": files, "manifest": manifest}


def _sbom_run(value: dict[str, Any], tmp: Path) -> Any:
    from leitir.sbom import infer_license, infer_repository_license

    root = tmp / "repo"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    for name, content in value["files"].items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", errors="surrogatepass")
    return {"repo": infer_repository_license(root), "manifest": infer_license(dict(value["manifest"]), root)}


def _sbom_allowed() -> tuple[type[BaseException], ...]:
    return ()


TARGETS: dict[str, Target] = {
    target.name: target
    for target in (
        Target("spec", _spec_generate, _spec_run, _spec_allowed, (_spec_prop_raw,), "parse_corpus_spec grammar"),
        Target("confined_path", _confined_generate, _confined_run, _confined_allowed, (_confined_prop_inside,), "safeio.confined_path traversal guard"),
        Target("treehash", _tree_generate, _tree_run, _tree_allowed, (_tree_prop_verify_and_tamper,), "materialized tree hash compute/verify/tamper"),
        Target("regex_budget", _regex_generate, _regex_run, _regex_allowed, (), "bounded regex matching and ReDoS shape guard"),
        Target("search", _search_generate, _search_run, _search_allowed, (_search_prop_permutation,), "scoped search kernel over an in-memory tree"),
        Target("ranking", _rank_generate, _rank_run, _rank_allowed, (_rank_prop_permutation,), "ADR-002 total-order ranking"),
        Target("trust", _trust_generate, _trust_run, _trust_allowed, (_trust_prop_bounds,), "seven-factor trust scoring on malformed manifests"),
        Target("spdx", _spdx_generate, _spdx_run, _spdx_allowed, (_spdx_prop_idempotent,), "SPDX expression canonicalization"),
        Target("lockfiles", _lockfile_generate, _lockfile_run, _lockfile_allowed, (), "lockfile version detection and closure on junk inputs"),
        Target("sbom_license", _sbom_generate, _sbom_run, _sbom_allowed, (), "license inference from repository files"),
    )
}


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FuzzFailure:
    target: str
    seed: int
    index: int
    kind: str  # crash | nondeterministic | slow | property
    signature: str
    detail: str
    input_repr: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class FuzzResult:
    target: str
    seed: int
    executed: int
    failures: list[FuzzFailure]
    by_design: int
    elapsed: float
    digests: list[str]

    def signature_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for failure in self.failures:
            counts[failure.signature] = counts.get(failure.signature, 0) + 1
        return counts


def _signature(target: str, exc: BaseException) -> str:
    frames = traceback.extract_tb(exc.__traceback__)
    inside = [frame for frame in frames if "/leitir/" in frame.filename.replace("\\", "/")]
    frame = inside[-1] if inside else (frames[-1] if frames else None)
    where = f"{Path(frame.filename).name}:{frame.name}" if frame else "?"
    return f"{target}:{type(exc).__name__}@{where}"


def input_for(target: Target, seed: int, index: int) -> Any:
    rng = random.Random(f"{target.name}:{seed}:{index}")
    return target.generate(rng)


def fuzz_target(
    target: Target,
    *,
    seed: int,
    count: int,
    budget_seconds: float | None = None,
    collect_digests: bool = False,
    only_index: int | None = None,
) -> FuzzResult:
    started = time.monotonic()
    warnings.simplefilter("ignore", FutureWarning)
    failures: list[FuzzFailure] = []
    digests: list[str] = []
    by_design = 0
    executed = 0
    allowed = target.allowed()
    with tempfile.TemporaryDirectory(prefix=f"leitir-fuzz-{target.name}-") as tmp_name:
        tmp = Path(tmp_name)
        roots = [str(tmp), str(tmp.resolve())]
        _TMP_ROOTS[:] = sorted(set(roots), key=len, reverse=True)
        for index in range(count):
            if only_index is not None and index != only_index:
                continue
            if budget_seconds is not None and time.monotonic() - started > budget_seconds:
                break
            value = input_for(target, seed, index)
            executed += 1
            input_repr = json.dumps(canon(value), sort_keys=True)[:400]
            outputs: list[Any] = []
            crashed = False
            for _attempt in range(2):
                t0 = time.monotonic()
                try:
                    with _deadline(HANG_SECONDS):
                        output = target.run(value, tmp)
                    outputs.append(("ok", stable_digest(output), output))
                except InputHang:
                    crashed = True
                    failures.append(FuzzFailure(target.name, seed, index, "slow", f"{target.name}:hang", f"input exceeded {HANG_SECONDS:.0f}s hard deadline", input_repr))
                    break
                except allowed as exc:
                    outputs.append(("by_design", type(exc).__name__, None))
                except RecursionError as exc:
                    crashed = True
                    failures.append(FuzzFailure(target.name, seed, index, "crash", _signature(target.name, exc), "RecursionError", input_repr))
                    break
                except Exception as exc:
                    crashed = True
                    failures.append(
                        FuzzFailure(
                            target.name,
                            seed,
                            index,
                            "crash",
                            _signature(target.name, exc),
                            f"{type(exc).__name__}: {str(exc)[:300]}",
                            input_repr,
                        )
                    )
                    break
                elapsed = time.monotonic() - t0
                if elapsed > SLOW_SECONDS:
                    failures.append(FuzzFailure(target.name, seed, index, "slow", f"{target.name}:slow", f"{elapsed:.2f}s for one input", input_repr))
            if crashed:
                if collect_digests:
                    digests.append("crash")
                continue
            first, second = outputs
            if (first[0], first[1]) != (second[0], second[1]):
                failures.append(
                    FuzzFailure(target.name, seed, index, "nondeterministic", f"{target.name}:nondeterministic", f"{first[:2]} != {second[:2]}", input_repr)
                )
            if first[0] == "by_design":
                by_design += 1
                if collect_digests:
                    digests.append("by_design:" + first[1])
                continue
            if collect_digests:
                digests.append(first[1])
            for prop in target.properties:
                try:
                    with _deadline(HANG_SECONDS):
                        verdict = prop(value, first[2], tmp)
                except InputHang:
                    verdict = f"property check exceeded {HANG_SECONDS:.0f}s hard deadline"
                except Exception as exc:
                    verdict = f"property check raised {type(exc).__name__}: {str(exc)[:200]}"
                if verdict:
                    failures.append(FuzzFailure(target.name, seed, index, "property", f"{target.name}:property:{prop.__name__}", verdict, input_repr))
    return FuzzResult(target.name, seed, executed, failures, by_design, time.monotonic() - started, digests)


def check_input(target: Target, seed: int, index: int) -> list[FuzzFailure]:
    """Re-run exactly one historical input (used to confirm or retire a ledger finding)."""
    result = fuzz_target(target, seed=seed, count=index + 1, only_index=index)
    return list(result.failures)


def worker_main(argv: list[str]) -> int:
    """Digest-only worker used by the determinism probe under varied environments."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    args = parser.parse_args(argv)
    target = TARGETS[args.target]
    result = fuzz_target(target, seed=args.seed, count=args.count, collect_digests=True)
    sys.stdout.write(json.dumps({"target": args.target, "digests": result.digests, "crashes": len([f for f in result.failures if f.kind == "crash"])}))
    return 0
