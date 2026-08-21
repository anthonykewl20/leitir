"""Unified, deterministic context for one materialized dependency."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, TypeGuard

from .apisurface import extract_api_surface
from .corpus import (
    api_index_path,
    examples_index_path,
    find_materialized_sources,
    read_api_index,
    read_examples_index,
    resolve_root,
    write_api_index,
    write_examples_index,
)
from .examples import EXAMPLES_SCHEMA_VERSION, extract_examples, valid_serialized_classification
from .license_policy import (
    REASON_LICENSE_UNDETERMINED,
    STUDY_ONLY,
    LicenseRouting,
    detect_routing_evidence,
    routing_for_source,
)
from .materialize import _refresh_license_manifest, _target_lock, update_manifest
from .sbom import infer_license
from .trust import compute_trust

TOP_SYMBOLS_LIMIT = 50
_KIND_PRIORITY = {"class": 0, "function": 1, "method": 2, "constant": 3}
logger = logging.getLogger(__name__)

# License routing guidance (issue #190).  Advisory only; detection inputs are
# the source root's top-level license files and directory markers.
_LICENSE_TEXT_READ_LIMIT = 1 << 20
_TOP_LEVEL_LICENSE_NAMES = re.compile(r"^(?:LICENSE|LICENCE|COPYING)(?:[._-].*)?$|^(?:copyright)$", re.IGNORECASE)
_ENTERPRISE_CARVE_OUT_DIRS = frozenset({"ee", "enterprise"})
_PROPRIETARY_LICENSE_REF = re.compile(r"(?i)^LicenseRef-[A-Za-z0-9.-]*proprietary[A-Za-z0-9.-]*$")


def _routing_signal_bytes(target: Path) -> tuple[tuple[str, ...], bool, bool]:
    """Collect (spdx ids, proprietary marker, carve-out marker) at the source root."""

    try:
        entries = sorted(target.iterdir(), key=lambda path: path.name)
    except OSError:
        return (), False, False
    texts: list[bytes] = []
    carve_out = False
    for entry in entries:
        try:
            if entry.is_dir():
                if entry.name.lower() in _ENTERPRISE_CARVE_OUT_DIRS and any(entry.iterdir()):
                    carve_out = True
            elif entry.is_file() and _TOP_LEVEL_LICENSE_NAMES.fullmatch(entry.name):
                texts.append(entry.read_bytes()[:_LICENSE_TEXT_READ_LIMIT])
        except OSError:
            continue
    identifiers, proprietary_text = detect_routing_evidence(tuple(texts))
    return identifiers, proprietary_text, carve_out


def source_routing(target: Path, identifier: object) -> dict[str, str]:
    """Advisory transplant-vs-study routing for one materialized source.

    Pure policy evaluation over locally detected evidence; never raises and
    never gates corpus operations (issue #190 C-5): an evaluation failure
    degrades fail-closed to ``study-only`` / ``license-undetermined`` with a
    WARN log.
    """

    try:
        text_ids, proprietary_text, carve_out = _routing_signal_bytes(target)
        proprietary = proprietary_text or (
            isinstance(identifier, str) and _PROPRIETARY_LICENSE_REF.fullmatch(identifier.strip()) is not None
        )
        expressions: tuple[object, ...]
        if isinstance(identifier, str) and identifier.strip():
            expressions = (identifier, *text_ids)
        else:
            expressions = text_ids or (None,)
        routing = routing_for_source(
            expressions,
            proprietary_marker=proprietary,
            enterprise_carve_out=carve_out,
        )
    except Exception:
        logger.warning(
            "license routing evaluation failed for %s; degrading to study-only/license-undetermined",
            target,
        )
        routing = LicenseRouting(STUDY_ONLY, REASON_LICENSE_UNDETERMINED)
    return {"verdict": routing.verdict, "reason": routing.reason}


def _source(spec: str, corpus_root: Path) -> tuple[dict[str, Any], dict[str, object], Path]:
    matches = find_materialized_sources(spec, corpus_root)
    if not matches:
        raise ValueError(f"source is not materialized: {spec}")
    if len(matches) != 1:
        raise ValueError(f"source spec is ambiguous: {spec}")
    return matches[0]


def _valid_api(index: object) -> TypeGuard[dict[str, object]]:
    return (
        isinstance(index, dict)
        and index.get("schema_version") == EXAMPLES_SCHEMA_VERSION
        and isinstance(index.get("methods"), list)
        and isinstance(index.get("modules"), list)
        and isinstance(index.get("symbols"), list)
        and all(
            isinstance(item, str) and item in {"ast", "heuristic"}
            for item in index["methods"]
        )
        and all(
            isinstance(item, dict)
            and isinstance(item.get("kind"), str)
            and item.get("kind") in {"function", "class", "method", "constant"}
            and isinstance(item.get("qualified_name"), str)
            for item in index["symbols"]
        )
    )


def _valid_examples(index: object) -> TypeGuard[dict[str, object]]:
    return (
        isinstance(index, dict)
        and index.get("schema_version") == 1
        and isinstance(index.get("symbols_source"), str)
        and index.get("symbols_source") == "api_index"
        and isinstance(index.get("snippets"), list)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and isinstance(item.get("line"), int)
            and not isinstance(item.get("line"), bool)
            and isinstance(item.get("language"), str)
            and isinstance(item.get("code"), str)
            and isinstance(item.get("symbols"), list)
            and all(isinstance(symbol, str) for symbol in item["symbols"])
            and valid_serialized_classification(item)
            for item in index["snippets"]
        )
    )


def _cached_trust(manifest: dict[str, object]) -> tuple[int, list[dict[str, object]]] | None:
    score = manifest.get("trust_score")
    breakdown = manifest.get("trust_breakdown")
    if (
        not isinstance(score, int)
        or isinstance(score, bool)
        or not 0 <= score <= 100
        or not isinstance(breakdown, list)
        or {item.get("factor") for item in breakdown if isinstance(item, dict)}
        != {
            "age", "artifact_checksum", "documentation", "license", "parity",
            "tests", "verification",
        }
        or not all(
            isinstance(item, dict)
            and isinstance(item.get("factor"), str)
            and isinstance(item.get("score"), int)
            and not isinstance(item.get("score"), bool)
            and 0 <= item["score"] <= 100
            and isinstance(item.get("weight"), int)
            and not isinstance(item.get("weight"), bool)
            and isinstance(item.get("evidence"), dict)
            for item in breakdown
        )
    ):
        return None
    rendered = [dict(item) for item in breakdown]
    rendered.sort(key=lambda item: str(item["factor"]))
    weighted = sum(int(item["score"]) * int(item["weight"]) for item in rendered)
    if sum(int(item["weight"]) for item in rendered) != 100 or (weighted + 50) // 100 != score:
        return None
    return score, rendered


def _line_sort_key(value: object) -> tuple[int, int, str]:
    if isinstance(value, int) and not isinstance(value, bool):
        return (0, value, "")
    return (1, 0, str(value))


def _top_symbols(index: dict[str, object]) -> list[dict[str, object]]:
    raw_symbols = index.get("symbols")
    symbols = (
        [item for item in raw_symbols if isinstance(item, dict)]
        if isinstance(raw_symbols, list)
        else []
    )
    symbols.sort(
        key=lambda item: (
            _KIND_PRIORITY.get(str(item.get("kind")), len(_KIND_PRIORITY)),
            str(item.get("kind", "")),
            str(item.get("qualified_name", "")),
            _line_sort_key(item.get("line")),
            str(item.get("path", "")),
            str(item.get("name", "")),
            str(item.get("signature", "")),
            str(item.get("docstring", "")),
        )
    )
    return [
        {
            "kind": item.get("kind"),
            "name": item.get("name"),
            "qualified_name": item.get("qualified_name"),
            "path": item.get("path"),
            "line": item.get("line"),
            "signature": item.get("signature"),
            "docstring": item.get("docstring"),
        }
        for item in symbols[:TOP_SYMBOLS_LIMIT]
    ]


def _api_summary(index: dict[str, object], path: Path) -> dict[str, object]:
    raw_symbols = index.get("symbols")
    symbols = (
        [item for item in raw_symbols if isinstance(item, dict)]
        if isinstance(raw_symbols, list)
        else []
    )
    by_kind = dict.fromkeys(("function", "class", "method", "constant"), 0)
    for symbol in symbols:
        kind = symbol.get("kind")
        if isinstance(kind, str) and kind in by_kind:
            by_kind[kind] += 1
    raw_methods = index.get("methods")
    methods_source = raw_methods if isinstance(raw_methods, list) else []
    methods = sorted(
        {
            item
            for item in methods_source
            if isinstance(item, str) and item in {"ast", "heuristic"}
        }
    )
    method: str | None
    if methods == ["ast"]:
        method = "ast"
    elif methods:
        method = "heuristic"
    else:
        method = None
    return {
        "symbols": len(symbols),
        "by_kind": by_kind,
        "method": method,
        "index_path": str(path.absolute()),
        "top_symbols": _top_symbols(index),
    }


def build_info(spec: str, *, corpus_root: str | Path) -> dict[str, object]:
    """Build context from one already-materialized source, filling missing caches."""

    logger.debug("building info spec=%s corpus_root=%s", spec, corpus_root)
    root = resolve_root(corpus_root)
    entry, manifest, target = _source(spec, root)
    raw_subpath = manifest.get("subpath")
    subpath = raw_subpath if isinstance(raw_subpath, str) else None
    scan_path = target / subpath if subpath else target

    api_index = read_api_index(root, entry, manifest)
    wrote_cache = False
    if not _valid_api(api_index):
        hint = manifest.get("ecosystem")
        api_index = extract_api_surface(
            scan_path, str(hint) if hint in {"pypi", "npm"} else None
        )
        api_path = write_api_index(root, entry, manifest, api_index)
        wrote_cache = True
    else:
        api_path = api_index_path(root, entry, manifest).absolute()

    examples_index = read_examples_index(root, entry, manifest)
    if not _valid_examples(examples_index):
        examples_index = extract_examples(target, api_index)
        examples_path = write_examples_index(root, entry, manifest, examples_index)
        wrote_cache = True
    else:
        examples_path = examples_index_path(root, entry, manifest).absolute()

    if wrote_cache:
        from .docpointers import regenerate_pointers

        regenerate_pointers(root)

    with _target_lock(root, target, str(entry["commit_sha"])):
        original_license = tuple(
            manifest.get(field)
            for field in ("license_identifier", "license_method", "license_confidence")
        )
        manifest = _refresh_license_manifest(target, manifest)
        license_updated = original_license != tuple(
            manifest.get(field)
            for field in ("license_identifier", "license_method", "license_confidence")
        )
        cached_trust = _cached_trust(manifest)
        if cached_trust is None or license_updated:
            trust = compute_trust(manifest, target)
            trust_score = trust.score
            trust_breakdown = [dict(item) for item in trust.breakdown]
            manifest = update_manifest(target, trust.as_dict())
        else:
            trust_score, trust_breakdown = cached_trust

    license_result = infer_license(manifest, target)
    raw_snippets = examples_index.get("snippets")
    snippets = (
        [dict(item) for item in raw_snippets if isinstance(item, dict)]
        if isinstance(raw_snippets, list)
        else []
    )
    snippets.sort(
        key=lambda item: (
            -len(item.get("symbols", [])) if isinstance(item.get("symbols"), list) else 0,
            str(item.get("path", "")),
            int(item.get("line", 0)) if isinstance(item.get("line"), int) else 0,
        )
    )
    top = [
        {
            "path": item.get("path"),
            "line": item.get("line"),
            "language": item.get("language"),
            "code": item.get("code"),
            "symbols": sorted(item.get("symbols", []))
            if isinstance(item.get("symbols"), list)
            else [],
        }
        for item in snippets
    ]
    api = _api_summary(api_index, api_path)
    return {
        "schema_version": 1,
        "spec": spec,
        "provenance": {
            "host": entry.get("host"),
            "owner": entry.get("owner"),
            "repo": entry.get("repo"),
            "commit_sha": entry.get("commit_sha"),
            "version": manifest.get("version"),
            "version_source": manifest.get("version_source"),
            "source": manifest.get("source"),
            "artifact_kind": manifest.get("artifact_kind"),
            "artifact_checksum": manifest.get("artifact_checksum"),
            "verified": manifest.get("verified"),
            "verified_at": manifest.get("verified_at"),
            "fetched_at": manifest.get("fetched_at", entry.get("fetched_at")),
            "repo_url": manifest.get("repo_url"),
            "subpath": subpath,
        },
        "parity": {
            "parity": manifest.get("parity", "unknown")
            if manifest.get("parity") in {"exact", "drift", "unknown"}
            else "unknown",
            "files_compared": manifest.get("files_compared", 0),
            "only_in_git": manifest.get("only_in_git", 0),
            "only_in_artifact": manifest.get("only_in_artifact", 0),
        },
        "license": {
            "identifier": license_result.identifier,
            "method": license_result.method,
            "confidence": license_result.confidence,
        },
        # Advisory transplant-vs-study license routing (issue #190).  A
        # sibling of "license" (not nested inside it) so the license evidence
        # document shape stays byte-identical for downstream consumers.
        "routing": source_routing(target, license_result.identifier),
        "api": api,
        "examples": {
            "count": len(snippets),
            "top": top,
            "index_path": str(examples_path.absolute()),
        },
        "trust": {"score": trust_score, "breakdown": trust_breakdown},
        "paths": {
            "tree": str(target.absolute()),
            "api_index": api["index_path"],
            "examples_index": str(examples_path.absolute()),
        },
    }


__all__ = ["build_info", "source_routing"]
