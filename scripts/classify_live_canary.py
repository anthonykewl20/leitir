#!/usr/bin/env python3
"""Classify pytest canary events and render deterministic GitHub summaries."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

_CLASSES = frozenset(
    {
        "configuration-failure",
        "infra-failure",
        "product-failure",
        "skipped-not-landed",
    }
)
_FAILURES = frozenset({"configuration-failure", "product-failure"})
_PRIORITY = {
    "configuration-failure": 0,
    "product-failure": 1,
    "infra-failure": 2,
    "skipped-not-landed": 3,
    "pass": 4,
}


def _escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _write_github(name: str, text: str) -> None:
    destination = os.environ.get(name)
    if destination:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write(text)
            if not text.endswith("\n"):
                stream.write("\n")


def _validate_events(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, list):
        raise ValueError("events document must be a JSON array")
    events: list[dict[str, str]] = []
    for index, raw in enumerate(payload):
        if not isinstance(raw, dict):
            raise ValueError(f"event {index} must be an object")
        event_class = raw.get("class")
        surface = raw.get("surface")
        nodeid = raw.get("nodeid")
        kind = raw.get("kind", "")
        if event_class not in _CLASSES:
            raise ValueError(f"event {index} has invalid class")
        if not isinstance(surface, str) or not surface:
            raise ValueError(f"event {index} has invalid surface")
        if not isinstance(nodeid, str) or not nodeid:
            raise ValueError(f"event {index} has invalid nodeid")
        if not isinstance(kind, str):
            raise ValueError(f"event {index} has invalid kind")
        if event_class == "infra-failure" and kind not in {"rate_limited", "transient"}:
            raise ValueError(f"event {index} has invalid infrastructure kind")
        events.append(
            {"class": event_class, "kind": kind, "nodeid": nodeid, "surface": surface}
        )
    return sorted(events, key=lambda item: (item["surface"], item["nodeid"], item["class"], item["kind"]))


def _classification(events: list[dict[str, str]], pytest_outcome: str) -> str:
    if not events:
        return "pass" if pytest_outcome == "success" else "configuration-failure"
    classes = {event["class"] for event in events}
    if pytest_outcome == "failure":
        if classes <= {"infra-failure"}:
            return "infra-failure"
        if classes <= {"skipped-not-landed"}:
            return "configuration-failure"
    return min(classes, key=lambda value: _PRIORITY[value])


def _detail(events: list[dict[str, str]], classification: str) -> str:
    matching = [event for event in events if event["class"] == classification]
    if not matching:
        return "selected probe completed" if classification == "pass" else "probe did not emit valid events"
    parts = []
    for event in matching:
        suffix = f"/{event['kind'].replace('_', '-')}" if event["kind"] else ""
        parts.append(f"{event['nodeid']}{suffix}")
    return "; ".join(parts)


def _table(rows: list[tuple[str, str, str]]) -> str:
    lines = [
        "## Live canary classification",
        "",
        "| Surface | Classification | Detail |",
        "| --- | --- | --- |",
    ]
    for surface, classification, detail in rows:
        lines.append(f"| {_escape(surface)} | `{classification}` | {_escape(detail)} |")
    return "\n".join(lines) + "\n"


def _emit(rows: list[tuple[str, str, str]]) -> int:
    rendered = _table(rows)
    print(rendered, end="")
    _write_github("GITHUB_STEP_SUMMARY", rendered)
    for surface, classification, detail in rows:
        if classification == "infra-failure":
            print(f"::warning title=Live canary infrastructure failure ({surface})::{_escape(detail)}")
    return 1 if any(classification in _FAILURES for _, classification, _ in rows) else 0


def _parse_bool(name: str) -> bool:
    value = os.environ.get(name)
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"{name} must be true or false")


def _summary_rows() -> list[tuple[str, str, str]]:
    surfaces = (
        ("baseline-live", None, "BASELINE_RESULT"),
        ("truncated-tree-recovery", "TREE_V2", "TREE_RESULT"),
        ("streamed-large-blob", "STREAM_V2", "STREAM_RESULT"),
        ("index-vs-scan-recall", "INDEX_V2", "INDEX_RESULT"),
    )
    gate_result = os.environ.get("GATE_RESULT")
    if gate_result != "success":
        detail = f"gate job did not succeed (result={gate_result or 'missing'})"
        return [(surface, "configuration-failure", detail) for surface, _, _ in surfaces]
    try:
        enabled = _parse_bool("LIVE_CANARY_ENABLED")
    except ValueError as exc:
        return [(surface, "configuration-failure", str(exc)) for surface, _, _ in surfaces]

    rows: list[tuple[str, str, str]] = []
    for surface, gate_name, result_name in surfaces:
        if not enabled:
            rows.append((surface, "skipped-not-landed", "required live secret is not configured"))
            continue
        if gate_name is not None:
            try:
                gate_enabled = _parse_bool(gate_name)
            except ValueError as exc:
                rows.append((surface, "configuration-failure", str(exc)))
                continue
            if not gate_enabled:
                rows.append((surface, "skipped-not-landed", "repository feature gate is disabled"))
                continue
        result = os.environ.get(result_name, "")
        if result not in _PRIORITY:
            rows.append((surface, "configuration-failure", f"{result_name} did not contain a valid job result"))
        else:
            rows.append((surface, result, "classified by the surface job"))
    try:
        extra_requested = _parse_bool("EXTRA_TESTS_REQUESTED")
    except ValueError as exc:
        rows.append(("extra-live", "configuration-failure", str(exc)))
    else:
        if extra_requested:
            result = os.environ.get("EXTRA_RESULT", "")
            if result not in _PRIORITY:
                rows.append(
                    (
                        "extra-live",
                        "configuration-failure",
                        "EXTRA_RESULT did not contain a valid job result",
                    )
                )
            else:
                rows.append(("extra-live", result, "classified by the surface job"))
    return rows


def _load_events(path: Path) -> list[dict[str, str]]:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
        return _validate_events(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid live canary events: {type(exc).__name__}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("events", nargs="?", type=Path)
    parser.add_argument("--surface", default="baseline-live")
    parser.add_argument("--pytest-outcome", choices=("failure", "success"), default="success")
    parser.add_argument("--summary-from-env", action="store_true")
    args = parser.parse_args(argv)

    if args.summary_from_env:
        return _emit(_summary_rows())
    if args.events is None:
        parser.error("events is required unless --summary-from-env is used")

    try:
        events = _load_events(args.events)
        if any(event["surface"] != args.surface for event in events):
            raise ValueError("event surface does not match --surface")
        classification = _classification(events, args.pytest_outcome)
        detail = _detail(events, classification)
    except ValueError as exc:
        classification = "configuration-failure"
        detail = str(exc)
    _write_github("GITHUB_OUTPUT", f"classification={classification}\n")
    return _emit([(args.surface, classification, detail)])


if __name__ == "__main__":
    raise SystemExit(main())
