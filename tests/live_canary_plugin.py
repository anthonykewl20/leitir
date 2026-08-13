"""Pytest event recorder for the live-provider canary workflow."""

from __future__ import annotations

import json
from collections.abc import Generator
from http.client import HTTPException
from pathlib import Path
from typing import Any

import pytest

from leitir import _http

_EVENTS_KEY: pytest.StashKey[list[dict[str, str]]] = pytest.StashKey()
_EVENT_PRIORITY = {
    "configuration-failure": 0,
    "product-failure": 1,
    "infra-failure": 2,
    "skipped-not-landed": 3,
}
_config: pytest.Config | None = None


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("live-canary")
    group.addoption("--live-canary-events", type=Path)
    group.addoption("--live-canary-surface", default="baseline-live")
    group.addoption("--live-canary-declared-test")
    group.addoption("--live-canary-enabled", choices=("true", "false"), default="true")


def _write(config: pytest.Config) -> None:
    destination: Path | None = config.getoption("--live-canary-events")
    if destination is None:
        return
    events = sorted(
        config.stash[_EVENTS_KEY],
        key=lambda item: (item["surface"], item["nodeid"], item["class"], item.get("kind", "")),
    )
    destination.write_text(json.dumps(events, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _record(config: pytest.Config, event: dict[str, str]) -> None:
    """Keep the most severe deterministic event for each collected node."""
    events = config.stash[_EVENTS_KEY]
    matching = [existing for existing in events if existing["nodeid"] == event["nodeid"]]
    if matching:
        best = min(
            (*matching, event),
            key=lambda item: (
                _EVENT_PRIORITY[item["class"]],
                item["surface"],
                item["nodeid"],
                item["class"],
                item.get("kind", ""),
            ),
        )
        events[:] = [existing for existing in events if existing["nodeid"] != event["nodeid"]]
        events.append(best)
    else:
        events.append(event)
    _write(config)


def pytest_sessionstart(session: pytest.Session) -> None:
    global _config
    _config = session.config
    session.config.stash[_EVENTS_KEY] = []
    declared: str | None = session.config.getoption("--live-canary-declared-test")
    enabled: str = session.config.getoption("--live-canary-enabled")
    if declared and enabled == "false":
        _record(
            session.config,
            {
                "class": "skipped-not-landed",
                "kind": "",
                "nodeid": declared,
                "surface": session.config.getoption("--live-canary-surface"),
            },
        )
    else:
        _write(session.config)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live-canary-enabled") == "false":
        marker = pytest.mark.skip(reason="live canary surface is not landed")
        for item in items:
            item.add_marker(marker)


def pytest_collectreport(report: pytest.CollectReport) -> None:
    """Fail closed when an enabled canary surface skips during collection."""
    config = _config
    if config is None or not report.skipped:
        return
    if config.getoption("--live-canary-enabled") == "true":
        location = report.location
        longrepr = report.longrepr
        nodeid = report.nodeid or (location[2] if location else "")
        if not nodeid and isinstance(longrepr, tuple):
            nodeid = longrepr[0]
        _record(
            config,
            {
                "class": "configuration-failure",
                "kind": "",
                "nodeid": nodeid,
                "surface": config.getoption("--live-canary-surface"),
            },
        )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
    call: pytest.CallInfo[Any],
) -> Generator[None, None, None]:
    outcome = yield
    report = outcome.get_result()
    if report.skipped and item.config.getoption("--live-canary-enabled") == "true":
        _record(
            item.config,
            {
                # Only an explicitly disabled, not-yet-landed surface may
                # report skipped-not-landed. A selected test that skips is
                # missing coverage and must fail closed.
                "class": "configuration-failure",
                "kind": "",
                "nodeid": item.nodeid,
                "surface": item.config.getoption("--live-canary-surface"),
            },
        )


def first_network_exception(exc: BaseException) -> BaseException | None:
    """Return the first HTTP/OSError in a cycle-safe cause/context chain."""
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (HTTPException, OSError)):
            return current
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return None


def classify_exception(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, AssertionError):
        return "product-failure", ""
    network = first_network_exception(exc)
    if network is not None:
        kind = _http.classify(network)
        if kind in {_http.HttpErrorKind.RATE_LIMITED, _http.HttpErrorKind.TRANSIENT}:
            return "infra-failure", kind.value
    return "configuration-failure", ""


def pytest_exception_interact(
    node: pytest.Node,
    call: pytest.CallInfo[Any],
    report: pytest.TestReport,
) -> None:
    del report
    event_class, kind = classify_exception(call.excinfo.value)
    _record(
        node.config,
        {
            "class": event_class,
            "kind": kind,
            "nodeid": node.nodeid,
            "surface": node.config.getoption("--live-canary-surface"),
        },
    )
