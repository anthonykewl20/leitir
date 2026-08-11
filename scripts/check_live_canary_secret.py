#!/usr/bin/env python3
"""Emit the live-canary opt-in decision without exposing the secret."""

from __future__ import annotations

import os
from pathlib import Path


def _append(path_name: str, text: str) -> None:
    destination = os.environ.get(path_name)
    if destination:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write(f"{text}\n")


def main() -> int:
    enabled = bool(os.environ.get("LIVE_GITHUB_TOKEN"))
    value = str(enabled).lower()
    _append("GITHUB_OUTPUT", f"enabled={value}")
    if enabled:
        message = "Live canary enabled: required GH_TOKEN secret is configured."
    else:
        message = "Live canary skipped: configure the GH_TOKEN repository secret to opt in."
    _append("GITHUB_STEP_SUMMARY", message)
    print(f"enabled={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
