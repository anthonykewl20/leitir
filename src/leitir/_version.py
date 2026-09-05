"""Public release formatting over Python's normalized distribution version."""
from __future__ import annotations

import importlib.metadata
import re


def display_version(value: str) -> str:
    """Pad the patch of a final three-component version; preserve other forms."""
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]{1,3}", value) is None:
        return value
    try:
        major, minor, patch = (int(part) for part in value.split("."))
    except ValueError:
        return value
    return f"{major}.{minor}.{patch:03d}"


def installed_version() -> str:
    try:
        return display_version(importlib.metadata.version("leitir"))
    except importlib.metadata.PackageNotFoundError:
        return "unknown"
