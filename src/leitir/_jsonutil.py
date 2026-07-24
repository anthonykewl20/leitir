"""Tolerant extraction helpers for non-deterministic model output."""

from __future__ import annotations

import ast
import json
import re


__all__ = ["extract_json_obj"]


def extract_json_obj(text: object) -> dict[str, object]:
    """Extract a JSON-like object from model text.

    Model providers may wrap the requested object in Markdown or prose, emit a
    top-level array, or use Python literal syntax despite a JSON response hint.
    """

    if not isinstance(text, str):
        raise TypeError("model content must be JSON text")
    source = text.strip()

    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", source, re.DOTALL)
    if fence:
        source = fence.group(1).strip()

    try:
        value, _ = json.JSONDecoder().raw_decode(source)
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            return {"queries": value}
    except json.JSONDecodeError:
        pass

    start, end = source.find("{"), source.rfind("}")
    if start != -1 and end > start:
        candidate = source[start : end + 1]
        for parser in (json.loads, ast.literal_eval):
            try:
                value = parser(candidate)
                if isinstance(value, dict):
                    return value
                if isinstance(value, list):
                    return {"queries": value}
            except (ValueError, SyntaxError):
                continue

    start, end = source.find("["), source.rfind("]")
    if start != -1 and end > start:
        candidate = source[start : end + 1]
        for parser in (json.loads, ast.literal_eval):
            try:
                value = parser(candidate)
                if isinstance(value, list):
                    return {"queries": value}
            except (ValueError, SyntaxError):
                continue

    raise ValueError("could not extract JSON object from model output")
