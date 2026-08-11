from __future__ import annotations

import os
import subprocess
import sys

import pytest

from leitir.adapters import GoAdapter, PythonAdapter, RustAdapter
from leitir.adapters._tier2 import (
    CAdapter,
    CppAdapter,
    JavaAdapter,
    JavaScriptAdapter,
    TypeScriptAdapter,
)
from leitir.adapters.python_ast import PythonAstAdapter
from leitir.adapters.registry import build_adapters


def test_build_adapters_default_order() -> None:
    adapters = build_adapters()

    assert isinstance(adapters, tuple)
    assert tuple(type(adapter) for adapter in adapters) == (
        PythonAdapter,
        RustAdapter,
        GoAdapter,
        JavaScriptAdapter,
        TypeScriptAdapter,
        JavaAdapter,
        CAdapter,
        CppAdapter,
    )


def test_build_adapters_filter_preserves_registry_order() -> None:
    adapters = build_adapters(("go", "python"))

    assert tuple(type(adapter) for adapter in adapters) == (
        PythonAdapter,
        GoAdapter,
    )


def test_build_adapters_all_selected_preserves_order() -> None:
    adapters = build_adapters(("go", "rust", "python"))

    assert tuple(type(adapter) for adapter in adapters) == (
        PythonAdapter,
        RustAdapter,
        GoAdapter,
    )


def test_build_adapters_rejects_duplicate_languages() -> None:
    with pytest.raises(ValueError, match="unique"):
        build_adapters(("python", "python"))


def test_build_adapters_rejects_unknown_language() -> None:
    with pytest.raises(ValueError, match="brainfuck"):
        build_adapters(("python", "brainfuck"))


def test_build_adapters_enables_ast_python() -> None:
    assert tuple(type(adapter) for adapter in build_adapters(ast_python=True)) == (
        PythonAstAdapter,
        RustAdapter,
        GoAdapter,
        JavaScriptAdapter,
        TypeScriptAdapter,
        JavaAdapter,
        CAdapter,
        CppAdapter,
    )


def test_build_adapters_is_deterministic_across_pythonhashseed() -> None:
    command = [
        sys.executable,
        "-c",
        "from leitir.adapters.registry import build_adapters; "
        "import json; "
        "print(json.dumps([type(a).__name__ for a in build_adapters()]))",
    ]
    outputs = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = "src"
        output = subprocess.check_output(command, env=environment)
        outputs.append(output.replace(b"\r\n", b"\n"))

    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0] == (
        b'["PythonAdapter", "RustAdapter", "GoAdapter", "JavaScriptAdapter", '
        b'"TypeScriptAdapter", "JavaAdapter", "CAdapter", "CppAdapter"]\n'
    )
