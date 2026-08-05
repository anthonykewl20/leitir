from __future__ import annotations

import json

from leitir.apisurface import extract_api_surface
from leitir.corpus import api_index_path, read_api_index, write_api_index


def test_python_ast_surface_is_exact_public_and_deterministic(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text('"""Package docs."""\n', encoding="utf-8")
    (package / "api.py").write_text(
        '''"""Module docs."""
def useful(a: int, /, b="x", *args: str, flag: bool, **kwargs) -> str:
    """Function docs."""
    def nested():
        pass
    return b

def _private():
    pass

class Service(Base, metaclass=Meta):
    """Class docs."""
    def run(self, value: int = 1) -> None:
        """Method docs."""
        pass
''',
        encoding="utf-8",
    )
    (package / "broken.py").write_text("def nope(:\n", encoding="utf-8")

    first = extract_api_surface(tmp_path, "python")
    second = extract_api_surface(tmp_path, "pypi")

    assert first == second
    assert first["methods"] == ["ast"]
    assert [module["path"] for module in first["modules"]] == ["pkg/__init__.py", "pkg/api.py"]
    symbols = {symbol["qualified_name"]: symbol for symbol in first["symbols"]}
    assert sorted(symbols) == ["pkg.api.Service", "pkg.api.Service.run", "pkg.api.useful"]
    assert symbols["pkg.api.useful"]["signature"] == '(a: int, /, b = \'x\', *args: str, flag: bool, **kwargs) -> str'
    assert symbols["pkg.api.useful"]["docstring"] == "Function docs."
    assert symbols["pkg.api.Service.run"]["kind"] == "method"
    assert all(symbol["method"] == "ast" for symbol in first["symbols"])


def test_python_ast_surface_skips_only_nodes_that_exceed_unparse_recursion_limit(tmp_path):
    deep_annotation = "root" + ".part" * 600
    (tmp_path / "pathological.py").write_text(
        f"def too_deep(value: {deep_annotation}):\n    pass\n\ndef retained():\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "normal.py").write_text("def sibling():\n    pass\n", encoding="utf-8")

    index = extract_api_surface(tmp_path, "python")

    assert [module["path"] for module in index["modules"]] == ["normal.py", "pathological.py"]
    assert [symbol["qualified_name"] for symbol in index["symbols"]] == [
        "normal.sibling",
        "pathological.retained",
    ]


def test_python_ast_surface_honors_pep_263_encoding_cookie(tmp_path):
    source = "# -*- coding: latin-1 -*-\n# café\ndef encoded():\n    pass\n"
    (tmp_path / "encoded.py").write_bytes(source.encode("latin-1"))

    index = extract_api_surface(tmp_path, "python")

    assert [symbol["qualified_name"] for symbol in index["symbols"]] == ["encoded.encoded"]


def test_python_ast_surface_honors_utf8_bom(tmp_path):
    (tmp_path / "bom.py").write_bytes("def bom_function():\n    pass\n".encode("utf-8-sig"))

    index = extract_api_surface(tmp_path, "python")

    assert [symbol["qualified_name"] for symbol in index["symbols"]] == ["bom.bom_function"]


def test_python_ast_surface_still_reads_plain_utf8(tmp_path):
    (tmp_path / "plain.py").write_text("# café\ndef plain():\n    pass\n", encoding="utf-8")

    index = extract_api_surface(tmp_path, "python")

    assert [symbol["qualified_name"] for symbol in index["symbols"]] == ["plain.plain"]


def test_api_cache_path_and_round_trip(tmp_path):
    entry = {"name": "demo", "host": "github.com", "commit_sha": "a" * 40}
    manifest = {"ecosystem": "pypi", "version": "1.2.3"}
    index = {"schema_version": 1, "methods": [], "modules": [], "symbols": []}
    path = write_api_index(tmp_path, entry, manifest, index)
    assert path == tmp_path / "api/pypi/demo/1.2.3/index.json"
    assert api_index_path(tmp_path, entry, manifest) == path
    assert read_api_index(tmp_path, entry, manifest) == index
    assert json.loads(path.read_text(encoding="utf-8")) == index
