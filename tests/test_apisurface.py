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


def test_api_cache_path_and_round_trip(tmp_path):
    entry = {"name": "demo", "host": "github.com", "commit_sha": "a" * 40}
    manifest = {"ecosystem": "pypi", "version": "1.2.3"}
    index = {"schema_version": 1, "methods": [], "modules": [], "symbols": []}
    path = write_api_index(tmp_path, entry, manifest, index)
    assert path == tmp_path / "api/pypi/demo/1.2.3/index.json"
    assert api_index_path(tmp_path, entry, manifest) == path
    assert read_api_index(tmp_path, entry, manifest) == index
    assert json.loads(path.read_text(encoding="utf-8")) == index
