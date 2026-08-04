from __future__ import annotations

from leitir.apisurface import extract_api_surface, register_extractor


def test_javascript_typescript_heuristic_exports_and_methods(tmp_path):
    (tmp_path / "api.ts").write_text(
        """export function parse(value: string): number { return 1; }
export class Client {
  run(value: string): void {
  }
}
export const build = (name: string) => name;
export const load = async value => value;
export const VERSION: string = "1";
""",
        encoding="utf-8",
    )
    (tmp_path / "binary.js").write_bytes(b"\xff\xfe")

    index = extract_api_surface(tmp_path, "typescript")

    symbols = {symbol["qualified_name"]: symbol for symbol in index["symbols"]}
    assert sorted(symbols) == ["api.Client", "api.Client.run", "api.VERSION", "api.build", "api.load", "api.parse"]
    assert symbols["api.Client.run"]["kind"] == "method"
    assert symbols["api.build"]["kind"] == "function"
    assert symbols["api.VERSION"]["kind"] == "constant"
    assert index["methods"] == ["heuristic"]
    assert all(symbol["method"] == "heuristic" for symbol in index["symbols"])


def test_registered_extractor_substitutes_without_contract_change(tmp_path):
    def plugin(target, language):
        return {
            "schema_version": 999,
            "methods": ["parser"],
            "modules": [{"name": "plugin", "path": "plugin.ts", "docstring": None, "method": "parser"}],
            "symbols": [{"kind": "function", "name": "plug", "qualified_name": "plugin.plug", "module": "plugin", "path": "plugin.ts", "line": 1, "signature": "()", "docstring": None, "method": "parser"}],
        }

    previous = register_extractor("typescript", plugin)
    try:
        index = extract_api_surface(tmp_path, "typescript")
    finally:
        assert previous is not None
        register_extractor("typescript", previous)
    assert set(index) == {"schema_version", "methods", "modules", "symbols"}
    assert index["schema_version"] == 1
    assert index["methods"] == ["parser"]
