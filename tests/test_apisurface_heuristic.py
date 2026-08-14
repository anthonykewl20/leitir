from __future__ import annotations

from collections import Counter

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


def test_go_heuristic_surface_is_exported_deterministic_and_multifile(tmp_path):
    (tmp_path / "alpha.go").write_text(
        """package example

type PublicStruct struct{}
type PublicInterface interface {
    Execute(value string) error
    Multi(
        value string,
    ) error
    hidden()
}
type PublicAlias = string
type privateType struct{}
type (
    BlockType struct {
        ExportedField string
    }
    hiddenBlock struct{}
)

const PublicConst = "value"
const privateConst = "hidden"
const (
    BlockOne = 1
    BlockTwo = 2
    hiddenBlockConst = 3
)
var PublicVar string = "value"
var privateVar = "hidden"
var (
    BlockVar = "value"
    hiddenBlockVar = "hidden"
)

func Exported(value string) error { return nil }
func privateFunction() {}
func Generic[T any](value T) T { return value }
func MultiLine(
    value string,
) error {
    return nil
}
func (receiver PublicStruct) Value() {}
func (receiver *PublicStruct) Pointer() {}
func (receiver privateType) VisibleOnPrivate() {}
func (receiver PublicStruct) hiddenMethod() {}
func Éxported() {}
""",
        encoding="utf-8",
    )
    nested = tmp_path / "internal"
    nested.mkdir()
    (nested / "tagged.go").write_text(
        """//go:build ignored

package internal

func Tagged() {}
""",
        encoding="utf-8",
    )

    first = extract_api_surface(tmp_path, "go")
    second = extract_api_surface(tmp_path)

    assert first == second
    assert [module["path"] for module in first["modules"]] == [
        "alpha.go",
        "internal/tagged.go",
    ]
    symbols = {symbol["qualified_name"]: symbol for symbol in first["symbols"]}
    assert Counter(symbol["kind"] for symbol in first["symbols"]) == {
        "class": 4,
        "constant": 5,
        "function": 5,
        "method": 5,
    }
    assert symbols["alpha.Generic"]["signature"] == "[T any](value T) T"
    assert symbols["alpha.MultiLine"]["signature"] == "(value string,) error"
    assert symbols["alpha.PublicStruct.Pointer"] == {
        "kind": "method",
        "name": "Pointer",
        "qualified_name": "alpha.PublicStruct.Pointer",
        "module": "alpha",
        "path": "alpha.go",
        "line": 43,
        "signature": "()",
        "docstring": None,
        "method": "heuristic",
    }
    assert symbols["alpha.PublicInterface.Execute"]["signature"] == "(value string) error"
    assert symbols["alpha.PublicInterface.Multi"]["signature"] == "(value string,) error"
    assert symbols["alpha.Éxported"]["kind"] == "function"
    assert symbols["internal/tagged.Tagged"]["line"] == 5
    assert "alpha.privateFunction" not in symbols
    assert "alpha.privateType" not in symbols
    assert "alpha.hiddenBlock" not in symbols
    assert "alpha.hiddenMethod" not in symbols


def test_go_heuristic_skips_vendor_and_testdata_directories(tmp_path):
    (tmp_path / "main.go").write_text("package example\n\nfunc Main() {}\n", encoding="utf-8")
    (tmp_path / "vendorlike.go").write_text(
        "package example\n\nfunc Vendorlike() {}\n", encoding="utf-8"
    )
    vendor = tmp_path / "vendor" / "other"
    vendor.mkdir(parents=True)
    (vendor / "x.go").write_text("package other\n\nfunc Vendored() {}\n", encoding="utf-8")
    testdata = tmp_path / "testdata"
    testdata.mkdir()
    (testdata / "t.go").write_text("package testdata\n\nfunc Testdata() {}\n", encoding="utf-8")

    index = extract_api_surface(tmp_path, "go")

    assert [module["path"] for module in index["modules"]] == ["main.go", "vendorlike.go"]
    assert [symbol["qualified_name"] for symbol in index["symbols"]] == [
        "main.Main",
        "vendorlike.Vendorlike",
    ]
