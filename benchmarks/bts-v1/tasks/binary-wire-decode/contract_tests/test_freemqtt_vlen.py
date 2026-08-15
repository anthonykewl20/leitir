import importlib
import sys
import types
from pathlib import Path


def _read_le_uint32(value, cursor):
    sys.modules.setdefault("aiorpcx", types.ModuleType("aiorpcx"))
    for name, location in (("electrumx", "electrumx"), ("electrumx.lib", "electrumx/lib")):
        module = sys.modules.setdefault(name, types.ModuleType(name))
        root = next(path for entry in sys.path if (path := Path(entry) / "electrumx/lib/tx.py").is_file()).parents[2]
        module.__path__ = [str(root / location)]
    return importlib.import_module("electrumx.lib.tx").read_le_uint32(value, cursor)


def test_multi_byte_ranges():
    assert _read_le_uint32(b"\xff\xff\x00\x00", 0)[0] == 65535


def test_over_limit_is_rejected():
    assert _read_le_uint32(b"\xff\xff\xff\xff", 0)[0] == 0xFFFFFFFF


def test_single_byte_range():
    assert _read_le_uint32(b"\x7f\x00\x00\x00", 0)[0] == 127
