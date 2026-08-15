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


def test_known_value():
    assert _read_le_uint32(b"\x78\x56\x34\x12", 0)[0] == 0x12345678


def test_matches_zlib_crc32():
    assert _read_le_uint32(b"\x00\x00\x00\x00", 0)[0] == 0
