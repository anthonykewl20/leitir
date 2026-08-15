import importlib
import sys
import types
from pathlib import Path


def _tx():
    sys.modules.setdefault("aiorpcx", types.ModuleType("aiorpcx"))
    for name, location in (("electrumx", "electrumx"), ("electrumx.lib", "electrumx/lib")):
        module = sys.modules.setdefault(name, types.ModuleType(name))
        root = next(path for entry in sys.path if (path := Path(entry) / "electrumx/lib/tx.py").is_file()).parents[2]
        module.__path__ = [str(root / location)]
    return importlib.import_module("electrumx.lib.tx")


def test_cursor_advancement_composition():
    tx = _tx()
    value, cursor = tx.read_le_uint16(b"\x01\x00\x02\x00\x00\x00", 0)
    assert (value, cursor) == (1, 2)


def test_read_le_uint16():
    assert _tx().read_le_uint16(b"\x34\x12", 0) == (0x1234, 2)


def test_read_le_uint32():
    assert _tx().read_le_uint32(b"\x78\x56\x34\x12", 0) == (0x12345678, 4)


def test_read_le_uint64_and_int32():
    tx = _tx()
    assert tx.read_le_uint64(bytes(range(8)), 0) == (0x0706050403020100, 8)
    assert tx.read_le_int32(b"\xff\xff\xff\xff", 0) == (-1, 4)
