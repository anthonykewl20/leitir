import importlib
import sys
import types
from pathlib import Path


def _read_le_uint16(value, cursor):
    sys.modules.setdefault("aiorpcx", types.ModuleType("aiorpcx"))
    for name, location in (("electrumx", "electrumx"), ("electrumx.lib", "electrumx/lib")):
        module = sys.modules.setdefault(name, types.ModuleType(name))
        root = next(path for entry in sys.path if (path := Path(entry) / "electrumx/lib/tx.py").is_file()).parents[2]
        module.__path__ = [str(root / location)]
    return importlib.import_module("electrumx.lib.tx").read_le_uint16(value, cursor)


def test_round_trip_against_reference_encoding():
    assert _read_le_uint16(b"\x01\x00", 0)[0] == 1


def test_zero_and_small_values():
    assert _read_le_uint16(b"\x00\x00", 0)[0] == 0
