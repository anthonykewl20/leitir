"""Regenerate the deterministic S9 streaming fixture golden set."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
LINE_BYTES = 64
LINE_COUNT = 34_000
LITERAL = b"STREAM_TARGET"


def _line(index: int, text: bytes | None = None) -> bytes:
    prefix = text if text is not None else f"row-{index:05d}-".encode()
    fill = bytes(97 + (index * 17 + offset * 11) % 26 for offset in range(63 - len(prefix)))
    return prefix + fill + b"\n"


def _sha(data: bytes, declared_size: int | None = None) -> str:
    size = len(data) if declared_size is None else declared_size
    digest = hashlib.sha1(b"blob %d\0" % size)
    digest.update(data)
    return digest.hexdigest()


def main() -> None:
    lines = [_line(index) for index in range(LINE_COUNT)]
    for index in (10, 10_000, 25_000):
        lines[index] = _line(index, LITERAL)
    # 1,024 fixed-width lines are exactly 65,536 bytes. This finite regex
    # therefore straddles a natural matching-window flush boundary.
    lines[1024] = _line(1024, b"BOUNDARY_START")
    lines[1025] = _line(1025, LITERAL + b"_BOUNDARY_END")
    lines[2048] = _line(2048, "utf8-é-STREAM_TARGET".encode())
    source = b"".join(lines)

    empty = b""
    utf8 = "prefix € STREAM_TARGET suffix\ninvalid:\ufffd\n".encode()
    boundary = b"0123456789BOUNDARY_TARGETabcdefghij"
    files = {
        "source.bin": source,
        "empty.bin": empty,
        "utf8.bin": utf8,
        "boundary.bin": boundary,
    }
    for name in sorted(files):
        (ROOT / name).write_bytes(files[name])

    utf8_euro = utf8.index("€".encode())
    variants = {
        "exact-boundary": [65_536],
        "many-small": list(range(4093, len(source), 4093)),
        "mid-multibyte-utf8": [2048 * LINE_BYTES + len(b"utf8-") + 1],
        "single-chunk": [],
    }
    actual_flip = bytearray(source)
    actual_flip[123_457] ^= 1
    tamper = {
        "flip": {"recipe": "flip", "offset": 123_457, "declared_size": len(source), "declared_sha": _sha(source)},
        "short": {"recipe": "prefix", "length": len(source) - 17, "declared_size": len(source), "declared_sha": _sha(source)},
        "long": {"recipe": "append", "hex": "00", "declared_size": len(source), "declared_sha": _sha(source)},
        "interrupted": {"recipe": "interrupt", "length": 98_321, "declared_size": len(source), "declared_sha": _sha(source)},
        "wrong-size": {"recipe": "identity", "declared_size": len(source) + 1, "declared_sha": _sha(source, len(source) + 1)},
        "wrong-sha": {"recipe": "identity", "declared_size": len(source), "declared_sha": _sha(bytes(actual_flip))},
    }
    for item in tamper.values():
        recipe = item["recipe"]
        if recipe == "flip":
            actual = bytes(actual_flip)
        elif recipe in {"prefix", "interrupt"}:
            actual = source[: item["length"]]
        elif recipe == "append":
            actual = source + bytes.fromhex(item["hex"])
        else:
            actual = source
        item["actual_size"] = len(actual)
        item["actual_sha"] = _sha(actual)
    known = []
    offset = 0
    while True:
        offset = source.find(LITERAL, offset)
        if offset < 0:
            break
        known.append({"byte_start": offset, "byte_end": offset + len(LITERAL)})
        offset += len(LITERAL)
    manifest = {
        "format": 1,
        "source": "deterministic arithmetic ASCII lines; no hash iteration or ambient randomness",
        "literal_regex": LITERAL.decode(),
        "known_match_spans": known,
        "blobs": {
            name: {"size": len(data), "blob_sha": _sha(data), "source": name}
            for name, data in sorted(files.items())
        },
        "chunk_variants": {name: variants[name] for name in sorted(variants)},
        "tamper_variants": {name: tamper[name] for name in sorted(tamper)},
        "utf8_split": {"source": "utf8.bin", "boundaries": [utf8_euro + 1]},
        "boundary_dedupe": {"source": "boundary.bin", "pattern": "BOUNDARY_TARGET", "boundaries": [20], "overlap_chars": 20},
    }
    (ROOT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
