"""Verification support for the public Go checksum database."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request

from leitir import _http
from leitir.materialize import MaterializationError, _file_lock, _write_manifest

SUM_GOLANG_ORG_KEY_FROM_GOLANG_GO_MODFETCH = (
    "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
)
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_BY = (4 * pow(5, _P - 2, _P)) % _P
_TILE_HEIGHT = 8


class SumDBVerificationError(MaterializationError):
    """Go checksum database authentication failed."""


@dataclass(frozen=True, slots=True)
class TreeHead:
    size: int
    hash: bytes

    def __post_init__(self) -> None:
        if self.size < 0 or len(self.hash) != 32:
            raise ValueError("invalid sumdb tree head")


def _recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        raise ValueError("invalid ed25519 point")
    if x & 1 != sign:
        x = _P - x
    return x


_BX = _recover_x(_BY, 0)
_B = (_BX, _BY)


def _decode_point(data: bytes) -> tuple[int, int] | None:
    if len(data) != 32:
        return None
    encoded = int.from_bytes(data, "little")
    y = encoded & ((1 << 255) - 1)
    if y >= _P:
        return None
    try:
        point = (_recover_x(y, encoded >> 255), y)
    except ValueError:
        return None
    if _encode_point(point) != data:
        return None
    return point


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _D * x1 * x2 * y1 * y2 % _P
    x = (x1 * y2 + x2 * y1) * pow(1 + product, _P - 2, _P) % _P
    y = (y1 * y2 + x1 * x2) * pow(1 - product, _P - 2, _P) % _P
    return x, y


def _scalar(point: tuple[int, int], value: int) -> tuple[int, int]:
    result = (0, 1)
    while value:
        if value & 1:
            result = _add(result, point)
        point = _add(point, point)
        value >>= 1
    return result


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify one RFC 8032 Ed25519 signature without signing support."""
    if len(signature) != 64:
        return False
    public = _decode_point(public_key)
    nonce = _decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    order = 2**252 + 27742317777372353535851937790883648493
    if public is None or nonce is None or scalar >= order:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % order
    cofactor = 8
    return _scalar(_scalar(_B, scalar), cofactor) == _add(
        _scalar(nonce, cofactor), _scalar(_scalar(public, challenge), cofactor)
    )


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _record_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _maxpow2(value: int) -> int:
    return 1 << ((value - 1).bit_length() - 1)


def _stored_hash_index(level: int, number: int) -> int:
    for _ in range(level):
        number = 2 * number + 1
    total = 0
    while number:
        total += number
        number >>= 1
    return total + level


def _split_stored_hash_index(index: int) -> tuple[int, int]:
    number = index // 2
    current = _stored_hash_index(0, number)
    while True:
        following = current + 1 + ((number + 1) & -(number + 1)).bit_length() - 1
        if following > index:
            break
        number += 1
        current = _stored_hash_index(0, number)
    level = index - current
    return level, number >> level


@dataclass(frozen=True, slots=True)
class _Tile:
    level: int
    number: int
    width: int

    def path(self) -> str:
        parts = [f"{self.number % 1000:03d}"]
        number = self.number
        while number >= 1000:
            number //= 1000
            parts.append(f"x{number % 1000:03d}")
        suffix = "" if self.width == 1 << _TILE_HEIGHT else f".p/{self.width}"
        return f"tile/{_TILE_HEIGHT}/{self.level}/{'/'.join(reversed(parts))}{suffix}"


def _tile_for_index(index: int) -> tuple[_Tile, int, int]:
    level, number = _split_stored_hash_index(index)
    outer_level = level // _TILE_HEIGHT
    inner_level = level - outer_level * _TILE_HEIGHT
    tile_number = number << inner_level >> _TILE_HEIGHT
    number -= tile_number << _TILE_HEIGHT >> inner_level
    width = (number + 1) << inner_level
    return _Tile(outer_level, tile_number, width), number << inner_level, (number + 1) << inner_level


def _tile_hash(data: bytes) -> bytes:
    if len(data) == 32:
        return data
    middle = len(data) // 2
    return _node_hash(_tile_hash(data[:middle]), _tile_hash(data[middle:]))


def _hash_from_tile(tile: _Tile, data: bytes, index: int) -> bytes:
    expected, start, end = _tile_for_index(index)
    if tile.level != expected.level or tile.number != expected.number or tile.width < expected.width:
        raise SumDBVerificationError("sumdb tile does not contain requested hash")
    if len(data) != tile.width * 32:
        raise SumDBVerificationError("sumdb tile has invalid length")
    return _tile_hash(data[start * 32 : end * 32])


def _subtree_indexes(size: int) -> list[int]:
    result: list[int] = []
    low = 0
    while low < size:
        width = _maxpow2(size - low + 1)
        result.append(_stored_hash_index(width.bit_length() - 1, low >> (width.bit_length() - 1)))
        low += width
    return result


def _tree_hash(size: int, get_hash: Callable[[int], bytes]) -> bytes:
    if size == 0:
        return hashlib.sha256(b"").digest()
    hashes = [get_hash(index) for index in _subtree_indexes(size)]
    result = hashes[-1]
    for item in reversed(hashes[:-1]):
        result = _node_hash(item, result)
    return result


def _parse_note(data: bytes) -> bytes:
    try:
        text, signature_lines = data.rsplit(b"\n\n", 1)
        text += b"\n"
        line = signature_lines.splitlines()[0]
        prefix, encoded = line.rsplit(b" ", 1)
        if prefix != "\u2014 sum.golang.org".encode() or b"\n" in signature_lines.rstrip(b"\n"):
            raise ValueError
        signature = base64.b64decode(encoded, validate=True)
        name, key_hash, encoded_key = SUM_GOLANG_ORG_KEY_FROM_GOLANG_GO_MODFETCH.split("+", 2)
        key = base64.b64decode(encoded_key, validate=True)
        if name != "sum.golang.org" or len(key) != 33 or key[0] != 1:
            raise ValueError
        if signature[:4].hex() != key_hash or not ed25519_verify(key[1:], text, signature[4:]):
            raise ValueError
    except (IndexError, ValueError, UnicodeError) as exc:
        raise SumDBVerificationError("sumdb signed tree note is invalid") from exc
    return text


def _parse_head(text: bytes) -> TreeHead:
    try:
        lines = text.decode("utf-8").splitlines()
        size = int(lines[1])
        digest = base64.b64decode(lines[2], validate=True)
        if lines[0] != "go.sum database tree" or str(size) != lines[1]:
            raise ValueError
        return TreeHead(size, digest)
    except (IndexError, ValueError, UnicodeError) as exc:
        raise SumDBVerificationError("sumdb signed tree head is malformed") from exc


class SumDBClient:
    """Fetch and authenticate Go module checksum records and tree heads."""

    def __init__(self, root: str | Path, *, base_url: str = "https://sum.golang.org", timeout: int = 30) -> None:
        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            raise ValueError("sumdb base URL must use HTTPS")
        self._root = Path(root)
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._tiles: dict[_Tile, bytes] = {}
        self._tree_size: int | None = None

    def _fetch(self, path: str) -> bytes:
        def request() -> bytes:
            with _http.safe_urlopen(
                Request(f"{self._base_url}/{path}", headers={"User-Agent": "leitir"}),
                timeout=self._timeout,
            ) as response:
                return response.read()

        try:
            return _http.retry_http(request)
        except _http.RETRIABLE_EXCEPTIONS as exc:
            raise SumDBVerificationError(f"sumdb request failed: {_http.describe_failure(exc)}") from exc

    def _tile(self, tile: _Tile) -> bytes:
        data = self._tiles.get(tile)
        if data is None:
            try:
                data = self._fetch(tile.path())
            except SumDBVerificationError as exc:
                if tile.width == 1 << _TILE_HEIGHT or "HTTP 404" not in str(exc):
                    raise
                full = _Tile(tile.level, tile.number, 1 << _TILE_HEIGHT)
                full_data = self._tiles.get(full)
                if full_data is None:
                    full_data = self._fetch(full.path())
                    if len(full_data) != full.width * 32:
                        raise SumDBVerificationError("sumdb tile has invalid length") from None
                    self._tiles[full] = full_data
                data = full_data[: tile.width * 32]
            if len(data) != tile.width * 32:
                raise SumDBVerificationError("sumdb tile has invalid length")
            self._tiles[tile] = data
        return data

    def _hash(self, index: int) -> bytes:
        tile, _start, _end = _tile_for_index(index)
        if self._tree_size is not None:
            max_width = self._tree_size >> (tile.level * _TILE_HEIGHT)
            tile_start = tile.number << _TILE_HEIGHT
            if tile_start >= max_width:
                raise SumDBVerificationError("sumdb tile is outside signed tree")
            tile = _Tile(
                tile.level,
                tile.number,
                min(1 << _TILE_HEIGHT, max_width - tile_start),
            )
        return _hash_from_tile(tile, self._tile(tile), index)

    def _verify_head(self, head: TreeHead) -> None:
        previous_tree_size = self._tree_size
        self._tree_size = head.size
        try:
            if _tree_hash(head.size, self._hash) != head.hash:
                raise SumDBVerificationError("sumdb tiles do not match signed tree head")
        finally:
            self._tree_size = previous_tree_size

    def _verify_record_inclusion(self, head: TreeHead, leaf: int, record: bytes) -> None:
        previous_tree_size = self._tree_size
        self._tree_size = head.size
        try:
            if self._hash(_stored_hash_index(0, leaf)) != _record_hash(record):
                raise SumDBVerificationError("sumdb lookup record is not included in signed tree")
        finally:
            self._tree_size = previous_tree_size

    def _perfect_subtree_hash(self, start: int, size: int) -> bytes:
        """Return a stored hash for the perfect subtree ``[start, start + size)``."""
        if size < 1 or size & (size - 1) or start % size:
            raise ValueError("sumdb subtree is not a valid aligned power of two")
        return self._hash(_stored_hash_index(size.bit_length() - 1, start // size))

    def _subtree_hash(self, start: int, size: int) -> bytes:
        """Return the tiled tree hash for an arbitrary aligned subtree."""
        if size < 1:
            raise ValueError("sumdb subtree size must be positive")
        if not size & (size - 1):
            return self._perfect_subtree_hash(start, size)
        left_size = _maxpow2(size)
        return _node_hash(
            self._perfect_subtree_hash(start, left_size),
            self._subtree_hash(start + left_size, size - left_size),
        )

    def _verify_consistency(self, stored: TreeHead, latest: TreeHead) -> None:
        """Prove that ``stored`` is a prefix of ``latest`` using SumDB tiles."""
        previous_tree_size = self._tree_size
        self._tree_size = latest.size
        try:
            if latest.size < stored.size:
                raise SumDBVerificationError("sumdb tree head moved backwards")
            if latest.size == stored.size:
                if latest.hash != stored.hash:
                    raise SumDBVerificationError("sumdb tree head changed at the same size")
                return
            if stored.size == 0:
                if stored.hash != hashlib.sha256(b"").digest():
                    raise SumDBVerificationError("sumdb tree is inconsistent with stored head")
                return

            def extend(old_size: int, new_size: int, old_hash: bytes, start: int) -> bytes:
                if old_size == new_size:
                    return old_hash
                left_size = _maxpow2(new_size)
                right_size = new_size - left_size
                if old_size <= left_size:
                    left_hash = extend(old_size, left_size, old_hash, start)
                    right_hash = self._subtree_hash(start + left_size, right_size)
                else:
                    left_hash = self._perfect_subtree_hash(start, left_size)
                    old_right = self._subtree_hash(start + left_size, old_size - left_size)
                    if _node_hash(left_hash, old_right) != old_hash:
                        raise SumDBVerificationError("sumdb tree is inconsistent with stored head")
                    right_hash = extend(
                        old_size - left_size,
                        right_size,
                        old_right,
                        start + left_size,
                    )
                return _node_hash(left_hash, right_hash)

            if extend(stored.size, latest.size, stored.hash, 0) != latest.hash:
                raise SumDBVerificationError("sumdb tree is inconsistent with stored head")
        finally:
            self._tree_size = previous_tree_size

    def _stored_head(self) -> TreeHead | None:
        path = self._root / "sumdb-tree-head.json"
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return TreeHead(int(payload["size"]), base64.b64decode(payload["hash"], validate=True))
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise SumDBVerificationError("stored sumdb tree head is malformed") from exc

    def _store_head(self, head: TreeHead) -> None:
        _write_manifest(self._root / "sumdb-tree-head.json", {"size": head.size, "hash": base64.b64encode(head.hash).decode("ascii")})

    def verify(self, module: str, version: str) -> str:
        # Unlike Go proxy paths, SumDB lookup paths retain the module and version
        # verbatim. In particular, nested module paths are not a proxy URL.
        response = self._fetch(f"lookup/{module}@{version}")
        try:
            record, note = response.split(b"\n\n", 1)
            record_id, text = record.split(b"\n", 1)
            text += b"\n"
            leaf = int(record_id)
            if leaf < 0:
                raise ValueError
            expected = f"{module} {version} h1:".encode()
            line = next(item for item in text.splitlines() if item.startswith(expected))
            sum_hash = line.decode("utf-8").split(" ", 2)[2]
            if not sum_hash.startswith("h1:"):
                raise ValueError
        except (StopIteration, ValueError, UnicodeError) as exc:
            raise SumDBVerificationError("sumdb lookup record is malformed or mismatched") from exc
        lookup_head = _parse_head(_parse_note(note))
        if leaf >= lookup_head.size:
            raise SumDBVerificationError("sumdb lookup record is outside signed tree")
        with _file_lock(self._root / ".sumdb-tree-head.lock"):
            stored = self._stored_head()
            # A lookup is signed at the point at which its record was included,
            # which can be much older than the locally persisted latest head.
            # It authenticates that record, not the current tree frontier.
            self._verify_head(lookup_head)
            self._verify_record_inclusion(lookup_head, leaf, text)
            latest = _parse_head(_parse_note(self._fetch("latest")))
            self._verify_head(latest)
            if stored is not None:
                self._verify_consistency(stored, latest)
            if stored is None or latest.size > stored.size:
                self._root.mkdir(parents=True, exist_ok=True)
                self._store_head(latest)
        return sum_hash
