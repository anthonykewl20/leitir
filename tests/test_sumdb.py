from __future__ import annotations

import base64

import pytest
from _http_server import scripted_server

from leitir import sumdb
from leitir.sumdb import SumDBClient, SumDBVerificationError, TreeHead, _parse_note, ed25519_verify


@pytest.mark.parametrize(
    ("public_key", "message", "signature"),
    [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ],
)
def test_ed25519_rfc8032_verify_vectors(public_key, message, signature):
    assert ed25519_verify(bytes.fromhex(public_key), bytes.fromhex(message), bytes.fromhex(signature))


NOTE = (
    b"go.sum database tree\n59801566\n"
    b"O2Gmkv6h0HsLmHsY+kDEDnVqnh6D2f7GbDdtogImc44=\n\n"
    b"\xe2\x80\x94 sum.golang.org "
    b"Az3grmyBfghs9QtVff190lrVvrtZT2cbjCTZBDP/01xxmkTfUxBHtoGdnnUof8Cq"
    b"JBt1k3tW7xFR7jUb8FluLhcZgQs=\n"
)


def test_real_sumdb_note_verifies_and_tampering_is_rejected():
    assert _parse_note(NOTE).startswith(b"go.sum database tree\n59801566\n")
    tampered = NOTE[:-2] + b"A\n"
    with pytest.raises(SumDBVerificationError):
        _parse_note(tampered)


MODULE = "example.com/module"
VERSION = "v1.2.3"


def _head(head: TreeHead) -> bytes:
    return (
        b"go.sum database tree\n"
        + str(head.size).encode()
        + b"\n"
        + base64.b64encode(head.hash)
        + b"\n"
    )


def _lookup(head: TreeHead, *, note: bytes | None = None) -> bytes:
    return (
        b"0\n"
        + f"{MODULE} {VERSION} h1:fixture=\n".encode()
        + b"\n"
        + (note if note is not None else _head(head))
    )


def _unverified_fixture_notes(monkeypatch):
    """Use plaintext fixture heads after the signature parser's own test above."""
    monkeypatch.setattr(sumdb, "_parse_note", lambda data: data)


def _prepare_client(monkeypatch, tmp_path, lookup_head: TreeHead, latest: TreeHead):
    _unverified_fixture_notes(monkeypatch)
    client = SumDBClient(tmp_path, base_url="http://127.0.0.1")
    responses = [_lookup(lookup_head), _head(latest)]
    monkeypatch.setattr(client, "_fetch", lambda _path: responses.pop(0))
    monkeypatch.setattr(client, "_verify_head", lambda _head: None)
    record_hash = sumdb._record_hash(f"{MODULE} {VERSION} h1:fixture=\n".encode())
    monkeypatch.setattr(client, "_hash", lambda _index: record_hash)
    return client


def test_historical_lookup_head_is_accepted_when_latest_advances(tmp_path, monkeypatch):
    historical = TreeHead(3, b"h" * 32)
    stored = TreeHead(8, b"s" * 32)
    latest = TreeHead(9, b"l" * 32)
    client = _prepare_client(monkeypatch, tmp_path, historical, latest)
    client._store_head(stored)
    seen: list[tuple[TreeHead, TreeHead]] = []
    monkeypatch.setattr(client, "_verify_consistency", lambda old, new: seen.append((old, new)))

    assert client.verify(MODULE, VERSION) == "h1:fixture="
    assert seen == [(stored, latest)]
    assert client._stored_head() == latest


def test_latest_rollback_is_rejected_even_with_historical_lookup_head(tmp_path, monkeypatch):
    client = _prepare_client(
        monkeypatch,
        tmp_path,
        TreeHead(3, b"h" * 32),
        TreeHead(7, b"l" * 32),
    )
    client._store_head(TreeHead(8, b"s" * 32))

    with pytest.raises(SumDBVerificationError, match="moved backwards"):
        client.verify(MODULE, VERSION)


def test_latest_same_size_hash_mismatch_is_rejected(tmp_path, monkeypatch):
    client = _prepare_client(
        monkeypatch,
        tmp_path,
        TreeHead(3, b"h" * 32),
        TreeHead(8, b"l" * 32),
    )
    client._store_head(TreeHead(8, b"s" * 32))

    with pytest.raises(SumDBVerificationError, match="changed at the same size"):
        client.verify(MODULE, VERSION)


def test_consistency_proof_uses_tile_subtrees_to_extend_stored_head(tmp_path, monkeypatch):
    leaves = [bytes([number]) * 32 for number in range(13)]

    def tree(items: list[bytes]) -> bytes:
        if len(items) == 1:
            return items[0]
        split = sumdb._maxpow2(len(items))
        return sumdb._node_hash(tree(items[:split]), tree(items[split:]))

    client = SumDBClient(tmp_path, base_url="http://127.0.0.1")
    monkeypatch.setattr(
        client,
        "_perfect_subtree_hash",
        lambda start, size: tree(leaves[start : start + size]),
    )

    client._verify_consistency(TreeHead(7, tree(leaves[:7])), TreeHead(13, tree(leaves)))


def test_partial_tile_fallback_caches_its_full_tile(tmp_path, monkeypatch):
    client = SumDBClient(tmp_path, base_url="http://127.0.0.1")
    calls: list[str] = []

    def fetch(path: str) -> bytes:
        calls.append(path)
        if path.endswith(".p/2") or path.endswith(".p/4"):
            raise SumDBVerificationError("sumdb request failed: HTTP 404")
        assert path == "tile/8/0/000"
        return b"x" * (256 * 32)

    monkeypatch.setattr(client, "_fetch", fetch)
    assert client._tile(sumdb._Tile(0, 0, 2)) == b"x" * 64
    assert client._tile(sumdb._Tile(0, 0, 4)) == b"x" * 128
    assert calls == ["tile/8/0/000.p/2", "tile/8/0/000", "tile/8/0/000.p/4"]


def test_lookup_rejects_invalid_signed_head_before_fetching_tiles(tmp_path, monkeypatch):
    client = SumDBClient(tmp_path, base_url="http://127.0.0.1")
    invalid_lookup = _lookup(TreeHead(1, b"x" * 32), note=NOTE[:-2] + b"A\n")
    monkeypatch.setattr(client, "_fetch", lambda _path: invalid_lookup)

    with pytest.raises(SumDBVerificationError, match="signed tree note is invalid"):
        client.verify(MODULE, VERSION)


def test_lookup_record_inclusion_is_verified_against_historical_fixture_tiles(tmp_path, monkeypatch):
    record = f"{MODULE} {VERSION} h1:fixture=\n".encode()
    historical = TreeHead(1, sumdb._record_hash(record))
    client = SumDBClient(tmp_path, base_url="http://127.0.0.1")
    _unverified_fixture_notes(monkeypatch)

    def fetch(path: str) -> bytes:
        if path == f"lookup/{MODULE}@{VERSION}":
            return _lookup(historical)
        if path == "latest":
            return _head(historical)
        assert path == "tile/8/0/000.p/1"
        return historical.hash

    monkeypatch.setattr(client, "_fetch", fetch)
    assert client.verify(MODULE, VERSION) == "h1:fixture="


def test_lookup_uses_verbatim_multi_slash_module_path(tmp_path):
    module = "google.golang.org/genproto/googleapis/rpc"
    version = "v0.0.0-20240429193739-8cf5692501f6"
    with scripted_server([(200, {}, b"")]) as server:
        client = SumDBClient(tmp_path, base_url=server.base_url)
        with pytest.raises(SumDBVerificationError, match="lookup record"):
            client.verify(module, version)

    assert server.state.request_paths == [f"/lookup/{module}@{version}"]
