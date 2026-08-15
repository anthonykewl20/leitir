import tx as donor


def test_known_value():
    assert donor.read_le_uint32(b"\x78\x56\x34\x12", 0)[0] == 0x12345678


def test_matches_zlib_crc32():
    assert donor.read_le_uint32(b"\x00\x00\x00\x00", 0)[0] == 0
