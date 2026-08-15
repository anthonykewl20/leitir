import tx as donor


def test_cursor_advancement_composition():
    value, cursor = donor.read_le_uint16(b"\x01\x00\x02\x00\x00\x00", 0)
    assert (value, cursor) == (1, 2)


def test_read_le_uint16():
    assert donor.read_le_uint16(b"\x34\x12", 0) == (0x1234, 2)


def test_read_le_uint32():
    assert donor.read_le_uint32(b"\x78\x56\x34\x12", 0) == (0x12345678, 4)


def test_read_le_uint64_and_int32():
    assert donor.read_le_uint64(bytes(range(8)), 0) == (0x0706050403020100, 8)
    assert donor.read_le_int32(b"\xff\xff\xff\xff", 0) == (-1, 4)
