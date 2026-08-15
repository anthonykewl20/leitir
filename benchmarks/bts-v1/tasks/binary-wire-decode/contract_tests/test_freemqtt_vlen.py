import tx as donor


def test_multi_byte_ranges():
    assert donor.read_le_uint32(b"\xff\xff\x00\x00", 0)[0] == 65535


def test_over_limit_is_rejected():
    assert donor.read_le_uint32(b"\xff\xff\xff\xff", 0)[0] == 0xFFFFFFFF


def test_single_byte_range():
    assert donor.read_le_uint32(b"\x7f\x00\x00\x00", 0)[0] == 127
