import tx as donor


def test_round_trip_against_reference_encoding():
    assert donor.read_le_uint16(b"\x01\x00", 0)[0] == 1


def test_zero_and_small_values():
    assert donor.read_le_uint16(b"\x00\x00", 0)[0] == 0
