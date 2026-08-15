import luhn as donor


def test_checksum_accepts_a_known_valid_number():
    assert donor.checksum("356938035643809") == 0


def test_checksum_rejects_a_known_invalid_number():
    assert donor.checksum("534618613411236") != 0
