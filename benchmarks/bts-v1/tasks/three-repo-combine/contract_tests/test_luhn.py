from luhn import append, checksum, generate, verify


def test_checksum_known_values():
    assert checksum("356938035643809") == 0


def test_generate_and_append():
    assert generate("35693803564380") == 9
    assert append("53461861341123") == "534618613411234"


def test_verify():
    assert verify("356938035643809") is True
