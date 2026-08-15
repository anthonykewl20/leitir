import url_normalize.normalize_fragment as donor


def test_normalize_fragment_percent_encodes_unicode():
    assert donor.normalize_fragment("Begriffsklärung") == "Begriffskl%C3%A4rung"


def test_normalize_fragment_preserves_encoded_space():
    assert donor.normalize_fragment("a%20b") == "a%20b"
