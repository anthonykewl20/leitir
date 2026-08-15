from url_normalize.normalize_fragment import normalize_fragment


def test_empty_userinfo_forms_are_stripped():
    assert normalize_fragment("Begriffsklärung") == "Begriffskl%C3%A4rung"


def test_fragment_is_round_tripped_percent_encoded():
    assert normalize_fragment("a%20b") == "a%20b"


def test_quote_percent_encodes_with_safe_characters():
    assert normalize_fragment("a b") == "a%20b"
