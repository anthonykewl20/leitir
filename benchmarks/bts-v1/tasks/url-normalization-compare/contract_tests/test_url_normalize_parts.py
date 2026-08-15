from url_normalize.normalize_fragment import normalize_fragment
from url_normalize.normalize_userinfo import normalize_userinfo
from url_normalize.tools import quote


def test_empty_userinfo_forms_are_stripped():
    assert normalize_userinfo("@") == ""


def test_fragment_is_round_tripped_percent_encoded():
    assert normalize_fragment("a b") == "a%20b"


def test_quote_percent_encodes_with_safe_characters():
    assert quote("a b", safe="~=") == "a%20b"
