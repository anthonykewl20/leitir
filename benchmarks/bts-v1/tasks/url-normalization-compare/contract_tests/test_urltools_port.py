from url_normalize.normalize_fragment import normalize_fragment


def test_custom_port_is_kept():
    assert normalize_fragment("example:8080") == "example%3A8080"


def test_default_port_is_dropped():
    assert normalize_fragment("example") == "example"


def test_missing_scheme_keeps_port():
    assert normalize_fragment("localhost:8000") == "localhost%3A8000"
