from url_normalize.normalize_fragment import normalize_fragment


def test_file_uri_to_path_posix():
    assert normalize_fragment("file/path") == "file%2Fpath"


def test_url_query_parameter_default_for_missing():
    assert normalize_fragment("") == ""


def test_url_query_parameter_reads_first_value():
    assert normalize_fragment("one%20two") == "one%20two"
