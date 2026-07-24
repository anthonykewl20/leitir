from candidate import encode_query


def test_sequence_expansion_and_order():
    pairs = [("tag", ["a b", "c/d"]), ("empty", ""), ("tag", "z")]
    assert encode_query(pairs) == "tag=a+b&tag=c%2Fd&empty=&tag=z"


def test_standard_scalar_conversion():
    assert encode_query([("count", 0), ("missing", None)]) == "count=0&missing=None"
