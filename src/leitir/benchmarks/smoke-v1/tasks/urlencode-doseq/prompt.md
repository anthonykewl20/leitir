Target Python 3.11.9. Implement `encode_query(pairs)` in `candidate.py`.

`pairs` is an iterable of `(name, value)` pairs. A value may be a string, an integer, `None`, or a list/tuple of those scalar values. Return an ASCII query string using the Python 3.11 `urllib.parse.urlencode` contract with sequence expansion enabled. Preserve pair order, repeated names, blank strings, and `None` using the standard library's behavior. Do not manually concatenate or pre-sort parameters.
