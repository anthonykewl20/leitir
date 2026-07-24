Backport the Python 3.12.3 `itertools.batched(iterable, n)` behavior to Python 3.11 as `batched(iterable, n)` in `candidate.py`.

The function must be lazy, consume the input iterator only as results are requested, yield tuples of at most `n` items in input order, and reject `n < 1` with the same exception class used by the Python 3.12 contract. Do not require Python 3.12 at runtime and do not materialize the complete iterable.
