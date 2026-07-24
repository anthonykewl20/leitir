import pytest
from candidate import batched


def test_lazy_partial_final_batch():
    seen = []

    def source():
        for value in range(5):
            seen.append(value)
            yield value

    batches = batched(source(), 2)
    assert seen == []
    assert next(batches) == (0, 1)
    assert seen == [0, 1]
    assert list(batches) == [(2, 3), (4,)]


def test_rejects_non_positive_size():
    with pytest.raises(ValueError):
        list(batched([1], 0))
