from donor_pkg.value import VALUE


def test_pass() -> None:
    assert VALUE == 7


def test_skip() -> None:
    import unittest

    raise unittest.SkipTest("fixture")


def helper() -> None:
    raise AssertionError("not a contract test")
