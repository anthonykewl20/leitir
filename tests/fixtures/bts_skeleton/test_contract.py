from skeleton_donor.policy import normalized_score

SKIPPED_CONTRACTS = ("test_platform_specific_contract",)


def test_increments_inside_range():
    assert normalized_score(4, 0, 10) == 5


def test_clamps_at_upper_bound():
    assert normalized_score(10, 0, 10) == 10


def test_platform_specific_contract():
    assert normalized_score(-5, 0, 10) == 0
