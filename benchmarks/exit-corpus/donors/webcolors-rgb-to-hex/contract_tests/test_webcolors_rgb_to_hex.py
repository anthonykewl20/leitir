import webcolors._conversion as donor


def test_rgb_to_hex_converts_primary_blue():
    assert donor.rgb_to_hex((0, 0, 255)) == "#0000ff"


def test_rgb_to_hex_converts_white():
    assert donor.rgb_to_hex((255, 255, 255)) == "#ffffff"
