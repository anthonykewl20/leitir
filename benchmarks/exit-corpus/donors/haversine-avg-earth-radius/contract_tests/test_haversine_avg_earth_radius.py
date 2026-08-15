from haversine.haversine import Unit, get_avg_earth_radius


def test_get_avg_earth_radius_returns_pinned_kilometer_constant():
    assert get_avg_earth_radius(Unit.KILOMETERS) == 6371.0088


def test_get_avg_earth_radius_converts_to_meters():
    assert get_avg_earth_radius(Unit.METERS) == 6371008.8
