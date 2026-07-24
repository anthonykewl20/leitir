import pytest
from candidate import read_project


def test_extracts_fresh_typed_project_contract():
    result = read_project(
        '[project]\nname="demo"\nrequires-python=">=3.11"\n'
        'dependencies=["a==1", "b"]\n'
    )
    assert result == {
        "name": "demo",
        "requires_python": ">=3.11",
        "dependencies": ["a==1", "b"],
    }
    result["dependencies"].append("changed")
    again = read_project(
        '[project]\nname="demo"\nrequires-python=">=3.11"\n'
        "dependencies=[]\n"
    )
    assert again["dependencies"] == []


def test_rejects_wrong_types_and_duplicate_keys():
    with pytest.raises(ValueError):
        read_project(
            '[project]\nname=3\nrequires-python=">=3.11"\ndependencies=[]\n'
        )
    with pytest.raises(Exception):
        read_project(
            '[project]\nname="a"\nname="b"\n'
            'requires-python=">=3.11"\ndependencies=[]\n'
        )
