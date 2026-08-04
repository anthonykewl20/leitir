from __future__ import annotations

import base64

import pytest

from leitir.credentials import Credentials


def test_anonymous_by_default():
    credentials = Credentials({})
    assert credentials.auth_for_url("https://registry.npmjs.org/demo") is None
    assert credentials.headers("https://registry.npmjs.org/demo", {"Accept": "x"}) == {"Accept": "x"}


@pytest.mark.parametrize(
    ("environment", "url", "expected"),
    [
        ({"GITHUB_TOKEN": "g"}, "https://api.github.com/repos/x/y", "Bearer g"),
        ({"GITHUB_TOKEN": "g"}, "https://codeload.github.com/x/y/tar.gz/a", "Bearer g"),
        ({"GITLAB_TOKEN": "g"}, "https://gitlab.com/api/v4/x", "g"),
        ({"NPM_TOKEN": "n"}, "https://registry.npmjs.org/demo", "Bearer n"),
        ({"PYPI_TOKEN": "p"}, "https://pypi.org/pypi/demo/json", "Bearer p"),
        ({"PIP_TOKEN": "p"}, "https://pypi.org/pypi/demo/json", "Bearer p"),
        ({"CARGO_TOKEN": "c"}, "https://crates.io/api/v1/crates/demo", "Bearer c"),
        ({"CARGO_TOKEN": "c"}, "https://static.crates.io/crates/demo", "Bearer c"),
    ],
)
def test_environment_mapping(environment, url, expected):
    headers = Credentials(environment).headers(url)
    assert expected in headers.values()


def test_bitbucket_username_selects_basic_for_api_and_archive():
    credentials = Credentials({"BITBUCKET_TOKEN": "secret", "BITBUCKET_USERNAME": "user"})
    expected = "Basic " + base64.b64encode(b"user:secret").decode()
    assert credentials.headers("https://api.bitbucket.org/2.0/x")["Authorization"] == expected
    assert credentials.headers("https://bitbucket.org/a/b/get/c.tar.gz")["Authorization"] == expected


def test_bitbucket_without_username_uses_bearer():
    headers = Credentials({"BITBUCKET_TOKEN": "secret"}).headers("https://bitbucket.org/a/b/get/c.tar.gz")
    assert headers["Authorization"] == "Bearer secret"


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.npmjs.org/demo",
        "https://registry.npmjs.org.example/demo",
        "https://registry.npmjs.org:8443/demo",
        "https://example.com/demo",
    ],
)
def test_credentials_are_not_attached_to_unapproved_endpoints(url):
    assert "Authorization" not in Credentials({"NPM_TOKEN": "secret"}).headers(url)


def test_auth_spec_representations_are_redacted():
    auth = Credentials({"NPM_TOKEN": "never-print"}).auth_for_url("https://registry.npmjs.org/x")
    assert auth is not None
    assert "never-print" not in repr(auth)
    assert "never-print" not in str(auth)
