from __future__ import annotations

import base64

import pytest

from leitir.credentials import Credentials, github_token_from_env


def test_anonymous_by_default():
    credentials = Credentials({})
    assert credentials.auth_for_url("https://registry.npmjs.org/demo") is None
    assert credentials.headers("https://registry.npmjs.org/demo", {"Accept": "x"}) == {"Accept": "x"}


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        ({"GH_TOKEN": "gh", "GITHUB_TOKEN": "github"}, "gh"),
        ({"GITHUB_TOKEN": "github"}, "github"),
        ({}, None),
    ],
)
def test_github_token_environment_precedence(monkeypatch, environment, expected):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    assert github_token_from_env() == expected


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
        ({"CODEBERG_TOKEN": "c"}, "https://codeberg.org/api/v1/repos/x/y", "Bearer c"),
        ({"SRHT_TOKEN": "s"}, "https://git.sr.ht/api/~x/repos/y", "Bearer s"),
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


def test_token_with_control_character_is_rejected_without_disclosure():
    token = "secret\nleak"
    with pytest.raises(ValueError) as exc_info:
        Credentials({"NPM_TOKEN": token}).auth_for_url("https://registry.npmjs.org/x")
    assert token not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


def test_basic_auth_username_with_control_character_is_rejected_without_disclosure():
    username = "user\rname"
    with pytest.raises(ValueError) as exc_info:
        Credentials({
            "BITBUCKET_TOKEN": "normal-token",
            "BITBUCKET_USERNAME": username,
        }).auth_for_url("https://api.bitbucket.org/2.0/x")
    assert username not in str(exc_info.value)


def test_normal_token_still_works():
    headers = Credentials({"NPM_TOKEN": "normal-token"}).headers(
        "https://registry.npmjs.org/x"
    )
    assert headers["Authorization"] == "Bearer normal-token"
