from __future__ import annotations

import base64

import pytest

from leitir.credentials import _PROVIDERS, Credentials, github_token_from_env


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


def test_github_provider_honors_gh_token():
    """Regression for the GH_TOKEN-only environment bug (issue #188 G-0 one-liner)."""
    auth = Credentials({"GH_TOKEN": "x"}).auth_for_url(
        "https://codeload.github.com/o/r/tar.gz/abc"
    )
    assert auth is not None
    assert auth.scheme == "bearer"
    assert auth.value == "x"
    assert auth.header == "Authorization"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.github.com/repos/o/r",
        "https://codeload.github.com/o/r/tar.gz/a",
    ],
)
def test_gh_token_authenticates_github_hosts(url):
    headers = Credentials({"GH_TOKEN": "gh"}).headers(url)
    assert headers["Authorization"] == "Bearer gh"


def test_gh_token_wins_over_github_token_in_provider_table():
    headers = Credentials({"GH_TOKEN": "first", "GITHUB_TOKEN": "second"}).headers(
        "https://api.github.com/repos/o/r"
    )
    assert headers["Authorization"] == "Bearer first"


def test_empty_gh_token_is_treated_as_unset():
    credentials = Credentials({"GH_TOKEN": ""})
    assert credentials.auth_for_url("https://api.github.com/repos/o/r") is None
    assert "Authorization" not in credentials.headers("https://api.github.com/repos/o/r")
    fallback = Credentials({"GH_TOKEN": "", "GITHUB_TOKEN": "g"})
    assert fallback.headers("https://api.github.com/repos/o/r")["Authorization"] == "Bearer g"


def test_gh_token_is_not_attached_to_unapproved_hosts():
    credentials = Credentials({"GH_TOKEN": "secret"})
    assert credentials.auth_for_url("https://api.github.com.evil.example/x") is None
    assert credentials.auth_for_url("https://evil.example/github") is None
    assert credentials.auth_for_url("http://api.github.com/repos/o/r") is None
    assert "Authorization" not in credentials.headers("https://example.com/x")


def test_gh_token_with_control_character_is_rejected_without_disclosure():
    token = "gh\nleak"
    with pytest.raises(ValueError) as exc_info:
        Credentials({"GH_TOKEN": token}).auth_for_url("https://api.github.com/repos/o/r")
    assert token not in str(exc_info.value)
    assert "leak" not in str(exc_info.value)


_EXPECTED_PROVIDER_ENV_NAMES = {
    "github": {"GH_TOKEN", "GITHUB_TOKEN"},
    "gitlab": {"GITLAB_TOKEN"},
    "bitbucket": {"BITBUCKET_TOKEN"},
    "codeberg": {"CODEBERG_TOKEN"},
    "sourcehut": {"SRHT_TOKEN"},
    "npm": {"NPM_TOKEN"},
    "pypi": {"PYPI_TOKEN", "PIP_TOKEN"},
    "crates": {"CARGO_TOKEN"},
}


def test_provider_table_env_names_are_pinned():
    observed = {name: set(provider.token_envs) for name, provider in _PROVIDERS.items()}
    assert observed == _EXPECTED_PROVIDER_ENV_NAMES
    # Precedence order matters: first truthy env var wins, so GH_TOKEN must lead.
    assert _PROVIDERS["github"].token_envs == ("GH_TOKEN", "GITHUB_TOKEN")


def test_each_documented_env_name_authenticates_its_provider_hosts():
    for name in sorted(_PROVIDERS):
        provider = _PROVIDERS[name]
        for env_name in provider.token_envs:
            credentials = Credentials({env_name: "token"})
            for host in provider.hosts:
                auth = credentials.auth_for_url(f"https://{host}/x")
                assert auth is not None, f"{env_name} failed to authenticate {host} ({name})"


# --- Issue #220: github provider host coverage (api/codeload/objects/raw/uploads) ---

_GITHUB_HOST_SET = frozenset(
    {
        "api.github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "raw.githubusercontent.com",
        "uploads.github.com",
    }
)

_COVERED_GITHUB_URLS = [
    f"https://{host}/x" for host in sorted(_GITHUB_HOST_SET)
]


@pytest.mark.parametrize("url", _COVERED_GITHUB_URLS)
@pytest.mark.parametrize("env_name", ["GH_TOKEN", "GITHUB_TOKEN"])
def test_github_token_authenticates_every_covered_github_host(url, env_name):
    """G-0 re-creation (issue #220): bearer auth on all five GitHub hosts."""
    auth = Credentials({env_name: "secret"}).auth_for_url(url)
    assert auth is not None
    assert auth.scheme == "bearer"
    assert auth.header == "Authorization"
    assert auth.value == "secret"
    headers = Credentials({env_name: "secret"}).headers(url)
    assert headers["Authorization"] == "Bearer secret"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.github.com.evil.example/x",
        "https://evil.example/github",
        "https://example.com/x",
        "https://api.github.com.evil.example/x/y/releases/assets/1",
        "https://objects.githubusercontent.com.evil.example/releases/x",
        "https://evil-objects.githubusercontent.com/x",
        "https://raw.githubusercontent.com.evil.example/o/r/main/f",
        "https://notraw.githubusercontent.com/o/r/main/f",
        "https://uploads.github.com.evil.example/repos/o/r/releases/1",
        "https://evil.example/codeload.github.com/o/r/tar.gz/a",
        "https://github.com/o/r",
        "https://gist.github.com/o/1",
        # A GitHub token must not authenticate another provider's hosts.
        "https://gitlab.com/api/v4/x",
        "https://registry.npmjs.org/demo",
    ],
)
def test_github_token_is_not_attached_to_unapproved_hosts(url):
    credentials = Credentials({"GH_TOKEN": "secret", "GITHUB_TOKEN": "secret"})
    assert credentials.auth_for_url(url) is None
    assert "Authorization" not in credentials.headers(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://objects.githubusercontent.com/releases/x",
        "http://raw.githubusercontent.com/o/r/main/f",
        "http://uploads.github.com/repos/o/r/releases/1",
        "https://objects.githubusercontent.com:8443/releases/x",
        "https://raw.githubusercontent.com:80/o/r/main/f",
        "https://uploads.github.com:8443/repos/o/r/releases/1",
    ],
)
def test_github_hosts_refuse_downgraded_channels(url):
    assert Credentials({"GITHUB_TOKEN": "secret"}).auth_for_url(url) is None
    assert "Authorization" not in Credentials({"GITHUB_TOKEN": "secret"}).headers(url)


@pytest.mark.parametrize(
    "host", sorted(_GITHUB_HOST_SET - {"api.github.com", "codeload.github.com"})
)
def test_control_character_token_rejected_on_newly_covered_hosts(host):
    token = "gh\rleak"
    with pytest.raises(ValueError) as exc_info:
        Credentials({"GITHUB_TOKEN": token}).auth_for_url(f"https://{host}/x")
    assert token not in str(exc_info.value)
    assert "leak" not in str(exc_info.value)
    assert "gh" not in str(exc_info.value)


@pytest.mark.parametrize("url", _COVERED_GITHUB_URLS)
def test_empty_github_token_falls_back_to_github_token_on_all_hosts(url):
    fallback = Credentials({"GH_TOKEN": "", "GITHUB_TOKEN": "g"})
    assert fallback.headers(url)["Authorization"] == "Bearer g"
    only_empty = Credentials({"GITHUB_TOKEN": ""})
    assert only_empty.auth_for_url(url) is None
    assert "Authorization" not in only_empty.headers(url)


@pytest.mark.parametrize("url", _COVERED_GITHUB_URLS)
def test_credential_lookup_is_stateless_across_repeated_calls(url):
    """SP-4: interleaved lookups across hosts are pure — identical every round."""
    credentials = Credentials({"GITHUB_TOKEN": "secret"})
    urls = _COVERED_GITHUB_URLS + ["https://example.com/x", "https://gitlab.com/api/v4/x"]
    first_round = [credentials.auth_for_url(candidate) for candidate in urls]
    second_round = [credentials.auth_for_url(candidate) for candidate in urls]
    third_round = [credentials.auth_for_url(candidate) for candidate in urls]
    assert first_round == second_round == third_round
    assert first_round[urls.index(url)] is not None
    assert all(auth is None for host_url, auth in zip(urls, first_round) if host_url not in _COVERED_GITHUB_URLS)


def test_github_provider_host_set_is_pinned_to_five_hosts():
    """C-5: single shared five-host tuple; no host duplicated across providers."""
    from leitir.credentials import _GITHUB_HOSTS

    assert _PROVIDERS["github"].hosts == _GITHUB_HOSTS
    assert len(_PROVIDERS["github"].hosts) == len(set(_PROVIDERS["github"].hosts))
    assert frozenset(_PROVIDERS["github"].hosts) == _GITHUB_HOST_SET
    seen_hosts: dict[str, str] = {}
    for name in sorted(_PROVIDERS):
        for host in _PROVIDERS[name].hosts:
            assert host not in seen_hosts, (
                f"host {host!r} duplicated across providers {seen_hosts[host]!r} and {name!r}"
            )
            seen_hosts[host] = name
    assert set(seen_hosts) >= _GITHUB_HOST_SET
