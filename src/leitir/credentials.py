"""Environment-backed credentials for approved HTTPS endpoints."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping


def github_token_from_env() -> str | None:
    """Return the GitHub token using the gh CLI environment precedence."""
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or None


def validate_secret(value: str, *, kind: str) -> None:
    """Reject HTTP-header control characters without disclosing the value."""
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError(f"configured {kind} contains invalid control characters")


@dataclass(frozen=True, slots=True, repr=False)
class AuthSpec:
    """A resolved HTTP authentication header whose representation is redacted."""

    scheme: str
    header: str
    value: str
    required_username: bool = False

    def __post_init__(self) -> None:
        if self.scheme not in {"bearer", "basic"}:
            raise ValueError("unsupported authentication scheme")

    def __repr__(self) -> str:
        return (
            f"AuthSpec(scheme={self.scheme!r}, header={self.header!r}, "
            f"value='<redacted>', required_username={self.required_username!r})"
        )

    __str__ = __repr__

    def header_value(self) -> str:
        if self.header.lower() != "authorization":
            return self.value
        if self.scheme == "basic":
            import base64

            return "Basic " + base64.b64encode(self.value.encode("utf-8")).decode("ascii")
        return f"Bearer {self.value}"


@dataclass(frozen=True, slots=True)
class _Provider:
    hosts: tuple[str, ...]
    token_envs: tuple[str, ...]
    header: str = "Authorization"
    username_env: str | None = None


_PROVIDERS = {
    "github": _Provider(("api.github.com", "codeload.github.com"), ("GITHUB_TOKEN",)),
    "gitlab": _Provider(("gitlab.com",), ("GITLAB_TOKEN",), "PRIVATE-TOKEN"),
    "bitbucket": _Provider(
        ("api.bitbucket.org", "bitbucket.org"),
        ("BITBUCKET_TOKEN",),
        username_env="BITBUCKET_USERNAME",
    ),
    "codeberg": _Provider(("codeberg.org",), ("CODEBERG_TOKEN",)),
    "sourcehut": _Provider(("git.sr.ht",), ("SRHT_TOKEN",)),
    "npm": _Provider(("registry.npmjs.org",), ("NPM_TOKEN",)),
    "pypi": _Provider(("pypi.org",), ("PYPI_TOKEN", "PIP_TOKEN")),
    "crates": _Provider(("crates.io", "static.crates.io"), ("CARGO_TOKEN",)),
}


class Credentials:
    """Resolve optional credentials without sending them to unapproved endpoints."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        if environ is None:
            import os

            environ = os.environ
        self._environ = environ

    def auth_for_url(
        self,
        url: str,
        *,
        provider: str | None = None,
        token: str | None = None,
    ) -> AuthSpec | None:
        from urllib.parse import urlsplit

        try:
            endpoint = urlsplit(url)
            port = endpoint.port
        except ValueError:
            return None
        if endpoint.scheme.lower() != "https" or port not in (None, 443):
            return None
        hostname = (endpoint.hostname or "").lower()
        selected = _PROVIDERS.get(provider) if provider is not None else None
        if selected is None and provider is not None:
            return None
        if selected is None:
            selected = next(
                (candidate for candidate in _PROVIDERS.values() if hostname in candidate.hosts),
                None,
            )
        if selected is None or hostname not in selected.hosts:
            return None
        secret = token
        if secret is None:
            secret = next(
                (self._environ[name] for name in selected.token_envs if self._environ.get(name)),
                None,
            )
        if not secret:
            return None
        validate_secret(secret, kind="token")
        username = self._environ.get(selected.username_env) if selected.username_env else None
        if username:
            validate_secret(username, kind="username")
            return AuthSpec("basic", selected.header, f"{username}:{secret}", True)
        return AuthSpec("bearer", selected.header, secret)

    def headers(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        *,
        provider: str | None = None,
        token: str | None = None,
    ) -> dict[str, str]:
        result = dict(headers or {})
        auth = self.auth_for_url(url, provider=provider, token=token)
        if auth is not None:
            result[auth.header] = auth.header_value()
        return result


__all__ = ["AuthSpec", "Credentials", "github_token_from_env", "validate_secret"]
