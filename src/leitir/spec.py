"""Parse corpus package and GitHub repository specifications.

The parser is deliberately independent of the CLI so every corpus operation
uses the same normalization and exact-host security checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+$")
_NPM_NAME = re.compile(r"^(?:[A-Za-z0-9_.~-][A-Za-z0-9_.~-]*|@[A-Za-z0-9_.~-]+/[A-Za-z0-9_.~-]+)$")
# PyPI project names: PEP 508/503 grammar (ASCII letters, digits, and the
# inner separators ``.``, ``-``, ``_``; no leading/trailing separator).
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
# crates.io crate names: ASCII alphanumerics, ``-``, and ``_``.
_CRATES_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")
_Ecosystem_NAME = {
    "npm": _NPM_NAME,
    "pypi": _PYPI_NAME,
    "crates": _CRATES_NAME,
}
_Ecosystem_FAILURE = {
    "npm": "invalid npm package name",
    "pypi": "invalid pypi package name",
    "crates": "invalid crates package name",
}
_PREFIXES = {
    "npm": "npm",
    "pypi": "pypi",
    "pip": "pypi",
    "python": "pypi",
    "crates": "crates",
    "cargo": "crates",
    "rust": "crates",
    # Kept from M2. Go is not part of the expanded M3 prefix table, but
    # removing it would break already accepted corpus specs.
    "go": "go",
}
_REPOSITORY_HOSTS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
    "codeberg": "codeberg.org",
    "sourcehut": "git.sr.ht",
}
SUPPORTED_SPEC_FORMS = (
    "npm:name[@version], pypi:name[@version], crates:name[@version], "
    "go:module[@version], owner/repo[@ref|#ref], "
    "github|bitbucket|codeberg:owner/repo[@ref|#ref], "
    "sourcehut:~user/repo[@ref|#ref], "
    "gitlab:group[/subgroup...]/project[@ref|#ref], or an HTTPS repository URL"
)
# Kept for internal call sites that predate the public name.
_SUPPORTED_FORMS = SUPPORTED_SPEC_FORMS


class SpecParseError(ValueError):
    """A corpus specification is malformed or unsafe."""

    def __init__(self, spec: object, reason: str) -> None:
        self.spec = spec
        self.input = spec
        super().__init__(
            f"unsupported source spec {spec!r}: {reason}; supported forms: {_SUPPORTED_FORMS}"
        )


@dataclass(frozen=True, slots=True)
class CorpusSpec:
    raw: str
    ecosystem: str | None
    name: str
    version: str | None = None
    ref: str | None = None
    ref_kind: str | None = None
    host: str | None = None


def _fail(raw: object, reason: str) -> SpecParseError:
    return SpecParseError(raw, reason)


def _non_ascii_url_unsafe(value: str) -> bool:
    """True when ``value`` contains anything outside visible ASCII."""

    return any(not 0x21 <= ord(character) <= 0x7E for character in value)


def _repo_result(
    raw: str,
    owner: str,
    repo: str,
    ref: str | None,
    kind: str | None,
    host: str = "github.com",
) -> CorpusSpec:
    parts = [owner, *repo.split("/")]
    parts[-1] = parts[-1].removesuffix(".git")
    if host != "gitlab.com" and len(parts) != 2:
        raise _fail(raw, "invalid repository owner or repository name")
    valid_parts = parts
    if host == "git.sr.ht":
        if not parts[0].startswith("~") or len(parts[0]) == 1:
            raise _fail(raw, "Sourcehut repository owners must start with '~'")
        valid_parts = [parts[0][1:], *parts[1:]]
    if len(parts) < 2 or any(
        part in {".", "..", "-"} or not _REPO.fullmatch(part) for part in valid_parts
    ):
        raise _fail(raw, "invalid repository owner or repository name")
    if ref is not None and (not ref or any(ch.isspace() for ch in ref)):
        raise _fail(raw, "repository ref must be non-empty and contain no whitespace")
    if ref is None:
        kind = "head"
    elif _SHA1.fullmatch(ref):
        ref, kind = ref.lower(), "sha"
    return CorpusSpec(raw, None, "/".join(parts), ref=ref, ref_kind=kind, host=host)


def _parse_repo_shorthand(
    raw: str, value: str, host: str = "github.com"
) -> CorpusSpec | None:
    value = value.rstrip("/")
    delimiter = None
    for candidate in ("#", "@"):
        if candidate in value:
            if delimiter is not None:
                raise _fail(raw, "repository spec has conflicting ref delimiters")
            delimiter = candidate
    if delimiter:
        slug, ref = value.split(delimiter, 1)
        if delimiter in ref or not ref:
            raise _fail(raw, "repository ref is malformed")
        kind = "branch" if delimiter == "#" else "tag"
    else:
        slug, ref, kind = value, None, None
    parts = slug.split("/")
    if len(parts) < 2 or (host != "gitlab.com" and len(parts) != 2):
        return None
    return _repo_result(raw, parts[0], "/".join(parts[1:]), ref, kind, host)


def _parse_repository_url(raw: str) -> CorpusSpec:
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise _fail(raw, "malformed URL") from exc
    if parsed.scheme.lower() != "https":
        raise _fail(raw, "repository URLs must use HTTPS")
    host = parsed.hostname.lower() if parsed.hostname is not None else None
    if host is None or host not in _REPOSITORY_HOSTS.values():
        raise _fail(raw, "repository URL host is not supported")
    try:
        port = parsed.port
    except ValueError as exc:
        raise _fail(raw, "malformed URL port") from exc
    if parsed.username is not None or parsed.password is not None or port not in (None, 443):
        raise _fail(raw, "repository URL contains unsupported authority data")
    if parsed.query or parsed.fragment:
        raise _fail(raw, "repository URL must not contain a query or fragment")
    encoded_parts = parsed.path.split("/")
    if encoded_parts and encoded_parts[0] == "":
        encoded_parts = encoded_parts[1:]
    if encoded_parts and encoded_parts[-1] == "":
        encoded_parts = encoded_parts[:-1]
    if any(not part for part in encoded_parts):
        raise _fail(raw, "repository URL contains an empty path segment")
    parts = [unquote(part) for part in encoded_parts]
    if len(parts) < 2:
        raise _fail(raw, "repository URL must include owner and repository")
    ref = None
    kind = None
    project_parts = parts
    if host == "gitlab.com":
        marker = next(
            (
                index
                for index in range(2, len(parts) - 2)
                if parts[index] == "-" and parts[index + 1] in {"tree", "blob"}
            ),
            None,
        )
        if marker is not None:
            project_parts = parts[:marker]
            ref = parts[marker + 2]
            kind = "branch"
        elif "-" in parts[2:]:
            raise _fail(raw, "unsupported repository URL path")
        elif len(parts) >= 4 and parts[2] in {"tree", "blob"}:
            project_parts = parts[:2]
            ref = parts[3]
            kind = "branch"
    elif host == "git.sr.ht" and len(parts) > 2:
        if parts[2] != "refs":
            raise _fail(raw, "unsupported repository URL path")
        project_parts = parts[:2]
        if len(parts) > 3:
            ref = "/".join(parts[2:])
            kind = "branch"
    elif len(parts) > 2:
        if len(parts) >= 4 and parts[2] in (
             {"src"} if host == "bitbucket.org" else {"tree", "blob"}
        ):
            project_parts = parts[:2]
            ref = parts[3]
            kind = "branch"
        else:
            raise _fail(raw, "unsupported repository URL path")
    return _repo_result(
        raw, project_parts[0], "/".join(project_parts[1:]), ref, kind, host
    )


def _split_package(raw: str, ecosystem: str, value: str) -> CorpusSpec:
    if ecosystem == "npm" and value.startswith("@"):
        match = re.fullmatch(r"(@[^/@\s]+/[^/@\s]+)(?:@([^@\s]+))?", value)
        if match is None:
            raise _fail(raw, "invalid scoped npm package")
        name, version = match.groups()
    else:
        name, separator, version = value.rpartition("@")
        if not separator:
            name, version = value, None
        elif not name or not version or "@" in name or "@" in version:
            raise _fail(raw, "package name or version is malformed")
    if not name or any(ch.isspace() for ch in name):
        raise _fail(raw, "package name must be non-empty and contain no whitespace")
    # Registry names and versions are request-URL material: reject anything
    # outside printable ASCII with the typed parser error instead of letting
    # a unicode spec surface later as a bare ``'ascii' codec can't encode``
    # failure (production-readiness audit 2026-08-23, P3).
    if _non_ascii_url_unsafe(name) or (version is not None and _non_ascii_url_unsafe(version)):
        raise _fail(raw, "package names and versions must be printable ASCII")
    grammar = _Ecosystem_NAME.get(ecosystem)
    if grammar is not None and grammar.fullmatch(name) is None:
        raise _fail(raw, _Ecosystem_FAILURE[ecosystem])
    if ecosystem == "go" and "/" not in name:
        raise _fail(raw, "go package specs require a module path")
    return CorpusSpec(raw, ecosystem, name, version=version)


def parse_corpus_spec(raw: str) -> CorpusSpec:
    """Parse one package or GitHub repository spec without network access."""
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise _fail(raw, "input must be a non-empty string without surrounding whitespace")

    lower = raw.lower()
    if lower.startswith("http://"):
        raise _fail(raw, "repository URLs must use HTTPS")
    if "://" in raw:
        return _parse_repository_url(raw)

    prefix, separator, remainder = raw.partition(":")
    if separator:
        canonical = _PREFIXES.get(prefix.lower())
        if canonical is not None:
            if not remainder:
                raise _fail(raw, "package name is empty")
            return _split_package(raw, canonical, remainder)
        host = _REPOSITORY_HOSTS.get(prefix.lower())
        if host is not None:
            parsed = _parse_repo_shorthand(raw, remainder, host)
            if parsed is None:
                raise _fail(raw, f"{prefix.lower()}: requires owner/repo")
            return parsed
        raise _fail(raw, "unknown registry or repository prefix")

    for host in _REPOSITORY_HOSTS.values():
        prefix = host + "/"
        if lower.startswith(prefix):
            parsed = _parse_repo_shorthand(raw, raw[len(prefix):], host)
            if parsed is None:
                raise _fail(raw, f"{host} form requires owner/repo")
            return parsed

    # A valid owner/repo is a repository. Scoped npm names are deliberately
    # excluded by the owner grammar and therefore fall through to npm.
    if not raw.startswith("@"):
        parsed = _parse_repo_shorthand(raw, raw)
        if parsed is not None:
            return parsed
    return _split_package(raw, "npm", raw)


__all__ = [
    "SUPPORTED_SPEC_FORMS",
    "CorpusSpec",
    "SpecParseError",
    "parse_corpus_spec",
]
