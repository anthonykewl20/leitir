"""Parse corpus package and GitHub repository specifications.

The parser is deliberately independent of the CLI so every corpus operation
uses the same normalization and exact-host security checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import unquote, urlsplit


_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_OWNER = re.compile(r"^[A-Za-z0-9_.-]+$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+$")
_NPM_NAME = re.compile(r"^(?:[A-Za-z0-9_.~-][A-Za-z0-9_.~-]*|@[A-Za-z0-9_.~-]+/[A-Za-z0-9_.~-]+)$")
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
_SUPPORTED_FORMS = (
    "npm:name[@version], pypi:name[@version], crates:name[@version], "
    "go:module[@version], owner/repo[@ref|#ref], github:owner/repo, or "
    "https://github.com/owner/repo"
)


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


def _fail(raw: object, reason: str) -> SpecParseError:
    return SpecParseError(raw, reason)


def _repo_result(raw: str, owner: str, repo: str, ref: str | None, kind: str | None) -> CorpusSpec:
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(repo):
        raise _fail(raw, "invalid GitHub owner or repository name")
    if ref is not None and (not ref or any(ch.isspace() for ch in ref)):
        raise _fail(raw, "repository ref must be non-empty and contain no whitespace")
    if ref is None:
        kind = "head"
    elif _SHA1.fullmatch(ref):
        ref, kind = ref.lower(), "sha"
    return CorpusSpec(raw, None, f"{owner}/{repo}", ref=ref, ref_kind=kind)


def _parse_repo_shorthand(raw: str, value: str) -> CorpusSpec | None:
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
    if len(parts) != 2:
        return None
    return _repo_result(raw, parts[0], parts[1], ref, kind)


def _parse_github_url(raw: str) -> CorpusSpec:
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise _fail(raw, "malformed URL") from exc
    if parsed.scheme.lower() != "https":
        raise _fail(raw, "GitHub repository URLs must use HTTPS")
    if parsed.hostname is None or parsed.hostname.lower() != "github.com":
        raise _fail(raw, "repository URL host must be exactly github.com")
    try:
        port = parsed.port
    except ValueError as exc:
        raise _fail(raw, "malformed URL port") from exc
    if parsed.username is not None or parsed.password is not None or port not in (None, 443):
        raise _fail(raw, "GitHub repository URL contains unsupported authority data")
    if parsed.query or parsed.fragment:
        raise _fail(raw, "GitHub repository URL must not contain a query or fragment")
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise _fail(raw, "GitHub repository URL must include owner and repository")
    ref = None
    kind = None
    if len(parts) > 2:
        if len(parts) < 4 or parts[2] not in {"tree", "blob"}:
            raise _fail(raw, "unsupported GitHub repository URL path")
        ref = parts[3]
        kind = "branch"
    return _repo_result(raw, parts[0], parts[1], ref, kind)


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
    if ecosystem == "npm" and not _NPM_NAME.fullmatch(name):
        raise _fail(raw, "invalid npm package name")
    if ecosystem == "go" and "/" not in name:
        raise _fail(raw, "go package specs require a module path")
    return CorpusSpec(raw, ecosystem, name, version=version)


def parse_corpus_spec(raw: str) -> CorpusSpec:
    """Parse one package or GitHub repository spec without network access."""
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise _fail(raw, "input must be a non-empty string without surrounding whitespace")

    lower = raw.lower()
    if lower.startswith("http://"):
        raise _fail(raw, "GitHub repository URLs must use HTTPS")
    if "://" in raw:
        return _parse_github_url(raw)

    prefix, separator, remainder = raw.partition(":")
    if separator:
        canonical = _PREFIXES.get(prefix.lower())
        if canonical is not None:
            if not remainder:
                raise _fail(raw, "package name is empty")
            return _split_package(raw, canonical, remainder)
        if prefix.lower() == "github":
            parsed = _parse_repo_shorthand(raw, remainder)
            if parsed is None:
                raise _fail(raw, "github: requires owner/repo")
            return parsed
        raise _fail(raw, "unknown registry or repository prefix")

    if lower.startswith("github.com/"):
        parsed = _parse_repo_shorthand(raw, raw[len("github.com/"):])
        if parsed is None:
            raise _fail(raw, "github.com form requires owner/repo")
        return parsed

    # A valid owner/repo is a repository. Scoped npm names are deliberately
    # excluded by the owner grammar and therefore fall through to npm.
    if not raw.startswith("@"):
        parsed = _parse_repo_shorthand(raw, raw)
        if parsed is not None:
            return parsed
    return _split_package(raw, "npm", raw)


__all__ = ["CorpusSpec", "SpecParseError", "parse_corpus_spec"]
