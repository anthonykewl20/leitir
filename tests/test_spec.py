"""Grammar and security coverage for ADR-004 corpus specs."""

from __future__ import annotations

import pytest

from leitir.spec import SpecParseError, parse_corpus_spec


@pytest.mark.parametrize(
    ("raw", "ecosystem", "name", "version"),
    [
        ("zod", "npm", "zod", None),
        ("npm:zod@3.22.0", "npm", "zod", "3.22.0"),
        ("@babel/core@7.0.0", "npm", "@babel/core", "7.0.0"),
        ("pypi:requests@2.31.0", "pypi", "requests", "2.31.0"),
        ("pip:requests", "pypi", "requests", None),
        ("python:requests", "pypi", "requests", None),
        ("crates:serde@1.0.0", "crates", "serde", "1.0.0"),
        ("cargo:serde", "crates", "serde", None),
        ("rust:serde", "crates", "serde", None),
        ("go:github.com/acme/demo@v1.0.0", "go", "github.com/acme/demo", "v1.0.0"),
    ],
)
def test_package_prefix_matrix(raw, ecosystem, name, version):
    parsed = parse_corpus_spec(raw)
    assert (parsed.ecosystem, parsed.name, parsed.version) == (ecosystem, name, version)


@pytest.mark.parametrize(
    ("raw", "name", "ref", "kind"),
    [
        ("owner/repo", "owner/repo", None, "head"),
        ("owner/repo@v1", "owner/repo", "v1", "tag"),
        ("owner/repo#feature/x", "owner/repo", "feature/x", "branch"),
        ("github:owner/repo", "owner/repo", None, "head"),
        ("github.com/owner/repo.git/", "owner/repo", None, "head"),
        ("https://github.com/owner/repo", "owner/repo", None, "head"),
        ("https://github.com/owner/repo.git/", "owner/repo", None, "head"),
        ("https://github.com/owner/repo/tree/main/src", "owner/repo", "main", "branch"),
        ("https://github.com/owner/repo/blob/v1/file.py", "owner/repo", "v1", "branch"),
        ("gitlab:owner/repo@v1", "owner/repo", "v1", "tag"),
        ("gitlab:owner/repo#main", "owner/repo", "main", "branch"),
        ("gitlab:group/subgroup/project@v1", "group/subgroup/project", "v1", "tag"),
        ("https://gitlab.com/group/subgroup/project", "group/subgroup/project", None, "head"),
        ("https://gitlab.com/group/subgroup/project/-/tree/main", "group/subgroup/project", "main", "branch"),
        ("https://gitlab.com/owner/repo/tree/main/src", "owner/repo", "main", "branch"),
        ("https://gitlab.com/owner/repo/-/blob/v1/file.py", "owner/repo", "v1", "branch"),
        ("bitbucket:owner/repo@" + "a" * 40, "owner/repo", "a" * 40, "sha"),
        ("https://bitbucket.org/owner/repo/src/main/file.py", "owner/repo", "main", "branch"),
        ("codeberg:owner/repo@v1", "owner/repo", "v1", "tag"),
        ("https://codeberg.org/owner/repo/tree/main", "owner/repo", "main", "branch"),
        ("sourcehut:~user/repo@v1", "~user/repo", "v1", "tag"),
        ("https://git.sr.ht/~user/repo/refs/heads/main", "~user/repo", "refs/heads/main", "branch"),
    ],
)
def test_repository_forms_normalize(raw, name, ref, kind):
    parsed = parse_corpus_spec(raw)
    assert (parsed.ecosystem, parsed.name, parsed.ref, parsed.ref_kind) == (
        None,
        name,
        ref,
        kind,
    )


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        ("github:owner/repo", "github.com"),
        ("gitlab:owner/repo", "gitlab.com"),
        ("https://bitbucket.org/owner/repo", "bitbucket.org"),
        ("codeberg:owner/repo", "codeberg.org"),
        ("sourcehut:~user/repo", "git.sr.ht"),
    ],
)
def test_repository_host_is_preserved(raw, host):
    assert parse_corpus_spec(raw).host == host


@pytest.mark.parametrize(
    "prefix",
    ["github", "gitlab", "bitbucket", "codeberg", "sourcehut"],
)
def test_all_repository_hosts_treat_full_sha_as_immutable(prefix):
    owner = "~owner" if prefix == "sourcehut" else "owner"
    sha = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

    parsed = parse_corpus_spec(f"{prefix}:{owner}/repo@{sha}")

    assert parsed.ref_kind == "sha"
    assert parsed.ref == sha.lower()


@pytest.mark.parametrize(
    "raw",
    [
        "https://github.com.attacker.example/owner/repo",
        "https://example.com/github.com/owner/repo",
        "https://gitlab.com.attacker.example/owner/repo",
        "https://bitbucket.org.attacker.example/owner/repo",
        "https://codeberg.org.attacker.example/owner/repo",
        "https://git.sr.ht.attacker.example/~user/repo",
        "http://github.com/owner/repo",
        "git://github.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/issues",
        "github:group/subgroup/project",
        "bitbucket:group/subgroup/project",
        "sourcehut:user/repo",
        "sourcehut:~/repo",
        "https://user@github.com/owner/repo",
        "gitlab:group//project",
        "https://gitlab.com/group//project",
        "https://gitlab.com/group/../project",
        "https://gitlab.com/group/subgroup/project/-/issues/1",
        "https://gitlab.com/group/-/tree/main",
        "gitlab:group/-",
        "owner/repo#",
        "npm:",
        "@babel",
        " owner/repo",
        "unknown:value",
        # Non-ASCII (emoji/unicode) names and versions must fail with the
        # typed parser error, never a later bare ``'ascii' codec`` failure
        # (production-readiness audit 2026-08-23, P3).
        "pypi:flask\U0001F389@1.0",
        "npm:data-\u00e9",
        "crates:demo-\u00fc@1.0",
        "go:example.com/\U0001F389@v1.0.0",
        "pypi:six@1.0\U0001F389",
        "pypi:-leading-sep@1.0",
        "crates:-leading-dash@1.0",
    ],
)
def test_malformed_or_unsafe_specs_raise_typed_error(raw):
    with pytest.raises(SpecParseError) as caught:
        parse_corpus_spec(raw)
    assert caught.value.spec == raw
    assert repr(raw) in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        "pypi:A_0-l.e@1.0.0",
        "crates:a_b-c@1.0",
        "go:example.com/mod@v1.0.0",
        "npm:@scope/pkg@1.0.0",
    ],
)
def test_printable_ascii_grammar_names_still_parse(raw):
    spec = parse_corpus_spec(raw)
    assert spec.ecosystem is not None
    assert spec.name
