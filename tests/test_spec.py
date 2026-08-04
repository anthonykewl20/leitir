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
    ],
)
def test_repository_host_is_preserved(raw, host):
    assert parse_corpus_spec(raw).host == host


@pytest.mark.parametrize(
    "raw",
    [
        "https://github.com.attacker.example/owner/repo",
        "https://example.com/github.com/owner/repo",
        "https://gitlab.com.attacker.example/owner/repo",
        "https://bitbucket.org.attacker.example/owner/repo",
        "http://github.com/owner/repo",
        "git://github.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/issues",
        "github:group/subgroup/project",
        "bitbucket:group/subgroup/project",
        "https://user@github.com/owner/repo",
        "gitlab:group//project",
        "https://gitlab.com/group//project",
        "https://gitlab.com/group/../project",
        "https://gitlab.com/group/subgroup/project/-/issues/1",
        "owner/repo#",
        "npm:",
        "@babel",
        " owner/repo",
        "unknown:value",
    ],
)
def test_malformed_or_unsafe_specs_raise_typed_error(raw):
    with pytest.raises(SpecParseError) as caught:
        parse_corpus_spec(raw)
    assert caught.value.spec == raw
    assert repr(raw) in str(caught.value)
