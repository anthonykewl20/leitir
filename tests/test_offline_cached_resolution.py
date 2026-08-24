"""Local-first resolution of exact ecosystem pins from cached shelves.

Issue #245: spec commands (get/info/api/examples/diff) must answer an
exact pin (``pypi:name@version`` etc.) from the already-verified corpus
shelf when the registry is unreachable, never serve a tampered shelf,
and keep floating/``latest`` specs on the live path.
"""

from __future__ import annotations

import base64
import io
import json
import shutil
from pathlib import Path

from leitir.cli import ExitCode, main
from leitir.corpus import write_sources
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

SHA_A = "a" * 40
SHA_B = "b" * 40


class _DeadRegistryResolver:
    """Simulates a registry outage: every live lookup fails."""

    def resolve(self, ref):  # pragma: no cover - must not be called
        raise AssertionError(
            f"live resolve reached for {ref.name}@{ref.version}"
        )

    def latest_version(self, ecosystem, name):
        raise ConnectionError("registry outage: latest-version lookup failed")

    def resolve_tag_to_sha(self, slug, tag, host=None):  # pragma: no cover
        raise ConnectionError("registry outage: tag lookup failed")


def _shelve_package(
    root: Path,
    *,
    sha: str,
    version: str,
    payload: str,
    checksum: str = "sha256:" + "1" * 64,
    tag: str | None = "v1.0.0",
    degraded: str | None = None,
) -> tuple[Path, dict]:
    # Degraded (registry-only) shelves live under the registry scope
    # owner (ADR-0023: ``registry/<name>``) with an empty repo_url.
    owner = "registry" if degraded is not None else "acme"
    relative = f"repos/github.com/{owner}/demo/{sha}"
    source = root / relative
    source.mkdir(parents=True)
    (source / "payload.txt").write_text(payload, encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(source)
    manifest: dict[str, object] = {
        "spec": "pypi:demo",
        "ecosystem": "pypi",
        "name": "demo",
        "version": version,
        "host": "github.com",
        "owner": owner,
        "repo": "demo",
        "commit_sha": sha,
        "fetch_method": "registry-artifact",
        "source": "registry-artifact",
        "repo_url": "https://github.com/acme/demo",
        "registry_url": "https://pypi.org/project/demo/" + version + "/",
        "artifact_kind": "sdist",
        "artifact_checksum": checksum,
        "docs_urls": ["https://demo.example/docs"],
        "fetched_at": "2026-08-23T00:00:00Z",
        "verified": True,
        "verified_at": "2026-08-23T00:00:00Z",
        **manifest_digest_fields(digest, scope=scope),
    }
    if tag is not None:
        manifest["tag"] = tag
    if degraded is not None:
        manifest["degraded_provenance"] = degraded
        manifest["repo_url"] = ""
    (source / "leitir-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    entry = {
        "name": "demo",
        "host": "github.com",
        "owner": owner,
        "repo": "demo",
        "commit_sha": sha,
        "path": relative,
        "fetched_at": "2026-08-23T00:00:00Z",
    }
    return source, entry


def _invoke(argv, resolver=None):
    out, err = io.StringIO(), io.StringIO()
    kwargs = {"stdout": out, "stderr": err}
    if resolver is not None:
        kwargs["resolver_factory"] = lambda _token: resolver
    code = main(argv, **kwargs)
    return code, out.getvalue(), err.getvalue()


def test_get_serves_exact_pin_offline_from_cached_shelf(tmp_path):
    source, entry = _shelve_package(tmp_path, sha=SHA_A, version="1.0.0", payload="v1")
    write_sources(tmp_path, [entry])
    manifest_before = (source / "leitir-manifest.json").read_bytes()

    code, out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    assert "resolved offline from the corpus index" in err
    assert str(source) in out
    # The pinned identity must survive the cache hit unchanged (the
    # pre-existing one-time license refresh may enrich other fields,
    # exactly as on the online cache-hit path).
    after = json.loads((source / "leitir-manifest.json").read_text())
    before = json.loads(manifest_before)
    for field in ("commit_sha", "version", "artifact_checksum", "source", "tag"):
        assert after[field] == before[field]
    # A second offline get is fully idempotent: no further rewrites.
    settled = (source / "leitir-manifest.json").read_bytes()
    code2, _out2, _err2 = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )
    assert code2 == ExitCode.SUCCESS
    assert (source / "leitir-manifest.json").read_bytes() == settled


def test_info_answers_exact_pin_offline(tmp_path):
    _source, entry = _shelve_package(tmp_path, sha=SHA_A, version="1.0.0", payload="v1")
    write_sources(tmp_path, [entry])

    code, out, err = _invoke(
        ["info", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    assert "version: 1.0.0" in out
    assert "resolved offline from the corpus index" in err


def test_tampered_cached_shelf_is_never_served_offline(tmp_path):
    """Security: local-first must fail closed on a corrupted shelf —
    the tampered bytes are neither trusted nor silently re-verified away
    while the live registry is unreachable."""
    source, entry = _shelve_package(tmp_path, sha=SHA_A, version="1.0.0", payload="v1")
    write_sources(tmp_path, [entry])
    (source / "payload.txt").write_text("tampered", encoding="utf-8")

    code, _out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS
    assert "resolved offline from the corpus index" not in err


def test_floating_spec_still_requires_the_live_registry(tmp_path):
    _source, entry = _shelve_package(tmp_path, sha=SHA_A, version="1.0.0", payload="v1")
    write_sources(tmp_path, [entry])

    code, _out, _err = _invoke(
        ["info", "pypi:demo", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS  # latest-version lookup cannot be cached


def test_unrecognized_checksum_format_falls_back_to_live(tmp_path):
    """Fail-closed: a shelf whose checksum format cannot be faithfully
    reconstructed never enters the cached path."""
    _source, entry = _shelve_package(
        tmp_path,
        sha=SHA_A,
        version="1.0.0",
        payload="v1",
        checksum="md5:deadbeef",
    )
    write_sources(tmp_path, [entry])

    code, _out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS
    assert "resolved offline from the corpus index" not in err


def test_degraded_cached_shelf_announces_warning_offline(tmp_path):
    _source, entry = _shelve_package(
        tmp_path,
        sha=SHA_A,
        version="1.0.0",
        payload="v1",
        tag=None,
        degraded="repository tag lookup unavailable: HTTP 403 rate limit",
    )
    write_sources(tmp_path, [entry])

    code, _out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    assert "resolved registry-only" in err
    assert "resolved offline from the corpus index" in err


def test_diff_answers_both_exact_pins_offline(tmp_path, monkeypatch):
    import leitir.diff

    class _NoNotes:
        def __init__(self, *_args, **_kwargs):
            pass

        def fetch(self, *_args):  # pragma: no cover - never reached
            raise ConnectionError("release notes are unavailable offline")

    # Keep the unit test deterministic: the CLI's default notes fetcher
    # would otherwise contact the real GitHub API.
    monkeypatch.setattr(leitir.diff, "GitHubReleaseNotes", _NoNotes)

    source_a, entry_a = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="v1\n"
    )
    source_b, entry_b = _shelve_package(
        tmp_path, sha=SHA_B, version="1.1.0", payload="v1\nadded\n"
    )
    write_sources(tmp_path, [entry_a, entry_b])

    code, out, err = _invoke(
        [
            "diff",
            "pypi:demo@1.0.0",
            "pypi:demo@1.1.0",
            "--root",
            str(tmp_path),
        ],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    assert err.count("resolved offline from the corpus index") == 2
    assert "payload.txt" in out
    assert source_a != source_b


def test_multiple_matching_shelves_pick_is_deterministic(tmp_path):
    """When more than one verified shelf claims the same name+version
    the cached pick must be order-independent (sorted candidates),
    PYTHONHASHSEED-independent by construction."""
    _a, entry_a = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="v1"
    )
    # A second shelf for the same pin under a lexicographically later
    # owner: sorted order must pick acme regardless of index order.
    relative_b = f"repos/github.com/zzz-later/demo/{SHA_B}"
    source_b = tmp_path / relative_b
    source_b.mkdir(parents=True)
    (source_b / "payload.txt").write_text("v1", encoding="utf-8")
    digest_b, scope_b = compute_materialized_tree_hash(source_b)
    (source_b / "leitir-manifest.json").write_text(
        json.dumps(
            {
                "spec": "pypi:demo",
                "ecosystem": "pypi",
                "version": "1.0.0",
                "host": "github.com",
                "owner": "zzz-later",
                "repo": "demo",
                "commit_sha": SHA_B,
                "fetch_method": "registry-artifact",
                "source": "registry-artifact",
                "repo_url": "https://github.com/zzz-later/demo",
                "registry_url": "https://pypi.org/project/demo/1.0.0/",
                "artifact_kind": "sdist",
                "artifact_checksum": "sha256:" + "1" * 64,
                "fetched_at": "2026-08-23T00:00:00Z",
                "verified": True,
                "verified_at": "2026-08-23T00:00:00Z",
                **manifest_digest_fields(digest_b, scope=scope_b),
            }
        ),
        encoding="utf-8",
    )
    entry_b = dict(entry_a, owner="zzz-later", commit_sha=SHA_B, path=relative_b)

    for order in ([entry_a, entry_b], [entry_b, entry_a]):
        write_sources(tmp_path, order)
        code, out, err = _invoke(
            ["get", "pypi:demo@1.0.0", "--root", str(tmp_path), "--json"],
            resolver=_DeadRegistryResolver(),
        )
        assert code == ExitCode.SUCCESS, err
        assert json.loads(out)["results"][0]["commit_sha"] == SHA_A


def test_go_pins_do_not_use_the_cached_path(tmp_path):
    """Go module-zip shelves stay on live resolution (ADR-0024)."""
    code, _out, err = _invoke(
        ["get", "go:github.com/acme/demo@v1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )
    assert code != ExitCode.SUCCESS
    assert "resolved offline from the corpus index" not in err


def test_cached_resolution_matches_shelf_identity(tmp_path):
    """The offline resolution must bind exactly the shelved pin: same
    commit, same version, same artifact checksum."""
    _source, entry = _shelve_package(
        tmp_path,
        sha=SHA_A,
        version="1.0.0",
        payload="v1",
        checksum="sha256:" + "c" * 64,
    )
    write_sources(tmp_path, [entry])

    code, out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path), "--json"],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    payload = json.loads(out)
    [result] = payload["results"]
    assert result["commit_sha"] == SHA_A
    assert result["source"] == "registry-artifact"

def test_index_name_substitution_is_rejected(tmp_path):
    """P1 (review): editing only the unanchored sources.json ``name`` must
    not serve a different shelved package as the requested pin — the
    manifest's own recorded spec must confirm the identity."""
    _source, entry = _shelve_package(
        tmp_path,
        sha=SHA_A,
        version="9.9.9",
        payload="genuine other package",
    )
    entry = dict(entry, name="other")
    write_sources(tmp_path, [entry])

    code, _out, err = _invoke(
        ["get", "pypi:other@9.9.9", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS
    assert "resolved offline from the corpus index" not in err


def test_manifest_spec_relabeled_index_entry_is_rejected(tmp_path):
    """Variant: index name matches the pin, manifest spec names another
    package — still no bind (the manifest, not the index, anchors
    identity)."""
    source, entry = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="v1"
    )
    manifest_path = source / "leitir-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["spec"] = "pypi:evil-pkg@1.0.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    write_sources(tmp_path, [entry])

    code, _out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    # The manifest is not part of the hashed file set, so tree
    # verification still passes — the identity check itself must refuse
    # the bind.
    assert "resolved offline from the corpus index" not in err


def test_index_path_escape_is_never_read(tmp_path):
    """P2 (review): an index entry whose path escapes the corpus root
    (relative or absolute) is skipped, like every other index
    consumer."""
    outside = tmp_path / "outside"
    source = outside / f"repos/github.com/acme/demo/{SHA_A}"
    source.mkdir(parents=True)
    (source / "payload.txt").write_text("v1", encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(source)
    (source / "leitir-manifest.json").write_text(
        json.dumps(
            {
                "spec": "pypi:demo@1.0.0",
                "ecosystem": "pypi",
                "version": "1.0.0",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA_A,
                "fetch_method": "registry-artifact",
                "source": "registry-artifact",
                "repo_url": "https://github.com/acme/demo",
                "registry_url": "https://pypi.org/project/demo/1.0.0/",
                "artifact_kind": "sdist",
                "artifact_checksum": "sha256:" + "1" * 64,
                "fetched_at": "2026-08-23T00:00:00Z",
                "verified": True,
                "verified_at": "2026-08-23T00:00:00Z",
                **manifest_digest_fields(digest, scope=scope),
            }
        ),
        encoding="utf-8",
    )
    for escaped in (
        f"../outside/repos/github.com/acme/demo/{SHA_A}",
        str(source),
    ):
        write_sources(
            tmp_path,
            [
                {
                    "name": "demo",
                    "host": "github.com",
                    "owner": "acme",
                    "repo": "demo",
                    "commit_sha": SHA_A,
                    "path": escaped,
                    "fetched_at": "2026-08-23T00:00:00Z",
                }
            ],
        )
        code, _out, err = _invoke(
            ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
            resolver=_DeadRegistryResolver(),
        )
        assert code != ExitCode.SUCCESS, escaped
        assert "resolved offline from the corpus index" not in err, escaped


def test_full_provenance_shelf_preferred_over_degraded(tmp_path):
    """P2 (review): the degraded ``registry`` owner sorts early, so a
    degraded shelf must not shadow a coexisting full-provenance shelf
    (``zzz-org`` sorts after ``registry``; the full shelf must win)."""
    _full, entry_full = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="full"
    )
    entry_full = dict(
        entry_full,
        owner="zzz-org",
        path=f"repos/github.com/zzz-org/demo/{SHA_A}",
    )
    source_full = tmp_path / str(entry_full["path"])
    source_full.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / f"repos/github.com/acme/demo/{SHA_A}").rename(source_full)
    manifest_path = source_full / "leitir-manifest.json"
    manifest_full = json.loads(manifest_path.read_text())
    manifest_full["owner"] = "zzz-org"
    manifest_full["repo_url"] = "https://github.com/zzz-org/demo"
    digest, scope = compute_materialized_tree_hash(source_full)
    manifest_full.update(manifest_digest_fields(digest, scope=scope))
    manifest_path.write_text(json.dumps(manifest_full), encoding="utf-8")

    _deg, entry_deg = _shelve_package(
        tmp_path,
        sha=SHA_B,
        version="1.0.0",
        payload="degraded",
        tag=None,
        degraded="repository tag lookup unavailable: HTTP 403 rate limit",
    )
    write_sources(tmp_path, [entry_deg, entry_full])

    code, out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path), "--json"],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["results"][0]["commit_sha"] == SHA_A
    assert "resolved registry-only" not in err


def test_npm_sha512_digest_reconstruction_uses_hex(tmp_path):
    """P1 (review): the reconstructed digest must equal what the live npm
    path would store — the base64 token decoded to hex, never the raw
    base64 string."""
    from leitir.cli import _resolve_from_cached_shelf
    from leitir.spec import parse_corpus_spec

    raw_digest = bytes(range(64))
    token = base64.b64encode(raw_digest).decode("ascii")
    _source, entry = _shelve_package(
        tmp_path,
        sha=SHA_A,
        version="1.0.0",
        payload="v1",
        checksum="sha512-" + token,
    )
    manifest_path = tmp_path / str(entry["path"]) / "leitir-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["spec"] = "npm:demo@1.0.0"
    manifest["ecosystem"] = "npm"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    write_sources(tmp_path, [entry])

    parsed = parse_corpus_spec("npm:demo@1.0.0")
    result = _resolve_from_cached_shelf(parsed, tmp_path, None)

    assert result is not None
    resolved = result[0]
    assert resolved.artifact is not None
    assert resolved.artifact.algorithm == "sha512"
    assert resolved.artifact.digest == raw_digest.hex()
    assert resolved.artifact.digest != token


def test_empty_or_malformed_digest_is_rejected(tmp_path):
    """P2 (review): ``sha256:`` (empty digest), short hex, non-hex, and
    undecodable/short base64 all reject the candidate."""
    from leitir.cli import _resolve_from_cached_shelf
    from leitir.spec import parse_corpus_spec

    bad_checksums = [
        "sha256:",
        "sha256:" + "1" * 63,
        "sha256:" + "z" * 64,
        "sha512-not-base64!!",
        "sha512-" + base64.b64encode(b"short").decode("ascii"),
    ]
    parsed = parse_corpus_spec("pypi:demo@1.0.0")
    for bad in bad_checksums:
        _source, entry = _shelve_package(
            tmp_path, sha=SHA_A, version="1.0.0", payload="v1", checksum=bad
        )
        write_sources(tmp_path, [entry])
        assert _resolve_from_cached_shelf(parsed, tmp_path, None) is None, bad
        shutil.rmtree(tmp_path / str(entry["path"]))


def test_unreconstructable_manifest_falls_back_to_live(tmp_path):
    """P2 (review): a tree-valid manifest whose fields cannot build a
    valid ResolvedPackage (non-HTTP docs URL) must fall back to live
    resolution — the ValueError must not escape as a hard failure."""
    source, entry = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="v1"
    )
    manifest_path = source / "leitir-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["docs_urls"] = ["ftp://demo.example/docs"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    write_sources(tmp_path, [entry])

    class _FailingLiveResolver:
        def resolve(self, ref):
            raise ConnectionError("live registry reached (expected)")

        def latest_version(self, ecosystem, name):
            raise ConnectionError("registry outage")

        def resolve_tag_to_sha(self, slug, tag, host=None):
            raise ConnectionError("registry outage")

    code, _out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_FailingLiveResolver(),
    )

    assert "live registry reached (expected)" in err
    assert "resolved offline from the corpus index" not in err


def test_second_candidate_serves_when_first_fails_verification(tmp_path):
    """Skip path: the first candidate's shelf is tampered; the second
    verified candidate serves the pin. (Asserted at the resolution
    layer: the CLI's broader raw-spec shelf enumeration additionally
    rejects a corpus holding an indexed tampered shelf, which is
    pre-existing fail-closed behavior, not cached-path behavior.)"""
    from leitir.cli import _resolve_from_cached_shelf
    from leitir.spec import parse_corpus_spec

    first, entry_first = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="v1"
    )
    (first / "payload.txt").write_text("tampered", encoding="utf-8")
    _second, entry_second = _shelve_package(
        tmp_path, sha=SHA_B, version="1.0.0", payload="v1-clean"
    )
    entry_second = dict(
        entry_second,
        owner="z-later",
        path=f"repos/github.com/z-later/demo/{SHA_B}",
    )
    source_second = tmp_path / str(entry_second["path"])
    source_second.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / f"repos/github.com/acme/demo/{SHA_B}").rename(source_second)
    manifest_second = json.loads(
        (source_second / "leitir-manifest.json").read_text()
    )
    manifest_second["owner"] = "z-later"
    manifest_second["repo_url"] = "https://github.com/z-later/demo"
    digest, scope = compute_materialized_tree_hash(source_second)
    manifest_second.update(manifest_digest_fields(digest, scope=scope))
    (source_second / "leitir-manifest.json").write_text(
        json.dumps(manifest_second), encoding="utf-8"
    )
    write_sources(tmp_path, [entry_first, entry_second])

    result = _resolve_from_cached_shelf(
        parse_corpus_spec("pypi:demo@1.0.0"), tmp_path, None
    )

    assert result is not None
    resolved = result[0]
    assert resolved.scope.commit_sha == SHA_B
    assert resolved.scope.slug == "z-later/demo"


def test_manifest_version_mismatch_falls_back(tmp_path):
    """A shelf shelved under a different version never serves this
    pin."""
    _source, entry = _shelve_package(
        tmp_path, sha=SHA_A, version="2.0.0", payload="other version"
    )
    write_sources(tmp_path, [entry])

    code, _out, err = _invoke(
        ["get", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code != ExitCode.SUCCESS
    assert "resolved offline from the corpus index" not in err


def test_api_and_examples_answer_exact_pins_offline(tmp_path):
    _source, entry = _shelve_package(
        tmp_path, sha=SHA_A, version="1.0.0", payload="v1"
    )
    write_sources(tmp_path, [entry])

    code, _out, err = _invoke(
        ["api", "pypi:demo@1.0.0", "--root", str(tmp_path), "--json"],
        resolver=_DeadRegistryResolver(),
    )
    assert code == ExitCode.SUCCESS, err

    code, _out, err = _invoke(
        ["examples", "pypi:demo@1.0.0", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )
    assert code == ExitCode.SUCCESS, err
