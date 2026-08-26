"""``leitir diff --impact`` (issue #266 B4): intersect the removed/changed
symbol delta between two resolved versions with actual consumer usage.

User-level intent tests driving the public entry point (docs/testing.md):
each test observes ``diff_packages``'s (or the CLI's) returned/rendered
report -- its impact counts, call sites, and honesty statuses -- never a
private helper's return value. ``diff_packages`` is the same public library
entry point the CLI dispatches to (see ``tests/test_diff.py`` and
``tests/test_diff_e2e.py`` for the established pattern of exercising it
directly with a fake resolver/materializer rather than real network I/O).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.corpus import write_sources
from leitir.diff import DiffReport, diff_packages
from leitir.resolver import ResolvedPackage
from leitir.search import RepoScope

_BEFORE_SOURCE = (
    "def public(value: int):\n"
    "    return value\n"
    "\n"
    "def old():\n"
    "    pass\n"
)

_AFTER_SOURCE = (
    "def public(value: str):\n"
    "    return value\n"
    "\n"
    "def new():\n"
    "    pass\n"
)


class _Resolver:
    def resolve(self, ref):
        digit = "1" if ref.version == "1.0.0" else "2"
        return ResolvedPackage(
            ref,
            RepoScope("acme/demo", digit * 40),
            f"v{ref.version}",
            f"https://example.invalid/demo/{ref.version}",
        )


def _materializer(spec, resolved, *, root, name, **options):
    root = Path(root)
    sha = resolved.scope.commit_sha
    target = root / "repos" / "github.com" / "acme" / "demo" / sha
    target.mkdir(parents=True, exist_ok=True)
    source = _BEFORE_SOURCE if resolved.ref.version == "1.0.0" else _AFTER_SOURCE
    (target / "demo.py").write_text(source, encoding="utf-8")
    manifest = {
        "ecosystem": "pypi",
        "version": resolved.ref.version,
        "fetched_at": "2026-08-04T00:00:00Z",
    }
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    entries = []
    index_path = root / "sources.json"
    if index_path.exists():
        entries = json.loads(index_path.read_text(encoding="utf-8"))
    entries.append(
        {
            "name": name,
            "host": "github.com",
            "owner": "acme",
            "repo": "demo",
            "commit_sha": sha,
            "path": target.relative_to(root).as_posix(),
            "fetched_at": manifest["fetched_at"],
        }
    )
    write_sources(root, entries)
    return target


def _diff(tmp_path, consumer_path):
    return diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
        impact_path=consumer_path,
    )


def _consumer(tmp_path, name, source):
    project = tmp_path / name
    project.mkdir()
    app = project / "app.py"
    app.write_text(source, encoding="utf-8")
    return project


# --- premise: the symbol delta carries usable, matchable names -----------


def test_premise_removed_symbols_carry_usable_names(tmp_path):
    report = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
    )
    assert [item["name"] for item in report.api.removed] == ["old"]
    assert [item["qualified_name"] for item in report.api.removed] == ["demo.old"]


# --- the three-way honesty model ------------------------------------------


def test_removed_symbol_used_is_impacted_with_call_sites(tmp_path):
    consumer = _consumer(
        tmp_path, "impacted", "import demo\n\ndemo.old()\ndemo.old()\n"
    )
    report = _diff(tmp_path, consumer)

    assert report.impact is not None
    impact = report.impact
    assert impact.status == "impact_found"
    assert impact.removed_total == 1
    assert [symbol.name for symbol in impact.impacted] == ["old"]
    symbol = impact.impacted[0]
    assert symbol.qualified_name == "demo.old"
    assert len(symbol.sites) == 2
    assert [site.line for site in symbol.sites] == [3, 4]
    assert impact.sites_impacted == 2
    assert impact.not_impacted == ()
    # JSON payload round-trips the same facts.
    payload = report.as_dict()["impact"]
    assert payload["counts"]["sites_impacted"] == 2
    assert payload["impacted"][0]["name"] == "old"
    assert len(payload["impacted"][0]["sites"]) == 2


def test_removed_symbol_unused_is_not_impacted(tmp_path):
    consumer = _consumer(tmp_path, "unused", "import demo\n\ndemo.public('x')\n")
    report = _diff(tmp_path, consumer)

    impact = report.impact
    assert impact is not None
    assert impact.impacted == ()
    assert impact.not_impacted == ("old",)
    assert impact.status == "clean"
    assert impact.sites_impacted == 0
    # The resolved-but-irrelevant usage of `public` was genuinely examined.
    assert impact.sites_other == 1
    assert impact.sites_examined == 1


def test_unresolvable_usage_is_counted_unresolved_never_silently_safe(tmp_path):
    consumer = _consumer(
        tmp_path,
        "dynamic",
        "import demo\n\ngetattr(demo, 'old')()\n",
    )
    report = _diff(tmp_path, consumer)

    impact = report.impact
    assert impact is not None
    assert impact.sites_unresolved >= 1
    assert len(impact.unresolved_sites) == impact.sites_unresolved
    # The unresolved count is visible in the JSON payload, not dropped.
    payload = report.as_dict()["impact"]
    assert payload["counts"]["sites_unresolved"] == impact.sites_unresolved
    assert len(payload["unresolved_sites"]) == impact.sites_unresolved


def test_zero_examined_sites_is_loud_not_a_clean_not_impacted(tmp_path):
    # The consumer never imports "demo" at all (guess_import_root mismatch
    # is the realistic trigger -- see check.py's own documented limitation
    # and issue #269 -- but any zero-reference consumer exercises the same
    # honesty requirement).
    consumer = _consumer(
        tmp_path, "unrelated", "import totallyunrelated\n\ntotallyunrelated.whatever()\n"
    )
    report = _diff(tmp_path, consumer)

    impact = report.impact
    assert impact is not None
    assert impact.sites_examined == 0
    assert impact.status == "no_sites_examined"
    # Zero evidence must never be reported as "0 of 1 removed symbols used".
    assert impact.not_impacted == ()
    assert impact.removed_total == 1


def test_no_removed_symbols_is_vacuously_clean_without_running_resolver(tmp_path):
    # Diffing a version against itself: nothing was removed, so there is
    # nothing to intersect -- a real "nothing to report", distinct from
    # "resolution failed to find evidence".
    consumer = _consumer(tmp_path, "same", "import demo\n\ndemo.public(1)\n")
    same_report = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@1.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
        impact_path=consumer,
    )
    assert same_report.impact is not None
    assert same_report.impact.removed_total == 0
    assert same_report.impact.status == "clean"
    assert same_report.impact.impacted == ()
    assert same_report.impact.not_impacted == ()
    assert same_report.impact.sites_examined == 0


# --- additive: default diff output is unaffected --------------------------


def test_default_diff_output_omits_impact_key(tmp_path):
    report = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
    )
    assert report.impact is None
    assert "impact" not in report.as_dict()


def test_default_diff_json_byte_identical_with_and_without_impact_field_absent(tmp_path):
    without_impact = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
    ).to_json()
    without_impact_again = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
    ).to_json()
    assert without_impact == without_impact_again
    assert "impact" not in without_impact


# --- CLI wiring -------------------------------------------------------------


def test_cli_impact_flag_threads_to_diff_packages(tmp_path, monkeypatch):
    import leitir.diff
    from leitir.apisurface import diff_api_indexes
    from leitir.diff import FileDiff, VersionIdentity

    identity = VersionIdentity("npm:demo@1", "demo", "1", "acme/demo", "a" * 40)
    captured: dict[str, object] = {}

    def fake_diff_packages(spec_a, spec_b, *, impact_path=None, **kwargs):
        captured["impact_path"] = impact_path
        return DiffReport(
            before=identity,
            after=identity,
            files=FileDiff((), (), ()),
            api=diff_api_indexes({"symbols": []}, {"symbols": []}),
        )

    monkeypatch.setattr(leitir.diff, "diff_packages", fake_diff_packages)
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    (consumer / "app.py").write_text("pass\n", encoding="utf-8")
    stdout, stderr = io.StringIO(), io.StringIO()

    code = main(
        [
            "diff",
            "npm:demo@1",
            "npm:demo@1",
            "--json",
            "--root",
            str(tmp_path),
            "--impact",
            str(consumer),
        ],
        resolver_factory=lambda _token: object(),
        code_search_factory=lambda _token: object(),
        stdout=stdout,
        stderr=stderr,
    )

    assert code == ExitCode.SUCCESS
    assert captured["impact_path"] == consumer.expanduser().absolute()
    # No "impact" section on the fake report (impact=None was returned by
    # the stub), and the base contract stays exactly as before.
    assert json.loads(stdout.getvalue())["files"] == {
        "added": [], "removed": [], "modified": []
    }


def test_cli_default_diff_without_impact_flag_is_unchanged(tmp_path, monkeypatch):
    import leitir.diff
    from leitir.apisurface import diff_api_indexes
    from leitir.diff import FileDiff, VersionIdentity

    identity = VersionIdentity("npm:demo@1", "demo", "1", "acme/demo", "a" * 40)
    report = DiffReport(
        before=identity,
        after=identity,
        files=FileDiff((), (), ()),
        api=diff_api_indexes({"symbols": []}, {"symbols": []}),
    )
    captured: dict[str, object] = {}

    def fake_diff_packages(*args, impact_path=None, **kwargs):
        captured["impact_path"] = impact_path
        return report

    monkeypatch.setattr(leitir.diff, "diff_packages", fake_diff_packages)
    stdout, stderr = io.StringIO(), io.StringIO()

    code = main(
        ["diff", "npm:demo@1", "npm:demo@1", "--json", "--root", str(tmp_path)],
        resolver_factory=lambda _token: object(),
        code_search_factory=lambda _token: object(),
        stdout=stdout,
        stderr=stderr,
    )

    assert code == ExitCode.SUCCESS
    assert captured["impact_path"] is None
    assert json.loads(stdout.getvalue()) == {
        "schema_version": 1,
        "before": identity.as_dict(),
        "after": identity.as_dict(),
        "files": {"added": [], "removed": [], "modified": []},
        "api": {"added": [], "removed": [], "changed": []},
    }
    assert stderr.getvalue() == ""


def test_cli_impact_summary_is_visible_on_stderr(tmp_path, monkeypatch):
    import leitir.diff
    from leitir.apisurface import diff_api_indexes
    from leitir.diff import (
        FileDiff,
        ImpactedSymbol,
        ImpactReport,
        ImpactSite,
        VersionIdentity,
    )

    identity = VersionIdentity("npm:demo@1", "demo", "1", "acme/demo", "a" * 40)
    impact = ImpactReport(
        against="npm:demo@1",
        package_name="demo",
        removed_total=3,
        status="impact_found",
        sites_examined=47,
        sites_impacted=7,
        sites_unresolved=40,
        sites_other=0,
        impacted=(
            ImpactedSymbol(
                name="old",
                qualified_name="demo.old",
                sites=(ImpactSite(file="app.py", line=1, col=0, symbol="old"),) * 7,
            ),
        ),
        not_impacted=("gone", "vanished"),
        unresolved_sites=(ImpactSite(file="app.py", line=2, col=0, symbol="<module>"),) * 40,
    )
    report = DiffReport(
        before=identity,
        after=identity,
        files=FileDiff((), (), ()),
        api=diff_api_indexes({"symbols": []}, {"symbols": []}),
        impact=impact,
    )
    monkeypatch.setattr(leitir.diff, "diff_packages", lambda *a, **k: report)
    stdout, stderr = io.StringIO(), io.StringIO()

    code = main(
        [
            "diff", "npm:demo@1", "npm:demo@1", "--json", "--root", str(tmp_path),
            "--impact", str(tmp_path),
        ],
        resolver_factory=lambda _token: object(),
        code_search_factory=lambda _token: object(),
        stdout=stdout,
        stderr=stderr,
    )

    assert code == ExitCode.SUCCESS
    # The falsification this brief warns against: 40 unresolved call sites
    # must never be silently dropped from the human-visible summary.
    assert "sites_unresolved=40" in stderr.getvalue()
    assert "impacted=1" in stderr.getvalue()


# --- real (non-injected) CLI path + hash-seed determinism -----------------


_SHA_BEFORE = "c" * 40
_SHA_AFTER = "d" * 40

_PKG_BEFORE = _BEFORE_SOURCE.encode("utf-8")
_PKG_AFTER = _AFTER_SOURCE.encode("utf-8")


def _tarball(files: dict[str, bytes]) -> bytes:
    import tarfile

    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _github_tree(sha: str, files: dict[str, bytes]) -> bytes:
    import hashlib

    from _http_server import json_body

    return json_body(
        {
            "sha": sha,
            "truncated": False,
            "tree": [
                {
                    "path": path,
                    "type": "blob",
                    "size": len(content),
                    "mode": "100644",
                    "sha": hashlib.sha1(
                        b"blob " + str(len(content)).encode() + b"\0" + content
                    ).hexdigest(),
                }
                for path, content in sorted(files.items())
            ],
        }
    )


def _network_routes():
    from _http_server import json_body

    return {
        "/pypi/demo/1.2/json": (
            200, {}, json_body({"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}})
        ),
        "/pypi/demo/1.3/json": (
            200, {}, json_body({"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}})
        ),
        "/repos/acme/demo/git/ref/tags/v1.2": (
            200, {}, json_body({"object": {"type": "commit", "sha": _SHA_BEFORE}})
        ),
        "/repos/acme/demo/git/ref/tags/v1.3": (
            200, {}, json_body({"object": {"type": "commit", "sha": _SHA_AFTER}})
        ),
        f"/acme/demo/tar.gz/{_SHA_BEFORE}": (
            200, {}, _tarball({f"demo-{_SHA_BEFORE}/demo.py": _PKG_BEFORE})
        ),
        f"/acme/demo/tar.gz/{_SHA_AFTER}": (
            200, {}, _tarball({f"demo-{_SHA_AFTER}/demo.py": _PKG_AFTER})
        ),
        f"/repos/acme/demo/git/trees/{_SHA_BEFORE}": (
            200, {}, _github_tree(_SHA_BEFORE, {"demo.py": _PKG_BEFORE})
        ),
        f"/repos/acme/demo/git/trees/{_SHA_AFTER}": (
            200, {}, _github_tree(_SHA_AFTER, {"demo.py": _PKG_AFTER})
        ),
    }


def test_real_cli_path_reports_impact_through_network_materialization(tmp_path, monkeypatch):
    """Exercises the built-in (non-injected) diff_packages branch end to
    end: real corpus-spec resolution, real materialization, real Python
    API extraction, and the real usage resolver -- not a fake report."""

    from _http_server import routed_server

    root = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    app = project / "app.py"
    app.write_text("import demo\n\ndemo.old()\n", encoding="utf-8")

    with routed_server(_network_routes()) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        stdout, stderr = io.StringIO(), io.StringIO()
        code = main(
            [
                "diff", "pypi:demo@1.2", "pypi:demo@1.3",
                "--impact", str(app),
                "--root", str(root),
                "--json",
            ],
            stdout=stdout,
            stderr=stderr,
        )

    assert code == ExitCode.SUCCESS, stderr.getvalue()
    payload = json.loads(stdout.getvalue())
    impact = payload["impact"]
    assert impact["counts"]["removed_total"] == 1
    assert impact["counts"]["sites_impacted"] == 1
    assert impact["impacted"][0]["name"] == "old"
    assert impact["impacted"][0]["sites"][0]["file"] == "app.py"
    assert "impacted=1" in stderr.getvalue()


@pytest.mark.parametrize("_unused", [0])
def test_impact_output_is_hash_seed_independent(tmp_path, _unused):
    import os
    import subprocess
    import sys

    from _http_server import routed_server

    repo_root = Path(__file__).parents[1]
    project = tmp_path / "project"
    project.mkdir()
    app = project / "app.py"
    app.write_text("import demo\n\ndemo.old()\ndemo.public(1)\n", encoding="utf-8")

    outputs: dict[str, bytes] = {}
    with routed_server(_network_routes()) as server:
        for seed in ("0", "1", "42", "7"):
            root = tmp_path / f"corpus-{seed}"
            environment = os.environ.copy()
            environment.update(
                PYTHONHASHSEED=seed,
                PYTHONPATH=str(repo_root / "src"),
                LEITIR_PYPI_BASE_URL=server.base_url + "/pypi",
                LEITIR_GITHUB_API_BASE_URL=server.base_url,
                LEITIR_CODELOAD_BASE_URL=server.base_url,
                LEITIR_HOME=str(root),
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from leitir.cli import main; sys.exit(main())",
                    "diff",
                    "pypi:demo@1.2",
                    "pypi:demo@1.3",
                    "--impact",
                    str(app),
                    "--root",
                    str(root),
                    "--json",
                ],
                cwd=repo_root,
                env=environment,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert completed.returncode == ExitCode.SUCCESS, completed.stderr
            payload = json.loads(completed.stdout)
            assert payload["impact"]["counts"] == {
                "removed_total": 1,
                "sites_examined": 2,
                "sites_impacted": 1,
                "sites_unresolved": 0,
                "sites_other": 1,
            }
            outputs[seed] = completed.stdout

    baseline = outputs["0"]
    for seed, stdout in outputs.items():
        assert stdout == baseline, f"seed {seed} produced different output than seed 0"
