"""Command-line boundary for search and local source materialization.

For offline integration tests, the corpus wiring honors
``LEITIR_CODELOAD_BASE_URL``, ``LEITIR_GITHUB_API_BASE_URL``,
``LEITIR_NPM_BASE_URL``, ``LEITIR_PYPI_BASE_URL``, ``LEITIR_CRATES_BASE_URL``, and
``LEITIR_GO_PROXY_BASE_URL``. Production defaults remain the official HTTPS
services.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from enum import IntEnum
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Protocol, TextIO

from .logging import redact
from .spec import CorpusSpec, parse_corpus_spec
from .search import (
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchReport,
    SearchSpec,
)


class ExitCode(IntEnum):
    """Stable process outcomes for automation."""

    SUCCESS = 0
    CORPUS_FAILURE = 1
    MALFORMED_USAGE = 2
    INFRASTRUCTURE_FAILURE = 3


class TreeSourceFactory(Protocol):
    def __call__(self, token: str | None) -> object: ...


class ResolverFactory(Protocol):
    def __call__(self, token: str | None) -> object: ...


class SearcherFactory(Protocol):
    def __call__(self, tree_source: object) -> object: ...


def _github_token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def _parse_predicate(raw: str) -> Predicate:
    parts = raw.split(":", 2)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(
            f"predicate must be kind:value, got {raw!r}"
        )
    kind_str, value = parts[0], parts[1]
    language = parts[2] if len(parts) == 3 else None
    try:
        kind = PredicateKind(kind_str)
    except ValueError:
        valid = ", ".join(k.value for k in PredicateKind)
        raise argparse.ArgumentTypeError(
            f"unknown predicate kind {kind_str!r}; valid kinds: {valid}"
        ) from None
    return Predicate(kind=kind, value=value, language=language)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leitir",
        description="Leitir deterministic code-search kernel",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    search = commands.add_parser("search", help="search a pinned code corpus")
    bench = commands.add_parser(
        "bench",
        help="run the pinned search benchmark",
    )
    bench.add_argument(
        "--manifest",
        default=None,
        help="local manifest or packaged benchmark id (default: search-v1)",
    )

    for command, help_text in (
        ("get", "materialize sources and print their local paths"),
        ("fetch", "materialize sources without printing their paths"),
    ):
        corpus_command = commands.add_parser(command, help=help_text)
        corpus_command.add_argument("specs", nargs="+", metavar="spec")
        roots = corpus_command.add_mutually_exclusive_group()
        roots.add_argument("--root", default=None, help="corpus root directory")
        roots.add_argument(
            "--local",
            action="store_true",
            help="use ./.leitir-refs and ensure it is gitignored",
        )
        corpus_command.add_argument(
            "--cwd",
            default=None,
            help="project directory used for lockfile resolution",
        )
        corpus_command.add_argument(
            "--no-verify",
            action="store_true",
            help="skip Git tree verification and record the source as unverified",
        )

    list_command = commands.add_parser("list", help="list materialized sources")
    list_command.add_argument("--json", action="store_true", dest="as_json")
    remove = commands.add_parser("remove", help="remove a materialized source")
    remove.add_argument("spec")
    clean = commands.add_parser("clean", help="empty the source corpus")
    clean.add_argument("--repos", action="store_true")
    lock = commands.add_parser("lock", help="materialize the project's dependency closure")
    lock.add_argument("--cwd", default=None, help="project directory containing lockfiles")
    lock_roots = lock.add_mutually_exclusive_group()
    lock_roots.add_argument("--root", default=None, help="corpus root directory")
    lock_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    lock.add_argument("--no-verify", action="store_true", help="skip Git tree verification")
    sbom = commands.add_parser("sbom", help="emit an SBOM for the materialized corpus")
    sbom.add_argument("--format", choices=("spdx", "cyclonedx"), default="spdx")
    sbom.add_argument("--cwd", default=None, help="project directory containing lockfiles")
    sbom_roots = sbom.add_mutually_exclusive_group()
    sbom_roots.add_argument("--root", default=None, help="corpus root directory")
    sbom_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    api = commands.add_parser("api", help="extract and cache a materialized source API")
    api.add_argument("spec")
    api_roots = api.add_mutually_exclusive_group()
    api_roots.add_argument("--root", default=None, help="corpus root directory")
    api_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    api.set_defaults(cwd=None, no_verify=False)
    examples = commands.add_parser("examples", help="extract and cache materialized source examples")
    examples.add_argument("spec")
    examples_roots = examples.add_mutually_exclusive_group()
    examples_roots.add_argument("--root", default=None, help="corpus root directory")
    examples_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    examples.set_defaults(cwd=None, no_verify=False)
    diff = commands.add_parser("diff", help="diff two resolved source versions")
    diff.add_argument("spec_a")
    diff.add_argument("spec_b")
    diff.add_argument("--json", action="store_true", dest="as_json")
    diff.add_argument("--cwd", default=None, help="project directory used for lockfile resolution")
    diff_roots = diff.add_mutually_exclusive_group()
    diff_roots.add_argument("--root", default=None, help="corpus root directory")
    diff_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    export = commands.add_parser("export", help="export an immutable corpus snapshot")
    export.add_argument("-o", "--output", default="corpus.lock")
    import_command = commands.add_parser("import", help="import an immutable corpus snapshot")
    import_command.add_argument("lock")
    for snapshot_command in (export, import_command):
        snapshot_roots = snapshot_command.add_mutually_exclusive_group()
        snapshot_roots.add_argument("--root", default=None, help="corpus root directory")
        snapshot_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")

    scope_group = search.add_mutually_exclusive_group(required=False)
    scope_group.add_argument(
        "--repo",
        default=None,
        help="repository slug (owner/repo); requires --commit",
    )
    scope_group.add_argument(
        "--package",
        default=None,
        help="package name; requires --version and --ecosystem",
    )
    scope_group.add_argument(
        "--global",
        action="store_true",
        default=False,
        dest="global_search",
        help="global discovery via GitHub Code Search (coverage is indeterminate)",
    )

    search.add_argument("--commit", default=None, help="40-char git SHA")
    search.add_argument("--version", default=None, help="exact package version")
    search.add_argument(
        "--ecosystem",
        default=None,
        choices=("npm", "pypi", "crates", "go"),
        help="package ecosystem",
    )

    search.add_argument(
        "--must",
        type=_parse_predicate,
        action="append",
        default=[],
        dest="must",
        help="required predicate (kind:value[:language])",
    )
    search.add_argument(
        "--should",
        type=_parse_predicate,
        action="append",
        default=[],
        dest="should",
        help="optional boosting predicate (kind:value[:language])",
    )
    search.add_argument(
        "--must-not",
        type=_parse_predicate,
        action="append",
        default=[],
        dest="must_not",
        help="exclusion predicate (kind:value[:language])",
    )

    return parser


def _validate_scope_args(args: argparse.Namespace) -> str | None:
    if args.global_search:
        return None
    if args.repo is not None:
        if args.commit is None:
            return "--repo requires --commit"
        return None
    if args.package is not None:
        if args.version is None:
            return "--package requires --version"
        if args.ecosystem is None:
            return "--package requires --ecosystem"
        return None
    return "one of --repo, --package, or --global is required"


def _build_default_tree_source(token: str | None) -> object:
    from .tree import GitHubTreeSource

    return GitHubTreeSource(token=token)


def _build_default_resolver(token: str | None) -> object:
    from .resolver import (
        CratesResolver,
        BitbucketResolver,
        GitHubTagResolver,
        GitLabResolver,
        GoResolver,
        MultiResolver,
        NpmResolver,
        PyPIResolver,
    )

    tag_options = {}
    github_api = os.environ.get("LEITIR_GITHUB_API_BASE_URL")
    if github_api:
        tag_options["base_url"] = github_api
    tag_resolver = GitHubTagResolver(token=token, **tag_options)
    pypi_options = {}
    npm_options = {}
    crates_options = {}
    go_options = {}
    if os.environ.get("LEITIR_PYPI_BASE_URL"):
        pypi_options["base_url"] = os.environ["LEITIR_PYPI_BASE_URL"]
    if os.environ.get("LEITIR_NPM_BASE_URL"):
        npm_options["base_url"] = os.environ["LEITIR_NPM_BASE_URL"]
    if os.environ.get("LEITIR_CRATES_BASE_URL"):
        crates_options["base_url"] = os.environ["LEITIR_CRATES_BASE_URL"]
    if os.environ.get("LEITIR_GO_PROXY_BASE_URL"):
        go_options["base_url"] = os.environ["LEITIR_GO_PROXY_BASE_URL"]
    return MultiResolver(
        pypi=PyPIResolver(tag_resolver, **pypi_options),
        crates=CratesResolver(tag_resolver, **crates_options),
        go=GoResolver(tag_resolver, **go_options),
        npm=NpmResolver(tag_resolver, **npm_options),
        gitlab=GitLabResolver(),
        bitbucket=BitbucketResolver(),
    )


def _build_default_searcher(tree_source: object) -> object:
    from .adapters import GoAdapter, PythonAdapter, RustAdapter
    from .engine import ScopedSearcher

    return ScopedSearcher(
        tree_source=tree_source,
        adapters=(PythonAdapter(), RustAdapter(), GoAdapter()),
    )


def _build_default_benchmark_runner(searcher: object) -> object:
    from .bench import BenchmarkRunner

    return BenchmarkRunner(searcher)


def _load_benchmark_manifest(path: str | None) -> object:
    from .bench import load_manifest

    return load_manifest(path)


def _build_default_global_searcher(
    code_search: object, tree_source: object
) -> object:
    from .adapters import GoAdapter, PythonAdapter, RustAdapter
    from .discovery_search import GlobalSearcher

    return GlobalSearcher(
        code_search=code_search,
        tree_source=tree_source,
        adapters=(PythonAdapter(), RustAdapter(), GoAdapter()),
        head_resolver=code_search.resolve_head_sha,
        blob_reader=code_search.read_blob_by_path,
    )


def _build_default_code_search(token: str | None) -> object:
    from .discovery_search import GitHubCodeSearchTransport

    options = {}
    github_api = os.environ.get("LEITIR_GITHUB_API_BASE_URL")
    if github_api:
        options["base_url"] = github_api
    return GitHubCodeSearchTransport(token=token, **options)


def _ensure_local_gitignore(cwd: Path) -> str:
    gitignore = cwd / ".gitignore"
    line = ".leitir-refs/"
    try:
        existing = gitignore.read_text(encoding="utf-8")
    except FileNotFoundError:
        gitignore.write_text(line + "\n", encoding="utf-8")
        return f"created {gitignore} with {line}"
    rules = {item.strip() for item in existing.splitlines() if item.strip() and not item.lstrip().startswith("#")}
    if rules.intersection({line, ".leitir-refs", "/.leitir-refs/", "/.leitir-refs", ".leitir-refs/**"}):
        return f"{gitignore} already covers {line}"
    separator = "" if not existing or existing.endswith("\n") else "\n"
    with gitignore.open("a", encoding="utf-8") as handle:
        handle.write(separator + line + "\n")
    return f"appended {line} to {gitignore}"


def _corpus_root(args: argparse.Namespace, err: TextIO) -> Path:
    from .corpus import resolve_root

    if getattr(args, "local", False):
        cwd = Path.cwd()
        print(f"leitir: {_ensure_local_gitignore(cwd)}", file=err)
        return (cwd / ".leitir-refs").absolute()
    return resolve_root(getattr(args, "root", None))


def _resolve_corpus_spec(
    parsed: CorpusSpec, resolver: object, heads: object, cwd: Path
) -> tuple[object, str | None, str | None, str | None]:
    from .resolver import resolve_corpus_spec

    return resolve_corpus_spec(parsed, resolver, heads, cwd)


def _write_diff_human(report: object, out: TextIO) -> None:
    for heading, values in (
        ("Added files", report.files.added),
        ("Removed files", report.files.removed),
        ("Modified files", report.files.modified),
    ):
        print(f"{heading} ({len(values)}):", file=out)
        for value in values:
            print(f"  {value}", file=out)
    for heading, values in (
        ("Added symbols", report.api.added),
        ("Removed symbols", report.api.removed),
    ):
        print(f"{heading} ({len(values)}):", file=out)
        for value in values:
            print(f"  {value['qualified_name']}", file=out)
    print(f"Changed signatures ({len(report.api.changed)}):", file=out)
    for value in report.api.changed:
        print(f"  {value.qualified_name}: {value.before} -> {value.after}", file=out)
    if report.release_notes:
        print(f"Release notes ({len(report.release_notes)}):", file=out)
        for note in report.release_notes:
            print(f"  {note.tag}: {note.url}", file=out)
            print(note.body, file=out)


def _corpus_list(root: Path, *, as_json: bool, out: TextIO) -> None:
    from .corpus import load_sources
    from .materialize import MANIFEST_NAME

    entries = load_sources(root)
    rendered = []
    for entry in entries:
        version = None
        verification = "unverified"
        try:
            manifest = json.loads((root / entry["path"] / MANIFEST_NAME).read_text(encoding="utf-8"))
            version = manifest.get("version")
            if manifest.get("verified") is True:
                verification = "verified"
            elif manifest.get("verified") == "sampled":
                verification = "sampled"
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            pass
        rendered.append((entry, version, verification))
    if as_json:
        payload = [dict(entry, verification=verification) for entry, _, verification in rendered]
        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
        return
    for entry, version, verification in rendered:
        version_text = f" {version}" if version else ""
        path = (root / entry["path"]).absolute()
        print(
            f"{entry['name']}{version_text} {entry['owner']}/{entry['repo']}@{entry['commit_sha']} "
            f"{verification} {path} {entry['fetched_at']}",
            file=out,
        )


def _run_corpus_command(
    args: argparse.Namespace,
    *,
    resolver_factory: Callable[[str | None], object],
    code_search_factory: Callable[[str | None], object],
    out: TextIO,
    err: TextIO,
) -> int:
    from .corpus import INDEX_NAME, materialize_source, remove_source
    from .docpointers import POINTERS_NAME
    from .materialize import MANIFEST_NAME

    try:
        root = _corpus_root(args, err)
        if args.command == "list":
            _corpus_list(root, as_json=args.as_json, out=out)
            return int(ExitCode.SUCCESS)
        if args.command == "diff":
            from .diff import GitHubReleaseNotes, diff_packages

            token = _github_token()
            resolver = resolver_factory(token)
            heads = code_search_factory(token)
            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            fetch_options: dict[str, object] = {}
            if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                fetch_options["tree_base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
            notes_options = {}
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                notes_options["base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
            report = diff_packages(
                args.spec_a,
                args.spec_b,
                corpus_root=root,
                resolver=resolver,
                heads=heads,
                cwd=cwd,
                release_notes=GitHubReleaseNotes(token, **notes_options),
                fetch_options=fetch_options,
                on_resolve=lambda spec: print(f"leitir: resolving {spec} (cwd={cwd})", file=err),
                on_materialize=lambda spec: print(f"leitir: materializing {spec}", file=err),
            )
            if args.as_json:
                print(report.to_json(), file=out)
            else:
                _write_diff_human(report, out)
            return int(ExitCode.SUCCESS)
        if args.command == "remove":
            parsed = parse_corpus_spec(args.spec)
            if parsed.ecosystem is None and parsed.ref_kind == "head":
                owner, repo = parsed.name.split("/", 1)
                sha = None
            else:
                token = _github_token()
                resolver = resolver_factory(token)
                heads = code_search_factory(token)
                resolved, _, _, _ = _resolve_corpus_spec(parsed, resolver, heads, Path.cwd())
                scope = resolved.scope if hasattr(resolved, "scope") else resolved
                owner, repo = scope.slug.split("/", 1)
                sha = scope.commit_sha
            removed = remove_source(
                root, owner, repo, sha, host=parsed.host or "github.com"
            )
            print(f"leitir: {'removed' if removed else 'not found'} {args.spec}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "clean":
            shutil.rmtree(root / "repos", ignore_errors=True)
            shutil.rmtree(root / "api", ignore_errors=True)
            shutil.rmtree(root / "examples", ignore_errors=True)
            (root / INDEX_NAME).unlink(missing_ok=True)
            (root / POINTERS_NAME).unlink(missing_ok=True)
            print(f"leitir: cleaned {root}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "export":
            from .snapshot import export_corpus

            lock_path, tarball_path = export_corpus(args.output, root=root)
            print(json.dumps({"lock": str(lock_path), "tarball": str(tarball_path)}, sort_keys=True), file=out)
            print(f"leitir: exported {lock_path}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "import":
            from .snapshot import import_corpus

            entries = import_corpus(args.lock, root=root)
            print(json.dumps({"root": str(root), "sources": len(entries)}, sort_keys=True), file=out)
            print(f"leitir: imported {len(entries)} source(s) into {root}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "sbom":
            from .sbom import generate_sbom

            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            document = generate_sbom(root, cwd, args.format)
            print(json.dumps(document, indent=2, sort_keys=True), file=out)
            print(f"leitir: generated {args.format} SBOM from {root}", file=err)
            return int(ExitCode.SUCCESS)

        token = _github_token()
        resolver = resolver_factory(token)
        if args.command == "lock":
            from .corpus import lock_project

            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            fetch_options = {"verify": not args.no_verify}
            if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                fetch_options["tree_base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
            summary = lock_project(
                cwd,
                resolver,
                root=root,
                on_resolve=lambda spec: print(f"leitir: resolving {spec}", file=err),
                on_fetch=lambda spec: print(f"leitir: materializing {spec}", file=err),
                **fetch_options,
            )
            print(json.dumps({"cwd": str(cwd), "dependencies": summary}, sort_keys=True), file=out)
            return int(ExitCode.SUCCESS)
        heads = code_search_factory(token)
        cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
        paths: list[tuple[Path, str | None]] = []
        fetch_options = {}
        if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
            fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
        fetch_options["verify"] = not args.no_verify
        if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
            fetch_options["tree_base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
        raw_specs = args.specs if hasattr(args, "specs") else [args.spec]
        index_paths: list[Path] = []
        for raw in raw_specs:
            print(f"leitir: resolving {raw} (cwd={cwd})", file=err)
            parsed = parse_corpus_spec(raw)
            resolved, tag, version_source, detection_source = _resolve_corpus_spec(
                parsed, resolver, heads, cwd
            )
            if version_source == "lockfile":
                print(
                    f"leitir: {parsed.name}: version {resolved.ref.version} from {detection_source}",
                    file=err,
                )
            path = materialize_source(
                raw,
                resolved,
                root=root,
                name=parsed.name,
                tag=tag,
                version_source=version_source,
                host=(parsed.host or "github.com")
                if parsed.ecosystem is None
                else "github.com",
                repository_resolver=(
                    getattr(resolver, "_repository_resolvers", {}).get(parsed.host)
                    if parsed.ecosystem is None and parsed.host not in (None, "github.com")
                    else None
                ),
                on_fetch=lambda raw=raw: print(
                    f"leitir: materializing {raw}", file=err
                ),
                **fetch_options,
            )
            manifest = json.loads((path / MANIFEST_NAME).read_text(encoding="utf-8"))
            if args.command in {"api", "examples"}:
                from .apisurface import extract_api_surface
                from .corpus import load_sources, read_api_index, write_api_index

                entry = next(
                    entry
                    for entry in load_sources(root)
                    if (root / entry["path"]).absolute() == path.absolute()
                )
                recorded_subpath = manifest.get("subpath")
                scan_path = path / recorded_subpath if isinstance(recorded_subpath, str) else path
                language_hint = manifest.get("ecosystem")
                index = read_api_index(root, entry, manifest)
                if index is None or args.command == "api":
                    print(f"leitir: extracting API surface for {raw}", file=err)
                    index = extract_api_surface(
                        scan_path,
                        str(language_hint) if language_hint in {"pypi", "npm"} else None,
                    )
                    api_path = write_api_index(root, entry, manifest, index)
                else:
                    from .corpus import api_index_path

                    api_path = api_index_path(root, entry, manifest).absolute()
                if args.command == "api":
                    index_paths.append(api_path)
                else:
                    from .corpus import write_examples_index
                    from .docpointers import regenerate_pointers
                    from .examples import extract_examples

                    print(f"leitir: extracting examples for {raw}", file=err)
                    examples_index = extract_examples(path, index)
                    index_paths.append(write_examples_index(root, entry, manifest, examples_index))
                    regenerate_pointers(root)
                continue
            recorded_subpath = manifest.get("subpath")
            subpath = recorded_subpath if isinstance(recorded_subpath, str) else None
            paths.append((path.absolute(), subpath))
        if args.command in {"api", "examples"}:
            if args.command == "api":
                from .docpointers import regenerate_pointers

                regenerate_pointers(root)
            for index_path in index_paths:
                print(index_path, file=out)
        elif args.command == "get":
            for path, subpath in paths:
                if subpath is None:
                    print(path, file=out)
                    continue
                package_path = path / subpath
                inside_target = package_path.resolve().is_relative_to(path.resolve())
                if inside_target and package_path.exists():
                    print(package_path, file=out)
                else:
                    print(path, file=out)
                    print(
                        f"leitir: warning: recorded subpath {subpath!r} does not exist "
                        f"inside {path}; using repository root",
                        file=err,
                    )
        return int(ExitCode.SUCCESS)
    except Exception as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.CORPUS_FAILURE)


def _resolve_scope_via_package(
    resolver: object,
    package: str,
    version: str,
    ecosystem: str,
) -> RepoScope:
    from .resolver import Ecosystem, PackageRef

    ref = PackageRef(
        ecosystem=Ecosystem(ecosystem),
        name=package,
        version=version,
    )
    resolved = resolver.resolve(ref)
    return resolved.scope


def _write_summary(report: SearchReport, *, file: TextIO) -> None:
    cov = report.coverage
    print(
        f"coverage={cov.status.value} "
        f"eligible={cov.files_eligible} "
        f"indexed={cov.files_indexed} "
        f"excluded={cov.files_excluded} "
        f"matches={len(report.matches)}",
        file=file,
    )
    for match in report.matches[:10]:
        src = match.source
        kinds = ",".join(k.value for k in match.matched_kinds)
        print(
            f"  {src.path}:{src.start_line}-{src.end_line} "
            f"score={match.score:.1f} [{kinds}] "
            f"{src.slug}@{src.commit_sha[:12]}",
            file=file,
        )
    if len(report.matches) > 10:
        print(f"  ... and {len(report.matches) - 10} more", file=file)


def main(
    argv: Sequence[str] | None = None,
    *,
    tree_source_factory: Callable[[str | None], object] = _build_default_tree_source,
    resolver_factory: Callable[[str | None], object] = _build_default_resolver,
    searcher_factory: Callable[[object], object] = _build_default_searcher,
    code_search_factory: Callable[[str | None], object] = _build_default_code_search,
    global_searcher_factory: Callable[[object, object], object] = _build_default_global_searcher,
    benchmark_runner_factory: Callable[[object], object] = _build_default_benchmark_runner,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Parse one command and wire resolver -> engine -> report."""

    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    if args.command == "bench":
        token = _github_token()
        try:
            manifest = _load_benchmark_manifest(args.manifest)
            from .corpus_bench import CorpusBenchmarkManifest, CorpusBenchmarkRunner

            if isinstance(manifest, CorpusBenchmarkManifest):
                runner = CorpusBenchmarkRunner(
                    resolver_factory(token), code_search_factory(token), token
                )
            else:
                tree_source = tree_source_factory(token)
                searcher = searcher_factory(tree_source)
                runner = benchmark_runner_factory(searcher)
            run = runner.run(manifest)
        except Exception as exc:
            print(f"leitir: error: {redact(str(exc))}", file=err)
            return int(ExitCode.INFRASTRUCTURE_FAILURE)

        print(run.to_json(), file=out)
        result_count = sum(len(task.results) for task in run.tasks)
        print(
            f"benchmark={run.benchmark_id} "
            f"tasks={len(run.tasks)} results={result_count} "
            f"artifact_sha256={run.digest()}",
            file=err,
        )
        return int(ExitCode.SUCCESS)

    if args.command in {"get", "fetch", "list", "remove", "clean", "lock", "export", "import", "sbom", "api", "examples", "diff"}:
        return _run_corpus_command(
            args,
            resolver_factory=resolver_factory,
            code_search_factory=code_search_factory,
            out=out,
            err=err,
        )

    scope_error = _validate_scope_args(args)
    if scope_error:
        print(f"leitir: error: {scope_error}", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    if not args.must:
        print("leitir: error: at least one --must predicate is required", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    token = _github_token()

    try:
        if args.global_search:
            spec = SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=tuple(args.must),
                should=tuple(args.should),
                must_not=tuple(args.must_not),
            )
            code_search = code_search_factory(token)
            tree_source = tree_source_factory(token)
            searcher = global_searcher_factory(code_search, tree_source)
            report = searcher.search(spec)
        else:
            if args.repo is not None:
                scope = RepoScope(slug=args.repo, commit_sha=args.commit)
            else:
                resolver = resolver_factory(token)
                scope = _resolve_scope_via_package(
                    resolver, args.package, args.version, args.ecosystem
                )

            spec = SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=tuple(args.must),
                should=tuple(args.should),
                must_not=tuple(args.must_not),
                scopes=(scope,),
            )

            tree_source = tree_source_factory(token)
            searcher = searcher_factory(tree_source)
            report = searcher.search(spec)
    except Exception as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.INFRASTRUCTURE_FAILURE)

    print(report.to_json(), file=out)
    _write_summary(report, file=err)
    return int(ExitCode.SUCCESS)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ExitCode",
    "build_parser",
    "main",
]
