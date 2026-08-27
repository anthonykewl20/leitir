"""The BTS/analysis/exit-gate/usage verb group: parsers and dispatch (#271).

Covers ``bts-compute``, ``bts-run``, ``bts-funnel``, ``analysis-architecture``,
``analysis-lineage``, ``exit-gate-validate``, ``exit-gate-run``,
``occupied-validate``, and ``usage`` -- one shared dispatcher in the pre-#271
``leitir.cli`` implementation, moved here verbatim. Purely structural: no
behavior, flag, or output change.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TextIO

from .cli_support import ExitCode, _corpus_root, _require_authenticated_manifest, _write_cli_payload, mark_successful
from .logging import redact


def register_bts_compute(commands: argparse._SubParsersAction) -> None:
    bts_compute = commands.add_parser(
        "bts-compute",
        help="compute a Behavioral Transplant Set from an exact verified shelf",
    )
    bts_compute.add_argument(
        "spec", type=_parse_bts_compute_spec, metavar="owner/repo@commit"
    )
    bts_roots = bts_compute.add_mutually_exclusive_group()
    bts_roots.add_argument("--root", default=None, help="corpus root directory")
    bts_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    bts_compute.add_argument(
        "--language",
        choices=("python", "javascript", "typescript", "rust", "go"),
        default="python",
    )
    bts_compute.add_argument(
        "--lock",
        default="requirements-tree-sitter.lock",
        help="tree-sitter requirements lock (resolved from the current directory)",
    )
    bts_compute.add_argument(
        "--policy",
        default=None,
        help="closed-schema BTS resolution policy JSON; without it the pinned empty policy is used, so COMPLETE typically requires policy coverage for stdlib or external usage",
    )
    bts_compute.add_argument("--seed-module")
    bts_compute.add_argument("--seed-name")
    bts_compute.add_argument("--out", help="empty artifact output directory")
    bts_compute.add_argument("--list-seeds", action="store_true", help="list selectable donor definition seeds without computing a BTS")
    bts_compute.add_argument("--allow-reject", action="store_true", help="return success after writing a REJECT BTS result")
    bts_compute.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on the donor shelf before computing",
    )
    bts_compute.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    bts_compute.add_argument("--json", action="store_true", dest="as_json")


def register_architecture(commands: argparse._SubParsersAction) -> None:
    architecture = commands.add_parser(
        "analysis-architecture",
        help="assess a canonical graph artifact for architecture compatibility",
    )
    architecture.add_argument("graph", metavar="graph.json")
    architecture.add_argument("--subject", required=True, type=_analysis_subject)
    architecture.add_argument("--catalog", default=None)
    architecture.add_argument(
        "--declared-concurrency",
        choices=("sync", "async", "mixed", "unknown"),
        default=None,
    )
    architecture.add_argument("--json", action="store_true", dest="as_json")


def register_lineage(commands: argparse._SubParsersAction) -> None:
    lineage = commands.add_parser(
        "analysis-lineage", help="validate a canonical lineage manifest"
    )
    lineage.add_argument("manifest", metavar="manifest.json")
    lineage.add_argument("--json", action="store_true", dest="as_json")


def register_exit_gate_validate(commands: argparse._SubParsersAction) -> None:
    exit_gate = commands.add_parser(
        "exit-gate-validate", help="validate pinned exit-corpus manifest evidence"
    )
    exit_gate.add_argument("corpus", metavar="corpus.json")
    exit_gate.add_argument("--json", action="store_true", dest="as_json")


def register_funnel(commands: argparse._SubParsersAction) -> None:
    funnel = commands.add_parser(
        "bts-funnel", help="run the recorded capability-to-candidate BTS funnel"
    )
    funnel.add_argument("--spec", required=True, help="canonical capability spec JSON")
    funnel.add_argument(
        "--recipient-manifest", required=True, help="closed recipient input manifest JSON"
    )
    funnel.add_argument("--stages", required=True, help="recorded discovery stages JSON")
    funnel.add_argument("--json", action="store_true", dest="as_json")


def register_bts_run(commands: argparse._SubParsersAction) -> None:
    bts_run = commands.add_parser(
        "bts-run", help="run the contained Python BTS pipeline from a verified shelf"
    )
    bts_run.add_argument("spec", type=_parse_bts_compute_spec, metavar="owner/repo@commit")
    bts_run_roots = bts_run.add_mutually_exclusive_group()
    bts_run_roots.add_argument("--root", default=None, help="corpus root directory")
    bts_run_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    bts_run.add_argument("--seed-module", required=True)
    bts_run.add_argument("--seed-name", required=True)
    bts_run.add_argument("--policy", default=None, help="closed-schema BTS resolution policy JSON")
    bts_run.add_argument("--contract-spec", required=True, help="contract-tests JSON")
    bts_run.add_argument("--out", required=True, help="empty artifact output directory")
    bts_run.add_argument("--recipient-package", required=True)
    bts_run.add_argument(
        "--nsjail-sha256", default=None,
        help="measured sha256:<hex> of /usr/bin/nsjail (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--nsjail-version", default=None,
        help="nsjail@<commit> build identity (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--nsjail-build-identity", default=None,
        help="derived nsjail release/build identity digest (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--config-schema-digest", default=None,
        help="pinned containment config schema digest (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--rootfs-source", default=None,
        help="local containment-rootfs-v1 materialization directory (default: $LEITIR_ROOTFS_SOURCE or ~/.leitir/containment-rootfs-v1)",
    )
    bts_run.add_argument(
        "--rootfs-digest", default=None,
        help="canonical sha256:<hex> tree digest of --rootfs-source (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--containment-environment", default=None, metavar="ENVIRONMENT.json",
        help=(
            "committed, self-verified containment environment descriptor used to resolve any of the five "
            "containment-substrate flags left unset (default: installed package directory); "
            "an explicit flag always overrides the descriptor for that field"
        ),
    )
    bts_run.add_argument("--emit-packets", default=None, metavar="PACKET_INPUTS.json")
    bts_run.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on the donor shelf before running the pipeline",
    )
    bts_run.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    bts_run.add_argument("--json", action="store_true", dest="as_json")


def register_exit_gate_run(commands: argparse._SubParsersAction) -> None:
    exit_run = commands.add_parser(
        "exit-gate-run",
        help="run a v1.1 runnable exit corpus under measured containment; phase A publishes corpus_manifest_digest, phase C requires its out-of-band ratified_runtime_digest",
    )
    exit_run.add_argument("corpus", metavar="corpus-v1.1.json")
    exit_run.add_argument("--corpus-root", required=True, help="root containing committed contract tests")
    exit_run.add_argument(
        "--donors-dir", default=None,
        help="root containing verified donor shelves and baseline sidecars (default: --corpus-root)",
    )
    exit_run.add_argument("--out", default=None, help="gate-report output directory")
    exit_run.add_argument("--substrate-nsjail-sha", required=True, help="measured sha256:<hex> of /usr/bin/nsjail")
    exit_run.add_argument("--substrate-rootfs-digest", required=True, help="measured sha256:<hex> canonical rootfs tree digest")
    exit_run.add_argument("--nsjail-version", required=True)
    exit_run.add_argument("--nsjail-build-identity", required=True)
    exit_run.add_argument("--config-schema-digest", required=True)
    exit_run.add_argument("--rootfs-source", required=True)
    exit_run.add_argument("--trusted-keys", default=None, help="out-of-band trusted-keys.json required when ratified_runtime_digest is set")
    exit_run.add_argument("--ratification-sidecar", default=None, help="detached Ed25519 ratification record (default: corpus directory/ratification-v1.json)")
    exit_run.add_argument("--json", action="store_true", dest="as_json")


def register_occupied_validate(commands: argparse._SubParsersAction) -> None:
    occupied_validate = commands.add_parser(
        "occupied-validate", help="validate a canonical occupied-recipient attachment artifact"
    )
    occupied_validate.add_argument("artifact", metavar="artifact.json")
    occupied_validate.add_argument("--json", action="store_true", dest="as_json")


def register_usage(commands: argparse._SubParsersAction) -> None:
    usage_cmd = commands.add_parser(
        "usage",
        help="assemble, verify, or replay a local usage evidence bundle (fully offline)",
    )
    usage_cmd.add_argument(
        "action",
        choices=["assemble", "verify", "replay"],
        help=(
            "assemble: build report.json (to --out) from an assemble-plan.json by calling "
            "assemble_usage_evidence, self-verifying the produced report before it is written; "
            "verify: parse/validate report.json; "
            "replay: also recompute digests against on-disk corpus bytes and confirm each "
            "reference's recorded span (not the whole source file) is byte-identical to what "
            "is on disk"
        ),
    )
    usage_cmd.add_argument("report", metavar="report.json", help="report.json for verify/replay; assemble-plan.json for assemble")
    usage_cmd.add_argument(
        "--corpus-root", default=None,
        help=(
            "consumer source root the report's references resolve against (required for replay; "
            "optional for assemble, where it backs the advisory per-file license scan)"
        ),
    )
    usage_cmd.add_argument(
        "--requirements", default=None,
        help="requirements.txt path backing the report's dependency evidence (required for replay)",
    )
    usage_cmd.add_argument(
        "--times", type=int, default=2,
        help="number of independent replay passes to compare for byte-identical output (replay only, default: 2)",
    )
    usage_cmd.add_argument(
        "--out", default=None,
        help="output path for the assembled report.json (required for assemble)",
    )
    usage_cmd.add_argument("--json", action="store_true", dest="as_json")

def _parse_bts_compute_spec(raw: str) -> tuple[str, str, str]:
    """Parse the exact ``owner/repo@commit`` shelf identity used by BTS."""

    try:
        slug, commit_sha = raw.rsplit("@", 1)
        owner, repo = slug.split("/", 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "BTS spec must be owner/repo@40-character-lowercase-commit-sha"
        ) from exc
    if (
        not owner
        or not repo
        or "@" in owner
        or "@" in repo
        or "/" in repo
        or len(commit_sha) != 40
        or any(character not in "0123456789abcdef" for character in commit_sha)
    ):
        raise argparse.ArgumentTypeError(
            "BTS spec must be owner/repo@40-character-lowercase-commit-sha"
        )
    return owner, repo, commit_sha


def _analysis_subject(raw: str) -> str:
    """Accept a bounded caller-declared analysis label, never a free-form claim."""

    if not raw or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in raw):
        raise argparse.ArgumentTypeError(
            "architecture subject must contain only letters, digits, '-', '_', or '.'"
        )
    return raw


def root_for_bts(args: argparse.Namespace) -> Path:
    """Resolve the corpus root for the BTS commands (no gitignore side talk)."""

    from .corpus import resolve_root

    if getattr(args, "local", False):
        return (Path.cwd() / ".leitir-refs").absolute()
    return resolve_root(getattr(args, "root", None))


def _require_bts_shelf_authenticated(
    root: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    args: argparse.Namespace,
    *,
    err: TextIO,
) -> None:
    """Fail closed unless the BTS donor shelf carries a valid signature."""

    from .materialize import read_valid_manifest, target_path

    target = target_path(root, owner, repo, commit_sha)
    manifest = read_valid_manifest(target, owner, repo, commit_sha)
    if manifest is None:
        raise ValueError(
            f"materialized source failed load-time verification: {target}"
        )
    _require_authenticated_manifest(
        manifest,
        target,
        trusted_keys=getattr(args, "trusted_keys", None),
        err=err,
    )


def _write_bts_error(exc: Exception, *, as_json: bool, err: TextIO) -> None:
    if as_json:
        from .bts_errors import BTSError
        from .usage import UsageError

        if isinstance(exc, BTSError):
            print(f"leitir: error: {exc.to_json().strip()}", file=err)
            return
        if isinstance(exc, UsageError):
            print(f"leitir: error: {json.dumps(exc.to_json(), sort_keys=True)}", file=err)
            return
    print(f"leitir: error: {redact(str(exc))}", file=err)
def run(args: argparse.Namespace, *, out: TextIO, err: TextIO) -> int:
    try:
        if args.command in {"bts-compute", "bts-run"} and getattr(
            args, "require_manifest_auth", False
        ):
            owner, repo, commit_sha = args.spec
            _require_bts_shelf_authenticated(root_for_bts(args), owner, repo, commit_sha, args, err=err)
        if args.command == "bts-compute":
            from .bts import BTSStatus
            from .bts_cli import SeedSelector, list_bts_seeds, run_bts_compute, write_artifacts

            owner, repo, commit_sha = args.spec
            if args.list_seeds:
                if args.seed_module is not None or args.seed_name is not None or args.out is not None:
                    raise ValueError("--list-seeds cannot be combined with --seed-module, --seed-name, or --out")
                seeds = list_bts_seeds(
                    _corpus_root(args, err), owner, repo, commit_sha,
                    language=args.language, lock_path=Path(args.lock).expanduser().absolute(),
                )
                _write_cli_payload({"schema_version": "leitir-bts-seed-list-v1", "seeds": [{"module": seed.module, "qualified_name": seed.qualified_name, "kind": seed.kind.value, "origin": seed.origin.value} for seed in seeds]}, as_json=True, out=out)
                return mark_successful()
            if args.seed_module is None or args.seed_name is None or args.out is None:
                raise ValueError("bts-compute requires --seed-module, --seed-name, and --out unless --list-seeds is used")
            artifacts = run_bts_compute(
                _corpus_root(args, err),
                owner,
                repo,
                commit_sha,
                language=args.language,
                lock_path=Path(args.lock).expanduser().absolute(),
                policy_path=None if args.policy is None else Path(args.policy).expanduser().absolute(),
                seed=SeedSelector(args.seed_module, args.seed_name),
            )
            output_directory = Path(args.out).expanduser().absolute()
            write_artifacts(artifacts, output_directory)
            if args.as_json:
                _write_cli_payload(artifacts.summary, as_json=True, out=out)
            else:
                _write_cli_payload(artifacts.summary, as_json=False, out=err)
                print(
                    f"leitir: wrote BTS artifacts to {output_directory}", file=err
                )
            if artifacts.result.status is BTSStatus.REJECT and not args.allow_reject:
                return int(ExitCode.CORPUS_FAILURE)
        elif args.command == "bts-funnel":
            from .funnel_cli import run_funnel

            payload = run_funnel(
                Path(args.spec), Path(args.recipient_manifest), Path(args.stages)
            )
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        elif args.command == "bts-run":
            from .bts_cli import (
                SeedSelector,
                resolve_containment_substrate,
                write_containment_environment_receipt,
            )
            from .pipeline_cli import run_pipeline

            packet_inputs = None
            if args.emit_packets is not None:
                from .safeio import read_regular_file
                from .transplant import _inputs_from_value, _strict_json

                packet_path = Path(args.emit_packets)
                # The packet parser verifies its embedded digest anchor.
                packet_bytes = read_regular_file(packet_path, maximum_bytes=1 << 20, no_follow=False)
                packet_inputs = _inputs_from_value(_strict_json(packet_bytes))
            owner, repo, commit_sha = args.spec
            # Any of the five containment-substrate flags may be omitted;
            # each unset field resolves independently from the committed,
            # self-verified descriptor (ADR-0009 Amendment 1). An explicit
            # flag always wins for that field. This is a convenience over
            # the runtime containment verification in exec_sandbox, never
            # a substitute for it: the resolved values flow unchanged into
            # the same measured checks an explicit flag goes through today.
            resolved_substrate = resolve_containment_substrate(
                nsjail_sha256=args.nsjail_sha256,
                nsjail_version=args.nsjail_version,
                nsjail_build_identity=args.nsjail_build_identity,
                config_schema_digest=args.config_schema_digest,
                rootfs_source=args.rootfs_source,
                rootfs_digest=args.rootfs_digest,
                descriptor_path=None if args.containment_environment is None else Path(args.containment_environment),
            )
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            # Written before the run so the audit trail of what was
            # resolved and from where survives even a rejected run.
            write_containment_environment_receipt(out_dir, resolved_substrate)
            pipeline_result = run_pipeline(
                _corpus_root(args, err), owner, repo, commit_sha,
                seed=SeedSelector(args.seed_module, args.seed_name),
                contract_tests_path=Path(args.contract_spec),
                out_dir=out_dir,
                recipient_package=args.recipient_package,
                nsjail_sha256=resolved_substrate.nsjail_sha256.value,
                nsjail_version=resolved_substrate.nsjail_version.value,
                nsjail_build_identity=resolved_substrate.nsjail_build_identity.value,
                config_schema_digest=resolved_substrate.config_schema_digest.value,
                rootfs_source=Path(resolved_substrate.rootfs_source.value),
                rootfs_digest=resolved_substrate.rootfs_digest.value,
                policy_path=None if args.policy is None else Path(args.policy),
                emit_packets=packet_inputs,
            )
            payload = {
                "schema_version": "leitir-pipeline-cli-v1",
                "verdict": pipeline_result.verdict.status.value,
                "bts_digest": pipeline_result.verdict.bts_digest,
                "relocation_digest": pipeline_result.verdict.relocation_digest,
                "rerun_report_digest": pipeline_result.verdict.rerun_report_digest,
                "probe_report_digest": pipeline_result.verdict.probe_report_digest,
                "containment_environment_resolution": resolved_substrate.receipt(),
            }
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        elif args.command == "analysis-architecture":
            from .analysis_cli import run_architecture_assessment

            payload = run_architecture_assessment(
                Path(args.graph),
                subject=args.subject,
                catalog_path=Path(args.catalog) if args.catalog is not None else None,
                declared_concurrency=args.declared_concurrency,
            )
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        elif args.command == "analysis-lineage":
            from .analysis_cli import validate_lineage_manifest

            payload = validate_lineage_manifest(Path(args.manifest))
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        elif args.command == "exit-gate-validate":
            from .exit_corpus import (
                cross_check_against_gate,
                validate_corpus_manifest,
            )

            corpus_path = Path(args.corpus)
            payload = {
                "cross_check_against_gate": cross_check_against_gate(corpus_path),
                "validation": validate_corpus_manifest(corpus_path),
            }
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        elif args.command == "exit-gate-run":
            from .pipeline_cli import exit_gate_run

            payload = exit_gate_run(
                Path(args.corpus), Path(args.corpus_root if args.donors_dir is None else args.donors_dir),
                corpus_root=Path(args.corpus_root),
                out_dir=None if args.out is None else Path(args.out),
                nsjail_version=args.nsjail_version,
                nsjail_build_identity=args.nsjail_build_identity,
                config_schema_digest=args.config_schema_digest,
                rootfs_source=Path(args.rootfs_source),
                substrate_nsjail_sha256=args.substrate_nsjail_sha,
                substrate_rootfs_digest=args.substrate_rootfs_digest,
                trusted_keys_path=None if args.trusted_keys is None else Path(args.trusted_keys),
                ratification_sidecar=None if args.ratification_sidecar is None else Path(args.ratification_sidecar),
            )
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        elif args.command == "usage":
            from .usage.cli_support import (
                assemble_payload,
                load_assemble_plan,
                load_report,
                replay_payload,
                verify_payload,
            )

            if args.action == "replay" and (args.corpus_root is None or args.requirements is None):
                print(
                    "leitir: error: usage replay requires --corpus-root and --requirements",
                    file=err,
                )
                return int(ExitCode.MALFORMED_USAGE)
            if args.action == "assemble" and args.out is None:
                print("leitir: error: usage assemble requires --out", file=err)
                return int(ExitCode.MALFORMED_USAGE)
            if args.times < 1:
                print("leitir: error: --times must be >= 1", file=err)
                return int(ExitCode.MALFORMED_USAGE)

            if args.action == "assemble":
                plan = load_assemble_plan(Path(args.report))
                consumer_root = None if args.corpus_root is None else Path(args.corpus_root)
                payload = assemble_payload(plan, consumer_root=consumer_root, out_path=Path(args.out))
                print(
                    f"leitir: usage assemble ok report_digest={payload['report_digest']}",
                    file=err,
                )
            else:
                usage_report = load_report(Path(args.report))
                if args.action == "verify":
                    payload = verify_payload(usage_report)
                else:
                    payload = replay_payload(
                        usage_report,
                        corpus_root=Path(args.corpus_root),
                        dependency_path=Path(args.requirements),
                        times=args.times,
                    )
                print(
                    f"leitir: usage {args.action} ok report_digest={usage_report.report_digest}",
                    file=err,
                )
            _write_cli_payload(payload, as_json=args.as_json, out=out)
        else:
            from .pipeline_cli import occupied_validate
            from .safeio import read_regular_file

            # Occupied artifacts are validated against their digest anchor.
            artifact = read_regular_file(Path(args.artifact), maximum_bytes=1 << 20, no_follow=False)
            payload = occupied_validate(artifact)
            _write_cli_payload(payload, as_json=args.as_json, out=out)
    except Exception as exc:
        _write_bts_error(exc, as_json=args.as_json, err=err)
        return int(ExitCode.CORPUS_FAILURE)
    return mark_successful()

