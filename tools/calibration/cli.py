"""Command surface for the calibration loop."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import CALIBRATION_SCHEMA_VERSION
from .ledger import SEVERITY_WEIGHT, Ledger
from .probes import DEFAULT_PROBES, ProbeContext, registry, run_probe
from .report import render_report, write_run_json

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = REPO_ROOT / "calibration" / "ledger.json"
REPORT_PATH = REPO_ROOT / "calibration" / "REPORT.md"
STATE_DIR = REPO_ROOT / ".leitir-calibration"


def _git_sha() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.decode().strip() or "unknown"
    except OSError:
        return "unknown"


def _git_dirty() -> bool:
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--", "src"], cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout
        return bool(out.strip())
    except OSError:
        return False


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _log(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def cmd_run(args: argparse.Namespace) -> int:
    ledger = Ledger.load(args.ledger)
    probes = registry()
    selected = list(args.probes.split(",")) if args.probes else list(DEFAULT_PROBES)
    if args.with_scorecard and "scorecard" not in selected:
        selected.append("scorecard")
    unknown = [name for name in selected if name not in probes]
    if unknown:
        _log(f"unknown probes: {', '.join(unknown)}; available: {', '.join(probes)}")
        return 2
    if "mutation" in selected and _git_dirty() and not args.allow_dirty:
        _log("src/ has uncommitted changes; the mutation probe rewrites source files in place. Commit/stash first or pass --allow-dirty.")
        return 2
    run_index = len(ledger.data["runs"]) + 1
    seed = args.seed if args.seed is not None else run_index
    started = _now()
    run_id = f"{started.replace(':', '').replace('-', '')}-{run_index:04d}"
    run_dir = args.state_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    git_sha = _git_sha()
    options: dict[str, Any] = {
        "seed": seed,
        "git_sha": git_sha,
        "mutants": args.mutants if args.mutants is not None else (40 if args.quick else 200),
        "mutation_budget": args.mutation_budget if args.mutation_budget is not None else (600 if args.quick else 3600),
        "fuzz_count": args.fuzz_count if args.fuzz_count is not None else (100 if args.quick else 400),
        "fuzz_budget": 30 if args.quick else 120,
        "determinism_count": 40 if args.quick else 120,
        "fuzz_targets": args.fuzz_targets.split(",") if args.fuzz_targets else None,
        "modules": args.modules.split(",") if args.modules else None,
        "update_perf_baseline": args.update_perf_baseline,
        "perf_repeat": 7 if args.quick else 11,
    }
    context = ProbeContext(REPO_ROOT, run_dir, args.state_dir, options, _log, ledger.open_findings())
    _log(f"calibration run {run_id} seed={seed} probes={','.join(selected)} sha={git_sha[:12]}")
    results = [run_probe(name, probes[name], context) for name in selected]
    executed = [result.name for result in results if result.status == "ok"]
    observed = [finding for result in results for finding in result.findings]
    metrics = {result.name: result.metrics for result in results}
    retested = {result.name: result.retested for result in results if result.status == "ok"}
    summary = ledger.record_run(run_id=run_id, started_at=started, git_sha=git_sha, executed_probes=executed, observed=observed, metrics=metrics, retested=retested)
    ledger.save(args.ledger)
    probe_payloads = [result.to_dict() for result in results]
    payload: dict[str, Any] = {"schema_version": CALIBRATION_SCHEMA_VERSION, "summary": summary, "options": options, "probes": probe_payloads}
    write_run_json(run_dir / "run.json", payload)
    report = render_report(ledger, summary, probe_payloads)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    (run_dir / "REPORT.md").write_text(report, encoding="utf-8")
    _log(f"run {run_id}: new={len(summary['new'])} fixed={len(summary['fixed'])} regressed={len(summary['regressed'])} blind-spot index={summary['blind_spot_index']}")
    _log(f"report: {REPORT_PATH}")
    threshold = {"none": 10**9, "critical": SEVERITY_WEIGHT["critical"], "high": SEVERITY_WEIGHT["high"], "any": 0}[args.fail_on]
    worst_new = max((SEVERITY_WEIGHT[ledger.findings[fid]["severity"]] for fid in summary["new"] + summary["regressed"]), default=-1)
    errored = [result.name for result in results if result.status == "error"]
    if errored:
        _log(f"probe errors: {', '.join(errored)}")
    return 1 if worst_new >= threshold and worst_new >= 0 else 0


def cmd_loop(args: argparse.Namespace) -> int:
    """Run repeatedly with fresh seeds until ``--until-stable`` consecutive runs add nothing new."""
    stable = 0
    for iteration in range(args.iterations):
        args.seed = None
        code = cmd_run(args)
        ledger = Ledger.load(args.ledger)
        last = ledger.previous_run() or {}
        added = len(last.get("new", [])) + len(last.get("regressed", []))
        stable = stable + 1 if added == 0 else 0
        _log(f"loop iteration {iteration + 1}/{args.iterations}: {added} new/regressed, stable streak {stable}")
        if stable >= args.until_stable:
            _log(f"converged: {args.until_stable} consecutive runs observed nothing new at the current budget")
            return 0
        del code
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    ledger = Ledger.load(args.ledger)
    counts = ledger.open_by_severity()
    print(f"blind-spot index: {ledger.blind_spot_index()}")
    print("open by severity: " + ", ".join(f"{severity}={count}" for severity, count in counts.items()))
    for run in ledger.data["runs"][-10:]:
        print(f"  {run['run_id']} sha={run['git_sha'][:8]} index={run['blind_spot_index']} new={len(run['new'])} fixed={len(run['fixed'])} regressed={len(run['regressed'])}")
    return 0


def cmd_next(args: argparse.Namespace) -> int:
    """Print the highest-value open findings as ready-to-work tasks (probe -> red test -> fix)."""
    ledger = Ledger.load(args.ledger)
    entries = ledger.open_findings()
    if args.probe:
        entries = [entry for entry in entries if entry["probe"] == args.probe]
    for entry in entries[: args.count]:
        print(f"## {entry['severity']} {entry['id']} — {entry['title']}")
        print(f"probe: {entry['probe']}/{entry['category']}    location: {entry['location']}    seen: {entry['seen_runs']}x")
        if entry.get("reproducer"):
            print(f"reproduce: {entry['reproducer']}")
        evidence = {key: value for key, value in entry.get("evidence", {}).items() if key not in {"identity", "environments"}}
        if evidence:
            print("evidence: " + json.dumps(evidence, sort_keys=True)[:700])
        print("task: probe it with the reproducer, write the failing user-level intent test, make the smallest honest fix, run the suite/ruff/mypy, and re-run `tools/calibrate.py run --probes <probe>` to confirm the ledger marks it fixed.")
        print()
    if not entries:
        print("no open findings")
    return 0


def cmd_issues(args: argparse.Namespace) -> int:
    """File open findings as GitHub issues (idempotent) and comment on issues whose findings are fixed."""
    from .issues import comment_fixed, file_issues

    ledger = Ledger.load(args.ledger)
    last = ledger.previous_run() or {}
    run_id = str(last.get("run_id", "unknown"))
    records = file_issues(ledger, run_id=run_id, min_severity=args.min_severity, limit=args.limit, dry_run=args.dry_run, log=_log)
    commented = 0 if args.dry_run else comment_fixed(ledger, run_id=run_id, log=_log)
    if not args.dry_run:
        ledger.save(args.ledger)
    for record in records:
        number = f"#{record['number']}" if record.get("number") else ""
        print(f"{record['action']:13s} {record['id']} {number} {record.get('title', '')}")
    print(f"{sum(1 for r in records if r['action'] == 'created')} created, {sum(1 for r in records if r['action'] == 'linked')} linked, {commented} fixed-comments")
    return 0


def cmd_disposition(args: argparse.Namespace) -> int:
    ledger = Ledger.load(args.ledger)
    if args.id not in ledger.findings:
        _log(f"unknown finding id {args.id}")
        return 2
    ledger.set_disposition(args.id, args.status, args.note)
    ledger.save(args.ledger)
    print(f"{args.id}: {args.status}")
    return 0


def cmd_mutant(args: argparse.Namespace) -> int:
    from .mutation import TestSelector, apply_mutant, enumerate_mutants, run_mutant

    path = REPO_ROOT / args.path
    mutants = {mutant.id: mutant for mutant in enumerate_mutants(REPO_ROOT, path)}
    mutant = mutants.get(args.id)
    if mutant is None:
        _log(f"mutant {args.id} not found in {args.path} (source may have changed since the run)")
        return 2
    source = path.read_text(encoding="utf-8")
    mutated = apply_mutant(source, mutant)
    import difflib

    sys.stdout.write("".join(difflib.unified_diff(source.splitlines(True), mutated.splitlines(True), f"a/{args.path}", f"b/{args.path}", n=2)))
    if args.run:
        selector = TestSelector.build(REPO_ROOT, STATE_DIR / "coverage-contexts.json")
        tests, mode = selector.select(mutant)
        if not tests:
            print("no tests cover this line")
            return 0
        outcome = run_mutant(REPO_ROOT, mutant, tests, mode, timeout=600)
        print(f"{outcome.outcome} (exit {outcome.exit_code}) against {len(tests)} tests [{mode}]")
        print(outcome.tail[-1200:])
    return 0


def cmd_fuzz_repro(args: argparse.Namespace) -> int:
    import tempfile
    import traceback

    from .fuzz import TARGETS, canon, input_for

    src = str(REPO_ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    target = TARGETS[args.target]
    value = input_for(target, args.seed, args.index)
    print("input:", json.dumps(canon(value), sort_keys=True, indent=1))
    with tempfile.TemporaryDirectory() as tmp:
        try:
            output = target.run(value, Path(tmp))
        except Exception:
            traceback.print_exc()
            return 1
        print("output:", json.dumps(canon(output), sort_keys=True, indent=1)[:4000])
        for prop in target.properties:
            verdict = prop(value, output, Path(tmp))
            print(f"property {prop.__name__}: {verdict or 'ok'}")
    return 0


def cmd_fuzz_worker(args: argparse.Namespace) -> int:
    from .fuzz import worker_main

    src = str(REPO_ROOT / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    return worker_main(["--target", args.target, "--seed", str(args.seed), "--count", str(args.count)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="calibrate", description="Leitir self-calibration loop")
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_run_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--probes", help="comma-separated probe names (default: " + ",".join(DEFAULT_PROBES) + ")")
        p.add_argument("--quick", action="store_true", help="small budgets for a fast smoke calibration")
        p.add_argument("--seed", type=int, help="fuzz/mutation sampling seed (default: run number)")
        p.add_argument("--mutants", type=int, help="mutants to sample")
        p.add_argument("--mutation-budget", type=float, help="seconds for the mutation probe")
        p.add_argument("--fuzz-count", type=int, help="inputs per fuzz target")
        p.add_argument("--fuzz-targets", help="comma-separated fuzz target names")
        p.add_argument("--modules", help="comma-separated leitir modules to mutate (e.g. spec,treehash)")
        p.add_argument("--with-scorecard", action="store_true", help="also run the ADR-002 offline scorecard (slow)")
        p.add_argument("--update-perf-baseline", action="store_true")
        p.add_argument("--allow-dirty", action="store_true", help="mutate even with uncommitted src/ changes")
        p.add_argument("--fail-on", choices=("none", "critical", "high", "any"), default="high", help="exit 1 when a NEW or regressed finding of at least this severity appears")

    run = sub.add_parser("run", help="execute probes once and update the ledger")
    add_run_options(run)
    run.set_defaults(func=cmd_run)
    loop = sub.add_parser("loop", help="repeat runs with fresh seeds until nothing new appears")
    add_run_options(loop)
    loop.add_argument("--iterations", type=int, default=5)
    loop.add_argument("--until-stable", type=int, default=2)
    loop.set_defaults(func=cmd_loop)
    status = sub.add_parser("status")
    status.set_defaults(func=cmd_status)
    nxt = sub.add_parser("next", help="print the top open findings as agent tasks")
    nxt.add_argument("--count", type=int, default=5)
    nxt.add_argument("--probe")
    nxt.set_defaults(func=cmd_next)
    issues = sub.add_parser("issues", help="file open findings as GitHub issues via gh (idempotent)")
    issues.add_argument("--min-severity", choices=("critical", "high", "medium", "low"), default="high")
    issues.add_argument("--limit", type=int, default=10, help="max new issues per invocation")
    issues.add_argument("--dry-run", action="store_true")
    issues.set_defaults(func=cmd_issues)
    disp = sub.add_parser("disposition", help="mark a finding accepted/equivalent/open")
    disp.add_argument("id")
    disp.add_argument("status", choices=("accepted", "equivalent", "open"))
    disp.add_argument("--note", default="")
    disp.set_defaults(func=cmd_disposition)
    mut = sub.add_parser("mutant", help="show (and optionally run) one mutant by id")
    mut.add_argument("id")
    mut.add_argument("--path", required=True)
    mut.add_argument("--run", action="store_true")
    mut.set_defaults(func=cmd_mutant)
    repro = sub.add_parser("fuzz-repro", help="regenerate one fuzz input and run it")
    repro.add_argument("--target", required=True)
    repro.add_argument("--seed", type=int, required=True)
    repro.add_argument("--index", type=int, required=True)
    repro.set_defaults(func=cmd_fuzz_repro)
    worker = sub.add_parser("fuzz-worker", help=argparse.SUPPRESS)
    worker.add_argument("--target", required=True)
    worker.add_argument("--seed", type=int, required=True)
    worker.add_argument("--count", type=int, required=True)
    worker.set_defaults(func=cmd_fuzz_worker)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))
