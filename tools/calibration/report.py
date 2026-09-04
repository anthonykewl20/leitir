"""Render the run JSON and the human-facing REPORT.md."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ledger import SEVERITIES, Ledger


def _table(rows: list[list[str]], header: list[str]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def write_run_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8")


def render_report(ledger: Ledger, run_summary: dict[str, Any], probe_results: list[dict[str, Any]]) -> str:
    metrics = run_summary["metrics"]
    lines: list[str] = []
    lines.append("# Leitir calibration report")
    lines.append("")
    lines.append(f"Run `{run_summary['run_id']}` at {run_summary['started_at']} on `{run_summary['git_sha'][:12]}`. Probes: {', '.join(run_summary['probes'])}.")
    lines.append("")
    lines.append("## Convergence")
    lines.append("")
    history = ledger.data["runs"][-12:]
    rows = [[run["run_id"], run["git_sha"][:8], run["blind_spot_index"], len(run["new"]), len(run["fixed"]), len(run["regressed"])] for run in history]
    lines.append(_table(rows, ["run", "sha", "blind-spot index", "new", "fixed", "regressed"]))
    lines.append("")
    counts = ledger.open_by_severity()
    lines.append("Open findings by severity: " + ", ".join(f"{severity} {counts[severity]}" for severity in SEVERITIES) + f". Blind-spot index **{ledger.blind_spot_index()}** (target 0).")
    lines.append("")
    lines.append("## Measurements")
    lines.append("")
    rows = []
    suite = metrics.get("suite", {})
    if suite:
        rows.append(["suite", f"{suite.get('passed')} passed / {suite.get('failed')} failed / {suite.get('skipped')} skipped in {suite.get('duration_seconds')}s"])
    cov = metrics.get("coverage", {})
    if cov:
        rows.append(["coverage", f"{cov.get('line_percent')}% lines; {cov.get('uncovered_raise_integrity')} untested fail-closed raises in integrity modules"])
    mut = metrics.get("mutation", {})
    if mut and mut.get("kill_rate") is not None:
        lo, hi = mut["kill_rate_wilson95"]
        rows.append(["mutation", f"kill rate {mut['kill_rate']:.1%} (95% CI {lo:.1%} to {hi:.1%}) over {mut['executed']} of {mut['enumerated']} enumerated mutants; {mut['survived']} survived; selection={mut.get('selection_mode')}"])
    fz = metrics.get("fuzz", {})
    if fz:
        worst = max((entry.get("unseen_mass_good_turing", 0.0) for entry in fz.get("targets", {}).values()), default=0.0)
        rows.append(["fuzz", f"{fz.get('inputs')} inputs, {fz.get('failures')} failures; worst Good-Turing unseen mass {worst:.4f}"])
    det = metrics.get("determinism", {})
    if det:
        rows.append(["determinism", f"{det.get('mismatches')} mismatches over {det.get('inputs_compared')} inputs x {det.get('environments')} environments"])
    perf = metrics.get("perf", {})
    if perf:
        rows.append(["perf", f"{perf.get('regressions', 'baseline')} regressions across {len(perf.get('benchmarks', {}))} hot paths"])
    sc = metrics.get("scorecard", {})
    if sc:
        rows.append(["scorecard", f"decision {sc.get('decision')} observed {sc.get('observed_score_bps')} bps"])
    st = metrics.get("static", {})
    if st:
        rows.append(["static", f"ruff {st.get('ruff_violations', 'n/a')}, mypy {st.get('mypy_errors', 'n/a')}, unsorted json {st.get('unsorted_json_calls')}"])
    lines.append(_table(rows, ["probe", "result"]))
    lines.append("")
    if fz.get("targets"):
        lines.append("### Fuzz targets")
        lines.append("")
        rows = [[name, entry["executed"], entry["by_design_ratio"], entry["failures"], entry["distinct_signatures"], entry["unseen_mass_good_turing"], entry["failure_rate_upper95_if_clean"] if entry["failure_rate_upper95_if_clean"] is not None else "—"] for name, entry in sorted(fz["targets"].items())]
        lines.append(_table(rows, ["target", "inputs", "rejected by design", "failures", "classes", "unseen mass (GT)", "rate ≤ (95%, if clean)"]))
        lines.append("")
    if mut.get("per_operator"):
        lines.append("### Mutation by operator")
        lines.append("")
        rows = [[op, v["killed"], v["survived"], f"{v['killed'] / (v['killed'] + v['survived']):.0%}" if v["killed"] + v["survived"] else "—"] for op, v in mut["per_operator"].items()]
        lines.append(_table(rows, ["operator", "killed", "survived", "kill %"]))
        lines.append("")
    lines.append("## Open findings (top 40)")
    lines.append("")
    for entry in ledger.open_findings()[:40]:
        lines.append(f"- **{entry['severity']}** `{entry['id']}` [{entry['probe']}/{entry['category']}] {entry['title']} — `{entry['location']}` (seen {entry['seen_runs']}x, status {entry['status']})")
        if entry.get("reproducer"):
            lines.append(f"  - repro: `{entry['reproducer']}`")
    if not ledger.open_findings():
        lines.append("None. Every probe that ran observed nothing it could not explain.")
    lines.append("")
    lines.append("## Probe notes")
    lines.append("")
    for probe in probe_results:
        if probe["notes"] or probe["status"] != "ok":
            lines.append(f"- {probe['name']} ({probe['status']}, {probe['elapsed']}s)")
            for note in probe["notes"]:
                lines.append(f"  - {note}")
    lines.append("")
    lines.append("Generated by `tools/calibrate.py`; see `docs/calibration.md` for how to read and act on this.")
    return "\n".join(lines) + "\n"
