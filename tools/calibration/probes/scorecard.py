"""ADR-002 self-scorecard as a probe: failed checks and dimension scores become ledger entries."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from ..ledger import Finding
from . import ProbeContext, ProbeResult


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("scorecard", "ok")
    script = context.repo_root / "tools" / "score_engine.py"
    if not script.exists():
        result.status = "skipped"
        result.notes.append("tools/score_engine.py missing")
        return result
    assessment = context.run_dir / "assessment.json"
    html = context.run_dir / "scorecard.html"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(context.repo_root / "src")
    completed = subprocess.run(
        [sys.executable, str(script), "run", "--profile", "offline", "--json-out", str(assessment), "--html-out", str(html)],
        cwd=context.repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (context.run_dir / "scorecard.log").write_text(completed.stdout.decode("utf-8", errors="replace"), encoding="utf-8")
    if not assessment.exists():
        result.status = "error"
        result.notes.append(f"score engine exited {completed.returncode} without an assessment; see scorecard.log")
        return result
    data = json.loads(assessment.read_text(encoding="utf-8"))
    aggregate = data.get("aggregate", {})
    result.metrics = {
        "decision": aggregate.get("decision"),
        "observed_score_bps": aggregate.get("observed_score_bps"),
        "lower_bound_bps": aggregate.get("lower_bound_bps"),
        "dimensions": {dimension.get("id"): dimension.get("observed_score_bps") for dimension in data.get("dimensions", [])},
    }
    if aggregate.get("decision") != "pass":
        result.findings.append(Finding("scorecard", "scorecard-decision", "critical", f"self-scorecard decision is {aggregate.get('decision')!r}", "scorecard", {"identity": "decision", "blockers": aggregate.get("blockers")}, "python tools/score_engine.py run --profile offline"))
    for check in data.get("checks", []):
        status = check.get("status") or check.get("outcome")
        if status in {"fail", "failed", "unresolved"}:
            identifier = str(check.get("id"))
            result.findings.append(
                Finding("scorecard", "scorecard-check", "high" if status != "unresolved" else "medium", f"scorecard check {identifier} is {status}", identifier, {"identity": identifier, "check": {key: check.get(key) for key in ("dimension", "criterion", "observed", "reason_code")}}, "python tools/score_engine.py run --profile offline")
            )
    return result
