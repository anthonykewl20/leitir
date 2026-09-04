"""File ledger findings as GitHub issues so agents can pick them up (``ready-for-agent``).

Uses the ``gh`` CLI (present on GitHub Actions runners and most developer
machines) through an injectable runner so the logic is testable offline.
Every issue body carries a ``calibration-id:<id>`` marker; that marker, plus
the id stored back into the ledger, is what makes filing idempotent.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from .ledger import SEVERITY_WEIGHT, Ledger

Runner = Callable[[Sequence[str]], tuple[int, str]]

PRIORITY_LABEL = {"critical": "priority:critical", "high": "priority:high", "medium": "priority:medium", "low": "priority:low", "info": "priority:low"}
BASE_LABELS = ("calibration", "ready-for-agent")


def gh_runner(command: Sequence[str]) -> tuple[int, str]:
    completed = subprocess.run(list(command), capture_output=True, check=False)
    return completed.returncode, (completed.stdout or completed.stderr).decode("utf-8", errors="replace")


def marker(finding_id: str) -> str:
    return f"calibration-id:{finding_id}"


def issue_title(entry: dict[str, Any]) -> str:
    title = " ".join(str(entry["title"]).split())
    return f"[calibration/{entry['probe']}] {title}"[:200]


def issue_body(entry: dict[str, Any], run_id: str) -> str:
    evidence = {key: value for key, value in entry.get("evidence", {}).items() if key not in {"identity", "environments", "tail"}}
    lines = [
        f"Automated finding from the self-calibration loop (ADR-0037), run `{run_id}`.",
        "",
        f"- **Probe / category:** `{entry['probe']}` / `{entry['category']}`",
        f"- **Severity:** {entry['severity']}",
        f"- **Location:** `{entry['location']}`",
        f"- **First seen:** run `{entry.get('first_seen', '?')}`, observed {entry.get('seen_runs', 1)} time(s)",
        "",
        "## Reproduce",
        "",
        "```bash",
        str(entry.get("reproducer") or "(see evidence)"),
        "```",
        "",
        "## Evidence",
        "",
        "```json",
        json.dumps(evidence, indent=1, sort_keys=True, default=str)[:6000],
        "```",
        "",
        "## Acceptance",
        "",
        "- Reproduce with the command above, then write the failing user-level intent test (AGENTS.md).",
        "- Smallest honest fix; integrity paths get a tamper/reject test in the same change.",
        "- Full suite, `ruff check .`, and `mypy src` green.",
        "- Done when `python tools/calibrate.py run --probes " + str(entry["probe"]) + "` no longer observes this finding (the ledger marks it fixed).",
        "",
        f"<!-- {marker(entry['id'])} -->",
    ]
    return "\n".join(lines)


def existing_issue(runner: Runner, finding_id: str) -> int | None:
    code, output = runner(["gh", "issue", "list", "--state", "all", "--search", f'"{marker(finding_id)}" in:body', "--json", "number", "--limit", "5"])
    if code != 0:
        return None
    try:
        rows = json.loads(output or "[]")
    except json.JSONDecodeError:
        return None
    numbers = [int(row["number"]) for row in rows if isinstance(row, dict) and "number" in row]
    return min(numbers) if numbers else None


def ensure_label(runner: Runner, name: str, color: str, description: str) -> None:
    runner(["gh", "label", "create", name, "--color", color, "--description", description, "--force"])


def file_issues(
    ledger: Ledger,
    *,
    run_id: str,
    min_severity: str = "high",
    limit: int = 10,
    dry_run: bool = False,
    runner: Runner = gh_runner,
    log: Callable[[str], None] = lambda message: None,
) -> list[dict[str, Any]]:
    """Create one issue per open finding at or above ``min_severity`` that has no issue yet.

    Returns the list of ``{"id", "number", "action"}`` records; ``action`` is
    ``created``, ``linked`` (an issue already existed), or ``would-create``.
    """
    threshold = SEVERITY_WEIGHT[min_severity]
    if not dry_run:
        ensure_label(runner, "calibration", "5319E7", "Filed by the self-calibration loop (ADR-0037)")
    records: list[dict[str, Any]] = []
    created = 0
    for entry in ledger.open_findings():
        if SEVERITY_WEIGHT[entry["severity"]] < threshold:
            continue
        if entry.get("issue"):
            continue
        if created >= limit:
            log(f"issue limit {limit} reached; remaining findings stay in the ledger")
            break
        finding_id = entry["id"]
        if dry_run:
            records.append({"id": finding_id, "number": None, "action": "would-create", "title": issue_title(entry)})
            created += 1
            continue
        number = existing_issue(runner, finding_id)
        if number is not None:
            entry["issue"] = number
            records.append({"id": finding_id, "number": number, "action": "linked"})
            continue
        labels = [*BASE_LABELS, PRIORITY_LABEL[entry["severity"]]]
        code, output = runner(["gh", "issue", "create", "--title", issue_title(entry), "--body", issue_body(entry, run_id), "--label", ",".join(labels)])
        if code != 0:
            log(f"gh issue create failed for {finding_id}: {output.strip()[:300]}")
            continue
        number = _number_from_url(output)
        entry["issue"] = number
        records.append({"id": finding_id, "number": number, "action": "created"})
        created += 1
        log(f"filed #{number} for {finding_id}")
    return records


def comment_fixed(ledger: Ledger, *, run_id: str, runner: Runner = gh_runner, log: Callable[[str], None] = lambda message: None) -> int:
    """Tell each linked issue when the ledger stops observing its finding.  Never closes issues (the PR merge does)."""
    count = 0
    for entry in ledger.findings.values():
        number = entry.get("issue")
        if not number or entry.get("status") != "fixed" or entry.get("fixed_commented"):
            continue
        code, _output = runner(["gh", "issue", "comment", str(number), "--body", f"Calibration run `{run_id}` re-tested this finding and no longer observes it (ledger status: fixed). If a PR with `Closes #{number}` merged, nothing else is needed."])
        if code == 0:
            entry["fixed_commented"] = run_id
            count += 1
            log(f"commented fixed on #{number}")
    return count


def _number_from_url(output: str) -> int | None:
    tail = output.strip().rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None
