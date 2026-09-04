"""Convergence ledger: every finding keeps a stable identity across runs.

The ledger is the memory of the loop.  A finding is *open* while a probe
keeps observing it, *fixed* once a run that executed the same probe no longer
observes it, and *regressed* if it comes back.  Human dispositions
(``accepted`` or ``equivalent``) silence a finding without deleting the
evidence that it exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import LEDGER_SCHEMA_VERSION

SEVERITY_WEIGHT = {"critical": 20, "high": 8, "medium": 3, "low": 1, "info": 0}
SEVERITIES = tuple(SEVERITY_WEIGHT)


@dataclass(frozen=True)
class Finding:
    """One observed blind spot, with enough evidence to reproduce it."""

    probe: str
    category: str
    severity: str
    title: str
    location: str
    evidence: dict[str, Any] = field(default_factory=dict)
    reproducer: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def id(self) -> str:
        key = self.evidence.get("identity")
        material = json.dumps(
            [self.probe, self.category, self.location, key if key is not None else self.title],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["id"] = self.id
        return data


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Ledger:
    def __init__(self, data: dict[str, Any]) -> None:
        if data.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise ValueError("unsupported ledger schema")
        self.data = data
        self.data.setdefault("findings", {})
        self.data.setdefault("runs", [])
        self.data.setdefault("dispositions", {})

    @classmethod
    def empty(cls) -> Ledger:
        return cls({"schema_version": LEDGER_SCHEMA_VERSION, "findings": {}, "runs": [], "dispositions": {}})

    @classmethod
    def load(cls, path: Path) -> Ledger:
        if not path.exists():
            return cls.empty()
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def save(self, path: Path) -> None:
        _atomic_write_text(path, _canonical_json(self.data))

    # -- findings -----------------------------------------------------------

    @property
    def findings(self) -> dict[str, dict[str, Any]]:
        return self.data["findings"]

    def disposition(self, finding_id: str) -> str | None:
        entry = self.data["dispositions"].get(finding_id)
        return entry.get("status") if isinstance(entry, dict) else None

    def set_disposition(self, finding_id: str, status: str, note: str) -> None:
        if status not in {"accepted", "equivalent", "open"}:
            raise ValueError("disposition must be accepted, equivalent, or open")
        if status == "open":
            self.data["dispositions"].pop(finding_id, None)
        else:
            self.data["dispositions"][finding_id] = {"status": status, "note": note}

    def record_run(
        self,
        *,
        run_id: str,
        started_at: str,
        git_sha: str,
        executed_probes: list[str],
        observed: list[Finding],
        metrics: dict[str, Any],
        retested: dict[str, set[str] | None] | None = None,
    ) -> dict[str, Any]:
        """Merge one run's observations and return the run's ledger summary.

        ``retested`` maps probe -> identities re-examined this run (``None`` =
        exhaustive).  A finding flips to ``fixed`` only if its probe ran and
        either the probe is exhaustive or the finding's identity was re-tested.
        """
        retested = retested or {}
        observed_ids = {finding.id for finding in observed}
        new_ids: list[str] = []
        regressed_ids: list[str] = []
        fixed_ids: list[str] = []
        for finding in observed:
            entry = self.findings.get(finding.id)
            if entry is None:
                self.findings[finding.id] = {
                    **finding.to_dict(),
                    "status": "open",
                    "first_seen": run_id,
                    "last_seen": run_id,
                    "seen_runs": 1,
                }
                new_ids.append(finding.id)
            else:
                if entry["status"] == "fixed":
                    entry["status"] = "regressed"
                    regressed_ids.append(finding.id)
                elif entry["status"] == "regressed":
                    pass
                else:
                    entry["status"] = "open"
                entry["last_seen"] = run_id
                entry["seen_runs"] = int(entry.get("seen_runs", 0)) + 1
                entry["evidence"] = finding.evidence
                entry["reproducer"] = finding.reproducer
                entry["severity"] = finding.severity
                entry["title"] = finding.title
        for finding_id, entry in self.findings.items():
            if entry["probe"] in executed_probes and finding_id not in observed_ids:
                scope = retested.get(entry["probe"])
                identity = str(entry.get("evidence", {}).get("identity", entry.get("title")))
                if scope is not None and identity not in scope:
                    continue
                if entry["status"] in {"open", "regressed"}:
                    entry["status"] = "fixed"
                    entry["fixed_in"] = run_id
                    fixed_ids.append(finding_id)
        summary = {
            "run_id": run_id,
            "started_at": started_at,
            "git_sha": git_sha,
            "probes": sorted(executed_probes),
            "new": sorted(new_ids),
            "regressed": sorted(regressed_ids),
            "fixed": sorted(fixed_ids),
            "open_by_severity": self.open_by_severity(),
            "blind_spot_index": self.blind_spot_index(),
            "metrics": metrics,
        }
        self.data["runs"].append(summary)
        return summary

    def open_findings(self) -> list[dict[str, Any]]:
        result = []
        for finding_id, entry in self.findings.items():
            if entry["status"] in {"open", "regressed"} and self.disposition(finding_id) is None:
                result.append(entry)
        result.sort(key=lambda item: (-SEVERITY_WEIGHT[item["severity"]], item["probe"], item["location"], item["id"]))
        return result

    def open_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for entry in self.open_findings():
            counts[entry["severity"]] += 1
        return counts

    def blind_spot_index(self) -> int:
        """Weighted count of open, undispositioned findings; the loop's objective is to drive it to zero."""
        return sum(SEVERITY_WEIGHT[entry["severity"]] for entry in self.open_findings())

    def previous_run(self) -> dict[str, Any] | None:
        runs = self.data["runs"]
        return runs[-1] if runs else None
