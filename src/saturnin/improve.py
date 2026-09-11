"""Continuous self-improvement loop.

Measure -> detect bottlenecks -> propose a concrete, reviewable change. The loop
never edits policies on its own: it files board tasks, so every structural
change still goes through the normal review pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import telemetry
from .automation import AutomationLibrary
from .board import Board, Task
from .config import Config, default_config


@dataclass
class Finding:
    id: str
    severity: str  # info | warn | critical
    detail: str
    recommendation: str
    metric: float | None = None
    title: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "metric": self.metric,
            "title": self.title,
        }


@dataclass
class ImprovementReport:
    metrics: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    backlog: list[Finding] = field(default_factory=list)
    proposed_tasks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics,
            "findings": [f.to_dict() for f in self.findings],
            "backlog": [f.to_dict() for f in self.backlog],
            "proposed_tasks": self.proposed_tasks,
        }


class ImprovementLoop:
    def __init__(self, config: Config | None = None, board: Board | None = None) -> None:
        self.config = config or default_config()
        self.board = board or Board(self.config)
        self.policy = self.config.policy("improvement")
        self.thresholds: dict[str, Any] = self.policy.get("thresholds", {})
        self.actions: dict[str, Any] = self.policy.get("actions", {})

    # -- detection -----------------------------------------------------
    def detect(self, metrics: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        t = self.thresholds

        latency = metrics.get("median_dispatch_latency_s")
        limit = t.get("max_median_dispatch_latency_s")
        if latency is not None and limit is not None and latency > limit:
            findings.append(
                Finding(
                    "slow-dispatch",
                    "critical",
                    f"median dispatch latency {latency}s exceeds {limit}s",
                    "Trim CEO deliberation: add a routing rule for the most frequent "
                    "task shape so the first match wins immediately.",
                    latency,
                )
            )

        undispatched = metrics.get("undispatched", 0)
        if undispatched > t.get("max_undispatched", 3):
            findings.append(
                Finding(
                    "intake-backlog",
                    "warn",
                    f"{undispatched} tasks are still in intake",
                    "Run `saturnin dispatch --all`; if it recurs, schedule the dispatch "
                    "worker more frequently.",
                    float(undispatched),
                )
            )

        max_wip = t.get("max_wip_per_role", 5)
        for role, wip in sorted(metrics.get("wip_by_role", {}).items()):
            if wip > max_wip:
                findings.append(
                    Finding(
                        f"overloaded-{role}",
                        "warn",
                        f"role {role} carries {wip} open tasks (limit {max_wip})",
                        f"Split the {role} role into a squad of parallel workers or "
                        "rebalance the routing rules that feed it.",
                        float(wip),
                    )
                )

        open_tasks = metrics.get("open", 0)
        blocked = metrics.get("blocked", 0)
        ratio = (blocked / open_tasks) if open_tasks else 0.0
        if ratio > t.get("max_blocked_ratio", 0.25):
            findings.append(
                Finding(
                    "blocked-heavy",
                    "critical",
                    f"{blocked}/{open_tasks} open tasks are blocked ({ratio:.0%})",
                    "Escalate the blockers to a human via a GitHub issue with checklist, "
                    "urgency and unblock criteria.",
                    round(ratio, 3),
                )
            )

        oldest = metrics.get("oldest_open_age_days", 0.0)
        if oldest > t.get("max_open_age_days", 14):
            findings.append(
                Finding(
                    "stale-work",
                    "warn",
                    f"oldest open task is {oldest} days old",
                    "Checkpoint it for delayed resume or cancel it; stale work distorts "
                    "every other metric.",
                    oldest,
                )
            )

        cycle = metrics.get("median_cycle_time_s")
        cycle_limit = t.get("max_median_cycle_time_s")
        if cycle is not None and cycle_limit is not None and cycle > cycle_limit:
            findings.append(
                Finding(
                    "slow-cycle",
                    "warn",
                    f"median cycle time {cycle}s exceeds {cycle_limit}s",
                    "Look for a recurring manual step and convert it into an automation "
                    "library script.",
                    cycle,
                )
            )
        return findings

    # -- known gaps ----------------------------------------------------
    def backlog(self) -> list[Finding]:
        """Known gaps in Saturnin itself, declared in the improvement policy.

        A gap that lives only in a document has no owner and no state, so each
        entry becomes a board task on the next run of the loop.
        """
        items = self.policy.get("backlog") or []
        return [
            Finding(
                str(item["id"]),
                str(item.get("severity", "warn")),
                " ".join(str(item.get("detail", "")).split()),
                " ".join(str(item.get("recommendation", "")).split()),
                title=str(item.get("title") or item["id"]),
            )
            for item in items
        ]

    # -- loop ----------------------------------------------------------
    def run(self, *, now: datetime | None = None, create_tasks: bool | None = None) -> ImprovementReport:
        metrics = telemetry.collect(self.board, now=now)
        report = ImprovementReport(
            metrics=metrics, findings=self.detect(metrics), backlog=self.backlog()
        )
        if create_tasks is None:
            create_tasks = bool(self.actions.get("create_tasks", True))
        if create_tasks:
            report.proposed_tasks = [task.id for task in self._file_tasks(report.findings)]
            report.proposed_tasks += [
                task.id for task in self._file_tasks(report.backlog, prefix="Gap", label="gap")
            ]
        library = AutomationLibrary(self.config)
        report.proposed_tasks += [t.id for t in library.propose(self.board)] if create_tasks else []
        self.write_report(report, now=now)
        return report

    def _file_tasks(
        self, findings: list[Finding], *, prefix: str = "Improve", label: str = "improve"
    ) -> list[Task]:
        labels = list(self.actions.get("labels", ["self-improvement"]))
        created: list[Task] = []
        for finding in findings:
            marker = f"finding:{finding.id}"
            task = self.board.create_if_labels_absent(
                [marker],
                f"{prefix}: {finding.title or finding.detail}",
                kind="improvement",
                body=f"{finding.detail}\n\nRecommendation: {finding.recommendation}",
                labels=[*labels, label],
                priority="P1" if finding.severity == "critical" else "P2",
                source="improvement-loop",
            )
            if task is not None:
                created.append(task)
        return created

    def write_report(self, report: ImprovementReport, *, now: datetime | None = None) -> Path:
        report_dir = Path(self.actions.get("report_dir", "var/reports"))
        if not report_dir.is_absolute():
            report_dir = self.config.root / report_dir
        report_dir.mkdir(parents=True, exist_ok=True)
        stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S")
        path = report_dir / f"improvement-{stamp}.json"
        path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
        return path
