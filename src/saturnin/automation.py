"""Reusable automation library + repeat detection.

Two jobs:

1. Keep an index of scripts that already exist so nobody rebuilds them.
2. Watch the board for work that keeps coming back and propose turning it into
   a script (the automation smith then owns the implementation).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .board import Board, Task
from .config import Config, default_config

DEFAULT_THRESHOLD = 3
MATCH_THRESHOLD = 2.0
STOPWORDS = {
    "that", "this", "with", "from", "into", "some", "have", "when", "then",
    "them", "your", "about", "which", "while", "there", "their", "please",
}


@dataclass
class Automation:
    id: str
    description: str
    path: str
    owner_role: str = "automation-smith"
    triggers: list[str] = field(default_factory=list)

    def exists(self, root: Path) -> bool:
        return (root / self.path).exists()


@dataclass
class Candidate:
    signature: str
    count: int
    task_ids: list[str]
    existing: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "count": self.count,
            "task_ids": self.task_ids,
            "existing": self.existing,
        }


class AutomationLibrary:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.registry_path: Path = self.config.automation_dir / "registry.yaml"

    def list(self) -> list[Automation]:
        if not self.registry_path.is_file():
            return []
        data = yaml.safe_load(self.registry_path.read_text(encoding="utf-8")) or {}
        return [Automation(**entry) for entry in data.get("automations", [])]

    def find(self, query: str) -> list[Automation]:
        """Search before you build - this is the anti-reinvention entry point.

        Trigger hits weigh most, then words shared with the id, then the
        description. A single weak word match is not enough to claim coverage.
        """
        lowered = query.lower()
        words = {w for w in lowered.split() if len(w) > 3 and w not in STOPWORDS}
        matches: list[tuple[float, Automation]] = []
        for automation in self.list():
            score = 0.0
            for trigger in automation.triggers:
                normalized = trigger.strip().lower()
                if normalized and normalized in lowered:
                    score += 3
            identity = automation.id.lower().replace("-", " ")
            score += sum(1 for word in words if word in identity)
            score += sum(0.5 for word in words if word in automation.description.lower())
            if score >= MATCH_THRESHOLD:
                matches.append((score, automation))
        return [automation for _, automation in sorted(matches, key=lambda m: -m[0])]

    def audit(self) -> list[str]:
        problems: list[str] = []
        seen: set[str] = set()
        for automation in self.list():
            if automation.id in seen:
                problems.append(f"duplicate automation id: {automation.id}")
            seen.add(automation.id)
            if not automation.exists(self.config.root):
                problems.append(f"{automation.id}: missing file {automation.path}")
        return problems

    # -- repeat detection ---------------------------------------------
    def detect_repeats(
        self, board: Board, *, threshold: int = DEFAULT_THRESHOLD
    ) -> list[Candidate]:
        counter: Counter[str] = Counter()
        by_signature: dict[str, list[str]] = defaultdict(list)
        for task in board:
            if task.kind in ("pr-review", "issue-review", "improvement", "automation"):
                continue
            counter[task.signature] += 1
            by_signature[task.signature].append(task.id)
        candidates: list[Candidate] = []
        for signature, count in counter.most_common():
            if count < threshold or not signature:
                continue
            existing = self.find(signature)
            candidates.append(
                Candidate(
                    signature=signature,
                    count=count,
                    task_ids=sorted(by_signature[signature]),
                    existing=existing[0].id if existing else None,
                )
            )
        return candidates

    def propose(
        self, board: Board, *, threshold: int = DEFAULT_THRESHOLD
    ) -> list[Task]:
        """Create board tasks for repeated work that has no automation yet."""
        proposed: list[Task] = []
        for candidate in self.detect_repeats(board, threshold=threshold):
            if candidate.existing:
                continue
            marker = f"repeat:{candidate.signature}"
            task = board.create_if_labels_absent(
                [marker],
                f"Automate repeated work: {candidate.signature}",
                kind="automation",
                body=(
                    f"Seen {candidate.count} times on the board "
                    f"({', '.join(candidate.task_ids)}).\n"
                    "Build a reusable script in automation/library and register it "
                    "in automation/registry.yaml."
                ),
                labels=["automation", "self-improvement"],
                source="automation-detector",
            )
            if task is None:
                continue
            proposed.append(task)
        return proposed
