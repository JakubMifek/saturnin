"""Checkpoint / handoff / delayed-resume framework.

Long running sessions die: rate limits, restarts, a lost network. A checkpoint
is the minimum context another agent needs to continue without archaeology.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .board import Board, Task, utcnow
from .config import Config, default_config

REQUIRED_FIELDS = ("task_id", "role", "summary", "next_steps")


class CheckpointError(RuntimeError):
    pass


@dataclass
class Checkpoint:
    task_id: str
    role: str
    summary: str
    next_steps: list[str] = field(default_factory=list)
    branch: str | None = None
    worktree: str | None = None
    artifacts: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    resume_after: str | None = None
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Checkpoint":
        known = {f for f in cls.__dataclass_fields__}  # noqa: SLF001 - dataclass API
        return cls(**{k: v for k, v in data.items() if k in known})

    def render(self) -> str:
        """Human readable handoff note."""
        lines = [
            f"# Handoff for {self.task_id} ({self.role})",
            "",
            f"Saved at: {self.created_at}",
            f"Branch: {self.branch or '-'}",
            f"Worktree: {self.worktree or '-'}",
            "",
            "## State",
            self.summary,
            "",
            "## Next steps",
        ]
        lines += [f"- [ ] {step}" for step in self.next_steps] or ["- [ ] (none recorded)"]
        if self.blockers:
            lines += ["", "## Blockers", *[f"- {b}" for b in self.blockers]]
        if self.artifacts:
            lines += ["", "## Artifacts", *[f"- {a}" for a in self.artifacts]]
        if self.resume_after:
            lines += ["", f"## Delayed resume\nDo not resume before: {self.resume_after}"]
        return "\n".join(lines) + "\n"


class CheckpointStore:
    def __init__(self, config: Config | None = None, board: Board | None = None) -> None:
        self.config = config or default_config()
        self.dir: Path = self.config.checkpoints_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.board = board or Board(self.config)

    def path_for(self, task_id: str) -> Path:
        if "/" in task_id:
            raise CheckpointError(f"invalid task id: {task_id!r}")
        return self.dir / f"{task_id}.jsonl"

    def save(self, checkpoint: Checkpoint) -> Checkpoint:
        for name in REQUIRED_FIELDS:
            if not getattr(checkpoint, name):
                raise CheckpointError(f"checkpoint field {name!r} must not be empty")
        path = self.path_for(checkpoint.task_id)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(checkpoint.to_dict()) + "\n")
        try:
            task: Task = self.board.get(checkpoint.task_id)
        except Exception:  # noqa: BLE001 - checkpoints may outlive their task file
            return checkpoint
        task.checkpoint = checkpoint.created_at
        task.log("checkpoint", actor=checkpoint.role, summary=checkpoint.summary[:120])
        self.board.save(task)
        return checkpoint

    def latest(self, task_id: str) -> Checkpoint | None:
        path = self.path_for(task_id)
        if not path.is_file():
            return None
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return None
        return Checkpoint.from_dict(json.loads(lines[-1]))

    def history(self, task_id: str) -> list[Checkpoint]:
        path = self.path_for(task_id)
        if not path.is_file():
            return []
        return [
            Checkpoint.from_dict(json.loads(line))
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def __iter__(self) -> Iterator[Checkpoint]:
        for path in sorted(self.dir.glob("*.jsonl")):
            checkpoint = self.latest(path.stem)
            if checkpoint:
                yield checkpoint

    def resume(self, task_id: str) -> str:
        """Return the handoff note a fresh agent should be started with."""
        checkpoint = self.latest(task_id)
        if checkpoint is None:
            raise CheckpointError(f"no checkpoint stored for {task_id}")
        return checkpoint.render()
