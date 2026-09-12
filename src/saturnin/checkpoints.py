"""Checkpoint / handoff / delayed-resume framework.

Long running sessions die: rate limits, restarts, a lost network. A checkpoint
is the minimum context another agent needs to continue without archaeology.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .board import Board, BoardError, utcnow
from .config import Config, default_config
from .locking import file_lock

REQUIRED_FIELDS = ("task_id", "role", "summary", "next_steps")


class CheckpointError(RuntimeError):
    pass


def _validate_resume_after(value: str | None) -> None:
    """Ensure *resume_after*, when given, is a parseable ISO-8601 timestamp."""
    if value is None:
        return
    try:
        datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise CheckpointError(
            f"resume_after must be a valid ISO-8601 timestamp, got {value!r}: {exc}"
        ) from exc


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
        _validate_resume_after(checkpoint.resume_after)
        path = self.path_for(checkpoint.task_id)
        with file_lock(path):
            # Repair any unterminated JSON fragment left by an interrupted write.
            if path.exists():
                raw = path.read_text(encoding="utf-8")
                if raw and not raw.endswith("\n"):
                    last_complete = raw.rfind("\n")
                    repaired = raw[: last_complete + 1] if last_complete >= 0 else ""
                    path.write_text(repaired, encoding="utf-8")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(checkpoint.to_dict()) + "\n")
            try:
                with self.board.edit(checkpoint.task_id) as task:
                    task.checkpoint = checkpoint.created_at
                    task.log("checkpoint", actor=checkpoint.role, summary=checkpoint.summary[:120])
            except BoardError:
                # Checkpoints may outlive their task file.
                return checkpoint
        return checkpoint

    def latest(self, task_id: str) -> Checkpoint | None:
        checkpoints = self.history(task_id)
        return checkpoints[-1] if checkpoints else None

    def history(self, task_id: str) -> list[Checkpoint]:
        path = self.path_for(task_id)
        if not path.is_file():
            return []
        with file_lock(path, exclusive=False):
            lines = [
                (line_number, line, line.endswith("\n"))
                for line_number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(keepends=True), start=1
                )
                if line.strip()
            ]
        checkpoints: list[Checkpoint] = []
        for index, (line_number, line, terminated) in enumerate(lines):
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise TypeError("checkpoint must be a JSON object")
                checkpoints.append(Checkpoint.from_dict(data))
            except (json.JSONDecodeError, TypeError) as exc:
                if index == len(lines) - 1 and not terminated:
                    break
                raise CheckpointError(
                    f"corrupt checkpoint store {path} at line {line_number}: {exc}"
                ) from exc
        return checkpoints

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

    def due(self, *, now: datetime | None = None) -> list[Checkpoint]:
        """Return latest delayed checkpoints whose task has not resumed yet."""
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        due: list[Checkpoint] = []
        for checkpoint in self:
            if not checkpoint.resume_after:
                continue
            resume_at = datetime.fromisoformat(checkpoint.resume_after)
            if resume_at.tzinfo is None:
                resume_at = resume_at.replace(tzinfo=timezone.utc)
            if resume_at > current:
                continue
            try:
                task = self.board.get(checkpoint.task_id)
            except BoardError:
                continue
            if task.state in ("done", "cancelled", "review"):
                continue
            if task.checkpoint_resumed_at == checkpoint.created_at:
                continue
            due.append(checkpoint)
        return due
