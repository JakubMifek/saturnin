"""The centralised work board.

One JSON file per task under ``board/tasks``. Files are plain text on purpose:
they diff well, survive crashes and can be inspected without any tooling.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import Config, default_config

STATES = (
    "intake",
    "routed",
    "in_progress",
    "review",
    "blocked",
    "done",
    "cancelled",
)
TERMINAL_STATES = ("done", "cancelled")
PRIORITIES = ("P0", "P1", "P2", "P3")

TRANSITIONS: dict[str, tuple[str, ...]] = {
    "intake": ("routed", "cancelled"),
    "routed": ("in_progress", "blocked", "cancelled"),
    "in_progress": ("review", "blocked", "done", "cancelled"),
    "review": ("in_progress", "blocked", "done", "cancelled"),
    "blocked": ("routed", "in_progress", "cancelled"),
    "done": (),
    "cancelled": (),
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class BoardError(RuntimeError):
    """Raised when an operation would corrupt the board."""


@dataclass
class Task:
    id: str
    title: str
    kind: str = "task"
    state: str = "intake"
    priority: str = "P2"
    role: str | None = None
    squad: str | None = None
    repo: str | None = None
    labels: list[str] = field(default_factory=list)
    body: str = ""
    branch: str | None = None
    worktree: str | None = None
    checkpoint: str | None = None
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)
    routed_at: str | None = None
    closed_at: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Task":
        known = {f for f in cls.__dataclass_fields__}  # noqa: SLF001 - dataclass API
        return cls(**{k: v for k, v in data.items() if k in known})

    def log(self, event: str, actor: str = "ceo", **detail: Any) -> None:
        entry = {"ts": utcnow(), "event": event, "actor": actor}
        entry.update(detail)
        self.history.append(entry)
        self.updated_at = entry["ts"]

    @property
    def signature(self) -> str:
        """Normalised fingerprint used to detect repeated work."""
        words = [w for w in self.title.lower().split() if w.isalpha()]
        return " ".join(sorted(set(words))[:8]) or self.kind


def new_task_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d")
    return f"T-{stamp}-{secrets.token_hex(3)}"


class Board:
    """File backed task store."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.config.tasks_dir.mkdir(parents=True, exist_ok=True)

    # -- persistence ---------------------------------------------------
    def path_for(self, task_id: str) -> Path:
        if "/" in task_id or task_id in {"", ".", ".."}:
            raise BoardError(f"invalid task id: {task_id!r}")
        return self.config.tasks_dir / f"{task_id}.json"

    def save(self, task: Task) -> Task:
        path = self.path_for(task.id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(task.to_dict(), indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
        return task

    def get(self, task_id: str) -> Task:
        path = self.path_for(task_id)
        if not path.is_file():
            raise BoardError(f"unknown task: {task_id}")
        return Task.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def __iter__(self) -> Iterator[Task]:
        for path in sorted(self.config.tasks_dir.glob("*.json")):
            yield Task.from_dict(json.loads(path.read_text(encoding="utf-8")))

    # -- operations ----------------------------------------------------
    def create(
        self,
        title: str,
        *,
        kind: str = "task",
        body: str = "",
        labels: Iterable[str] = (),
        repo: str | None = None,
        priority: str = "P2",
        source: str = "cli",
    ) -> Task:
        if not title.strip():
            raise BoardError("task title must not be empty")
        if priority not in PRIORITIES:
            raise BoardError(f"unknown priority: {priority}")
        task = Task(
            id=new_task_id(),
            title=title.strip(),
            kind=kind,
            body=body,
            labels=sorted({label.strip() for label in labels if label.strip()}),
            repo=repo,
            priority=priority,
        )
        task.log("intake", actor=source)
        return self.save(task)

    def transition(self, task: Task, state: str, *, actor: str = "ceo", note: str = "") -> Task:
        if state not in STATES:
            raise BoardError(f"unknown state: {state}")
        allowed = TRANSITIONS[task.state]
        if state != task.state and state not in allowed:
            raise BoardError(
                f"illegal transition {task.state} -> {state} (allowed: {', '.join(allowed) or 'none'})"
            )
        task.state = state
        if state in TERMINAL_STATES:
            task.closed_at = utcnow()
        task.log(f"state:{state}", actor=actor, note=note)
        return self.save(task)

    def list(
        self,
        *,
        state: str | None = None,
        role: str | None = None,
        priority: str | None = None,
        open_only: bool = False,
    ) -> list[Task]:
        tasks = list(self)
        if state:
            tasks = [t for t in tasks if t.state == state]
        if role:
            tasks = [t for t in tasks if t.role == role]
        if priority:
            tasks = [t for t in tasks if t.priority == priority]
        if open_only:
            tasks = [t for t in tasks if t.state not in TERMINAL_STATES]
        return sorted(tasks, key=lambda t: (PRIORITIES.index(t.priority), t.created_at))

    def open_tasks_for_branch(self, branch: str) -> list[Task]:
        return [t for t in self.list(open_only=True) if t.branch == branch]
