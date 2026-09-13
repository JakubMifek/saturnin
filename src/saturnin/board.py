"""The centralised work board.

One JSON file per task under ``board/tasks``. Files are plain text on purpose:
they diff well, survive crashes and can be inspected without any tooling.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import Config, default_config
from .locking import file_lock

KINDS = ("objective", "epic", "feature", "task", "pr-review", "issue-review",
         "automation", "improvement")
# Kinds that only contain other work; they are tracked, never executed directly.
CONTAINER_KINDS = ("objective", "epic", "feature")

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
    "in_progress": ("review", "blocked", "cancelled"),
    "review": ("in_progress", "blocked", "done", "cancelled"),
    "blocked": ("routed", "in_progress", "cancelled"),
    "done": (),
    "cancelled": (),
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


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
    unit: str | None = None
    squad: list[str] = field(default_factory=list)
    repo: str | None = None
    labels: list[str] = field(default_factory=list)
    body: str = ""
    branch: str | None = None
    worktree: str | None = None
    checkpoint: str | None = None
    checkpoint_resumed_at: str | None = None
    launch_deferred_at: str | None = None
    launch_deferred_reason: str | None = None
    # Work hierarchy: objective > epic > feature > task.
    parent: str | None = None
    # Rule 8: the mirrored GitHub issue is the durable copy of this task.
    issue: str | None = None
    issue_synced_at: str | None = None
    issue_synced_digest: str | None = None
    # How the dispatcher will learn that this task finished, so that nobody has
    # to sit and wait for a worker (see docs/operating-model.md).
    result_contract: str | None = None
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
        words = re.findall(r"[^\W\d_]+", self.title.lower())
        return " ".join(sorted(set(words))[:8]) or self.kind


def new_task_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d")
    return f"T-{stamp}-{secrets.token_hex(3)}"


def _escalation_reference(note: str) -> str:
    prefix = "escalated:"
    if not note.startswith(prefix):
        return ""
    return note[len(prefix):].strip()


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
        with file_lock(path):
            self._write(path, task)
        return task

    def _write(self, path: Path, task: Task) -> None:
        tmp = path.with_suffix(f".json.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(task.to_dict(), indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    @contextmanager
    def edit(self, task_id: str) -> Iterator[Task]:
        """Read-modify-write a task under an exclusive lock.

        Parallel squads share one board; every mutation that depends on the
        current value must go through here rather than get()/save().
        """
        path = self.path_for(task_id)
        with file_lock(path):
            if not path.is_file():
                raise BoardError(f"unknown task: {task_id}")
            task = Task.from_dict(json.loads(path.read_text(encoding="utf-8")))
            yield task
            self._write(path, task)

    def get(self, task_id: str) -> Task:
        path = self.path_for(task_id)
        if not path.is_file():
            raise BoardError(f"unknown task: {task_id}")
        with file_lock(path, exclusive=False):
            return Task.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def __iter__(self) -> Iterator[Task]:
        for path in sorted(self.config.tasks_dir.glob("*.json")):
            with file_lock(path, exclusive=False):
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
        parent: str | None = None,
        source: str = "cli",
    ) -> Task:
        return self._create(
            title,
            kind=kind,
            body=body,
            labels=labels,
            repo=repo,
            priority=priority,
            parent=parent,
            source=source,
        )

    def create_if_labels_absent(
        self,
        required_labels: Iterable[str],
        title: str,
        *,
        open_only: bool = False,
        **kwargs: Any,
    ) -> Task | None:
        """Atomically create a task unless one already carries every marker."""
        markers = {label.casefold() for label in required_labels}
        with file_lock(self.config.tasks_dir / ".board"):
            if any(
                markers <= {label.casefold() for label in task.labels}
                for task in self
                if not open_only or task.state not in TERMINAL_STATES
            ):
                return None
            labels = {*kwargs.pop("labels", ()), *required_labels}
            return self._create(title, labels=labels, **kwargs)

    def _create(
        self,
        title: str,
        *,
        kind: str = "task",
        body: str = "",
        labels: Iterable[str] = (),
        repo: str | None = None,
        priority: str = "P2",
        parent: str | None = None,
        source: str = "cli",
    ) -> Task:
        if not title.strip():
            raise BoardError("task title must not be empty")
        if priority not in PRIORITIES:
            raise BoardError(f"unknown priority: {priority}")
        if kind not in KINDS:
            raise BoardError(f"unknown kind: {kind} (expected one of {', '.join(KINDS)})")
        if parent is not None:
            self.check_parent(parent, kind)
        task_id = new_task_id()
        while self.path_for(task_id).exists():
            task_id = new_task_id()
        task = Task(
            id=task_id,
            title=title.strip(),
            kind=kind,
            body=body,
            labels=sorted({label.strip() for label in labels if label.strip()}),
            repo=repo,
            priority=priority,
            parent=parent,
        )
        task.log("intake", actor=source)
        return self.save(task)

    def transition(self, task: Task, state: str, *, actor: str | None = None, note: str = "") -> Task:
        """Transition ``task`` by id under the exclusive lock.

        Delegates to :meth:`transition_id` rather than saving the in-memory
        ``task`` directly, so a caller holding a stale ``Task`` instance can't
        clobber concurrent updates made by another squad.
        """
        return self.transition_id(task.id, state, actor=actor, note=note)

    def transition_id(self, task_id: str, state: str, *, actor: str | None = None, note: str = "") -> Task:
        """Read-modify-write a state transition under the task's exclusive lock."""
        with self.edit(task_id) as task:
            self._apply_transition(task, state, actor=actor or self.config.ceo_role, note=note)
        return task

    @staticmethod
    def _apply_transition(task: Task, state: str, *, actor: str, note: str) -> None:
        if state not in STATES:
            raise BoardError(f"unknown state: {state}")
        allowed = TRANSITIONS[task.state]
        if state != task.state and state not in allowed:
            raise BoardError(
                f"illegal transition {task.state} -> {state} (allowed: {', '.join(allowed) or 'none'})"
            )
        if state == "blocked" and task.state != "blocked" and not _escalation_reference(note):
            raise BoardError(
                "blocking a task requires an escalation reference in the note "
                "(use 'escalated: <issue-url>')"
            )
        task.state = state
        if state in TERMINAL_STATES:
            task.closed_at = utcnow()
        task.log(f"state:{state}", actor=actor, note=note)

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

    # -- hierarchy -----------------------------------------------------
    def check_parent(self, parent_id: str, kind: str) -> Task:
        """A task may only hang under a container that is broader than itself."""
        parent = self.get(parent_id)
        if parent.kind not in CONTAINER_KINDS:
            raise BoardError(
                f"{parent_id} is a {parent.kind}; only {', '.join(CONTAINER_KINDS)} "
                "can hold children"
            )
        if KINDS.index(kind) <= KINDS.index(parent.kind) and kind in CONTAINER_KINDS:
            raise BoardError(f"a {kind} cannot live under a {parent.kind}")
        return parent

    def children(self, task_id: str) -> list[Task]:
        return sorted(
            (t for t in self if t.parent == task_id),
            key=lambda t: (PRIORITIES.index(t.priority), t.created_at),
        )

    def descendants(self, task_id: str) -> list[Task]:
        found: list[Task] = []
        queue = [task_id]
        seen = {task_id}
        while queue:
            for child in self.children(queue.pop()):
                if child.id in seen:  # pragma: no cover - defensive
                    continue
                seen.add(child.id)
                found.append(child)
                queue.append(child.id)
        return found

    def rollup(self, task_id: str) -> dict[str, Any]:
        """Progress of a container, derived from its descendants."""
        leaves = [t for t in self.descendants(task_id) if t.kind not in CONTAINER_KINDS]
        done = [t for t in leaves if t.state == "done"]
        return {
            "id": task_id,
            "leaves": len(leaves),
            "done": len(done),
            "open": len([t for t in leaves if t.state not in TERMINAL_STATES]),
            "percent": round(100 * len(done) / len(leaves), 1) if leaves else 0.0,
        }

    def open_tasks_for_branch(self, branch: str) -> list[Task]:
        return [t for t in self.list(open_only=True) if t.branch == branch]
