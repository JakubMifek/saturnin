"""Measurement layer for the self-improvement loop."""

from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any, Iterable

from .board import Board, TERMINAL_STATES, Task, parse_ts


def _first_ts(task: Task, event: str) -> datetime | None:
    for entry in task.history:
        if entry.get("event") == event:
            return parse_ts(entry["ts"])
    return None


def dispatch_latency_seconds(task: Task) -> float | None:
    """How long the task waited before the CEO handed it to somebody."""
    if not task.routed_at:
        return None
    return (parse_ts(task.routed_at) - parse_ts(task.created_at)).total_seconds()


def cycle_time_seconds(task: Task) -> float | None:
    if not task.closed_at:
        return None
    return (parse_ts(task.closed_at) - parse_ts(task.created_at)).total_seconds()


def _median(values: Iterable[float]) -> float | None:
    values = [v for v in values if v is not None]
    return round(statistics.median(values), 2) if values else None


def collect(board: Board, *, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    tasks = list(board)
    open_tasks = [t for t in tasks if t.state not in TERMINAL_STATES]
    by_state: dict[str, int] = {}
    by_role: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    for task in tasks:
        by_state[task.state] = by_state.get(task.state, 0) + 1
        by_priority[task.priority] = by_priority.get(task.priority, 0) + 1
    for task in open_tasks:
        if task.role:
            by_role[task.role] = by_role.get(task.role, 0) + 1
    ages = [(now - parse_ts(t.created_at)).total_seconds() / 86400.0 for t in open_tasks]
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "total": len(tasks),
        "open": len(open_tasks),
        "by_state": by_state,
        "wip_by_role": by_role,
        "by_priority": by_priority,
        "undispatched": sum(1 for t in open_tasks if t.state == "intake"),
        "blocked": sum(1 for t in open_tasks if t.state == "blocked"),
        "median_dispatch_latency_s": _median(dispatch_latency_seconds(t) for t in tasks),
        "median_cycle_time_s": _median(cycle_time_seconds(t) for t in tasks),
        "oldest_open_age_days": round(max(ages), 2) if ages else 0.0,
        "checkpointed_open": sum(1 for t in open_tasks if t.checkpoint),
    }
