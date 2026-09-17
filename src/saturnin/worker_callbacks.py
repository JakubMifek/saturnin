"""Narrow callback queue for sandboxed workers."""

from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path
from typing import Any

from .board import Board
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config
from .jsonlines import durable_append_text, objects

ENV_CALLBACK_DIR = "SATURNIN_CALLBACK_DIR"
ENV_CALLBACK_TASK_ID = "SATURNIN_CALLBACK_TASK_ID"
CALLBACKS_FILE = "callbacks.jsonl"


class WorkerCallbackError(RuntimeError):
    pass


def queue_from_args(args: Namespace) -> dict[str, Any] | None:
    callback_dir = os.environ.get(ENV_CALLBACK_DIR)
    task_id = os.environ.get(ENV_CALLBACK_TASK_ID)
    if not callback_dir or not task_id:
        return None
    record = _record_from_args(args, task_id)
    if record is None:
        return None
    target = Path(callback_dir) / CALLBACKS_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    durable_append_text(target, json.dumps(record, sort_keys=True) + "\n")
    return record


def apply_queued(
    config: Config,
    board: Board,
    *,
    task_id: str,
    callback_dir: str | None,
) -> list[dict[str, Any]]:
    if not callback_dir:
        return []
    path = Path(callback_dir) / CALLBACKS_FILE
    if not path.is_file():
        return []
    records = list(
        objects(
            path.read_text(encoding="utf-8"),
            path,
            required_fields=("type", "task_id"),
            validator=_validate_record,
        )
    )
    checkpoint_store = CheckpointStore(config, board)
    for record in records:
        if record["task_id"] != task_id:
            raise WorkerCallbackError(
                f"callback for {record['task_id']} cannot update task {task_id}"
            )
        if record["type"] == "task_move":
            board.transition_id(
                task_id,
                record["state"],
                actor=record.get("actor"),
                note=record.get("note", ""),
            )
        elif record["type"] == "checkpoint_save":
            checkpoint_store.save(
                Checkpoint(
                    task_id=task_id,
                    role=record["role"],
                    summary=record["summary"],
                    next_steps=record["next_steps"],
                    blockers=record["blockers"],
                    artifacts=record["artifacts"],
                    branch=record.get("branch"),
                    worktree=record.get("worktree"),
                    resume_after=record.get("resume_after"),
                )
            )
        else:  # pragma: no cover - validator guards this
            raise WorkerCallbackError(f"unknown worker callback {record['type']!r}")
    if records:
        path.unlink(missing_ok=True)
    return records


def _record_from_args(args: Namespace, task_id: str) -> dict[str, Any] | None:
    if args.command == "task" and args.task_command == "move":
        _check_task(args.task_id, task_id)
        note = args.note
        if args.state == "blocked" and args.escalation.strip():
            escalation_ref = args.escalation.strip()
            note = (
                f"escalated: {escalation_ref}"
                if not note
                else f"escalated: {escalation_ref}; {note}"
            )
        return {
            "type": "task_move",
            "task_id": args.task_id,
            "state": args.state,
            "actor": args.actor,
            "note": note,
        }
    if args.command == "checkpoint" and args.checkpoint_command == "save":
        _check_task(args.task_id, task_id)
        return {
            "type": "checkpoint_save",
            "task_id": args.task_id,
            "role": args.role,
            "summary": args.summary,
            "next_steps": args.next_steps,
            "blockers": args.blockers,
            "artifacts": args.artifacts,
            "branch": args.branch,
            "worktree": args.worktree,
            "resume_after": args.resume_after,
        }
    return None


def _check_task(requested: str, allowed: str) -> None:
    if requested != allowed:
        raise WorkerCallbackError(f"worker may only update its own task {allowed}")


def _validate_record(record: dict[str, Any]) -> None:
    if record["type"] == "task_move":
        for name in ("task_id", "state"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        if record.get("actor") is not None and not isinstance(record["actor"], str):
            raise TypeError("callback field 'actor' must be a string or null")
        if not isinstance(record.get("note", ""), str):
            raise TypeError("callback field 'note' must be a string")
        return
    if record["type"] == "checkpoint_save":
        for name in ("task_id", "role", "summary"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        for name in ("next_steps", "blockers", "artifacts"):
            if not isinstance(record.get(name), list) or not all(
                isinstance(item, str) for item in record[name]
            ):
                raise TypeError(f"callback field {name!r} must be a list of strings")
        for name in ("branch", "worktree", "resume_after"):
            if record.get(name) is not None and not isinstance(record[name], str):
                raise TypeError(f"callback field {name!r} must be a string or null")
        return
    raise TypeError(f"callback field 'type' is unsupported: {record['type']!r}")
