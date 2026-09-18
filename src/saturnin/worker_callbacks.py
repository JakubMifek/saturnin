"""Narrow callback queue for sandboxed workers."""

from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path
from typing import Any

from .board import Board, BoardError, Task
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config
from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text, durable_append_text, objects

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
            with board.edit(task_id) as task:
                trusted_role = _trusted_task_role(task)
                _reject_conflicting_identity(record.get("actor"), trusted_role, "actor")
                board._apply_transition(  # noqa: SLF001 - callback replay is a board mutation
                    task,
                    record["state"],
                    actor=trusted_role,
                    note=record.get("note", ""),
                )
        elif record["type"] == "checkpoint_save":
            trusted_role = _trusted_task_role(board.get(task_id))
            _reject_conflicting_identity(record.get("role"), trusted_role, "role")
            checkpoint_store.save(
                Checkpoint(
                    task_id=task_id,
                    role=trusted_role,
                    summary=record["summary"],
                    next_steps=record["next_steps"],
                    blockers=record["blockers"],
                    artifacts=record["artifacts"],
                    branch=record.get("branch"),
                    worktree=record.get("worktree"),
                    resume_after=record.get("resume_after"),
                )
            )
        elif record["type"] == "poller_register":
            trusted_role = _trusted_task_role(board.get(task_id))
            _reject_conflicting_identity(record.get("actor"), trusted_role, "actor")
            register_poller(
                config,
                board,
                task_id=task_id,
                status_file=record["status_file"],
                pending_message=record.get("pending_message", ""),
                actor=trusted_role,
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
    if args.command == "poller" and args.poller_command == "register":
        _check_task(args.task_id, task_id)
        return {
            "type": "poller_register",
            "task_id": args.task_id,
            "status_file": args.status_file,
            "pending_message": args.pending_message,
            "actor": args.actor,
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
    if record["type"] == "poller_register":
        for name in ("task_id", "status_file"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        for name in ("pending_message", "actor"):
            if record.get(name) is not None and not isinstance(record[name], str):
                raise TypeError(f"callback field {name!r} must be a string or null")
        return
    raise TypeError(f"callback field 'type' is unsupported: {record['type']!r}")


def _trusted_task_role(task: Task) -> str:
    if not task.role:
        raise WorkerCallbackError(f"task {task.id} has no trusted assigned role")
    return task.role


def _reject_conflicting_identity(value: Any, trusted_role: str, field: str) -> None:
    if value is not None and value != trusted_role:
        raise WorkerCallbackError(
            f"callback {field} {value!r} does not match trusted task role {trusted_role!r}"
        )


def register_poller(
    config: Config,
    board: Board,
    *,
    task_id: str,
    status_file: str,
    pending_message: str = "",
    actor: str | None = None,
) -> dict[str, Any]:
    """Install a trusted declarative poller registration."""
    signal_path = _validated_signal_path(config, status_file)
    with board.edit(task_id) as task:
        if task.result_contract != "poller":
            raise WorkerCallbackError(
                f"task {task_id} does not use the poller result contract"
            )
        trusted_role = _trusted_task_role(task)
        _reject_conflicting_identity(actor, trusted_role, "actor")
        payload: dict[str, Any] = {
            "task_id": task_id,
            "probe": {
                "type": "status-file",
                "path": signal_path,
            },
            "pending_message": pending_message or "awaiting external signal",
        }
        pollers_dir = config.var_dir / "pollers"
        pollers_dir.mkdir(parents=True, exist_ok=True)
        atomic_replace_text(
            pollers_dir / f"{task_id}.json",
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            mode=PRIVATE_FILE_MODE,
        )
        task.log("poller:registered", actor=trusted_role, status_file=signal_path)
        return payload


def _validated_signal_path(config: Config, value: str) -> str:
    requested = Path(value)
    if requested.is_absolute() or any(part == ".." for part in requested.parts):
        raise WorkerCallbackError("poller status file must be relative to var/poller-signals")
    root = (config.var_dir / "poller-signals").resolve()
    candidate = (config.data_root / requested).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise WorkerCallbackError(
            "poller status file must be under var/poller-signals"
        ) from exc
    if not relative.parts:
        raise WorkerCallbackError("poller status file must name a file")
    return candidate.relative_to(config.data_root).as_posix()
