"""Narrow callback queue for sandboxed workers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import shlex
import signal
import subprocess
import time
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from . import escalation
from .board import Board, Task
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config
from .governance import Governance, _git_targets, github_repo_slug
from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text, durable_append_text, objects
from .locking import file_lock
from .review import ReviewLedger, normalize_repository_slug
from .worktrees import GitError, validated_task_worktree

ENV_CALLBACK_DIR = "SATURNIN_CALLBACK_DIR"
ENV_CALLBACK_TASK_ID = "SATURNIN_CALLBACK_TASK_ID"
CALLBACKS_FILE = "callbacks.jsonl"
_HEX_SHA_RE = re.compile(r"[0-9a-f]{40}")
_REMOTE_RE = re.compile(r"[A-Za-z0-9._-]+")
_CALLBACK_ID_RE = re.compile(r"[0-9a-f]{32,64}")
_COMMAND_TIMEOUT_SECONDS = 300.0
_COMMAND_OUTPUT_LIMIT_BYTES = 1024 * 1024
_OUTPUT_TRUNCATED = "\n...[output truncated]...\n"


class WorkerCallbackError(RuntimeError):
    pass


def queue_from_args(
    args: Namespace,
    *,
    argv: Sequence[str] | None = None,
) -> dict[str, Any] | None:
    callback_dir = os.environ.get(ENV_CALLBACK_DIR)
    task_id = os.environ.get(ENV_CALLBACK_TASK_ID)
    if not callback_dir and not task_id:
        return None
    if not callback_dir or not task_id:
        raise WorkerCallbackError(
            f"{ENV_CALLBACK_DIR} and {ENV_CALLBACK_TASK_ID} must be set together"
        )
    record = _record_from_args(args, task_id, argv=argv)
    if record is None:
        if _sandbox_local_command_allowed(args):
            return None
        raise WorkerCallbackError(
            "sandboxed workers may not execute this command directly; "
            "no trusted callback is defined"
        )
    record.setdefault("callback_id", secrets.token_hex(16))
    try:
        _validate_record(record)
    except (TypeError, ValueError) as exc:
        raise WorkerCallbackError(str(exc)) from exc
    target = Path(callback_dir) / CALLBACKS_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(target):
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
    expected = (
        config.var_dir
        / "launches"
        / f"{task_id}.home"
        / ".saturnin-callbacks"
    ).resolve(strict=False)
    callback_root = Path(callback_dir).resolve(strict=False)
    if callback_root != expected:
        raise WorkerCallbackError(
            f"callback directory for {task_id} is outside its isolated worker home"
        )
    path = callback_root / CALLBACKS_FILE
    if not path.is_file():
        return []
    if path.is_symlink():
        raise WorkerCallbackError(f"callback queue must be a regular file: {path}")
    applied: list[dict[str, Any]] = []
    with file_lock(path):
        records = list(
            objects(
                path.read_text(encoding="utf-8"),
                path,
                required_fields=("type", "task_id"),
                validator=_validate_record,
            )
        )
        migrated = False
        for record in records:
            if "callback_id" not in record:
                record["callback_id"] = secrets.token_hex(16)
                migrated = True
        if migrated:
            atomic_replace_text(
                path,
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in records),
                mode=PRIVATE_FILE_MODE,
            )
        for index, record in enumerate(records):
            if record["task_id"] != task_id:
                raise WorkerCallbackError(
                    f"callback for {record['task_id']} cannot update task {task_id}"
                )
            _apply_record(
                config,
                board,
                task_id=task_id,
                callback_dir=callback_root,
                record=record,
            )
            applied.append(record)
            remaining = records[index + 1 :]
            if remaining:
                atomic_replace_text(
                    path,
                    "".join(json.dumps(item, sort_keys=True) + "\n" for item in remaining),
                    mode=PRIVATE_FILE_MODE,
                )
            else:
                path.unlink(missing_ok=True)
                _fsync_directory(path.parent)
    return applied


def _apply_record(
    config: Config,
    board: Board,
    *,
    task_id: str,
    callback_dir: Path,
    record: dict[str, Any],
) -> None:
    checkpoint_store = CheckpointStore(config, board)
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
    elif record["type"] == "escalation_request":
        trusted_role = _trusted_task_role(board.get(task_id))
        _reject_conflicting_identity(record.get("actor"), trusted_role, "actor")
        body = escalation.render(
            title=record["title"],
            context=record.get("context", ""),
            checklist=record["checklist"],
            urgency=record["urgency"],
            unblock_criteria=record["unblock"],
            task_id=task_id,
            config=config,
        )
        escalation.submit_task_escalation(
            config=config,
            board=board,
            task_id=task_id,
            title=record["title"],
            body=body,
            urgency=record["urgency"],
            actor=trusted_role,
        )
    elif record["type"] == "server_command":
        trusted_role = _trusted_task_role(board.get(task_id))
        run_server_command(
            config,
            board,
            task_id=task_id,
            cmdline=record["cmdline"],
            service=record.get("service"),
            actor=trusted_role,
            callback_id=record["callback_id"],
        )
    elif record["type"] == "git_push":
        _deliver_isolated_commit(
            config,
            board,
            task_id=task_id,
            callback_dir=callback_dir,
            record=record,
        )
    elif record["type"] == "trusted_cli":
        _run_trusted_cli(config, board, task_id=task_id, record=record)
    else:  # pragma: no cover - validator guards this
        raise WorkerCallbackError(f"unknown worker callback {record['type']!r}")


def _record_from_args(
    args: Namespace,
    task_id: str,
    *,
    argv: Sequence[str] | None,
) -> dict[str, Any] | None:
    if args.command == "task" and args.task_command == "move":
        _check_task(args.task_id, task_id)
        if args.state == "blocked":
            raise WorkerCallbackError(
                "sandboxed workers must request escalations with "
                "`saturnin escalate --push --task`, not `task move blocked`"
            )
        note = args.note
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
    if args.command == "escalate" and args.push and args.task:
        _check_task(args.task, task_id)
        return {
            "type": "escalation_request",
            "task_id": args.task,
            "title": args.title,
            "context": args.context,
            "checklist": args.checklist,
            "unblock": args.unblock,
            "urgency": args.urgency,
            "actor": args.actor,
        }
    if (
        args.command == "check"
        and args.check_command == "command"
        and getattr(args, "execute", False)
    ):
        callback_task = args.task or task_id
        _check_task(callback_task, task_id)
        return {
            "type": "server_command",
            "task_id": callback_task,
            "cmdline": args.cmdline,
            "service": args.service,
        }
    if args.command == "push":
        return _git_push_record(args, task_id)
    operation = _trusted_cli_operation(args)
    if operation is not None:
        if argv is None:
            raise WorkerCallbackError("sandboxed trusted callbacks require command arguments")
        command = list(argv)
        if args.home or any(
            value == "--home" or value.startswith("--home=") for value in command
        ):
            raise WorkerCallbackError("sandboxed callbacks may not override --home")
        return {
            "type": "trusted_cli",
            "task_id": task_id,
            "callback_id": secrets.token_hex(16),
            "operation": operation,
            "argv": command,
        }
    return None


def _check_task(requested: str, allowed: str) -> None:
    if requested != allowed:
        raise WorkerCallbackError(f"worker may only update its own task {allowed}")


def _sandbox_local_command_allowed(args: Namespace) -> bool:
    if args.command == "doctor":
        return True
    if args.command == "task":
        return args.task_command in {"list", "show", "tree"}
    if args.command == "board":
        return True
    if args.command == "checkpoint":
        return args.checkpoint_command == "resume" or (
            args.checkpoint_command == "sweep" and args.dry_run
        )
    if args.command == "review":
        return args.review_command in {"attest", "gate"}
    if args.command == "check":
        return not getattr(args, "execute", False)
    if args.command == "automation":
        return args.automation_command in {"list", "find"} or (
            args.automation_command == "detect" and not args.propose
        )
    if args.command == "repo":
        return args.repo_command == "check"
    if args.command == "docs":
        return args.docs_command == "render" and args.check
    if args.command == "escalate":
        return not args.push
    if args.command == "worktree":
        return args.worktree_command == "list" or (
            args.worktree_command == "cleanup" and not args.apply
        )
    return False


def _trusted_cli_operation(args: Namespace) -> str | None:
    if args.command == "task" and args.task_command == "add":
        return "task_add"
    if args.command == "task" and args.task_command == "reroute":
        return "task_reroute"
    if (
        args.command == "worktree"
        and args.worktree_command == "cleanup"
        and args.apply
    ):
        return "worktree_cleanup"
    if args.command == "review" and args.review_command in {
        "record",
        "merge",
        "submit-issue",
    }:
        return f"review_{args.review_command.replace('-', '_')}"
    if (
        args.command == "automation"
        and args.automation_command == "detect"
        and args.propose
    ):
        return "automation_propose"
    if args.command == "improve":
        return "improve"
    if args.command == "docs" and args.docs_command == "render" and not args.check:
        return "docs_render"
    return None


def _git_push_record(args: Namespace, task_id: str) -> dict[str, Any]:
    worktree = os.environ.get("SATURNIN_WORKTREE")
    if not worktree:
        raise WorkerCallbackError("sandboxed push requires SATURNIN_WORKTREE")
    current = _git_output(
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=Path(worktree),
        env=os.environ.copy(),
    )
    branch = args.branch or current
    if branch != current:
        raise WorkerCallbackError(
            f"destination branch {branch!r} does not match current branch {current!r}"
        )
    commit = _git_output(
        ["rev-parse", "--verify", "HEAD^{commit}"],
        cwd=Path(worktree),
        env=os.environ.copy(),
    )
    return {
        "type": "git_push",
        "task_id": task_id,
        "remote": args.remote,
        "branch": branch,
        "commit": commit.lower(),
    }


def _validate_record(record: dict[str, Any]) -> None:
    callback_id = record.get("callback_id")
    if callback_id is not None and (
        not isinstance(callback_id, str) or not _CALLBACK_ID_RE.fullmatch(callback_id)
    ):
        raise ValueError(
            "callback field 'callback_id' must be a 32-64 character lowercase hex id"
        )
    if record["type"] == "task_move":
        for name in ("task_id", "state"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        if record["state"] == "blocked":
            raise TypeError("blocked transitions require an escalation_request callback")
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
    if record["type"] == "escalation_request":
        for name in ("task_id", "title", "urgency"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        if not isinstance(record.get("context", ""), str):
            raise TypeError("callback field 'context' must be a string")
        for name in ("checklist", "unblock"):
            if not isinstance(record.get(name), list) or not all(
                isinstance(item, str) for item in record[name]
            ):
                raise TypeError(f"callback field {name!r} must be a list of strings")
        if record.get("actor") is not None and not isinstance(record["actor"], str):
            raise TypeError("callback field 'actor' must be a string or null")
        return
    if record["type"] == "server_command":
        for name in ("task_id", "cmdline"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        if record.get("service") is not None and not isinstance(record["service"], str):
            raise TypeError("callback field 'service' must be a string or null")
        return
    if record["type"] == "git_push":
        for name in ("task_id", "remote", "branch", "commit"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        if not _REMOTE_RE.fullmatch(record["remote"]):
            raise ValueError("callback field 'remote' must be a Git remote name")
        if not _HEX_SHA_RE.fullmatch(record["commit"]):
            raise ValueError("callback field 'commit' must be a full lowercase Git SHA")
        return
    if record["type"] == "trusted_cli":
        for name in ("task_id", "operation"):
            if not isinstance(record.get(name), str) or not record[name]:
                raise TypeError(f"callback field {name!r} must be a non-empty string")
        argv = record.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(value, str) for value in argv
        ):
            raise TypeError("callback field 'argv' must be a non-empty list of strings")
        if any(value == "--home" or value.startswith("--home=") for value in argv):
            raise ValueError("trusted CLI callbacks may not override --home")
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


def _run_trusted_cli(
    config: Config,
    board: Board,
    *,
    task_id: str,
    record: dict[str, Any],
) -> None:
    from .cli import _run, build_parser

    try:
        args = build_parser().parse_args(record["argv"])
    except SystemExit as exc:
        raise WorkerCallbackError("trusted CLI callback contains invalid arguments") from exc
    operation = _trusted_cli_operation(args)
    if operation != record["operation"]:
        raise WorkerCallbackError(
            f"trusted CLI callback operation mismatch: {record['operation']!r}"
        )
    task = board.get(task_id)
    trusted_role = _trusted_task_role(task)
    callback_marker = f"worker-callback:{_callback_id(record)}"
    if operation == "task_reroute":
        _check_task(args.task_id, task_id)
        if callback_marker in task.labels:
            return
        if trusted_role != "chief-of-staff":
            raise WorkerCallbackError("only chief-of-staff may request task rerouting")
        _reject_conflicting_identity(args.actor, trusted_role, "actor")
        args.actor = trusted_role
        args.label.append(callback_marker)
    elif operation == "worktree_cleanup":
        if trusted_role != "janitor":
            raise WorkerCallbackError("only janitor may request worktree cleanup")
    elif operation == "review_record":
        allowed = {
            str(role).strip().lower()
            for role in config.governance.get("review", {})
            .get(args.kind, {})
            .get("allowed_reviewer_roles", [])
        }
        if trusted_role.strip().lower() not in allowed:
            raise WorkerCallbackError(
                f"task role {trusted_role!r} may not record {args.kind} reviews"
            )
        _reject_conflicting_identity(
            args.reviewer.strip().lower(),
            trusted_role.strip().lower(),
            "reviewer",
        )
        if args.attestation and args.attestation.startswith("@"):
            raise WorkerCallbackError(
                "trusted review callbacks require the attestation value inline"
            )
        _require_review_scope(task, args)
        if _review_callback_already_recorded(config, args):
            return
    elif operation == "review_merge":
        _reject_conflicting_identity(
            args.author.strip().lower(),
            trusted_role.strip().lower(),
            "author",
        )
        _require_task_repository(config, task, args.repo)
        if _require_task_pr_merge(task, args.subject, args.repo):
            return
    elif operation == "review_submit_issue":
        _reject_conflicting_identity(
            args.author.strip().lower(),
            trusted_role.strip().lower(),
            "author",
        )
        _require_task_repository(config, task, args.repo)
        if args.subject != task.id:
            raise WorkerCallbackError(
                f"issue submission subject must be the originating task id {task.id}"
            )
    elif operation == "automation_propose":
        if trusted_role != "automation-smith":
            raise WorkerCallbackError(
                "only automation-smith may request automation proposals"
            )
    elif operation == "improve":
        if trusted_role != "improver":
            raise WorkerCallbackError("only improver may run the improvement loop")
    elif operation == "task_add":
        expected_repo = task.repo or str(
            config.governance.get("autonomy", {}).get("self_repo", "")
        )
        if args.repo:
            _require_task_repository(config, task, args.repo)
        args.repo = expected_repo
        if callback_marker not in args.label:
            args.label.append(callback_marker)
        if _resume_replayed_task_add(config, board, args, callback_marker):
            return
    elif operation != "docs_render":  # pragma: no cover - classifier guards this
        raise WorkerCallbackError(f"unsupported trusted CLI callback {operation!r}")
    execution_config = config
    if operation == "docs_render":
        try:
            execution_config = Config(validated_task_worktree(task))
        except GitError as exc:
            raise WorkerCallbackError(str(exc)) from exc
    code = _run(args, execution_config)
    if code:
        raise WorkerCallbackError(
            f"trusted CLI callback {operation!r} exited with status {code}"
        )
    with board.edit(task_id) as stored:
        stored.log("worker:callback", actor=trusted_role, operation=operation)


def _callback_id(record: dict[str, Any]) -> str:
    value = record.get("callback_id")
    if isinstance(value, str) and value:
        return value
    payload = {key: item for key, item in record.items() if key != "callback_id"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _resume_replayed_task_add(
    config: Config,
    board: Board,
    args: Namespace,
    marker: str,
) -> bool:
    existing = next((task for task in board if marker in task.labels), None)
    if existing is None:
        return False
    if args.dispatch:
        from .cli import _provision_and_launch
        from .routing import Router

        if existing.state == "intake":
            Router(config).dispatch(board, existing, actor="worker-callback")
            existing = board.get(existing.id)
        if not args.no_launch and existing.state == "routed":
            _provision_and_launch(config, board, existing.id)
    return True


def _review_callback_already_recorded(config: Config, args: Namespace) -> bool:
    try:
        attestation_id = str(json.loads(args.attestation)["attestation_id"])
    except (json.JSONDecodeError, KeyError, TypeError):
        return False
    return any(
        record.attestation_id == attestation_id
        for record in ReviewLedger(config).for_subject(args.subject, args.kind)
    )


def _require_task_repository(config: Config, task: Task, requested: str) -> None:
    expected = task.repo or str(
        config.governance.get("autonomy", {}).get("self_repo", "")
    )
    try:
        matches = normalize_repository_slug(requested) == normalize_repository_slug(
            expected
        )
    except ValueError as exc:
        raise WorkerCallbackError(f"invalid task repository binding: {exc}") from exc
    if not matches:
        raise WorkerCallbackError(
            f"callback repository {requested!r} does not match task repository {expected!r}"
        )


def _require_review_scope(task: Task, args: Namespace) -> None:
    if task.kind != f"{args.kind}-review":
        raise WorkerCallbackError(
            f"task {task.id} is not a {args.kind}-review task"
        )
    required = {
        "review_subject": args.subject,
        "review_author": args.author,
    }
    if args.kind == "pr":
        required["review_head_sha"] = args.head_sha
    else:
        required["review_issue_digest"] = args.issue_digest
        required["review_destination_repo"] = normalize_repository_slug(args.repo)
    for field, requested in required.items():
        expected = getattr(task, field)
        if field == "review_destination_repo" and expected:
            expected = normalize_repository_slug(expected)
        if not expected or expected != requested:
            raise WorkerCallbackError(
                f"review callback {field} {requested!r} does not match "
                f"trusted task scope {expected!r}"
            )


def _require_task_pr_merge(task: Task, subject: str, repo: str) -> bool:
    from .cli import _parse_pr_subject
    from .issues import MirrorError, run_gh

    subject_repo, number = _parse_pr_subject(subject, repo=repo)
    try:
        payload = json.loads(run_gh(["api", f"repos/{subject_repo}/pulls/{number}"]))
        head = payload["head"]
        branch = str(head["ref"]).strip()
        commit = str(head["sha"]).strip().lower()
    except (MirrorError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise WorkerCallbackError(
            f"could not validate task PR binding for {subject}: {exc}"
        ) from exc
    if branch != task.branch:
        raise WorkerCallbackError(
            f"PR head branch {branch!r} does not match task branch {task.branch!r}"
        )
    delivered = {
        str(entry.get("commit", "")).lower()
        for entry in task.history
        if entry.get("event") == "git:push_finished"
    }
    if commit not in delivered:
        raise WorkerCallbackError(
            f"PR head {commit[:12]} was not delivered by task {task.id}"
        )
    return bool(payload.get("merged"))


def _validate_worktree_repository(config: Config, task: Task, worktree: Path) -> None:
    urls = _git_output(
        ["remote", "get-url", "--all", "origin"],
        cwd=worktree,
    ).splitlines()
    if not urls:
        raise WorkerCallbackError("task worktree has no origin repository")
    trusted_proxy_hosts = config.governance.get("git", {}).get(
        "trusted_github_proxy_hosts", []
    )
    for url in urls:
        repo = github_repo_slug(url, trusted_proxy_hosts=trusted_proxy_hosts)
        if repo is None:
            raise WorkerCallbackError("task worktree origin is not a recognized GitHub repository")
        _require_task_repository(config, task, repo)


def _deliver_isolated_commit(
    config: Config,
    board: Board,
    *,
    task_id: str,
    callback_dir: Path,
    record: dict[str, Any],
) -> None:
    failure: WorkerCallbackError | None = None
    with board.edit(task_id) as task:
        trusted_role = _trusted_task_role(task)
        if task.branch != record["branch"]:
            raise WorkerCallbackError(
                f"callback branch {record['branch']!r} does not match task branch "
                f"{task.branch!r}"
            )
        try:
            worktree = validated_task_worktree(task)
            _validate_worktree_repository(config, task, worktree)
            isolated_git_dir = callback_dir.parent / ".saturnin-git"
            if not isolated_git_dir.is_dir() or isolated_git_dir.is_symlink():
                raise WorkerCallbackError(
                    f"isolated Git metadata is unavailable for task {task_id}"
                )
            isolated_head = _git_output(
                [
                    "--git-dir",
                    str(isolated_git_dir),
                    "rev-parse",
                    "--verify",
                    f"refs/heads/{record['branch']}^{{commit}}",
                ],
                cwd=worktree,
            ).lower()
            if isolated_head != record["commit"]:
                raise WorkerCallbackError(
                    "isolated branch head changed after the push request was queued"
                )
            status = _git_output(
                [
                    "--git-dir",
                    str(isolated_git_dir),
                    "--work-tree",
                    str(worktree),
                    "status",
                    "--porcelain",
                ],
                cwd=worktree,
            )
            if status:
                raise WorkerCallbackError(
                    "isolated worker has uncommitted changes; refusing delivery"
                )
            canonical_head = _git_output(
                ["rev-parse", "--verify", f"refs/heads/{task.branch}"],
                cwd=worktree,
            )
            ancestor = _git_run(
                [
                    "--git-dir",
                    str(isolated_git_dir),
                    "merge-base",
                    "--is-ancestor",
                    canonical_head,
                    record["commit"],
                ],
                cwd=worktree,
            )
            if ancestor.returncode != 0:
                raise WorkerCallbackError(
                    "isolated commit is not a fast-forward of the task branch"
                )
            push_urls = _git_output(
                ["remote", "get-url", "--push", "--all", record["remote"]],
                cwd=worktree,
            ).splitlines()
            if not push_urls:
                raise WorkerCallbackError(
                    f"Git remote {record['remote']!r} has no push destination"
                )
            trusted_proxy_hosts = config.governance.get("git", {}).get(
                "trusted_github_proxy_hosts", []
            )
            for push_url in push_urls:
                repo = github_repo_slug(
                    push_url,
                    trusted_proxy_hosts=trusted_proxy_hosts,
                )
                if repo is None:
                    raise WorkerCallbackError(
                        f"Git remote {record['remote']!r} has an unrecognized push destination"
                    )
                _require_task_repository(config, task, repo)
                decision = Governance(config).push_allowed(
                    repo=repo,
                    branch=record["branch"],
                )
                if not decision.allowed:
                    raise WorkerCallbackError("; ".join(decision.reasons))
            if any(
                entry.get("event") == "git:push_finished"
                and entry.get("commit") == record["commit"]
                and entry.get("remote") == record["remote"]
                for entry in task.history
            ):
                return
            task.log(
                "git:push_started",
                actor=trusted_role,
                branch=record["branch"],
                commit=record["commit"],
                remote=record["remote"],
            )
            _git_output(
                [
                    "fetch",
                    "--no-tags",
                    "--no-write-fetch-head",
                    str(isolated_git_dir),
                    record["commit"],
                ],
                cwd=worktree,
            )
            _git_output(
                [
                    "push",
                    "--",
                    record["remote"],
                    f"{record['commit']}:refs/heads/{record['branch']}",
                ],
                cwd=worktree,
            )
            _git_output(["reset", "--hard", record["commit"]], cwd=worktree)
            task.log(
                "git:push_finished",
                actor=trusted_role,
                branch=record["branch"],
                commit=record["commit"],
                remote=record["remote"],
            )
        except (GitError, OSError, WorkerCallbackError) as exc:
            failure = (
                exc
                if isinstance(exc, WorkerCallbackError)
                else WorkerCallbackError(str(exc))
            )
            task.log(
                "git:push_failed",
                actor=trusted_role,
                branch=record["branch"],
                commit=record["commit"],
                remote=record["remote"],
                reason=str(failure),
            )
    if failure is not None:
        raise failure


def _git_run(
    args: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if env is None:
        env = os.environ.copy()
        for name in (
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_WORK_TREE",
        ):
            env.pop(name, None)
    result = _run_bounded_command(
        ["git", *args],
        cwd=cwd,
        env=env,
    )
    if result.timed_out:
        raise WorkerCallbackError(
            f"git {' '.join(args)} timed out after {_COMMAND_TIMEOUT_SECONDS:g}s"
        )
    return subprocess.CompletedProcess(
        ["git", *args],
        result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _git_output(
    args: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> str:
    result = _git_run(args, cwd=cwd, env=env)
    if result.returncode:
        raise WorkerCallbackError(
            result.stderr.strip() or f"git {' '.join(args)} failed"
        )
    return result.stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_server_command(
    config: Config,
    board: Board,
    *,
    task_id: str,
    cmdline: str,
    service: str | None = None,
    actor: str = "ops-worker",
    callback_id: str | None = None,
) -> dict[str, Any]:
    if actor != "ops-worker":
        raise WorkerCallbackError("only ops-worker tasks may request host server commands")
    try:
        parts = shlex.split(cmdline)
    except ValueError as exc:
        raise WorkerCallbackError(f"unparsable command: {exc}") from exc
    logs_dir = config.var_dir / "logs" / "host-operations"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{task_id}.jsonl"
    operation_id = callback_id or secrets.token_hex(16)
    if not _CALLBACK_ID_RE.fullmatch(operation_id):
        raise WorkerCallbackError(
            "callback ID must be a 32-64 character lowercase hex value"
        )
    with board.edit(task_id) as task:
        if task.role != actor:
            raise WorkerCallbackError(
                f"task {task_id} is assigned to {task.role!r}, not {actor!r}"
            )
        try:
            worktree = validated_task_worktree(task)
        except GitError as exc:
            raise WorkerCallbackError(str(exc)) from exc
        _validate_worktree_repository(config, task, worktree)
        if not parts:
            raise WorkerCallbackError("empty command")
        binary = Path(parts[0]).name
        if binary in {"env", "nice", "ionice", "stdbuf", "timeout", "exec", "command"}:
            raise WorkerCallbackError(
                "host-operation callbacks do not accept command wrappers"
            )
        if binary == "saturnin" or (
            binary in {"python", "python3"}
            and len(parts) >= 3
            and parts[1:3] == ["-m", "saturnin"]
        ):
            raise WorkerCallbackError(
                "Saturnin state changes require a dedicated trusted callback"
            )
        decision = Governance(config).check_server_command(
            cmdline,
            dedicated_service=service,
            cwd=worktree,
        )
        if not decision.allowed:
            raise WorkerCallbackError("; ".join(decision.reasons))
        if binary == "git":
            try:
                targets = _git_targets(parts[1:])
            except ValueError as exc:
                raise WorkerCallbackError(str(exc)) from exc
            for target in targets:
                candidate = Path(target).expanduser()
                if not candidate.is_absolute():
                    candidate = worktree / candidate
                resolved = candidate.resolve(strict=False)
                if resolved != worktree and not resolved.is_relative_to(worktree):
                    raise WorkerCallbackError(
                        f"repository command target {resolved} is outside task worktree "
                        f"{worktree}"
                    )
        for entry in reversed(task.history):
            if (
                entry.get("event") == "host:command_finished"
                and entry.get("callback_id") == operation_id
                and entry.get("returncode") == 0
            ):
                return {
                    "command": cmdline,
                    "service": service,
                    "returncode": 0,
                    "log": str(entry.get("log", log_path)),
                }
        task.log(
            "host:command_started",
            actor=actor,
            callback_id=operation_id,
            command=cmdline,
            service=service,
        )
    command_environment = os.environ.copy()
    for name in (
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
    ):
        command_environment.pop(name, None)
    result = _run_bounded_command(
        parts,
        cwd=worktree,
        env=command_environment,
    )
    failure: WorkerCallbackError | None = None
    if result.timed_out:
        failure = WorkerCallbackError(
            f"host command timed out after {_COMMAND_TIMEOUT_SECONDS:g}s; see {log_path}"
        )
    elif result.returncode:
        failure = WorkerCallbackError(
            f"host command exited {result.returncode}; see {log_path}"
        )
    with board.edit(task_id) as task:
        task.log(
            "host:command_finished",
            actor=actor,
            callback_id=operation_id,
            command=cmdline,
            service=service,
            returncode=result.returncode,
            log=str(log_path),
            timed_out=result.timed_out,
            output_truncated=result.output_truncated,
        )
    record = {
        "task_id": task_id,
        "callback_id": operation_id,
        "command": cmdline,
        "service": service,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "output_truncated": result.output_truncated,
    }
    durable_append_text(log_path, json.dumps(record, sort_keys=True) + "\n")
    if failure is not None:
        raise failure
    return {
        "command": cmdline,
        "service": service,
        "returncode": result.returncode,
        "log": str(log_path),
    }


@dataclass(frozen=True)
class _BoundedCommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool


def _run_bounded_command(
    args: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float = _COMMAND_TIMEOUT_SECONDS,
    output_limit: int = _COMMAND_OUTPUT_LIMIT_BYTES,
) -> _BoundedCommandResult:
    process = subprocess.Popen(
        list(args),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated: set[str] = set()
    selector = selectors.DefaultSelector()
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    kill_deadline: float | None = None
    timed_out = False
    while selector.get_map():
        now = time.monotonic()
        if kill_deadline is None and now >= deadline:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            kill_deadline = now + 1
        if kill_deadline is not None and now >= kill_deadline:
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
                key.fileobj.close()
            break
        wait_until = kill_deadline if kill_deadline is not None else deadline
        for key, _ in selector.select(timeout=min(0.1, max(0.0, wait_until - now))):
            try:
                chunk = os.read(key.fd, 64 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            name = key.data
            remaining = output_limit - len(buffers[name])
            if remaining > 0:
                buffers[name].extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated.add(name)
    selector.close()
    try:
        returncode = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        returncode = process.wait()
    stdout = buffers["stdout"].decode("utf-8", errors="replace")
    stderr = buffers["stderr"].decode("utf-8", errors="replace")
    if "stdout" in truncated:
        stdout += _OUTPUT_TRUNCATED
    if "stderr" in truncated:
        stderr += _OUTPUT_TRUNCATED
    return _BoundedCommandResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_truncated=bool(truncated),
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
        task.launch_deferred_at = None
        task.launch_deferred_reason = None
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
