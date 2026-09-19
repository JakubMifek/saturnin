from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from saturnin import worker_callbacks
from saturnin.board import Board, utcnow
from saturnin.checkpoints import Checkpoint, CheckpointStore
from saturnin.cli import main
from saturnin.config import Config
from saturnin.launcher import AgentLauncher, LauncherError
from saturnin.mcp import MCPError
from saturnin.review import (
    ReviewLedger,
    review_attestation_signing_key,
    sign_review_attestation,
)
from saturnin.routing import Router
from saturnin.worktrees import WorktreeManager
from saturnin.worker_callbacks import (
    CALLBACKS_FILE,
    ENV_CALLBACK_DIR,
    ENV_CALLBACK_TASK_ID,
    WorkerCallbackError,
    apply_queued,
    queue_from_args,
    run_server_command,
)


_REAL_PROCESS_START_TIME = AgentLauncher._process_start_time


@pytest.fixture(autouse=True)
def verified_github_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saturnin.launcher.verify_github_binary",
        lambda config: config.var_dir / "bin" / "github-mcp-server",
    )
    monkeypatch.setattr(
        AgentLauncher,
        "_process_start_time",
        staticmethod(lambda pid: 123456),
    )


def test_launcher_starts_routed_role_with_filtered_mcp(
    config: Config, board: Board, git_repo: Path, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement a small fix")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create("feature/launch")
    manifest = worktree.path / ".saturnin" / "repo.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        "stack: python\nentry_points:\n  - saturnin\nrun:\n  test: python -m pytest\n",
        encoding="utf-8",
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/launch"
        stored.worktree = str(worktree.path)
        stored.launch_deferred_at = "2026-09-12T10:00:00+00:00"
        stored.launch_deferred_reason = "waiting for worktree"
    calls: list[tuple[list[str], dict]] = []

    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen

    def fake_popen(command, **kwargs):
        if command[0] == "git":
            return real_popen(command, **kwargs)
        calls.append((command, kwargs))
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr("saturnin.launcher.subprocess.Popen", fake_popen)

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    assert result.pid == 4242
    launched_task = board.get(task.id)
    assert launched_task.state == "in_progress"
    assert (
        [entry["event"] for entry in launched_task.history].count("state:in_progress")
        == 1
    )
    assert launched_task.launch_deferred_at is None
    assert launched_task.launch_deferred_reason is None
    mcp = json.loads((config.var_dir / "launches" / f"{task.id}.mcp.json").read_text())
    assert set(mcp["mcpServers"]) == {"github", "filesystem"}
    assert mcp["mcpServers"]["github"]["command"] == str(
        config.data_root / "var/bin/github-mcp-server"
    )
    assert mcp["mcpServers"]["github"]["args"] == ["stdio", "--read-only"]
    assert mcp["mcpServers"]["filesystem"]["args"][-1] == str(worktree.path)
    command = calls[0][0]
    assert "--no-ask-user" in command
    assert "Implement a small fix" in command[-1]
    assert "role: code-worker" in command[-1]
    assert "Managed repository manifest (.saturnin/repo.yaml):" in command[-1]
    assert "stack: python" in command[-1]
    assert calls[0][1]["cwd"] == worktree.path
    assert calls[0][1]["env"]["SATURNIN_HOME"] == str(config.root)
    assert calls[0][1]["env"]["SATURNIN_WORKTREE"] == str(worktree.path)
    assert calls[0][1]["env"]["PYTHONPATH"] == str(config.root / "src")
    assert calls[0][1]["env"]["HOME"] == str(config.var_dir / "launches" / f"{task.id}.home")
    metadata = json.loads(
        (config.var_dir / "launches" / f"{task.id}.json").read_text()
    )
    assert metadata["process_start_time_ticks"] == 123456


def test_launcher_relaunches_only_deferred_in_progress_task(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Retry a failed launch")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/retry-launch"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/retry-launch"
        stored.worktree = str(worktree.path)
    board.transition_id(task.id, "in_progress", actor="launcher")
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")

    with pytest.raises(LauncherError, match="cannot launch from state in_progress"):
        AgentLauncher(config, board).launch(task.id)

    with board.edit(task.id) as stored:
        stored.launch_deferred_at = utcnow()
        stored.launch_deferred_reason = "agent process exited"
    real_popen = subprocess.Popen
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs)
            if command[0] == "git"
            else SimpleNamespace(pid=4242)
        ),
    )

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    relaunched = board.get(task.id)
    assert relaunched.state == "in_progress"
    assert relaunched.launch_deferred_at is None
    assert relaunched.launch_deferred_reason is None
    assert (
        [entry["event"] for entry in relaunched.history].count("state:in_progress")
        == 1
    )


def test_launcher_does_not_relaunch_in_progress_poller(
    config: Config,
    board: Board,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Wait for a poller")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    with board.edit(task.id) as stored:
        stored.result_contract = "poller"
        stored.launch_deferred_at = utcnow()
        stored.launch_deferred_reason = "agent process exited"
    poller = config.var_dir / "pollers" / f"{task.id}.json"
    poller.parent.mkdir(parents=True)
    poller.write_text('{"task_id": "waiting"}\n', encoding="utf-8")
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("poller task must not relaunch"),
    )

    assert AgentLauncher(config, board).launch(task.id) is None

    waiting = board.get(task.id)
    assert waiting.state == "in_progress"
    assert waiting.launch_deferred_at is None
    assert waiting.launch_deferred_reason is None


@pytest.mark.parametrize("existing", [False, True])
def test_launch_logs_are_private(
    config: Config,
    board: Board,
    existing: bool,
) -> None:
    path = config.var_dir / "launches" / "worker.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    if existing:
        path.write_bytes(b"existing\n")
        path.chmod(0o666)

    with AgentLauncher(config, board)._private_log(path) as output:
        output.write(b"next\n")

    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes().endswith(b"next\n")


def test_launcher_initialization_tightens_all_existing_logs(
    config: Config,
    board: Board,
) -> None:
    launch_dir = config.var_dir / "launches"
    launch_dir.mkdir(parents=True, exist_ok=True)
    logs = [launch_dir / "first.log", launch_dir / "second.log"]
    for path in logs:
        path.write_text("existing\n", encoding="utf-8")
        path.chmod(0o666)

    AgentLauncher(config, board)

    assert [path.stat().st_mode & 0o777 for path in logs] == [0o600, 0o600]


def test_launcher_does_not_follow_existing_log_symlinks(
    config: Config,
    board: Board,
) -> None:
    launch_dir = config.var_dir / "launches"
    launch_dir.mkdir(parents=True, exist_ok=True)
    target = config.root / "not-a-log"
    target.write_text("protected\n", encoding="utf-8")
    target.chmod(0o666)
    (launch_dir / "unsafe.log").symlink_to(target)

    with pytest.raises(LauncherError, match="unsafe launch log"):
        AgentLauncher(config, board)

    assert target.stat().st_mode & 0o777 == 0o666


def test_worker_command_uses_mandatory_os_sandbox(
    config: Config,
    board: Board,
    git_repo: Path,
) -> None:
    task = board.create("Run inside a sandbox")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/sandbox"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/sandbox"
        stored.worktree = str(worktree.path)
    task = board.get(task.id)
    launcher = AgentLauncher(config, board)
    home = launcher._isolated_home(task.id)
    git_environment, git_objects = launcher._isolated_git_environment(
        task,
        worktree.path,
        home,
    )
    staged_board = launcher._stage_worker_board_context(task, home, config)
    credential = config.root / ".env"
    credential.write_text("not mounted\n", encoding="utf-8")
    mcp_config = config.var_dir / "launches" / f"{task.id}.mcp.json"
    mcp_config.write_text('{"mcpServers": {}}\n', encoding="utf-8")

    command = launcher._sandbox_command(
        "/usr/bin/bwrap",
        "/usr/bin/copilot",
        ["--autopilot"],
        workdir=worktree.path,
        isolated_home=home,
        trusted_config=config,
        git_objects=git_objects,
        mcp_config=mcp_config,
    )

    assert command[:2] == ["/usr/bin/bwrap", "--unshare-all"]
    assert ["--tmpfs", "/"] == command[
        command.index("--tmpfs"):command.index("--tmpfs") + 2
    ]
    assert not any(
        command[index:index + 3] == ["--ro-bind", "/", "/"]
        for index in range(len(command) - 2)
    )
    assert ["--tmpfs", "/run"] == command[
        command.index("/run") - 1:command.index("/run") + 1
    ]
    runtime_mount = [
        "--ro-bind",
        str(config.root / "policies"),
        str(config.root / "policies"),
    ]
    objects_mount = ["--ro-bind", str(git_objects), str(git_objects)]
    mcp_mount = ["--ro-bind", str(mcp_config), str(mcp_config)]
    staged_board_mount = ["--ro-bind", str(staged_board), str(config.board_dir)]
    worktree_mount = ["--bind", str(worktree.path), str(worktree.path)]
    home_mount = ["--bind", str(home), str(home)]
    assert any(
        command[index:index + 3] == runtime_mount
        for index in range(len(command) - 2)
    )
    assert any(
        command[index:index + 3] == objects_mount
        for index in range(len(command) - 2)
    )
    assert any(
        command[index:index + 3] == mcp_mount
        for index in range(len(command) - 2)
    )
    assert any(
        command[index:index + 3] == staged_board_mount
        for index in range(len(command) - 2)
    )
    assert any(
        command[index:index + 3] == worktree_mount
        for index in range(len(command) - 2)
    )
    assert any(
        command[index:index + 3] == home_mount
        for index in range(len(command) - 2)
    )
    writable_sources = {
        command[index + 1]
        for index, value in enumerate(command[:-2])
        if value == "--bind"
    }
    assert writable_sources == {str(worktree.path), str(home)}
    assert str(config.root) not in [
        command[index + 1]
        for index, value in enumerate(command[:-1])
        if value == "--ro-bind"
    ]
    assert str(config.board_dir) not in [
        command[index + 1]
        for index, value in enumerate(command[:-1])
        if value == "--ro-bind"
    ]
    assert (staged_board / "tasks" / f"{task.id}.json").is_file()
    assert list((staged_board / "tasks").glob("*.json")) == [
        staged_board / "tasks" / f"{task.id}.json"
    ]
    assert str(credential) not in command
    assert git_environment["GIT_DIR"].startswith(str(home))
    assert command[-3:] == ["--", "/usr/bin/copilot", "--autopilot"]


def test_reconcile_applies_worker_callbacks_before_requeue(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Fix worker callbacks")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    launcher = AgentLauncher(config, board)
    callback_dir = launcher._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callbacks = [
        {
            "type": "checkpoint_save",
            "task_id": task.id,
            "role": "code-worker",
            "summary": "paused",
            "next_steps": ["resume"],
            "blockers": [],
            "artifacts": [],
            "branch": "feature/callback",
            "worktree": "/tmp/worktree",
            "resume_after": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
        {
            "type": "task_move",
            "task_id": task.id,
            "state": "review",
            "actor": "code-worker",
            "note": "ready",
        },
    ]
    (callback_dir / CALLBACKS_FILE).write_text(
        "".join(json.dumps(record) + "\n" for record in callbacks),
        encoding="utf-8",
    )
    metadata_path = launcher.dir / f"{task.id}.json"
    metadata_path.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "pid": 123,
                "process_start_time_ticks": 123456,
                "callback_dir": str(callback_dir),
                "completed": True,
            }
        ),
        encoding="utf-8",
    )

    assert not launcher.has_active_launch(task.id)
    assert launcher.reconcile_exited_launches() == []

    assert board.get(task.id).state == "review"
    assert CheckpointStore(config, board).latest(task.id).summary == "paused"
    assert not metadata_path.exists()
    assert not (callback_dir / CALLBACKS_FILE).exists()


def test_reconcile_retries_only_unacknowledged_callbacks_after_task_state_changes(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Fix retry worker callbacks")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    launcher = AgentLauncher(config, board)
    callback_dir = launcher._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callbacks = [
        {
            "type": "task_move",
            "task_id": task.id,
            "state": "review",
            "actor": "code-worker",
            "note": "ready",
        },
        {
            "type": "checkpoint_save",
            "task_id": task.id,
            "role": "chief-of-staff",
            "summary": "handoff",
            "next_steps": ["review"],
            "blockers": [],
            "artifacts": [],
            "branch": None,
            "worktree": None,
            "resume_after": None,
        },
    ]
    queue_path = callback_dir / CALLBACKS_FILE
    queue_path.write_text(
        "".join(json.dumps(record) + "\n" for record in callbacks),
        encoding="utf-8",
    )
    metadata_path = launcher.dir / f"{task.id}.json"
    metadata_path.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "pid": 123,
                "process_start_time_ticks": 999,
                "callback_dir": str(callback_dir),
            }
        ),
        encoding="utf-8",
    )

    assert launcher.reconcile_exited_launches() == []

    assert board.get(task.id).state == "review"
    assert metadata_path.exists()
    remaining = [
        json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines()
    ]
    assert remaining[0].pop("callback_id")
    assert remaining == [callbacks[1]]

    remaining[0]["role"] = "code-worker"
    queue_path.write_text(json.dumps(remaining[0]) + "\n", encoding="utf-8")

    assert launcher.reconcile_exited_launches() == []
    assert CheckpointStore(config, board).latest(task.id).summary == "handoff"
    assert not metadata_path.exists()
    assert not queue_path.exists()


def test_reconcile_discovers_orphaned_callbacks_after_partial_state_change(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Retry orphaned worker callbacks")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    callback_actor = board.get(task.id).role
    launcher = AgentLauncher(config, board)
    callback_dir = launcher._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callbacks = [
        {
            "type": "task_move",
            "task_id": task.id,
            "state": "review",
            "actor": callback_actor,
            "note": "ready",
        },
        {
            "type": "checkpoint_save",
            "task_id": task.id,
            "role": "wrong-role",
            "summary": "handoff",
            "next_steps": ["review"],
            "blockers": [],
            "artifacts": [],
            "branch": None,
            "worktree": None,
            "resume_after": None,
        },
    ]
    queue_path = callback_dir / CALLBACKS_FILE
    queue_path.write_text(
        "".join(json.dumps(record) + "\n" for record in callbacks),
        encoding="utf-8",
    )

    _, callbacks_complete, _ = launcher._reconcile_exited_launch(
        {
            "task_id": task.id,
            "pid": 4242,
            "callback_dir": str(callback_dir),
            "completed": True,
        }
    )

    assert not callbacks_complete
    assert board.get(task.id).state == "review"
    remaining = json.loads(queue_path.read_text(encoding="utf-8"))
    assert remaining.pop("callback_id")
    assert remaining == callbacks[1]

    remaining["role"] = board.get(task.id).role
    queue_path.write_text(json.dumps(remaining) + "\n", encoding="utf-8")

    assert launcher.reconcile_exited_launches() == []
    assert CheckpointStore(config, board).latest(task.id).summary == "handoff"
    assert board.get(task.id).state == "review"
    assert not queue_path.exists()


def test_orphan_reconcile_rechecks_launch_metadata_under_lock(
    config: Config,
    board: Board,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Preserve live worker callbacks")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    launcher = AgentLauncher(config, board)
    callback_dir = launcher._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    queue_path = callback_dir / CALLBACKS_FILE
    queue_path.write_text(
        json.dumps(
            {
                "type": "task_move",
                "task_id": task.id,
                "state": "review",
                "actor": board.get(task.id).role,
                "note": "ready",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    metadata_path = launcher.dir / f"{task.id}.json"
    real_file_lock = worker_callbacks.file_lock
    injected = False

    @contextmanager
    def launch_race_lock(path, **kwargs):
        nonlocal injected
        with real_file_lock(path, **kwargs):
            if path == metadata_path and not injected:
                injected = True
                metadata_path.write_text(
                    json.dumps(
                        {
                            "task_id": task.id,
                            "pid": 4242,
                            "process_start_time_ticks": 123456,
                            "callback_dir": str(callback_dir),
                        }
                    ),
                    encoding="utf-8",
                )
            yield

    monkeypatch.setattr("saturnin.launcher.file_lock", launch_race_lock)

    assert launcher.reconcile_exited_launches() == []
    assert board.get(task.id).state == "in_progress"
    assert queue_path.is_file()
    assert metadata_path.is_file()


def test_callback_append_waits_for_replay_replacement(
    config: Config,
    board: Board,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Serialize callback replay")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    role = board.get(task.id).role
    callback_dir = (
        AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    )
    callback_dir.mkdir(parents=True)
    queue_path = callback_dir / CALLBACKS_FILE
    queue_path.write_text(
        json.dumps(
            {
                "type": "checkpoint_save",
                "task_id": task.id,
                "role": role,
                "summary": "first",
                "next_steps": ["continue"],
                "blockers": [],
                "artifacts": [],
                "branch": None,
                "worktree": None,
                "resume_after": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(ENV_CALLBACK_DIR, str(callback_dir))
    monkeypatch.setenv(ENV_CALLBACK_TASK_ID, task.id)
    append_entered = threading.Event()
    writer: threading.Thread | None = None
    real_append = worker_callbacks.durable_append_text
    real_apply_record = worker_callbacks._apply_record

    def tracked_append(path: Path, text: str) -> None:
        append_entered.set()
        real_append(path, text)

    def append_callback() -> None:
        queue_from_args(
            SimpleNamespace(
                command="task",
                task_command="move",
                task_id=task.id,
                state="review",
                actor=role,
                note="ready",
            )
        )

    def apply_with_concurrent_append(*args, **kwargs) -> None:
        nonlocal writer
        real_apply_record(*args, **kwargs)
        writer = threading.Thread(target=append_callback)
        writer.start()
        append_entered.wait(timeout=0.1)

    monkeypatch.setattr(worker_callbacks, "durable_append_text", tracked_append)
    monkeypatch.setattr(worker_callbacks, "_apply_record", apply_with_concurrent_append)

    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))
    assert writer is not None
    writer.join(timeout=1)

    assert not writer.is_alive()
    remaining = [json.loads(line) for line in queue_path.read_text().splitlines()]
    assert remaining[0].pop("callback_id")
    assert remaining == [
        {
            "actor": role,
            "note": "ready",
            "state": "review",
            "task_id": task.id,
            "type": "task_move",
        }
    ]


def test_reconcile_callback_failure_keeps_in_progress_task_for_retry(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Retry failed worker callback")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    launcher = AgentLauncher(config, board)
    callback_dir = launcher._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "task_move",
        "task_id": task.id,
        "state": "review",
        "actor": "not-the-task-role",
        "note": "ready",
    }
    queue_path = callback_dir / CALLBACKS_FILE
    queue_path.write_text(json.dumps(callback) + "\n", encoding="utf-8")
    metadata_path = launcher.dir / f"{task.id}.json"
    metadata_path.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "pid": 123,
                "process_start_time_ticks": 123456,
                "callback_dir": str(callback_dir),
                "completed": True,
            }
        ),
        encoding="utf-8",
    )

    assert launcher.reconcile_exited_launches() == []

    retained = board.get(task.id)
    assert retained.state == "in_progress"
    assert retained.launch_deferred_at is None
    assert retained.history[-1]["event"] == "agent:callback_failed"
    assert metadata_path.exists()
    assert queue_path.exists()

    callback["actor"] = board.get(task.id).role
    queue_path.write_text(json.dumps(callback) + "\n", encoding="utf-8")

    assert launcher.reconcile_exited_launches() == []
    assert board.get(task.id).state == "review"
    assert not metadata_path.exists()
    assert not queue_path.exists()


def test_trusted_cli_callback_applies_task_add(
    config: Config,
    board: Board,
) -> None:
    task = board.create("File a follow-up")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    callback_dir = AgentLauncher(config, board)._isolated_home(
        task.id
    ) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "trusted_cli",
        "task_id": task.id,
        "operation": "task_add",
        "argv": [
            "task",
            "add",
            "Extract shared controller",
            "--label",
            "architecture",
        ],
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    created = [item for item in board if item.id != task.id]
    assert [item.title for item in created] == ["Extract shared controller"]
    assert created[0].labels[0] == "architecture"
    assert created[0].labels[1].startswith("worker-callback:")
    assert created[0].repo == "JakubMifek/saturnin"
    assert board.get(task.id).history[-1]["operation"] == "task_add"


def test_trusted_cli_task_add_cannot_escape_task_repository(
    config: Config,
    board: Board,
) -> None:
    task = board.create("File scoped follow-up", repo="JakubMifek/saturnin")
    with board.edit(task.id) as stored:
        stored.role = "code-worker"
        stored.state = "in_progress"
    callback_dir = AgentLauncher(config, board)._isolated_home(
        task.id
    ) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "trusted_cli",
        "task_id": task.id,
        "operation": "task_add",
        "argv": [
            "task",
            "add",
            "Escape repository",
            "--repo",
            "JakubMifek/saturnin-ops",
            "--dispatch",
        ],
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(WorkerCallbackError, match="does not match task repository"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    assert [item.id for item in board] == [task.id]


def test_trusted_cli_callback_records_review_as_assigned_reviewer(
    config: Config,
    board: Board,
) -> None:
    subject = "JakubMifek/saturnin#trusted-review"
    head_sha = "c" * 40
    task = board.create("Review the change", kind="pr-review")
    with board.edit(task.id) as stored:
        stored.role = "pr-reviewer"
        stored.state = "in_progress"
        stored.review_subject = subject
        stored.review_author = "code-worker"
        stored.review_head_sha = head_sha
    attestation = sign_review_attestation(
        key=review_attestation_signing_key(config, "pr-reviewer"),
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=head_sha,
    )
    callback_dir = AgentLauncher(config, board)._isolated_home(
        task.id
    ) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "trusted_cli",
        "task_id": task.id,
        "operation": "review_record",
        "argv": [
            "review",
            "record",
            subject,
            "--kind",
            "pr",
            "--author",
            "code-worker",
            "--reviewer",
            "pr-reviewer",
            "--verdict",
            "approved",
            "--head-sha",
            head_sha,
            "--attestation",
            attestation,
        ],
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    records = ReviewLedger(config).for_subject(subject, "pr")
    assert len(records) == 1
    assert records[0].reviewer == "pr-reviewer"


def test_trusted_cli_review_record_requires_exact_task_scope(
    config: Config,
    board: Board,
) -> None:
    trusted_subject = "JakubMifek/saturnin#trusted"
    requested_subject = "JakubMifek/saturnin#other"
    head_sha = "d" * 40
    task = board.create(
        "Review one pull request",
        kind="pr-review",
        review_subject=trusted_subject,
        review_author="code-worker",
        review_head_sha=head_sha,
    )
    with board.edit(task.id) as stored:
        stored.role = "pr-reviewer"
        stored.state = "in_progress"
    attestation = sign_review_attestation(
        key=review_attestation_signing_key(config, "pr-reviewer"),
        subject=requested_subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=head_sha,
    )
    callback_dir = AgentLauncher(config, board)._isolated_home(
        task.id
    ) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "trusted_cli",
        "task_id": task.id,
        "operation": "review_record",
        "argv": [
            "review",
            "record",
            requested_subject,
            "--kind",
            "pr",
            "--author",
            "code-worker",
            "--reviewer",
            "pr-reviewer",
            "--verdict",
            "approved",
            "--head-sha",
            head_sha,
            "--attestation",
            attestation,
        ],
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(WorkerCallbackError, match="review_subject"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    assert ReviewLedger(config).for_subject(requested_subject, "pr") == []


def test_trusted_cli_merge_requires_pr_on_task_branch(
    config: Config,
    board: Board,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Merge only this task", repo="JakubMifek/saturnin")
    with board.edit(task.id) as stored:
        stored.role = "code-worker"
        stored.state = "in_progress"
        stored.branch = "feature/owned"
        stored.log(
            "git:push_finished",
            actor="code-worker",
            branch=stored.branch,
            commit="e" * 40,
            remote="origin",
        )
    callback_dir = AgentLauncher(config, board)._isolated_home(
        task.id
    ) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "trusted_cli",
        "task_id": task.id,
        "operation": "review_merge",
        "argv": [
            "review",
            "merge",
            "JakubMifek/saturnin#9",
            "--repo",
            "JakubMifek/saturnin",
            "--author",
            "code-worker",
        ],
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "saturnin.issues.run_gh",
        lambda args: json.dumps(
            {"head": {"ref": "feature/another-task", "sha": "e" * 40}}
        ),
    )

    with pytest.raises(WorkerCallbackError, match="does not match task branch"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))


def test_trusted_cli_issue_submission_requires_originating_task_subject(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Submit reviewed issue", repo="JakubMifek/saturnin-ops")
    with board.edit(task.id) as stored:
        stored.role = "code-worker"
        stored.state = "in_progress"
    callback_dir = AgentLauncher(config, board)._isolated_home(
        task.id
    ) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "trusted_cli",
        "task_id": task.id,
        "operation": "review_submit_issue",
        "argv": [
            "review",
            "submit-issue",
            "another-task",
            "--repo",
            "JakubMifek/saturnin-ops",
            "--author",
            "code-worker",
            "--title",
            "Reviewed issue",
            "--body",
            "Exact body",
        ],
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(WorkerCallbackError, match="originating task id"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))


@pytest.mark.parametrize(
    "callback",
    [
        {
            "type": "task_move",
            "state": "review",
            "actor": "chief-of-staff",
            "note": "ready",
        },
        {
            "type": "checkpoint_save",
            "role": "chief-of-staff",
            "summary": "paused",
            "next_steps": ["resume"],
            "blockers": [],
            "artifacts": [],
        },
    ],
)
def test_worker_callbacks_reject_forged_role_identity(
    config: Config,
    board: Board,
    callback: dict[str, object],
) -> None:
    task = board.create("Fix forged callback")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    callback_dir = AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback["task_id"] = task.id
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(WorkerCallbackError, match="trusted task role"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    assert board.get(task.id).state == "in_progress"


def test_worker_callback_registers_trusted_poller(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Fix poller")
    Router(config).dispatch(board, task)
    board.transition_id(task.id, "in_progress", actor="launcher")
    with board.edit(task.id) as stored:
        stored.result_contract = "poller"
        stored.launch_deferred_at = utcnow()
        stored.launch_deferred_reason = "agent process exited"
    callback_dir = AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "poller_register",
        "task_id": task.id,
        "status_file": f"var/poller-signals/{task.id}.json",
        "pending_message": "waiting for CI",
        "actor": "chief-of-staff",
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(WorkerCallbackError, match="trusted task role"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))
    callback["actor"] = "code-worker"
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    poller = json.loads(
        (config.var_dir / "pollers" / f"{task.id}.json").read_text(encoding="utf-8")
    )
    assert poller == {
        "pending_message": "waiting for CI",
        "probe": {
            "path": f"var/poller-signals/{task.id}.json",
            "type": "status-file",
        },
        "task_id": task.id,
    }
    registered = board.get(task.id)
    assert registered.launch_deferred_at is None
    assert registered.launch_deferred_reason is None


def test_worker_callback_submits_escalation_on_trusted_host(
    config: Config,
    board: Board,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Escalate safely")
    with board.edit(task.id) as stored:
        stored.role = "code-worker"
        stored.state = "in_progress"
    callback_dir = AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "escalation_request",
        "task_id": task.id,
        "title": "Need help",
        "context": "stuck",
        "checklist": ["decide"],
        "unblock": ["answer"],
        "urgency": "high",
        "actor": "code-worker",
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "saturnin.escalation.submit",
        lambda **kwargs: "https://github.com/JakubMifek/saturnin/issues/1",
    )

    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    stored = board.get(task.id)
    assert stored.state == "blocked"
    assert any(
        entry["event"] == "state:blocked"
        and entry["actor"] == "code-worker"
        and entry["note"] == "escalated: https://github.com/JakubMifek/saturnin/issues/1"
        for entry in stored.history
    )


def test_worker_callback_rejects_direct_blocked_transition(
    config: Config,
    board: Board,
) -> None:
    task = board.create("Reject fake escalation")
    with board.edit(task.id) as stored:
        stored.role = "code-worker"
        stored.state = "in_progress"
    callback_dir = AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "task_move",
        "task_id": task.id,
        "state": "blocked",
        "actor": "code-worker",
        "note": "escalated: https://github.com/example/repo/issues/1",
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="escalation_request"):
        apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    assert board.get(task.id).state == "in_progress"


def test_worker_callback_runs_ops_host_command(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Restart timer")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "fix/restart-timer"
    )
    with board.edit(task.id) as stored:
        stored.role = "ops-worker"
        stored.state = "in_progress"
        stored.branch = worktree.branch
        stored.worktree = str(worktree.path)
    callback_dir = AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    callback = {
        "type": "server_command",
        "task_id": task.id,
        "cmdline": "systemctl --user restart saturnin-janitor.timer",
        "service": None,
    }
    (callback_dir / CALLBACKS_FILE).write_text(
        json.dumps(callback) + "\n",
        encoding="utf-8",
    )
    calls: list[tuple[list[str], Path]] = []
    real_bounded = worker_callbacks._run_bounded_command

    def run_command(args, *, cwd, env, **kwargs):
        if args[0] == "git":
            return real_bounded(args, cwd=cwd, env=env, **kwargs)
        calls.append((list(args), cwd))
        return worker_callbacks._BoundedCommandResult(
            returncode=0,
            stdout="ok\n",
            stderr="",
            timed_out=False,
            output_truncated=False,
        )

    monkeypatch.setattr("saturnin.governance.os.geteuid", lambda: 1000)
    monkeypatch.setattr("saturnin.worker_callbacks._run_bounded_command", run_command)

    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    assert calls == [
        (
            ["systemctl", "--user", "restart", "saturnin-janitor.timer"],
            worktree.path.resolve(),
        )
    ]
    stored = board.get(task.id)
    assert any(entry["event"] == "host:command_started" for entry in stored.history)
    assert any(
        entry["event"] == "host:command_finished" and entry["returncode"] == 0
        for entry in stored.history
    )
    assert (
        config.var_dir / "logs" / "host-operations" / f"{task.id}.jsonl"
    ).is_file()


def test_host_commands_dedupe_only_the_same_callback(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Repeat host command")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "fix/repeat-host-command"
    )
    with board.edit(task.id) as stored:
        stored.role = "ops-worker"
        stored.state = "in_progress"
        stored.branch = worktree.branch
        stored.worktree = str(worktree.path)
    calls: list[list[str]] = []
    real_bounded = worker_callbacks._run_bounded_command

    def run_command(args, *, cwd, env, **kwargs):
        if args[0] == "git":
            return real_bounded(args, cwd=cwd, env=env, **kwargs)
        calls.append(list(args))
        with board.edit(task.id) as stored:
            stored.labels.append(f"host-call-{len(calls)}")
        return worker_callbacks._BoundedCommandResult(
            returncode=0,
            stdout="",
            stderr="",
            timed_out=False,
            output_truncated=False,
        )

    monkeypatch.setattr("saturnin.governance.os.geteuid", lambda: 1000)
    monkeypatch.setattr("saturnin.worker_callbacks._run_bounded_command", run_command)
    command = "systemctl --user restart saturnin-janitor.timer"

    run_server_command(
        config,
        board,
        task_id=task.id,
        cmdline=command,
        callback_id="a" * 32,
    )
    run_server_command(
        config,
        board,
        task_id=task.id,
        cmdline=command,
        callback_id="b" * 32,
    )
    run_server_command(
        config,
        board,
        task_id=task.id,
        cmdline=command,
        callback_id="b" * 32,
    )

    assert calls == [
        ["systemctl", "--user", "restart", "saturnin-janitor.timer"],
        ["systemctl", "--user", "restart", "saturnin-janitor.timer"],
    ]


def test_bounded_command_caps_output_and_times_out(git_repo: Path) -> None:
    output = worker_callbacks._run_bounded_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
        cwd=git_repo,
        env=os.environ.copy(),
        timeout=5,
        output_limit=128,
    )

    assert output.returncode == 0
    assert output.output_truncated
    assert output.stdout == "x" * 128 + worker_callbacks._OUTPUT_TRUNCATED

    timed_out = worker_callbacks._run_bounded_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=git_repo,
        env=os.environ.copy(),
        timeout=0.01,
    )

    assert timed_out.timed_out
    assert timed_out.returncode != 0


def test_bounded_command_tracks_closed_pipes_and_kills_descendants(
    git_repo: Path,
) -> None:
    script = (
        "import os, subprocess, sys, time;"
        "child=subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(30)'], stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL);"
        "print(child.pid, flush=True);"
        "os.close(1); os.close(2);"
        "time.sleep(30)"
    )

    result = worker_callbacks._run_bounded_command(
        [sys.executable, "-c", script],
        cwd=git_repo,
        env=os.environ.copy(),
        timeout=0.05,
    )

    assert result.timed_out
    child_pid = int(result.stdout.strip())
    deadline = time.monotonic() + 2
    while _process_is_running(child_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _process_is_running(child_pid)


def _process_is_running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


def test_host_command_timeout_is_audited(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Bound host command")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "fix/bound-host-command"
    )
    with board.edit(task.id) as stored:
        stored.role = "ops-worker"
        stored.state = "in_progress"
        stored.branch = worktree.branch
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.governance.os.geteuid", lambda: 1000)
    real_bounded = worker_callbacks._run_bounded_command

    def timeout_command(args, *, cwd, env, **kwargs):
        if args[0] == "git":
            return real_bounded(args, cwd=cwd, env=env, **kwargs)
        return worker_callbacks._BoundedCommandResult(
            returncode=-9,
            stdout="",
            stderr="",
            timed_out=True,
            output_truncated=False,
        )

    monkeypatch.setattr(
        "saturnin.worker_callbacks._run_bounded_command",
        timeout_command,
    )

    with pytest.raises(WorkerCallbackError, match="timed out"):
        run_server_command(
            config,
            board,
            task_id=task.id,
            cmdline="systemctl --user restart saturnin-janitor.timer",
            callback_id="c" * 32,
        )

    finished = board.get(task.id).history[-1]
    assert finished["event"] == "host:command_finished"
    assert finished["callback_id"] == "c" * 32
    assert finished["timed_out"] is True


def test_ops_host_git_command_cannot_escape_task_worktree(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Repair task branch")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "fix/task-branch"
    )
    with board.edit(task.id) as stored:
        stored.role = "ops-worker"
        stored.state = "in_progress"
        stored.branch = worktree.branch
        stored.worktree = str(worktree.path)
    config.policy("server_scope")["filesystem"]["writable_roots"] = [
        str(config.root)
    ]
    monkeypatch.setattr("saturnin.governance.os.geteuid", lambda: 1000)

    with pytest.raises(WorkerCallbackError, match="outside task worktree"):
        run_server_command(
            config,
            board,
            task_id=task.id,
            cmdline=f"git -C {config.root} reset --hard",
        )


def test_trusted_push_callback_delivers_exact_isolated_commit(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Deliver isolated commit", repo="JakubMifek/saturnin")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/trusted-delivery"
    )
    with board.edit(task.id) as stored:
        stored.branch = worktree.branch
        stored.worktree = str(worktree.path)
    launcher = AgentLauncher(config, board)
    home = launcher._isolated_home(task.id)
    callback_dir = home / ".saturnin-callbacks"
    callback_dir.mkdir(parents=True)
    environment, _ = launcher._isolated_git_environment(
        board.get(task.id),
        worktree.path,
        home,
    )
    process_environment = {**os.environ, **environment}
    assert subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        text=True,
    ).returncode != 0
    assert subprocess.run(
        ["git", "remote", "get-url", "--push", "origin"],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        text=True,
    ).returncode != 0
    changed = worktree.path / "delivered.txt"
    changed.write_text("trusted\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "delivered.txt"],
        cwd=worktree.path,
        env=process_environment,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "isolated delivery"],
        cwd=worktree.path,
        env=process_environment,
        check=True,
        capture_output=True,
    )
    isolated_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    remote = config.root / "delivery-remote.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "remote", "set-url", "--push", "origin", str(remote)],
        cwd=git_repo,
        check=True,
    )
    monkeypatch.setenv(ENV_CALLBACK_DIR, str(callback_dir))
    monkeypatch.setenv(ENV_CALLBACK_TASK_ID, task.id)
    monkeypatch.setenv("SATURNIN_WORKTREE", str(worktree.path))
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    assert main(["push", "--remote", "bad/name"]) == 1
    assert not (callback_dir / CALLBACKS_FILE).exists()
    assert main(["push"]) == 0
    queued = json.loads(
        (callback_dir / CALLBACKS_FILE).read_text(encoding="utf-8")
    )
    assert queued["commit"] == isolated_head
    assert queued["branch"] == worktree.branch
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(
        "saturnin.worker_callbacks.github_repo_slug",
        lambda value, **kwargs: "JakubMifek/saturnin",
    )
    apply_queued(config, board, task_id=task.id, callback_dir=str(callback_dir))

    remote_head = subprocess.run(
        ["git", "--git-dir", str(remote), "rev-parse", worktree.branch],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    local_head = subprocess.run(
        ["git", "rev-parse", worktree.branch],
        cwd=git_repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert remote_head == isolated_head
    assert local_head == isolated_head
    assert subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=worktree.path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout == ""


def test_isolated_git_metadata_supports_commit_without_changing_shared_refs(
    config: Config,
    board: Board,
    git_repo: Path,
) -> None:
    task = board.create("Commit with isolated Git metadata")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/isolated-git"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/isolated-git"
        stored.worktree = str(worktree.path)
    task = board.get(task.id)
    launcher = AgentLauncher(config, board)
    home = launcher._isolated_home(task.id)
    subprocess.run(
        ["git", "config", "credential.helper", "!host-secret-helper"],
        cwd=git_repo,
        check=True,
    )
    environment, objects = launcher._isolated_git_environment(
        task,
        worktree.path,
        home,
    )
    process_environment = {**os.environ, **environment}
    shared_branch_before = subprocess.run(
        ["git", "rev-parse", task.branch],
        cwd=git_repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    protected_before = subprocess.run(
        ["git", "rev-parse", "main"],
        cwd=git_repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    changed = worktree.path / "worker-change.txt"
    changed.write_text("isolated\n", encoding="utf-8")

    subprocess.run(
        ["git", "add", "worker-change.txt"],
        cwd=worktree.path,
        env=process_environment,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "isolated worker commit"],
        cwd=worktree.path,
        env=process_environment,
        check=True,
        capture_output=True,
    )

    private_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    isolated_remote = subprocess.run(
        ["git", "remote", "get-url", "--push", "--all", "origin"],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    isolated_remote_config = subprocess.run(
        ["git", "config", "--get-regexp", r"^remote\.origin\."],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert private_head != shared_branch_before
    assert isolated_remote.returncode != 0
    assert isolated_remote_config.returncode != 0
    assert subprocess.run(
        ["git", "rev-parse", task.branch],
        cwd=git_repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip() == shared_branch_before
    assert subprocess.run(
        ["git", "rev-parse", "main"],
        cwd=git_repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip() == protected_before
    assert Path(environment["GIT_DIR"]).is_relative_to(home)
    assert Path(environment["GIT_DIR"]).stat().st_mode & 0o777 == 0o700
    assert objects == (git_repo / ".git" / "objects").resolve()
    assert subprocess.run(
        ["git", "config", "--get", "credential.helper"],
        cwd=worktree.path,
        env=process_environment,
        capture_output=True,
        check=False,
    ).returncode == 1


@pytest.mark.parametrize(
    ("remote_url", "message"),
    [
        ("file:///home/runner/repository", "unrecognized"),
        ("https://token@github.com/JakubMifek/saturnin.git", "unrecognized"),
        ("https://github.com/other/project.git", "direct pushes"),
    ],
)
def test_isolated_git_rejects_untrusted_push_destinations(
    config: Config,
    board: Board,
    git_repo: Path,
    remote_url: str,
    message: str,
) -> None:
    task = board.create("Reject unsafe push destination")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/reject-push-url"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/reject-push-url"
        stored.worktree = str(worktree.path)
    subprocess.run(
        ["git", "remote", "set-url", "--push", "origin", remote_url],
        cwd=git_repo,
        check=True,
    )
    launcher = AgentLauncher(config, board)

    with pytest.raises(LauncherError, match=message):
        launcher._isolated_git_environment(
            board.get(task.id),
            worktree.path,
            launcher._isolated_home(task.id),
        )


def test_launcher_fails_closed_without_worker_sandbox(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Do not launch unsandboxed")
    Router(config).dispatch(board, task)

    monkeypatch.setattr(
        "saturnin.launcher.shutil.which",
        lambda executable: "/usr/bin/copilot" if executable == "copilot" else None,
    )

    with pytest.raises(LauncherError, match="required worker sandbox executable"):
        AgentLauncher(config, board).launch(task.id)

    assert board.get(task.id).state == "routed"


def test_launcher_intersects_role_mcp_with_project_allowlist(
    config: Config, board: Board, git_repo: Path, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement a restricted fix")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/restricted-launch"
    )
    manifest = worktree.path / ".saturnin" / "repo.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("mcp: []\n", encoding="utf-8")
    with board.edit(task.id) as stored:
        stored.branch = "feature/restricted-launch"
        stored.worktree = str(worktree.path)

    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs)
            if command[0] == "git"
            else SimpleNamespace(pid=4242)
        ),
    )

    AgentLauncher(config, board).launch(task.id)

    mcp = json.loads((config.var_dir / "launches" / f"{task.id}.mcp.json").read_text())
    assert mcp["mcpServers"] == {}


def test_launcher_loads_project_local_contract(
    config: Config, board: Board, git_repo: Path
) -> None:
    task = board.create("Run a project migration")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/local-agent"
    )
    agent = worktree.path / ".saturnin" / "agents" / "db-migrator.md"
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.write_text(
        "---\nrole: db-migrator\nskills: [checkpointing]\nmcp: []\n---\n"
        "# Database migrator\n",
        encoding="utf-8",
    )
    (worktree.path / ".saturnin" / "repo.yaml").write_text(
        "agents: [.saturnin/agents/db-migrator.md]\n",
        encoding="utf-8",
    )
    with board.edit(task.id) as stored:
        stored.role = "db-migrator"
        stored.worktree = str(worktree.path)

    contract = AgentLauncher(config, board)._contract(board.get(task.id))

    assert contract.role == "db-migrator"
    assert contract.path == agent


def test_launcher_rejects_project_agent_symlink_escape(
    config: Config, board: Board, git_repo: Path
) -> None:
    task = board.create("Run a project migration")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/symlink-agent"
    )
    outside = config.root / "outside-agent.md"
    outside.write_text(
        "---\nrole: db-migrator\nskills: [checkpointing]\nmcp: []\n---\n",
        encoding="utf-8",
    )
    agent = worktree.path / ".saturnin" / "agents" / "db-migrator.md"
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.symlink_to(outside)
    (worktree.path / ".saturnin" / "repo.yaml").write_text(
        "agents: [.saturnin/agents/db-migrator.md]\n",
        encoding="utf-8",
    )
    with board.edit(task.id) as stored:
        stored.role = "db-migrator"
        stored.worktree = str(worktree.path)

    with pytest.raises(LauncherError, match="stay inside"):
        AgentLauncher(config, board)._contract(board.get(task.id))


def test_launcher_rejects_manifest_symlink_escape(
    config: Config, board: Board, git_repo: Path
) -> None:
    task = board.create("Run a project migration")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/symlink-manifest"
    )
    manifest = worktree.path / ".saturnin" / "repo.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    outside = config.root / "outside-manifest.yaml"
    outside.write_text("agents: []\n", encoding="utf-8")
    manifest.symlink_to(outside)
    with board.edit(task.id) as stored:
        stored.role = "code-worker"
        stored.worktree = str(worktree.path)

    with pytest.raises(LauncherError, match="manifest must stay inside"):
        AgentLauncher(config, board)._contract(board.get(task.id))


def test_malformed_project_yaml_leaves_checkpoint_available_for_retry(
    config: Config, board: Board, git_repo: Path, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Resume a restricted fix")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/retry-launch"
    )
    manifest = worktree.path / ".saturnin" / "repo.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("mcp: [\n", encoding="utf-8")
    with board.edit(task.id) as stored:
        stored.branch = "feature/retry-launch"
        stored.worktree = str(worktree.path)
    checkpoint = CheckpointStore(config, board).save(
        Checkpoint(
            task_id=task.id,
            role="code-worker",
            summary="Retry after launcher validation.",
            next_steps=["Resume implementation."],
            resume_after=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        )
    )
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")

    with pytest.raises(LauncherError, match="invalid managed repository manifest"):
        AgentLauncher(config, board).launch(
            task.id, resumed_checkpoint=checkpoint.created_at
        )

    stored = board.get(task.id)
    assert stored.state == "routed"
    assert stored.checkpoint_resumed_at is None
    assert [item.task_id for item in CheckpointStore(config, board).due()] == [task.id]

    manifest.write_text("mcp: []\n", encoding="utf-8")
    real_popen = subprocess.Popen
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs)
            if command[0] == "git"
            else SimpleNamespace(pid=4242)
        ),
    )
    AgentLauncher(config, board).launch(
        task.id, resumed_checkpoint=checkpoint.created_at
    )

    assert CheckpointStore(config, board).due() == []


def test_launcher_refuses_to_run_without_attached_worktree(
    config: Config, board: Board, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement a small fix")
    Router(config).dispatch(board, task)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")

    try:
        AgentLauncher(config, board).launch(task.id, resumed_checkpoint="checkpoint-1")
    except LauncherError as exc:
        assert "attached branch" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("launcher accepted a task without a worktree")
    stored = board.get(task.id)
    assert stored.state == "routed"
    assert stored.checkpoint_resumed_at is None


def test_launcher_refuses_an_external_repository_main_checkout(
    config: Config, board: Board
) -> None:
    checkout = config.root / "managed-main"
    checkout.mkdir()
    subprocess.run(
        ["git", "init", "-b", "feature/direct"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )
    task = board.create("Do not launch in a primary checkout")
    with board.edit(task.id) as stored:
        stored.branch = "feature/direct"
        stored.worktree = str(checkout)

    with pytest.raises(LauncherError, match="repository's main checkout"):
        AgentLauncher(config, board)._validated_workdir(board.get(task.id))


def test_launcher_reads_checkpoint_before_claiming_board_lock(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Launch without inverted locks")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/ordered-locks"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/ordered-locks"
        stored.worktree = str(worktree.path)

    inside_edit = False
    original_edit = board.edit

    @contextmanager
    def tracked_edit(task_id):
        nonlocal inside_edit
        with original_edit(task_id) as stored:
            inside_edit = True
            try:
                yield stored
            finally:
                inside_edit = False

    def latest(self, task_id):
        assert not inside_edit
        return None

    monkeypatch.setattr(board, "edit", tracked_edit)
    monkeypatch.setattr(CheckpointStore, "latest", latest)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs)
            if command[0] == "git"
            else SimpleNamespace(pid=4242)
        ),
    )

    AgentLauncher(config, board).launch(task.id)


def test_launcher_rolls_back_claim_when_spawn_fails(
    config: Config, board: Board, git_repo: Path, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement a small fix")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create("feature/fail-launch")
    with board.edit(task.id) as stored:
        stored.branch = "feature/fail-launch"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs)
            if command[0] == "git"
            else (_ for _ in ()).throw(OSError("boom"))
        ),
    )

    try:
        AgentLauncher(config, board).launch(task.id, resumed_checkpoint="checkpoint-1")
    except LauncherError as exc:
        assert "boom" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("launcher did not report spawn failure")

    stored = board.get(task.id)
    assert stored.state == "routed"
    assert stored.checkpoint_resumed_at is None
    assert stored.history[-1]["event"] == "agent:launch_failed"
    assert not any(entry["event"] == "state:in_progress" for entry in stored.history)


def test_launcher_terminates_and_rolls_back_when_metadata_persistence_fails(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Persist launch recovery metadata")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/metadata-failure"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/metadata-failure"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen

    class RunningProcess:
        pid = 4242
        terminated = False

        def wait(self, timeout=None):
            if not self.terminated:
                raise subprocess.TimeoutExpired("copilot", timeout)
            return -15

        def terminate(self):
            self.terminated = True

    process = RunningProcess()
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs) if command[0] == "git" else process
        ),
    )

    def fail_after_replace(
        path: Path,
        text: str,
        *,
        mode: int | None = None,
    ) -> None:
        path.write_text(text, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)
        if path.name == f"{task.id}.json":
            raise OSError("metadata fsync failed")

    monkeypatch.setattr("saturnin.launcher.atomic_replace_text", fail_after_replace)

    with pytest.raises(LauncherError, match="metadata fsync failed"):
        AgentLauncher(config, board).launch(task.id, resumed_checkpoint="checkpoint-1")

    stored = board.get(task.id)
    assert process.terminated
    assert stored.state == "routed"
    assert stored.checkpoint_resumed_at is None
    assert stored.history[-1]["event"] == "agent:launch_failed"
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()


def test_launcher_terminates_without_illegal_partial_board_rollback(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Recover partially persisted launch")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/board-persistence-failure"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/board-persistence-failure"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen

    class RunningProcess:
        pid = 4242
        terminated = False

        def wait(self, timeout=None):
            if not self.terminated:
                raise subprocess.TimeoutExpired("copilot", timeout)
            return -15

        def terminate(self):
            self.terminated = True

    process = RunningProcess()
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs) if command[0] == "git" else process
        ),
    )
    original_write = board._write
    failed = False

    def fail_after_board_replace(path: Path, stored) -> None:
        nonlocal failed
        original_write(path, stored)
        if not failed and any(
            entry["event"] == "agent:launched" for entry in stored.history
        ):
            failed = True
            raise OSError("board directory fsync failed")

    monkeypatch.setattr(board, "_write", fail_after_board_replace)

    with pytest.raises(LauncherError, match="board directory fsync failed"):
        AgentLauncher(config, board).launch(task.id, resumed_checkpoint="checkpoint-1")

    stored = board.get(task.id)
    assert process.terminated
    assert stored.state == "in_progress"
    assert stored.checkpoint_resumed_at is None
    assert stored.launch_deferred_at is not None
    assert "board directory fsync failed" in stored.launch_deferred_reason
    assert stored.history[-1]["event"] == "agent:launch_failed"
    assert [entry["event"] for entry in stored.history].count("state:routed") == 1
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()


def test_launcher_rolls_back_claim_when_child_exits_immediately(
    config: Config, board: Board, git_repo: Path, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement a small fix")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create("feature/exit-launch")
    with board.edit(task.id) as stored:
        stored.branch = "feature/exit-launch"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen

    class ExitedProcess:
        pid = 4242

        def wait(self, timeout=None):
            return 17

    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: real_popen(command, **kwargs)
        if command[0] == "git"
        else ExitedProcess(),
    )

    with pytest.raises(LauncherError, match="exited immediately"):
        AgentLauncher(config, board).launch(task.id, resumed_checkpoint="checkpoint-1")

    stored = board.get(task.id)
    assert stored.state == "routed"
    assert stored.checkpoint_resumed_at is None
    assert stored.history[-1]["event"] == "agent:launch_failed"
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()


def test_launcher_reconciles_callbacks_when_child_completes_during_grace(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Complete a small fix")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/complete-launch"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/complete-launch"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    callback_dir = (
        AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    )
    callback_dir.mkdir(parents=True)
    process_events: list[str] = []
    real_popen = subprocess.Popen

    class CompletedProcess:
        pid = 4242

        def wait(self, timeout=None):
            process_events.append("wait")
            (callback_dir / CALLBACKS_FILE).write_text(
                json.dumps(
                    {
                        "type": "task_move",
                        "task_id": task.id,
                        "state": "review",
                        "actor": "code-worker",
                        "note": "ready",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return 0

    monkeypatch.setattr(
        AgentLauncher,
        "_process_start_time",
        staticmethod(lambda pid: process_events.append("identity") or 123456),
    )
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs)
            if command[0] == "git"
            else CompletedProcess()
        ),
    )

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    assert process_events == ["identity", "wait"]
    assert board.get(task.id).state == "review"
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()
    assert not (callback_dir / CALLBACKS_FILE).exists()


@pytest.mark.parametrize("failed_persistence", ["metadata", "board"])
def test_launcher_preserves_completed_callback_when_persistence_fails(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_persistence: str,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Fix and preserve a completed worker result")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        f"feature/completed-{failed_persistence}-failure"
    )
    with board.edit(task.id) as stored:
        stored.branch = f"feature/completed-{failed_persistence}-failure"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    callback_dir = (
        AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    )
    callback_dir.mkdir(parents=True)
    real_popen = subprocess.Popen

    class CompletedProcess:
        pid = 4242
        terminated = False

        def wait(self, timeout=None):
            (callback_dir / CALLBACKS_FILE).write_text(
                json.dumps(
                    {
                        "type": "task_move",
                        "task_id": task.id,
                        "state": "review",
                        "actor": "code-worker",
                        "note": "ready",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return 0

        def terminate(self):
            self.terminated = True

    process = CompletedProcess()
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs) if command[0] == "git" else process
        ),
    )
    failed = False
    if failed_persistence == "metadata":

        def fail_metadata_once(
            path: Path,
            text: str,
            *,
            mode: int | None = None,
        ) -> None:
            nonlocal failed
            if not failed and path.name == f"{task.id}.json":
                failed = True
                raise OSError("metadata fsync failed")
            path.write_text(text, encoding="utf-8")
            if mode is not None:
                path.chmod(mode)

        monkeypatch.setattr(
            "saturnin.launcher.atomic_replace_text", fail_metadata_once
        )
    else:
        original_write = board._write

        def fail_board_once(path: Path, stored) -> None:
            nonlocal failed
            if not failed and any(
                entry["event"] == "agent:launched" for entry in stored.history
            ):
                failed = True
                raise OSError("board directory fsync failed")
            original_write(path, stored)

        monkeypatch.setattr(board, "_write", fail_board_once)

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    assert failed
    assert not process.terminated
    assert board.get(task.id).state == "review"
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()
    assert not (callback_dir / CALLBACKS_FILE).exists()


@pytest.mark.parametrize("failed_persistence", ["metadata", "board"])
def test_launcher_recovers_completion_after_grace_when_persistence_fails(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_persistence: str,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Recover a worker that exits while launch persistence fails")
    Router(config).dispatch(board, task)
    callback_actor = board.get(task.id).role
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        f"feature/post-grace-{failed_persistence}-failure"
    )
    with board.edit(task.id) as stored:
        stored.branch = f"feature/post-grace-{failed_persistence}-failure"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    callback_dir = (
        AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    )
    callback_dir.mkdir(parents=True)
    real_popen = subprocess.Popen

    class CompletingProcess:
        pid = 4242
        wait_count = 0
        terminated = False

        def wait(self, timeout=None):
            self.wait_count += 1
            if self.wait_count == 1:
                raise subprocess.TimeoutExpired("copilot", timeout)
            (callback_dir / CALLBACKS_FILE).write_text(
                json.dumps(
                    {
                        "type": "task_move",
                        "task_id": task.id,
                        "state": "review",
                        "actor": callback_actor,
                        "note": "ready",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return 0

        def terminate(self):
            self.terminated = True

    process = CompletingProcess()
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs) if command[0] == "git" else process
        ),
    )
    failed = False
    if failed_persistence == "metadata":

        def fail_metadata_once(
            path: Path,
            text: str,
            *,
            mode: int | None = None,
        ) -> None:
            nonlocal failed
            if not failed and path.name == f"{task.id}.json":
                failed = True
                raise OSError("metadata fsync failed")
            path.write_text(text, encoding="utf-8")
            if mode is not None:
                path.chmod(mode)

        monkeypatch.setattr(
            "saturnin.launcher.atomic_replace_text", fail_metadata_once
        )
    else:
        original_write = board._write

        def fail_board_once(path: Path, stored) -> None:
            nonlocal failed
            if not failed and any(
                entry["event"] == "agent:launched" for entry in stored.history
            ):
                failed = True
                raise OSError("board directory fsync failed")
            original_write(path, stored)

        monkeypatch.setattr(board, "_write", fail_board_once)

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    assert failed
    assert process.wait_count == 2
    assert not process.terminated
    assert board.get(task.id).state == "review"
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()
    assert not (callback_dir / CALLBACKS_FILE).exists()


def test_launcher_preserves_completion_racing_with_termination(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Recover a worker completing during cleanup")
    Router(config).dispatch(board, task)
    callback_actor = board.get(task.id).role
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/cleanup-race"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/cleanup-race"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    callback_dir = (
        AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    )
    callback_dir.mkdir(parents=True)
    real_popen = subprocess.Popen

    class CompletingProcess:
        pid = 4242
        wait_count = 0
        terminate_attempted = False

        def wait(self, timeout=None):
            self.wait_count += 1
            if self.wait_count < 3:
                if self.wait_count == 2:
                    (callback_dir / CALLBACKS_FILE).write_text(
                        json.dumps(
                            {
                                "type": "task_move",
                                "task_id": task.id,
                                "state": "review",
                                "actor": callback_actor,
                                "note": "ready",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                raise subprocess.TimeoutExpired("copilot", timeout)
            return 0

        def terminate(self):
            self.terminate_attempted = True
            raise ProcessLookupError

    process = CompletingProcess()
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs) if command[0] == "git" else process
        ),
    )
    failed = False

    def fail_metadata_once(
        path: Path,
        text: str,
        *,
        mode: int | None = None,
    ) -> None:
        nonlocal failed
        if not failed and path.name == f"{task.id}.json":
            failed = True
            raise OSError("metadata fsync failed")
        path.write_text(text, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)

    monkeypatch.setattr("saturnin.launcher.atomic_replace_text", fail_metadata_once)

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    assert process.terminate_attempted
    assert process.wait_count == 3
    assert board.get(task.id).state == "review"
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()
    assert not (callback_dir / CALLBACKS_FILE).exists()


@pytest.mark.parametrize("callback_valid", [True, False])
def test_launcher_directly_reconciles_when_completed_metadata_cannot_persist(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    callback_valid: bool,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Recover a completed worker without launch metadata")
    Router(config).dispatch(board, task)
    callback_actor = board.get(task.id).role if callback_valid else "wrong-role"
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/completed-metadata-failure"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/completed-metadata-failure"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    callback_dir = (
        AgentLauncher(config, board)._isolated_home(task.id) / ".saturnin-callbacks"
    )
    callback_dir.mkdir(parents=True)
    real_popen = subprocess.Popen

    class CompletedProcess:
        pid = 4242
        terminated = False

        def wait(self, timeout=None):
            (callback_dir / CALLBACKS_FILE).write_text(
                json.dumps(
                    {
                        "type": "task_move",
                        "task_id": task.id,
                        "state": "review",
                        "actor": callback_actor,
                        "note": "ready",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return 0

        def terminate(self):
            self.terminated = True

    process = CompletedProcess()
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            real_popen(command, **kwargs) if command[0] == "git" else process
        ),
    )
    failed_writes = 0

    def fail_metadata(
        path: Path,
        text: str,
        *,
        mode: int | None = None,
    ) -> None:
        nonlocal failed_writes
        if path.name == f"{task.id}.json":
            failed_writes += 1
            raise OSError("metadata fsync failed")
        path.write_text(text, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)

    monkeypatch.setattr("saturnin.launcher.atomic_replace_text", fail_metadata)

    inside_board_edit = False
    original_edit = board.edit

    @contextmanager
    def tracked_edit(task_id):
        nonlocal inside_board_edit
        with original_edit(task_id) as stored:
            inside_board_edit = True
            try:
                yield stored
            finally:
                inside_board_edit = False

    callback_lock_states: list[bool] = []

    def tracked_apply_queued(*args, **kwargs):
        callback_lock_states.append(inside_board_edit)
        return apply_queued(*args, **kwargs)

    monkeypatch.setattr(board, "edit", tracked_edit)
    monkeypatch.setattr("saturnin.launcher.apply_queued", tracked_apply_queued)

    if callback_valid:
        result = AgentLauncher(config, board).launch(task.id)
        assert result is not None
        assert board.get(task.id).state == "review"
        assert not (callback_dir / CALLBACKS_FILE).exists()
    else:
        with pytest.raises(
            LauncherError,
            match="recovery remains pending: .*worker callbacks failed",
        ):
            AgentLauncher(config, board).launch(task.id)
        retained = board.get(task.id)
        assert retained.state == "in_progress"
        assert retained.launch_deferred_at is None
        assert retained.history[-1]["event"] == "agent:callback_failed"
        assert (callback_dir / CALLBACKS_FILE).exists()

        callback = json.loads((callback_dir / CALLBACKS_FILE).read_text())
        callback["actor"] = retained.role
        (callback_dir / CALLBACKS_FILE).write_text(
            json.dumps(callback) + "\n", encoding="utf-8"
        )

        assert AgentLauncher(config, board).reconcile_exited_launches() == []
        assert board.get(task.id).state == "review"
        assert not (callback_dir / CALLBACKS_FILE).exists()

    assert failed_writes == 2
    assert not process.terminated
    assert callback_lock_states == ([False] if callback_valid else [False, False])
    assert not (config.var_dir / "launches" / f"{task.id}.json").exists()


def test_launcher_rejects_unauthorized_project_mcp(
    config: Config, board: Board, git_repo: Path, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Run a project migration")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/local-mcp"
    )
    agent = worktree.path / ".saturnin" / "agents" / "db-migrator.md"
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.write_text(
        "---\nrole: db-migrator\nskills: [checkpointing]\nmcp: [filesystem]\n---\n"
        "# Database migrator\n",
        encoding="utf-8",
    )
    (worktree.path / ".saturnin" / "repo.yaml").write_text(
        "agents: [.saturnin/agents/db-migrator.md]\nmcp: [filesystem]\n",
        encoding="utf-8",
    )
    with board.edit(task.id) as stored:
        stored.state = "routed"
        stored.role = "db-migrator"
        stored.branch = "feature/local-mcp"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")

    with pytest.raises(LauncherError, match="not authorized"):
        AgentLauncher(config, board).launch(task.id)


def test_launcher_uses_trusted_source_for_linked_saturnin_worktree(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Use trusted worker policy")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/branch-local-source"
    )
    routed = board.get(task.id)
    contract = worktree.path / "agents" / f"{routed.role}.md"
    heading = contract.read_text(encoding="utf-8").splitlines()[8]
    contract.write_text(
        contract.read_text(encoding="utf-8").replace(
            heading, "# Branch-local Worker"
        ),
        encoding="utf-8",
    )
    skill = worktree.path / "skills" / "pr-authoring.md"
    skill.write_text("UNTRUSTED SKILL BODY\n", encoding="utf-8")
    runtime = worktree.path / "src" / "saturnin" / "governance.py"
    runtime.parent.mkdir(parents=True, exist_ok=True)
    runtime.write_text("raise SystemExit('untrusted runtime')\n", encoding="utf-8")
    with board.edit(task.id) as stored:
        stored.branch = "feature/branch-local-source"
        stored.worktree = str(worktree.path)
    calls: list[tuple[list[str], dict]] = []
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen

    def fake_popen(command, **kwargs):
        if command[0] == "git":
            return real_popen(command, **kwargs)
        calls.append((command, kwargs))
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr("saturnin.launcher.subprocess.Popen", fake_popen)

    launcher = AgentLauncher(config, board)
    assert launcher._worker_config(worktree.path).root == config.root.resolve()
    assert "# Branch-local Worker" not in launcher._contract(
        board.get(task.id), launcher._worker_config(worktree.path)
    ).path.read_text(encoding="utf-8")
    launcher.launch(task.id)

    assert "# Branch-local Worker" not in calls[0][0][-1]
    assert "UNTRUSTED SKILL BODY" not in calls[0][0][-1]
    assert calls[0][1]["env"]["SATURNIN_HOME"] == str(config.root)
    assert calls[0][1]["env"]["PYTHONPATH"] == str(config.root / "src")
    generated = json.loads(
        (config.var_dir / "launches" / f"{task.id}.mcp.json").read_text()
    )
    assert generated["mcpServers"]["github"]["args"] == [
        "stdio",
        "--read-only",
    ]
    assert (config.var_dir / "launches" / f"{task.id}.json").is_file()


def test_reconcile_exited_launch_keeps_legal_task_state(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Recover exited launch")
    Router(config).dispatch(board, task)
    board.transition(board.get(task.id), "in_progress")
    launch_file = config.var_dir / "launches" / f"{task.id}.json"
    launch_file.parent.mkdir(parents=True, exist_ok=True)
    launch_file.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "role": "code-worker",
                "pid": 4242,
                "process_start_time_ticks": 123456,
                "started_at": utcnow(),
                "cwd": str(config.root),
                "mcp_config": str(config.root / ".mcp.json"),
                "log": str(config.var_dir / "launches" / f"{task.id}.log"),
            }
        ),
        encoding="utf-8",
    )
    launcher = AgentLauncher(config, board)
    monkeypatch.setattr(launcher, "_process_start_time", lambda pid: None)

    reconciled = launcher.reconcile_exited_launches()

    restored = board.get(task.id)
    assert reconciled == [task.id]
    assert restored.state == "in_progress"
    assert restored.launch_deferred_reason == (
        "agent process exited or identity changed after launch with pid 4242"
    )
    assert (
        [entry["event"] for entry in restored.history].count("state:routed")
        == 1
    )
    assert restored.history[-1]["event"] == "agent:launch_failed"
    assert not launch_file.exists()


def test_reconcile_exited_poller_launch_keeps_waiting_task(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Wait for external signal")
    Router(config).dispatch(board, task)
    board.transition(board.get(task.id), "in_progress")
    with board.edit(task.id) as stored:
        stored.result_contract = "poller"
    poller = config.var_dir / "pollers" / f"{task.id}.json"
    poller.parent.mkdir(parents=True, exist_ok=True)
    poller.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "probe": {"type": "status-file", "path": "var/poller-signals/done.json"},
            }
        ),
        encoding="utf-8",
    )
    launch_file = config.var_dir / "launches" / f"{task.id}.json"
    launch_file.parent.mkdir(parents=True, exist_ok=True)
    launch_file.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "role": "code-worker",
                "pid": 4242,
                "process_start_time_ticks": 123456,
                "started_at": utcnow(),
                "cwd": str(config.root),
                "mcp_config": str(config.root / ".mcp.json"),
                "log": str(config.var_dir / "launches" / f"{task.id}.log"),
            }
        ),
        encoding="utf-8",
    )
    launcher = AgentLauncher(config, board)
    monkeypatch.setattr(launcher, "_process_start_time", lambda pid: None)

    reconciled = launcher.reconcile_exited_launches()

    waiting = board.get(task.id)
    assert reconciled == []
    assert waiting.state == "in_progress"
    assert waiting.launch_deferred_reason is None
    assert any(entry["event"] == "agent:poller_waiting" for entry in waiting.history)
    assert not launch_file.exists()


def test_reconcile_recovers_running_launch_with_partial_board_state(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Recover running launch")
    Router(config).dispatch(board, task)
    launch_file = config.var_dir / "launches" / f"{task.id}.json"
    launch_file.parent.mkdir(parents=True, exist_ok=True)
    launch_file.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "role": "code-worker",
                "pid": 4242,
                "process_start_time_ticks": 123456,
                "started_at": utcnow(),
                "cwd": str(config.root),
                "mcp_config": str(config.root / ".mcp.json"),
                "log": str(config.var_dir / "launches" / f"{task.id}.log"),
                "resumed_checkpoint": "checkpoint-1",
            }
        ),
        encoding="utf-8",
    )
    launcher = AgentLauncher(config, board)
    transitions: list[tuple[str, str]] = []
    apply_transition = board._apply_transition

    def tracked_transition(stored, state, *, actor, note):
        transitions.append((stored.state, state))
        apply_transition(stored, state, actor=actor, note=note)

    monkeypatch.setattr(board, "_apply_transition", tracked_transition)

    assert launcher.reconcile_exited_launches() == []

    restored = board.get(task.id)
    assert restored.state == "in_progress"
    assert restored.checkpoint_resumed_at == "checkpoint-1"
    assert restored.history[-2]["event"] == "agent:launch_recovered"
    assert transitions == [("routed", "in_progress")]
    assert launch_file.exists()
    with pytest.raises(LauncherError, match="already has an active"):
        launcher.launch(task.id)


def test_reconcile_records_failure_when_pid_belongs_to_different_process(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Recover reused pid")
    Router(config).dispatch(board, task)
    board.transition(board.get(task.id), "in_progress")
    launch_file = config.var_dir / "launches" / f"{task.id}.json"
    launch_file.parent.mkdir(parents=True, exist_ok=True)
    launch_file.write_text(
        json.dumps(
            {
                "task_id": task.id,
                "role": "code-worker",
                "pid": 4242,
                "process_start_time_ticks": 111111,
                "started_at": utcnow(),
            }
        ),
        encoding="utf-8",
    )
    launcher = AgentLauncher(config, board)
    monkeypatch.setattr(launcher, "_process_start_time", lambda pid: 222222)

    assert launcher.reconcile_exited_launches() == [task.id]

    assert board.get(task.id).state == "in_progress"
    assert not launch_file.exists()


@pytest.mark.parametrize(
    "proc_stat",
    [
        "malformed",
        "4242 (worker) S " + " ".join(["1"] * 18 + ["not-a-number"]),
    ],
)
def test_process_start_time_rejects_malformed_proc_stat(
    monkeypatch: pytest.MonkeyPatch, proc_stat: str
) -> None:
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: proc_stat)

    assert _REAL_PROCESS_START_TIME(4242) is None


def test_process_start_time_handles_inaccessible_proc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_read(self, **kwargs):
        raise PermissionError

    monkeypatch.setattr(Path, "read_text", deny_read)

    assert _REAL_PROCESS_START_TIME(4242) is None


def test_launcher_keeps_engine_source_for_managed_repository(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    primary = config.root / "managed-project"
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=primary,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "managed@example.com"],
        cwd=primary,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Managed"], cwd=primary, check=True)
    subprocess.run(
        [
            "git",
            "remote",
            "add",
            "origin",
            "http://localhost:26831/JakubMifek/saturnin",
        ],
        cwd=primary,
        check=True,
    )
    (primary / "README.md").write_text("managed\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=primary, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=primary, check=True)
    worktree = config.root / "managed-project-worktree"
    subprocess.run(
        ["git", "worktree", "add", "-b", "feature/managed", str(worktree)],
        cwd=primary,
        check=True,
        capture_output=True,
        text=True,
    )
    task = board.create("Change a managed repository")
    Router(config).dispatch(board, task)
    with board.edit(task.id) as stored:
        stored.branch = "feature/managed"
        stored.worktree = str(worktree)
    calls: list[dict] = []
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    real_popen = subprocess.Popen

    def fake_popen(command, **kwargs):
        if command[0] == "git":
            return real_popen(command, **kwargs)
        calls.append(kwargs)
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr("saturnin.launcher.subprocess.Popen", fake_popen)

    AgentLauncher(config, board).launch(task.id)

    assert calls[0]["env"]["SATURNIN_HOME"] == str(config.root)
    assert calls[0]["env"]["PYTHONPATH"].split(":")[0] == str(config.root / "src")


def test_launcher_worker_environment_uses_allowlist_and_constrained_github_token(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Constrain worker environment")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/worker-env-allowlist"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/worker-env-allowlist"
        stored.worktree = str(worktree.path)

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("GH_TOKEN", "host-gh-token")
    monkeypatch.setenv("GITHUB_TOKEN", "host-github-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "host-secret")
    monkeypatch.setenv("PYTHONPATH", "/host/untrusted")
    monkeypatch.setenv("HOME", "/host/home")
    monkeypatch.setenv("SATURNIN_GITHUB_MCP_TOKEN", "scoped-read-token")
    monkeypatch.setenv(
        "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY",
        "old-master-key",
    )
    config.policy("mcp")["launcher"]["env_allowlist"].append(
        "SATURNIN_REVIEW_ATTESTATION_KEY"
    )

    launcher = AgentLauncher(config, board)
    worker_config = launcher._worker_config(worktree.path)
    contract = launcher._contract(board.get(task.id), worker_config)
    environment = launcher._worker_environment(
        worker_config,
        contract,
        task=board.get(task.id),
        workdir=worktree.path,
    )

    assert environment["SATURNIN_HOME"] == str(config.root)
    assert environment["SATURNIN_WORKTREE"] == str(worktree.path)
    assert environment["PYTHONPATH"] == str(config.root / "src")
    assert environment["HOME"] != str(Path.home())
    assert Path(environment["HOME"]).is_dir()
    assert (Path(environment["HOME"]).stat().st_mode & 0o777) == 0o700
    assert environment["XDG_CONFIG_HOME"] == str(Path(environment["HOME"]) / ".config")
    assert environment["GITHUB_PERSONAL_ACCESS_TOKEN"] == "scoped-read-token"
    assert "GH_TOKEN" not in environment
    assert "GITHUB_TOKEN" not in environment
    assert "SATURNIN_REVIEW_ATTESTATION_KEY" not in environment
    assert "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY" not in environment
    assert environment["SATURNIN_AGENT_ROLE"] == contract.role
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "host" not in environment["PYTHONPATH"]


def test_launcher_preserves_approved_config_path_under_isolated_home(
    config: Config,
    board: Board,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_home = tmp_path / "real-home"
    gh_config = real_home / ".config" / "gh"
    gh_config.mkdir(parents=True)
    (gh_config / "hosts.yml").write_text("github.com: {}\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(real_home))
    config.policy("mcp")["launcher"]["approved_home_config"] = [str(gh_config)]

    isolated = AgentLauncher(config, board)._isolated_home("nested-xdg")

    assert (isolated / ".config" / "gh" / "hosts.yml").read_text(
        encoding="utf-8"
    ) == "github.com: {}\n"
    assert not (isolated / "gh").exists()


def test_launcher_supports_explicit_safe_approved_config_destination(
    config: Config,
    board: Board,
) -> None:
    source = config.root / "approved-gh-hosts.yml"
    source.write_text("github.com: {}\n", encoding="utf-8")
    config.policy("mcp")["launcher"]["approved_home_config"] = [
        {"source": str(source), "destination": ".config/gh/hosts.yml"}
    ]

    isolated = AgentLauncher(config, board)._isolated_home("explicit-destination")

    assert (isolated / ".config" / "gh" / "hosts.yml").read_text(
        encoding="utf-8"
    ) == "github.com: {}\n"


@pytest.mark.parametrize("destination", ["../outside", "/tmp/outside"])
def test_launcher_rejects_unsafe_approved_config_destinations(
    config: Config,
    board: Board,
    destination: str,
) -> None:
    source = config.root / "approved-config"
    source.write_text("ok\n", encoding="utf-8")
    config.policy("mcp")["launcher"]["approved_home_config"] = [
        {"source": str(source), "destination": destination}
    ]

    with pytest.raises(LauncherError, match="destination"):
        AgentLauncher(config, board)._isolated_home("unsafe-destination")


def test_launcher_rejects_approved_config_destination_collisions(
    config: Config,
    board: Board,
) -> None:
    first = config.root / "first-config"
    second = config.root / "second-config"
    first.write_text("one\n", encoding="utf-8")
    second.write_text("two\n", encoding="utf-8")
    config.policy("mcp")["launcher"]["approved_home_config"] = [
        {"source": str(first), "destination": ".config/tool/config"},
        {"source": str(second), "destination": ".config/tool/config"},
    ]

    with pytest.raises(LauncherError, match="duplicate approved_home_config destination"):
        AgentLauncher(config, board)._isolated_home("duplicate-destination")


def test_launcher_injects_role_scoped_attestation_key_only_for_reviewers(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY", "old-master-key")
    task = board.create("Review a pull request")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/reviewer-key"
    )
    with board.edit(task.id) as stored:
        stored.state = "routed"
        stored.role = "pr-reviewer"
        stored.unit = "assurance"
        stored.branch = "feature/reviewer-key"
        stored.worktree = str(worktree.path)

    launcher = AgentLauncher(config, board)
    worker_config = launcher._worker_config(worktree.path)
    contract = launcher._contract(board.get(task.id), worker_config)
    environment = launcher._worker_environment(
        worker_config,
        contract,
        task=board.get(task.id),
        workdir=worktree.path,
    )

    role_key = environment["SATURNIN_REVIEW_ATTESTATION_KEY"]
    assert role_key != "test-review-attestation-key"
    assert environment["SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE"] == "role"
    assert environment["SATURNIN_AGENT_ROLE"] == "pr-reviewer"
    assert "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY" not in environment

    attestation = sign_review_attestation(
        key=role_key,
        subject="JakubMifek/saturnin#reviewer-key",
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha="c" * 40,
    )
    with monkeypatch.context() as scoped:
        scoped.setenv("SATURNIN_REVIEW_ATTESTATION_KEY", role_key)
        scoped.setenv("SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE", "role")
        scoped.setenv("SATURNIN_AGENT_ROLE", "pr-reviewer")
        scoped.setenv("SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY", "old-master-key")
        ReviewLedger(config).record(
            subject="JakubMifek/saturnin#reviewer-key",
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha="c" * 40,
            attestation=attestation,
        )
    assert ReviewLedger(config).for_subject("JakubMifek/saturnin#reviewer-key", "pr")


def test_launcher_refuses_reviewer_without_attestation_key(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Review without a signing key")
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/no-reviewer-key"
    )
    with board.edit(task.id) as stored:
        stored.state = "routed"
        stored.role = "pr-reviewer"
        stored.unit = "assurance"
        stored.branch = "feature/no-reviewer-key"
        stored.worktree = str(worktree.path)
    monkeypatch.delenv("SATURNIN_REVIEW_ATTESTATION_KEY", raising=False)

    launcher = AgentLauncher(config, board)
    worker_config = launcher._worker_config(worktree.path)
    contract = launcher._contract(board.get(task.id), worker_config)

    with pytest.raises(LauncherError, match="requires SATURNIN_REVIEW_ATTESTATION_KEY"):
        launcher._worker_environment(
            worker_config,
            contract,
            task=board.get(task.id),
            workdir=worktree.path,
        )


def test_launcher_rejects_unverified_github_binary(
    config: Config,
    board: Board,
    git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement checksum validation")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/checksum-validation"
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/checksum-validation"
        stored.worktree = str(worktree.path)
    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")
    verification_roots: list[Path] = []

    def reject_binary(trusted: Config) -> Path:
        verification_roots.append(trusted.root)
        raise MCPError("checksum mismatch")

    monkeypatch.setattr(
        "saturnin.launcher.verify_github_binary",
        reject_binary,
    )

    with pytest.raises(LauncherError, match="checksum mismatch"):
        AgentLauncher(config, board).launch(task.id)

    assert verification_roots == [config.data_root]
    assert board.get(task.id).state == "routed"


def test_launcher_rejects_branch_local_github_replacement(
    config: Config, board: Board, git_repo: Path
) -> None:
    task = board.create("Reject a replaced GitHub server")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/replaced-github-mcp"
    )
    policy_path = worktree.path / "policies" / "mcp.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["servers"]["github"]["command"] = "/bin/echo"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with board.edit(task.id) as stored:
        stored.branch = "feature/replaced-github-mcp"
        stored.worktree = str(worktree.path)
    launcher = AgentLauncher(config, board)
    worker_config = launcher._worker_config(worktree.path)
    contract = launcher._contract(board.get(task.id), worker_config)

    with pytest.raises(LauncherError, match="alters trusted MCP server"):
        launcher._write_mcp_config(
            board.get(task.id),
            contract,
            config=worker_config,
            worktree_scope=worktree.path,
        )


def test_launcher_rejects_branch_local_shell_alias_for_github(
    config: Config, board: Board, git_repo: Path
) -> None:
    task = board.create("Implement an MCP alias rejection")
    Router(config).dispatch(board, task)
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/reject-mcp-alias"
    )
    policy_path = worktree.path / "policies" / "mcp.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["servers"]["github-write"] = {
        "transport": "stdio",
        "command": "sh",
        "args": [
            "-c",
            "{data_root}/var/bin/github-mcp-server stdio",
        ],
        "write_roles": ["code-worker"],
    }
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    contract_path = worktree.path / "agents" / "code-worker.md"
    contract_path.write_text(
        contract_path.read_text(encoding="utf-8").replace(
            "mcp: [github, filesystem]",
            "mcp: [github, filesystem, github-write]",
        ),
        encoding="utf-8",
    )
    with board.edit(task.id) as stored:
        stored.branch = "feature/reject-mcp-alias"
        stored.worktree = str(worktree.path)
    launcher = AgentLauncher(config, board)
    worker_config = launcher._worker_config(worktree.path)
    contract = launcher._contract(board.get(task.id), worker_config)

    with pytest.raises(LauncherError, match="defines untrusted MCP server"):
        launcher._write_mcp_config(
            board.get(task.id),
            contract,
            config=worker_config,
            worktree_scope=worktree.path,
        )


def test_launcher_policy_always_comes_from_canonical_checkout(
    config: Config, board: Board, git_repo: Path
) -> None:
    worktree = WorktreeManager(config, repo=git_repo, board=board).create(
        "feature/untrusted-launcher"
    )
    policy_path = worktree.path / "policies" / "mcp.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["launcher"]["command"] = "sh"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    linked_config = Config(worktree.path)

    launcher = AgentLauncher(linked_config, Board(linked_config))

    assert launcher.policy["command"] == config.policy("mcp")["launcher"]["command"]


def test_root_mcp_config_has_no_blanket_grants() -> None:
    config = json.loads((Path(__file__).parents[1] / ".mcp.json").read_text())
    assert config["mcpServers"] == {}
