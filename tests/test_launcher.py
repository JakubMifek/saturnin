from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.board import Board
from saturnin.checkpoints import Checkpoint, CheckpointStore
from saturnin.config import Config
from saturnin.launcher import AgentLauncher, LauncherError
from saturnin.routing import Router
from saturnin.worktrees import WorktreeManager


class FakeProcess:
    def __init__(self, command, *, stdout: str = "", returncode: int = 0, pid: int = 4242):
        self.args = command
        self._stdout = stdout
        self._stderr = ""
        self.returncode = returncode
        self.pid = pid

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def communicate(self, input=None, timeout=None):  # noqa: A002 - subprocess API
        return self._stdout, self._stderr

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


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

    def fake_popen(command, **kwargs):
        if command == ["git", "branch", "--show-current"]:
            return FakeProcess(command, stdout="feature/launch\n")
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
    assert mcp["mcpServers"]["filesystem"]["args"][-1] == str(config.var_dir / "worktrees")
    command = calls[0][0]
    assert "--no-ask-user" in command
    assert "Implement a small fix" in command[-1]
    assert "role: code-worker" in command[-1]
    assert "Managed repository manifest (.saturnin/repo.yaml):" in command[-1]
    assert "stack: python" in command[-1]
    assert calls[0][1]["cwd"] == worktree.path


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
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            FakeProcess(command, stdout="feature/restricted-launch\n")
            if command == ["git", "branch", "--show-current"]
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
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            FakeProcess(command, stdout="feature/retry-launch\n")
            if command == ["git", "branch", "--show-current"]
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
    monkeypatch.setattr(
        "saturnin.launcher.subprocess.Popen",
        lambda command, **kwargs: (
            FakeProcess(command, stdout="feature/fail-launch\n")
            if command == ["git", "branch", "--show-current"]
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
        "---\nrole: db-migrator\nskills: [checkpointing]\nmcp: [github]\n---\n"
        "# Database migrator\n",
        encoding="utf-8",
    )
    (worktree.path / ".saturnin" / "repo.yaml").write_text(
        "agents: [.saturnin/agents/db-migrator.md]\nmcp: [github]\n",
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


def test_root_mcp_config_has_no_blanket_grants() -> None:
    config = json.loads((Path(__file__).parents[1] / ".mcp.json").read_text())
    assert config["mcpServers"] == {}
