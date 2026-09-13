from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager
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
    assert mcp["mcpServers"]["github"]["args"] == ["stdio"]
    assert mcp["mcpServers"]["filesystem"]["args"][-1] == str(worktree.path)
    command = calls[0][0]
    assert "--no-ask-user" in command
    assert "Implement a small fix" in command[-1]
    assert "role: code-worker" in command[-1]
    assert "Managed repository manifest (.saturnin/repo.yaml):" in command[-1]
    assert "stack: python" in command[-1]
    assert calls[0][1]["cwd"] == worktree.path
    assert calls[0][1]["env"]["SATURNIN_HOME"] == str(config.root)


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
