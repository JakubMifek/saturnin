from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from saturnin.board import Board
from saturnin.checkpoints import Checkpoint, CheckpointStore
from saturnin.config import Config
from saturnin.launcher import AgentLauncher, LauncherError
from saturnin.mcp import MCPError
from saturnin.review import ReviewLedger, sign_review_attestation
from saturnin.routing import Router
from saturnin.worktrees import WorktreeManager


@pytest.fixture(autouse=True)
def verified_github_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saturnin.launcher.verify_github_binary",
        lambda config: config.var_dir / "bin" / "github-mcp-server",
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
    assert environment["SATURNIN_AGENT_ROLE"] == contract.role
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "host" not in environment["PYTHONPATH"]


def test_launcher_injects_role_scoped_attestation_key_only_for_reviewers(
    config: Config, board: Board, git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
