from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from saturnin import worktrees
from saturnin.board import Board
from saturnin.config import Config
from saturnin.worktrees import GitError, WorktreeManager


def git(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture()
def manager(config: Config, git_repo: Path, board: Board) -> WorktreeManager:
    return WorktreeManager(config, repo=git_repo, board=board)


def test_create_rejects_protected_branch(manager: WorktreeManager) -> None:
    with pytest.raises(GitError, match="protected"):
        manager.create("main")


def test_create_rejects_unprefixed_branch(manager: WorktreeManager) -> None:
    with pytest.raises(GitError):
        manager.create("random-branch")


def test_create_and_list(manager: WorktreeManager) -> None:
    worktree = manager.create("feature/alpha")
    assert worktree.path.is_dir()
    branches = {w.branch for w in manager.list()}
    assert {"main", "feature/alpha"} <= branches
    assert manager.is_clean(worktree.path)


def test_list_identifies_main_worktree_by_path(
    manager: WorktreeManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    linked = manager.repo / "var" / "worktrees" / "feature__alpha"
    output = (
        f"worktree {linked}\nHEAD abc\nbranch refs/heads/feature/alpha\n\n"
        f"worktree {manager.repo}\nHEAD def\nbranch refs/heads/main\n"
    )
    monkeypatch.setattr(worktrees, "git", lambda args, cwd: output)

    listed = manager.list()

    assert [worktree.is_main for worktree in listed] == [False, True]


def test_dirty_worktree_is_never_removed(manager: WorktreeManager) -> None:
    worktree = manager.create("feature/dirty")
    (worktree.path / "scratch.txt").write_text("work in progress\n", encoding="utf-8")
    later = datetime.now(timezone.utc) + timedelta(days=90)
    plan = manager.plan_cleanup(now=later)
    reasons = {a.target: a.reason for a in plan.skipped}
    assert reasons[str(worktree.path)] == "uncommitted changes present"
    assert str(worktree.path) not in {a.target for a in plan.actions}


def test_fresh_worktree_is_kept(manager: WorktreeManager) -> None:
    worktree = manager.create("feature/fresh")
    plan = manager.plan_cleanup(now=datetime.now(timezone.utc))
    assert str(worktree.path) not in {a.target for a in plan.actions}


def test_open_task_protects_worktree(manager: WorktreeManager, board: Board) -> None:
    worktree = manager.create("feature/guarded")
    task = board.create("guarded work")
    task.branch = "feature/guarded"
    board.save(task)
    plan = manager.plan_cleanup(now=datetime.now(timezone.utc) + timedelta(days=90))
    assert str(worktree.path) not in {a.target for a in plan.actions}
    assert "has an open board task" in {a.reason for a in plan.skipped}


def test_stale_worktree_is_planned_and_applied(
    manager: WorktreeManager, git_repo: Path
) -> None:
    worktree = manager.create("feature/stale")
    later = datetime.now(timezone.utc) + timedelta(days=30)
    plan = manager.plan_cleanup(now=later)
    assert str(worktree.path) in {a.target for a in plan.actions}
    assert not plan.applied

    manager.apply(plan)
    assert plan.errors == []
    assert not worktree.path.exists()
    log = (manager.config.root / "var" / "logs" / "janitor.log").read_text(encoding="utf-8")
    assert "APPLY remove_worktree" in log


def test_merged_branch_is_deleted_and_protected_ones_are_not(
    manager: WorktreeManager, git_repo: Path
) -> None:
    worktree = manager.create("feature/merged")
    (worktree.path / "file.txt").write_text("done\n", encoding="utf-8")
    git(["add", "."], worktree.path)
    git(["-c", "user.email=a@b.c", "-c", "user.name=w", "commit", "-m", "work"], worktree.path)
    git(["merge", "--no-ff", "-m", "merge", "feature/merged"], git_repo)
    manager.remove(worktree.path)

    later = datetime.now(timezone.utc) + timedelta(days=5)
    plan = manager.plan_cleanup(now=later)
    targets = {(a.kind, a.target) for a in plan.actions}
    assert ("delete_branch", "feature/merged") in targets
    assert ("delete_branch", "main") not in targets

    manager.apply(plan)
    assert "feature/merged" not in git(["branch", "--format=%(refname:short)"], git_repo)


def test_removal_cap_defers_extra_actions(manager: WorktreeManager) -> None:
    manager.policy = {
        **manager.policy,
        "safety": {**manager.policy["safety"], "max_removals_per_run": 1},
    }
    manager.create("feature/one")
    manager.create("feature/two")
    plan = manager.plan_cleanup(now=datetime.now(timezone.utc) + timedelta(days=30))
    assert len(plan.actions) == 1
    assert any("deferred" in a.reason for a in plan.skipped)
