from __future__ import annotations

import subprocess
from contextlib import contextmanager
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


def test_relative_worktree_root_uses_shared_data_root_from_linked_source(
    config: Config, git_repo: Path, board: Board
) -> None:
    linked = config.root / "linked-source"
    git(["worktree", "add", "-b", "feature/linked-source", str(linked)], git_repo)
    linked_config = Config(linked)

    worktree = WorktreeManager(
        linked_config, repo=linked, board=Board(linked_config)
    ).create("feature/from-linked")

    assert worktree.path.parent == config.data_root / "var" / "worktrees"


def test_managed_repo_relative_worktree_root_stays_with_repo(
    config: Config, git_repo: Path
) -> None:
    linked = config.root / "linked-engine"
    git(["worktree", "add", "-b", "feature/linked-engine", str(linked)], git_repo)
    linked_config = Config(linked)
    managed = config.root / "managed-repo"
    managed.mkdir()
    git(["init", "-b", "main"], managed)
    git(["config", "user.email", "managed@example.com"], managed)
    git(["config", "user.name", "Managed"], managed)
    (managed / "README.md").write_text("managed\n", encoding="utf-8")
    git(["add", "."], managed)
    git(["commit", "-m", "initial"], managed)

    worktree = WorktreeManager(
        linked_config, repo=managed, board=Board(linked_config)
    ).create("feature/managed")

    assert worktree.path.parent == managed / "var" / "worktrees"


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


def test_detached_worktree_is_skipped_during_plan_and_apply(
    manager: WorktreeManager, git_repo: Path
) -> None:
    detached = git_repo / "var" / "worktrees" / "detached"
    git(["worktree", "add", "--detach", str(detached), "HEAD"], git_repo)
    later = datetime.now(timezone.utc) + timedelta(days=90)

    plan = manager.plan_cleanup(now=later)
    assert str(detached) not in {a.target for a in plan.actions}
    assert any(a.target == str(detached) and a.reason == "detached HEAD" for a in plan.skipped)

    plan.actions.append(worktrees.Action("remove_worktree", str(detached), "stale"))
    manager.apply(plan, now=later)

    assert detached.exists()
    assert any(a.target == str(detached) and a.reason == "detached HEAD" for a in plan.skipped)


def test_unmerged_worktree_uses_hard_stale_threshold(manager: WorktreeManager) -> None:
    worktree = manager.create("feature/local-commit")
    (worktree.path / "local.txt").write_text("unmerged\n", encoding="utf-8")
    git(["add", "local.txt"], worktree.path)
    git(
        ["-c", "user.email=a@b.c", "-c", "user.name=w", "commit", "-m", "local"],
        worktree.path,
    )
    now = datetime.now(timezone.utc)
    threshold = manager.policy["worktree"]["hard_stale_after_days"]

    before_hard_stale = manager.plan_cleanup(now=now + timedelta(days=threshold - 1))
    at_hard_stale = manager.plan_cleanup(now=now + timedelta(days=threshold + 1))

    assert str(worktree.path) not in {a.target for a in before_hard_stale.actions}
    assert str(worktree.path) in {a.target for a in at_hard_stale.actions}
    assert any(
        f"{threshold}d (unmerged)" in action.reason
        for action in at_hard_stale.actions
        if action.target == str(worktree.path)
    )


def test_open_task_protects_worktree(manager: WorktreeManager, board: Board) -> None:
    worktree = manager.create("feature/guarded")
    task = board.create("guarded work")
    with board.edit(task.id) as stored:
        stored.branch = "feature/guarded"
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

    manager.apply(plan, now=later)
    assert plan.errors == []
    assert not worktree.path.exists()
    log = (manager.config.var_dir / "logs" / "janitor.log").read_text(encoding="utf-8")
    assert "APPLY remove_worktree" in log


def test_cleanup_enforces_configured_reflog_retention(
    manager: WorktreeManager, git_repo: Path
) -> None:
    plan = manager.plan_cleanup()

    manager.apply(plan)

    assert (
        git(["config", "--local", "--get", "core.logAllRefUpdates"], git_repo).strip()
        == "true"
    )
    for key in ("gc.reflogExpire", "gc.reflogExpireUnreachable", "gc.pruneExpire"):
        assert git(["config", "--local", "--get", key], git_repo).strip() == "90 days ago"
    git(["reflog", "expire", "--dry-run", "--all"], git_repo)


def test_worktree_prune_stays_inside_lifecycle_lock(
    manager: WorktreeManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked = False
    original_git = worktrees.git

    @contextmanager
    def lifecycle_lock():
        nonlocal locked
        locked = True
        try:
            yield
        finally:
            locked = False

    def checked_git(args: list[str], cwd: Path) -> str:
        if args == ["worktree", "prune"]:
            assert locked
        return original_git(args, cwd)

    monkeypatch.setattr(manager, "lifecycle_lock", lifecycle_lock)
    monkeypatch.setattr(worktrees, "git", checked_git)

    manager.apply(manager.plan_cleanup())


def test_invalid_reflog_retention_blocks_cleanup(
    manager: WorktreeManager,
) -> None:
    manager.policy["safety"]["keep_reflog_days"] = 0
    worktree = manager.create("feature/invalid-retention")
    plan = manager.plan_cleanup(now=datetime.now(timezone.utc) + timedelta(days=30))

    manager.apply(plan)

    assert worktree.path.exists()
    assert plan.actions == []
    assert plan.errors == [
        "reflog retention: cleanup safety.keep_reflog_days must be a positive integer"
    ]


def test_janitor_log_uses_shared_data_root_from_linked_source(
    manager: WorktreeManager,
) -> None:
    linked_root = manager.config.root / "var" / "worktrees" / "linked"
    linked_root.mkdir(parents=True)
    manager.config.root = linked_root

    path = manager.log_plan(worktrees.CleanupPlan())

    assert path == manager.config.var_dir / "logs" / "janitor.log"


def test_apply_rechecks_open_task_before_removing_worktree(
    manager: WorktreeManager, board: Board
) -> None:
    worktree = manager.create("feature/recheck")
    later = datetime.now(timezone.utc) + timedelta(days=30)
    plan = manager.plan_cleanup(now=later)
    assert str(worktree.path) in {a.target for a in plan.actions}

    task = board.create("newly attached")
    with board.edit(task.id) as stored:
        stored.branch = "feature/recheck"

    manager.apply(plan, now=later)

    assert worktree.path.exists()
    assert str(worktree.path) not in {a.target for a in plan.actions}
    assert any(
        action.target == str(worktree.path) and action.reason == "has an open board task"
        for action in plan.skipped
    )


def test_apply_skips_recreated_worktree_from_stale_plan(manager: WorktreeManager) -> None:
    worktree = manager.create("feature/recreated")
    later = datetime.now(timezone.utc) + timedelta(days=30)
    plan = manager.plan_cleanup(now=later)
    assert str(worktree.path) in {a.target for a in plan.actions}

    manager.rollback_create(worktree)
    recreated = manager.create("feature/recreated", path=worktree.path)

    manager.apply(plan, now=later)

    assert recreated.path.exists()
    assert str(recreated.path) not in {a.target for a in plan.actions}
    assert any(
        action.target == str(recreated.path)
        and action.reason == "worktree identity changed since planning"
        for action in plan.skipped
    )


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

    manager.apply(plan, now=later)
    assert "feature/merged" not in git(["branch", "--format=%(refname:short)"], git_repo)


def test_apply_rechecks_merge_grace_before_deleting_branch(
    manager: WorktreeManager, git_repo: Path
) -> None:
    worktree = manager.create("feature/recently-merged")
    (worktree.path / "file.txt").write_text("done\n", encoding="utf-8")
    git(["add", "."], worktree.path)
    git(["-c", "user.email=a@b.c", "-c", "user.name=w", "commit", "-m", "work"], worktree.path)
    git(["merge", "--no-ff", "-m", "merge", "feature/recently-merged"], git_repo)
    manager.remove(worktree.path)

    now = datetime.now(timezone.utc)
    plan = manager.plan_cleanup(now=now + timedelta(days=5))
    assert ("delete_branch", "feature/recently-merged") in {
        (a.kind, a.target) for a in plan.actions
    }

    manager.apply(plan, now=now)

    assert "feature/recently-merged" in git(["branch", "--format=%(refname:short)"], git_repo)
    assert any(
        action.kind == "delete_branch"
        and action.target == "feature/recently-merged"
        and action.reason == "inside merge grace period"
        for action in plan.skipped
    )


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


def test_fresh_worktree_uses_stale_after_days_threshold(
    manager: WorktreeManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clean unmerged branch with no local commits uses stale_after_days, not hard_stale."""
    worktree = manager.create("feature/never-used")
    stale_threshold = manager.policy["worktree"]["stale_after_days"]
    hard_threshold = manager.policy["worktree"]["hard_stale_after_days"]
    assert stale_threshold < hard_threshold, "policy invariant violated"
    now = datetime.now(timezone.utc)

    # Simulate: branch is not yet merged into the default branch, but has no local commits.
    monkeypatch.setattr(manager, "merged_branches", lambda: set())
    monkeypatch.setattr(manager, "has_local_commits", lambda branch: False)

    # Not yet stale (age < stale_after_days).
    before = manager.plan_cleanup(now=now + timedelta(days=stale_threshold - 1))
    assert str(worktree.path) not in {a.target for a in before.actions}, (
        "should not be removed before stale_after_days"
    )

    # Past stale (but still before hard_stale) → must be cleaned via stale_after_days.
    at_stale = manager.plan_cleanup(now=now + timedelta(days=stale_threshold + 1))
    assert str(worktree.path) in {a.target for a in at_stale.actions}, (
        "fresh worktree should be removed at stale_after_days, not hard_stale_after_days"
    )
