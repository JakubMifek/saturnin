"""Worktree and feature-branch lifecycle management.

Parallel execution means one worktree per worker. Worktrees are cheap to create
and easy to forget, so the janitor gets a policy-driven, dry-run-by-default
cleanup planner.
"""

from __future__ import annotations

from contextlib import contextmanager
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .board import Board, Task
from .config import Config, default_config
from .governance import Governance
from .locking import file_lock


class GitError(RuntimeError):
    pass


def git(args: Sequence[str], cwd: Path) -> str:
    result = subprocess.run(  # noqa: S603 - fixed executable, arguments are not shell-parsed
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def validated_task_worktree(task: Task) -> Path:
    """Return the task's registered, non-primary worktree on its assigned branch."""
    if not task.branch:
        raise GitError(f"task {task.id} has no attached branch")
    if not task.worktree:
        raise GitError(f"task {task.id} has no attached worktree")
    try:
        worktree = Path(task.worktree).resolve(strict=True)
    except OSError as exc:
        raise GitError(f"task worktree does not exist: {task.worktree}") from exc
    if not worktree.is_dir():
        raise GitError(f"task worktree does not exist: {worktree}")
    output = git(["worktree", "list", "--porcelain", "-z"], worktree)
    registered = [
        Path(line.removeprefix("worktree ")).resolve()
        for line in output.split("\0")
        if line.startswith("worktree ")
    ]
    if not registered or worktree not in registered:
        raise GitError(f"task worktree is not registered with Git: {worktree}")
    if worktree == registered[0]:
        raise GitError(f"task {task.id} cannot use a repository's main checkout")
    current = git(["branch", "--show-current"], worktree).strip()
    if current != task.branch:
        raise GitError(
            f"task worktree {worktree} is not checked out on branch {task.branch}"
        )
    return worktree


@dataclass
class Worktree:
    path: Path
    branch: str | None
    head: str | None = None
    is_main: bool = False
    locked: bool = False

    @property
    def name(self) -> str:
        return self.path.name


@dataclass(frozen=True)
class WorktreeIdentity:
    branch: str | None
    head: str | None
    inode: int | None
    mtime_ns: int | None


@dataclass
class Action:
    kind: str  # remove_worktree | delete_branch
    target: str
    reason: str


@dataclass
class CleanupPlan:
    actions: list[Action] = field(default_factory=list)
    skipped: list[Action] = field(default_factory=list)
    applied: bool = False
    errors: list[str] = field(default_factory=list)
    worktree_identities: dict[str, WorktreeIdentity] = field(
        default_factory=dict, repr=False
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "actions": [vars(a) for a in self.actions],
            "skipped": [vars(a) for a in self.skipped],
            "errors": self.errors,
        }


class WorktreeManager:
    def __init__(
        self,
        config: Config | None = None,
        *,
        repo: Path | None = None,
        board: Board | None = None,
    ) -> None:
        self.config = config or default_config()
        self.repo = Path(repo or self.config.root)
        self.governance = Governance(self.config)
        self.board = board or Board(self.config)
        self.policy = self.config.cleanup
        self._lifecycle_depth = 0

    def audit(self) -> list[str]:
        safety = self.policy.get("safety", {})
        dry_run_default = safety.get("dry_run_default")
        if not isinstance(dry_run_default, bool):
            return ["cleanup safety.dry_run_default must be a boolean"]
        days = safety.get("keep_reflog_days")
        if isinstance(days, bool) or not isinstance(days, int) or days < 1:
            return ["cleanup safety.keep_reflog_days must be a positive integer"]
        return []

    def enforce_reflog_retention(self) -> None:
        problems = self.audit()
        if problems:
            raise GitError(problems[0])
        days = self.policy["safety"]["keep_reflog_days"]
        expiry = f"{days} days ago"
        for key, value in (
            ("core.logAllRefUpdates", "true"),
            ("gc.reflogExpire", expiry),
            ("gc.reflogExpireUnreachable", expiry),
            ("gc.pruneExpire", expiry),
        ):
            git(["config", "--local", key, value], self.repo)

    @contextmanager
    def lifecycle_lock(self) -> Iterator[None]:
        if self._lifecycle_depth:
            yield
            return
        with file_lock(self.config.var_dir / "worktree-lifecycle"):
            self._lifecycle_depth += 1
            try:
                yield
            finally:
                self._lifecycle_depth -= 1

    # -- inspection ----------------------------------------------------
    def list(self) -> list[Worktree]:
        out = git(["worktree", "list", "--porcelain"], self.repo)
        worktrees: list[Worktree] = []
        current: dict[str, Any] = {}
        for line in out.splitlines() + [""]:
            if not line.strip():
                if current:
                    path = Path(current["worktree"])
                    worktrees.append(
                        Worktree(
                            path=path,
                            branch=current.get("branch"),
                            head=current.get("HEAD"),
                            is_main=path.resolve() == self.repo.resolve(),
                            locked=bool(current.get("locked")),
                        )
                    )
                current = {}
                continue
            key, _, value = line.partition(" ")
            if key == "branch":
                value = value.replace("refs/heads/", "")
            current[key] = value or True
        return worktrees

    def branch_last_commit(self, branch: str) -> datetime:
        raw = git(["log", "-1", "--format=%cI", branch], self.repo).strip()
        return datetime.fromisoformat(raw)

    def default_branch(self) -> str:
        if self.repo.resolve() == self.config.root.resolve():
            return self.governance.default_branch
        for source in self.config.policy("repos").get("discovery", {}).get("sources", []) or []:
            if not isinstance(source, dict) or not source.get("checkout"):
                continue
            checkout = Path(str(source["checkout"])).expanduser()
            if not checkout.is_absolute():
                checkout = self.config.root / checkout
            if checkout.resolve() == self.repo.resolve() and source.get("default_branch"):
                return str(source["default_branch"])
        try:
            remote_head = git(
                ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
                self.repo,
            ).strip()
        except GitError:
            remote_head = ""
        if remote_head.startswith("origin/"):
            return remote_head.removeprefix("origin/")
        raise GitError(
            f"cannot resolve default branch for managed repository {self.repo}; "
            "configure discovery.sources[].default_branch or origin/HEAD"
        )

    def merged_branches(self) -> set[str]:
        default = self.default_branch()
        try:
            out = git(["branch", "--merged", default, "--format=%(refname:short)"], self.repo)
        except GitError:
            return set()
        return {line.strip() for line in out.splitlines() if line.strip()}

    def is_clean(self, path: Path) -> bool:
        try:
            return not git(["status", "--porcelain"], path).strip()
        except GitError:
            return False

    def has_local_commits(self, branch: str) -> bool:
        """Return True if *branch* has commits not present in the default branch."""
        default = self.default_branch()
        try:
            out = git(["log", f"{default}..{branch}", "--oneline"], self.repo)
            return bool(out.strip())
        except GitError:
            return True  # Treat indeterminate as having local work (safer default).

    # -- creation ------------------------------------------------------
    def create(self, branch: str, *, base: str | None = None, path: Path | None = None) -> Worktree:
        with self.lifecycle_lock():
            return self._create_unlocked(branch, base=base, path=path)

    def _create_unlocked(
        self, branch: str, *, base: str | None = None, path: Path | None = None
    ) -> Worktree:
        decision = self.governance.check_branch(branch)
        if not decision.allowed:
            raise GitError("; ".join(decision.reasons))
        default = self.default_branch()
        if branch == default:
            raise GitError(f"branch {branch!r} is protected")
        base = base or default
        root = Path(self.config.governance.get("git", {}).get("worktree_root", "var/worktrees"))
        if not root.is_absolute():
            repository_config = Config(self.repo)
            anchor = (
                self.config.data_root
                if repository_config.data_root == self.config.data_root
                else self.repo
            )
            root = anchor / root
        root.mkdir(parents=True, exist_ok=True)
        target = path or root / branch.replace("/", "__")
        if target.exists():
            raise GitError(f"worktree path already exists: {target}")
        git(["worktree", "add", "-b", branch, str(target), base], self.repo)
        return Worktree(path=target, branch=branch)

    def remove(self, path: Path, *, force: bool = False) -> None:
        args = ["worktree", "remove", str(path)]
        if force:
            args.append("--force")
        git(args, self.repo)

    def rollback_create(self, worktree: Worktree) -> None:
        """Remove a worktree and branch that were created by an uncommitted lifecycle."""
        with self.lifecycle_lock():
            self.remove(worktree.path)
            if worktree.branch:
                git(["branch", "-D", worktree.branch], self.repo)

    # -- cleanup -------------------------------------------------------
    def plan_cleanup(self, *, now: datetime | None = None) -> CleanupPlan:
        now = now or datetime.now(timezone.utc)
        wt_policy = self.policy.get("worktree", {})
        br_policy = self.policy.get("branch", {})
        safety = self.policy.get("safety", {})
        protected = set(self.governance.protected_branches) | {self.default_branch()}
        merged = self.merged_branches()
        plan = CleanupPlan()

        for worktree in self.list():
            if worktree.is_main:
                continue
            target = str(worktree.path)
            if worktree.locked:
                plan.skipped.append(Action("remove_worktree", target, "worktree is locked"))
                continue
            if worktree.branch is None:
                plan.skipped.append(Action("remove_worktree", target, "detached HEAD"))
                continue
            if any(fnmatch(target, pattern) for pattern in wt_policy.get("keep_globs", [])):
                plan.skipped.append(Action("remove_worktree", target, "matches keep_globs"))
                continue
            if worktree.branch in protected:
                plan.skipped.append(Action("remove_worktree", target, "protected branch"))
                continue
            if worktree.branch and self.board.open_tasks_for_branch(worktree.branch):
                plan.skipped.append(Action("remove_worktree", target, "has an open board task"))
                continue
            if safety.get("require_clean_worktree", True) and not self.is_clean(worktree.path):
                plan.skipped.append(
                    Action("remove_worktree", target, "uncommitted changes present")
                )
                continue
            eligible, reason = self._staleness_decision(worktree, now=now, merged=merged)
            if eligible:
                plan.actions.append(Action("remove_worktree", target, reason))
                plan.worktree_identities[target] = self._worktree_identity(worktree)
            else:
                plan.skipped.append(Action("remove_worktree", target, reason))

        if br_policy.get("delete_merged_local", True):
            grace = timedelta(days=br_policy.get("merged_grace_days", 1))
            checked_out = {w.branch for w in self.list()}
            for branch in sorted(merged - protected):
                if branch in checked_out:
                    plan.skipped.append(Action("delete_branch", branch, "checked out in a worktree"))
                    continue
                if br_policy.get("protect_with_open_tasks", True) and self.board.open_tasks_for_branch(
                    branch
                ):
                    plan.skipped.append(Action("delete_branch", branch, "has an open board task"))
                    continue
                try:
                    last = self.branch_last_commit(branch)
                except GitError:  # pragma: no cover - defensive
                    plan.skipped.append(Action("delete_branch", branch, "cannot read history"))
                    continue
                if now - last < grace:
                    plan.skipped.append(Action("delete_branch", branch, "inside merge grace period"))
                    continue
                plan.actions.append(Action("delete_branch", branch, "merged into default branch"))

        cap = int(safety.get("max_removals_per_run", 10))
        if len(plan.actions) > cap:
            overflow = plan.actions[cap:]
            plan.actions = plan.actions[:cap]
            for action in overflow:
                action.reason += f" (deferred: over cap of {cap} per run)"
            plan.skipped.extend(overflow)
        return plan

    def _age_days(self, worktree: Worktree, now: datetime) -> float | None:
        stamps: list[datetime] = []
        if worktree.branch:
            try:
                stamps.append(self.branch_last_commit(worktree.branch))
            except GitError:
                pass
        if worktree.path.exists():
            stamps.append(
                datetime.fromtimestamp(worktree.path.stat().st_mtime, tz=timezone.utc)
            )
        if not stamps:
            return None
        return (now - max(stamps)).total_seconds() / 86400.0

    def apply(self, plan: CleanupPlan, *, now: datetime | None = None) -> CleanupPlan:
        applied: list[Action] = []
        now = now or datetime.now(timezone.utc)
        with self.lifecycle_lock():
            try:
                self.enforce_reflog_retention()
            except GitError as exc:
                plan.errors.append(f"reflog retention: {exc}")
                plan.skipped.extend(
                    Action(action.kind, action.target, "reflog retention could not be enforced")
                    for action in plan.actions
                )
                plan.actions = []
                plan.applied = True
                self.log_plan(plan)
                return plan
            for action in plan.actions:
                try:
                    skip_reason = self._execution_skip_reason(action, plan=plan, now=now)
                    if skip_reason is not None:
                        plan.skipped.append(Action(action.kind, action.target, skip_reason))
                        continue
                    if action.kind == "remove_worktree":
                        self.remove(Path(action.target))
                    elif action.kind == "delete_branch":
                        git(["branch", "-d", action.target], self.repo)
                    applied.append(action)
                except GitError as exc:
                    plan.errors.append(f"{action.kind} {action.target}: {exc}")
            plan.actions = applied
            try:
                git(["worktree", "prune"], self.repo)
            except GitError as exc:  # pragma: no cover - defensive
                plan.errors.append(f"worktree prune: {exc}")
        plan.applied = True
        self.log_plan(plan)
        return plan

    def _execution_skip_reason(
        self, action: Action, *, plan: CleanupPlan | None = None, now: datetime | None = None
    ) -> str | None:
        if action.kind == "remove_worktree":
            expected_identity = None
            if plan is not None:
                expected_identity = plan.worktree_identities.get(action.target)
            return self._remove_worktree_skip_reason(
                Path(action.target), expected_identity=expected_identity, now=now
            )
        if action.kind == "delete_branch":
            return self._delete_branch_skip_reason(action.target, now=now)
        return None

    def _remove_worktree_skip_reason(
        self,
        path: Path,
        *,
        expected_identity: WorktreeIdentity | None = None,
        now: datetime | None = None,
    ) -> str | None:
        now = now or datetime.now(timezone.utc)
        matches = [worktree for worktree in self.list() if worktree.path == path]
        if not matches:
            return "worktree no longer exists"
        worktree = matches[0]
        if expected_identity is not None and self._worktree_identity(worktree) != expected_identity:
            return "worktree identity changed since planning"
        if worktree.locked:
            return "worktree is locked"
        if worktree.branch is None:
            return "detached HEAD"
        if worktree.branch in set(self.governance.protected_branches) | {self.default_branch()}:
            return "protected branch"
        if worktree.branch and self.board.open_tasks_for_branch(worktree.branch):
            return "has an open board task"
        if self.policy.get("safety", {}).get("require_clean_worktree", True) and not self.is_clean(path):
            return "uncommitted changes present"
        stale, reason = self._staleness_decision(worktree, now=now)
        if not stale:
            return reason
        return None

    def _delete_branch_skip_reason(self, branch: str, *, now: datetime | None = None) -> str | None:
        now = now or datetime.now(timezone.utc)
        if branch in set(self.governance.protected_branches) | {self.default_branch()}:
            return "protected branch"
        if branch in {worktree.branch for worktree in self.list()}:
            return "checked out in a worktree"
        if self.policy.get("branch", {}).get("protect_with_open_tasks", True):
            if self.board.open_tasks_for_branch(branch):
                return "has an open board task"
        if branch not in self.merged_branches():
            return "not merged into default branch"
        grace_days = self.policy.get("branch", {}).get("merged_grace_days", 1)
        try:
            if now - self.branch_last_commit(branch) < timedelta(days=grace_days):
                return "inside merge grace period"
        except GitError:
            return "cannot read history"
        return None

    def _worktree_identity(self, worktree: Worktree) -> WorktreeIdentity:
        inode: int | None = None
        mtime_ns: int | None = None
        try:
            stat = worktree.path.stat()
        except OSError:
            pass
        else:
            inode = stat.st_ino
            mtime_ns = stat.st_mtime_ns
        return WorktreeIdentity(
            branch=worktree.branch,
            head=worktree.head,
            inode=inode,
            mtime_ns=mtime_ns,
        )

    def _staleness_decision(
        self,
        worktree: Worktree,
        *,
        now: datetime,
        merged: set[str] | None = None,
    ) -> tuple[bool, str]:
        age = self._age_days(worktree, now)
        if age is None:
            return False, "age unknown"
        wt_policy = self.policy.get("worktree", {})
        merged_branches = merged if merged is not None else self.merged_branches()
        is_merged = bool(worktree.branch and worktree.branch in merged_branches)
        if is_merged:
            threshold = wt_policy.get("merged_stale_after_days", 1)
        elif worktree.branch and self.has_local_commits(worktree.branch):
            threshold = wt_policy.get("hard_stale_after_days", 30)
        else:
            threshold = wt_policy.get("stale_after_days", 7)
        if age >= threshold:
            return True, f"idle {age:.1f}d >= {threshold}d ({'merged' if is_merged else 'unmerged'})"
        return False, f"idle {age:.1f}d < {threshold}d"

    def log_plan(self, plan: CleanupPlan) -> Path:
        log_file = Path(self.policy.get("safety", {}).get("log_file", "var/logs/janitor.log"))
        log_file = self.config.shared_path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        lines: Iterable[str] = (
            f"{stamp} {'APPLY' if plan.applied else 'DRYRUN'} {a.kind} {a.target} :: {a.reason}"
            for a in plan.actions
        )
        with log_file.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")
            for skip in plan.skipped:
                handle.write(
                    f"{stamp} {'APPLY' if plan.applied else 'DRYRUN'}"
                    f" SKIP {skip.kind} {skip.target} :: {skip.reason}\n"
                )
            for error in plan.errors:
                handle.write(f"{stamp} ERROR {error}\n")
        return log_file
