"""Non-blocking, contract-aware agent process launcher."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from yaml import YAMLError

from .board import Board, BoardError, Task, utcnow
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config, default_config, load_yaml
from .contracts import (
    FRONT_MATTER,
    AgentContract,
    load_contracts,
    mcp_authorization_problem,
    project_agent_path,
)
from .governance import Governance, github_repo_slug
from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text
from .mcp import MCPError, server_process, verify_github_binary
from .review import role_scoped_review_attestation_key


class LauncherError(RuntimeError):
    pass


@dataclass(frozen=True)
class LaunchResult:
    task_id: str
    role: str
    pid: int
    log: str
    mcp_config: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentLauncher:
    """Start the routed role and return immediately."""

    def __init__(self, config: Config | None = None, board: Board | None = None) -> None:
        self.config = config or default_config()
        self.board = board or Board(self.config)
        trusted_config = self._trusted_config(self.config)
        self.policy = trusted_config.policy("mcp").get("launcher", {})
        self.dir = self.config.var_dir / "launches"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._tighten_existing_logs()

    @property
    def enabled(self) -> bool:
        return bool(self.policy.get("enabled", True))

    def launch(
        self,
        task_id: str,
        *,
        resumed_checkpoint: str | None = None,
    ) -> LaunchResult | None:
        if not self.enabled:
            return None
        task = self.board.get(task_id)
        metadata_path = self.dir / f"{task.id}.json"
        if metadata_path.exists():
            self.reconcile_exited_launches()
            if metadata_path.exists():
                raise LauncherError(
                    f"task {task.id} already has an active or unrecoverable launch"
                )
            task = self.board.get(task_id)
        checkpoint = CheckpointStore(self.config, self.board).latest(task.id)
        executable = str(self.policy.get("command", "copilot"))
        executable_path = shutil.which(executable)
        if executable_path is None:
            raise LauncherError(f"agent launcher executable not found: {executable}")
        executable_path = str(Path(executable_path).resolve())
        sandbox_path = self._sandbox_executable()
        mcp_path: Path | None = None
        log_path = self.dir / f"{task.id}.log"
        launch_error: LauncherError | None = None
        process: subprocess.Popen[bytes] | None = None
        workdir: Path | None = None
        metadata_attempted = False
        failure_cleanup_problem: str | None = None
        previous_state = task.state
        previous_checkpoint_resumed_at = task.checkpoint_resumed_at
        previous_launch_deferred_at = task.launch_deferred_at
        previous_launch_deferred_reason = task.launch_deferred_reason
        try:
            with self.board.edit(task.id) as stored:
                previous_state = stored.state
                previous_checkpoint_resumed_at = stored.checkpoint_resumed_at
                previous_launch_deferred_at = stored.launch_deferred_at
                previous_launch_deferred_reason = stored.launch_deferred_reason
                if stored.state == "in_progress" and resumed_checkpoint:
                    if stored.checkpoint_resumed_at == resumed_checkpoint:
                        raise LauncherError(
                            f"checkpoint {resumed_checkpoint} already resumed for task {stored.id}"
                        )
                elif stored.state != "routed":
                    raise LauncherError(
                        f"task {stored.id} cannot launch from state {stored.state}"
                    )
                if stored.state == "routed":
                    stored.state = "in_progress"
                if resumed_checkpoint:
                    stored.checkpoint_resumed_at = resumed_checkpoint
                stored.log(
                    "agent:claim",
                    actor="launcher",
                    previous_state=previous_state,
                    resumed_checkpoint=resumed_checkpoint,
                )
                claimed = Task.from_dict(stored.to_dict())
                try:
                    workdir = self._validated_workdir(claimed)
                    worker_config = self._worker_config(workdir)
                    contract = self._contract(claimed, worker_config)
                    mcp_path = self._write_mcp_config(
                        claimed,
                        contract,
                        config=worker_config,
                        worktree_scope=workdir,
                    )
                    prompt = self._prompt(
                        claimed,
                        contract,
                        config=worker_config,
                        checkpoint=checkpoint,
                    )
                    args = [
                        str(value).format(
                            mcp_config=str(mcp_path), prompt=prompt, task_id=claimed.id
                        )
                        for value in self.policy.get(
                            "args",
                            [
                                "--autopilot",
                                "--no-ask-user",
                                "--additional-mcp-config",
                                "{mcp_config}",
                                "-p",
                                "{prompt}",
                            ],
                        )
                    ]
                    environment = self._worker_environment(
                        worker_config,
                        contract,
                        task=claimed,
                        workdir=workdir,
                    )
                    home = Path(environment["HOME"])
                    git_environment, git_objects = self._isolated_git_environment(
                        claimed,
                        workdir,
                        home,
                    )
                    environment.update(git_environment)
                    command = self._sandbox_command(
                        sandbox_path,
                        executable_path,
                        args,
                        workdir=workdir,
                        isolated_home=home,
                        trusted_config=self._trusted_config(worker_config),
                        git_objects=git_objects,
                        mcp_config=mcp_path,
                    )
                    with self._private_log(log_path) as output:
                        process = subprocess.Popen(
                            command,
                            cwd=workdir,
                            env=environment,
                            stdin=subprocess.DEVNULL,
                            stdout=output,
                            stderr=subprocess.STDOUT,
                            start_new_session=True,
                        )
                        immediate_status = self._immediate_exit_status(process)
                        if immediate_status is not None:
                            raise LauncherError(
                                "agent launcher exited immediately with "
                                f"status {immediate_status}; see {log_path}"
                            )
                        process_start_time = self._process_start_time(process.pid)
                        if process_start_time is None:
                            raise LauncherError(
                                f"could not read process identity for agent pid {process.pid}"
                            )
                    metadata = {
                        "task_id": claimed.id,
                        "role": contract.role,
                        "pid": process.pid,
                        "process_start_time_ticks": process_start_time,
                        "started_at": utcnow(),
                        "cwd": str(workdir),
                        "mcp_config": str(mcp_path),
                        "log": str(log_path),
                        "resumed_checkpoint": resumed_checkpoint,
                    }
                    metadata_attempted = True
                    atomic_replace_text(
                        metadata_path, json.dumps(metadata, indent=2) + "\n"
                    )
                except (LauncherError, MCPError, OSError) as exc:
                    failure_cleanup_problem = self._terminate_process(process)
                    if previous_state in ("routed", "in_progress"):
                        stored.state = previous_state
                    stored.checkpoint_resumed_at = previous_checkpoint_resumed_at
                    reason = str(exc)
                    if failure_cleanup_problem:
                        reason = f"{reason}; {failure_cleanup_problem}"
                    stored.log("agent:launch_failed", actor="launcher", reason=reason)
                    launch_error = LauncherError(
                        f"agent launcher failed for task {task.id}: {reason}"
                    )
                else:
                    stored.launch_deferred_at = None
                    stored.launch_deferred_reason = None
                    stored.log(
                        "agent:launched",
                        actor="launcher",
                        role=contract.role,
                        pid=process.pid,
                    )
                    stored.log(
                        "state:in_progress",
                        actor=stored.role or "launcher",
                        note=f"agent pid={process.pid}",
                    )
                    task = Task.from_dict(stored.to_dict())
        except OSError as exc:
            termination_problem = self._terminate_process(process)
            reason = f"could not persist launch state: {exc}"
            if termination_problem:
                reason = f"{reason}; {termination_problem}"
            restored = self._restore_launch_claim(
                task.id,
                previous_state=previous_state,
                previous_checkpoint_resumed_at=previous_checkpoint_resumed_at,
                previous_launch_deferred_at=previous_launch_deferred_at,
                previous_launch_deferred_reason=previous_launch_deferred_reason,
                reason=reason,
            )
            if not restored:
                reason = f"{reason}; launch-state rollback remains pending"
            elif not termination_problem and metadata_attempted:
                removal_problem = self._remove_launch_metadata(metadata_path)
                if removal_problem:
                    reason = f"{reason}; {removal_problem}"
            raise LauncherError(f"agent launcher failed for task {task.id}: {reason}") from exc
        if launch_error is not None:
            if not failure_cleanup_problem and metadata_attempted:
                removal_problem = self._remove_launch_metadata(metadata_path)
                if removal_problem:
                    raise LauncherError(f"{launch_error}; {removal_problem}") from launch_error
            raise launch_error
        if process is None or workdir is None or mcp_path is None:  # pragma: no cover
            raise LauncherError(f"agent launcher failed for task {task.id}")
        return LaunchResult(
            task_id=task.id,
            role=contract.role,
            pid=process.pid,
            log=str(log_path),
            mcp_config=str(mcp_path),
        )

    def reconcile_exited_launches(self) -> list[str]:
        resumed: list[str] = []
        for metadata_path in sorted(self.dir.glob("*.json")):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            task_id = str(metadata.get("task_id", "")).strip()
            pid = metadata.get("pid")
            if not task_id or not isinstance(pid, int):
                continue
            process_start_time = metadata.get("process_start_time_ticks")
            if (
                isinstance(process_start_time, int)
                and not isinstance(process_start_time, bool)
                and self._process_start_time(pid) == process_start_time
            ):
                resumed_checkpoint = metadata.get("resumed_checkpoint")
                try:
                    with self.board.edit(task_id) as task:
                        recovered = False
                        if task.state == "routed":
                            task.state = "in_progress"
                            task.launch_deferred_at = None
                            task.launch_deferred_reason = None
                            recovered = True
                        if (
                            isinstance(resumed_checkpoint, str)
                            and resumed_checkpoint
                            and task.checkpoint_resumed_at != resumed_checkpoint
                        ):
                            task.checkpoint_resumed_at = resumed_checkpoint
                            recovered = True
                        if recovered:
                            task.log(
                                "agent:launch_recovered",
                                actor="launcher",
                                pid=pid,
                            )
                            task.log(
                                "state:in_progress",
                                actor=task.role or "launcher",
                                note=f"recovered agent pid={pid}",
                            )
                except (BoardError, OSError):
                    pass
                continue
            reason = f"agent process exited or identity changed after launch with pid {pid}"
            try:
                with self.board.edit(task_id) as task:
                    if task.state == "in_progress":
                        task.state = "routed"
                        task.launch_deferred_at = utcnow()
                        task.launch_deferred_reason = reason
                        task.log("agent:launch_failed", actor="launcher", reason=reason)
                        task.log("state:routed", actor="launcher", note=reason)
                        resumed.append(task.id)
            except OSError:
                continue
            except BoardError:
                pass
            try:
                metadata_path.unlink()
            except OSError:
                pass
        return resumed

    @staticmethod
    def _remove_launch_metadata(metadata_path: Path) -> str | None:
        try:
            metadata_path.unlink(missing_ok=True)
        except OSError as exc:
            return f"could not remove launch metadata: {exc}"
        return None

    def _terminate_process(self, process: subprocess.Popen[bytes] | None) -> str | None:
        if process is None:
            return None
        try:
            process.terminate()
        except ProcessLookupError:
            return None
        except (AttributeError, OSError) as exc:
            return f"could not terminate spawned agent pid {process.pid}: {exc}"
        wait = getattr(process, "wait", None)
        if wait is None:
            return None
        try:
            wait(timeout=float(self.policy.get("termination_grace_seconds", 5)))
            return None
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
            wait(timeout=float(self.policy.get("termination_grace_seconds", 5)))
        except ProcessLookupError:
            return None
        except (AttributeError, OSError, subprocess.TimeoutExpired) as exc:
            return f"could not terminate spawned agent pid {process.pid}: {exc}"
        return None

    def _restore_launch_claim(
        self,
        task_id: str,
        *,
        previous_state: str,
        previous_checkpoint_resumed_at: str | None,
        previous_launch_deferred_at: str | None,
        previous_launch_deferred_reason: str | None,
        reason: str,
    ) -> bool:
        try:
            with self.board.edit(task_id) as task:
                if task.state not in ("routed", "in_progress"):
                    return True
                task.state = previous_state
                task.checkpoint_resumed_at = previous_checkpoint_resumed_at
                task.launch_deferred_at = previous_launch_deferred_at
                task.launch_deferred_reason = previous_launch_deferred_reason
                task.log("agent:launch_failed", actor="launcher", reason=reason)
        except (BoardError, OSError):
            return False
        return True

    @staticmethod
    def _process_start_time(pid: int) -> int | None:
        if pid <= 0:
            return None
        try:
            stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None
        prefix, separator, suffix = stat.rpartition(")")
        fields = suffix.split()
        if (
            not separator
            or not prefix.startswith(f"{pid} (")
            or len(fields) < 20
        ):
            return None
        try:
            start_time = int(fields[19])
        except ValueError:
            return None
        return start_time if start_time >= 0 else None

    def _immediate_exit_status(self, process: subprocess.Popen[bytes]) -> int | None:
        wait = getattr(process, "wait", None)
        if wait is None:
            return None
        try:
            return wait(timeout=float(self.policy.get("failure_grace_seconds", 0.05)))
        except subprocess.TimeoutExpired:
            return None

    def _sandbox_executable(self) -> str:
        sandbox = self.policy.get("sandbox", {})
        if not isinstance(sandbox, dict):
            raise LauncherError("mcp.launcher.sandbox must be a mapping")
        executable = str(sandbox.get("command", "bwrap")).strip()
        path = shutil.which(executable)
        if path is None:
            raise LauncherError(f"required worker sandbox executable not found: {executable}")
        return str(Path(path).resolve())

    def _tighten_existing_logs(self) -> None:
        for path in self.dir.glob("*.log"):
            try:
                self._tighten_log(path)
            except FileNotFoundError:
                continue

    @staticmethod
    def _tighten_log(path: Path) -> None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise LauncherError(f"unsafe launch log {path}: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LauncherError(f"unsafe launch log is not a regular file: {path}")
            os.fchmod(fd, PRIVATE_FILE_MODE)
        finally:
            os.close(fd)

    @staticmethod
    @contextmanager
    def _private_log(path: Path) -> Iterator[BinaryIO]:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK | os.O_NOFOLLOW,
            PRIVATE_FILE_MODE,
        )
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LauncherError(f"unsafe launch log is not a regular file: {path}")
            os.fchmod(fd, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "ab") as output:
                fd = -1
                yield output
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _sandbox_command(
        sandbox: str,
        executable: str,
        args: list[str],
        *,
        workdir: Path,
        isolated_home: Path,
        trusted_config: Config,
        git_objects: Path,
        mcp_config: Path,
    ) -> list[str]:
        sandbox_policy = trusted_config.policy("mcp").get("launcher", {}).get(
            "sandbox", {}
        )
        read_only_paths = sandbox_policy.get("read_only_paths", [])
        if not isinstance(read_only_paths, list) or not all(
            isinstance(path, str) and Path(path).is_absolute()
            for path in read_only_paths
        ):
            raise LauncherError(
                "mcp.launcher.sandbox.read_only_paths must be a list of absolute paths"
            )
        command = [
            sandbox,
            "--unshare-all",
            "--share-net",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--tmpfs",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
        ]

        trusted_paths = (
            trusted_config.root / "src",
            trusted_config.root / "policies",
            trusted_config.root / "agents",
            trusted_config.root / "skills",
            trusted_config.root / "automation",
            trusted_config.root / ".venv",
            trusted_config.var_dir / "bin",
        )
        read_only_mounts = [
            Path(path) for path in read_only_paths if Path(path).exists()
        ]
        read_only_mounts.extend(path for path in trusted_paths if path.exists())
        read_only_mounts.extend((Path(executable), git_objects, mcp_config))
        mounts = [
            *[("--ro-bind", path) for path in dict.fromkeys(read_only_mounts)],
            ("--bind", workdir.resolve()),
            ("--bind", isolated_home.resolve()),
        ]
        created: set[Path] = set()
        for _, target in mounts:
            parent = target if target.is_dir() else target.parent
            for directory in reversed(parent.parents):
                if directory != Path("/") and directory not in created:
                    command.extend(("--dir", str(directory)))
                    created.add(directory)
            if parent != Path("/") and parent not in created:
                command.extend(("--dir", str(parent)))
                created.add(parent)
        for operation, path in mounts:
            command.extend((operation, str(path), str(path)))
        command.extend(("--chdir", str(workdir.resolve()), "--", executable, *args))
        return command

    def _isolated_git_environment(
        self,
        task: Task,
        workdir: Path,
        isolated_home: Path,
    ) -> tuple[dict[str, str], Path]:
        common_output = self._git_output(
            ["rev-parse", "--git-common-dir"],
            cwd=workdir,
        )
        common_dir = Path(common_output)
        if not common_dir.is_absolute():
            common_dir = workdir / common_dir
        objects = common_dir.resolve() / "objects"
        if not objects.is_dir():
            raise LauncherError(f"Git object store does not exist: {objects}")

        git_dir = isolated_home / ".saturnin-git"
        initialized = git_dir / ".saturnin-initialized"
        if not initialized.is_file():
            if git_dir.exists():
                shutil.rmtree(git_dir)
            git_dir.mkdir(mode=0o700)
            self._git_output(["init", "--bare", str(git_dir)])
            self._git_output(
                ["--git-dir", str(git_dir), "config", "core.bare", "false"]
            )
            self._git_output(
                [
                    "--git-dir",
                    str(git_dir),
                    "config",
                    "core.worktree",
                    str(workdir.resolve()),
                ]
            )
            alternates = git_dir / "objects" / "info" / "alternates"
            atomic_replace_text(
                alternates,
                f"{objects}\n",
                mode=PRIVATE_FILE_MODE,
            )
            head = self._git_output(["rev-parse", "HEAD"], cwd=workdir)
            branch_ref = f"refs/heads/{task.branch}"
            self._git_output(
                ["--git-dir", str(git_dir), "update-ref", branch_ref, head]
            )
            self._git_output(
                ["--git-dir", str(git_dir), "symbolic-ref", "HEAD", branch_ref]
            )
            for key in ("user.name", "user.email"):
                value = self._git_output(
                    ["config", "--get", key],
                    cwd=workdir,
                    required=False,
                )
                if value:
                    self._git_output(
                        ["--git-dir", str(git_dir), "config", key, value]
                    )
            self._git_output(
                [
                    "--git-dir",
                    str(git_dir),
                    "--work-tree",
                    str(workdir.resolve()),
                    "read-tree",
                    "HEAD",
                ]
            )
            atomic_replace_text(
                initialized,
                f"{task.branch}\n",
                mode=PRIVATE_FILE_MODE,
            )
        push_urls = self._validated_push_urls(task, workdir)
        self._git_output(
            ["--git-dir", str(git_dir), "config", "--unset-all", "remote.origin.url"],
            required=False,
        )
        self._git_output(
            ["--git-dir", str(git_dir), "config", "--unset-all", "remote.origin.pushurl"],
            required=False,
        )
        self._git_output(
            ["--git-dir", str(git_dir), "config", "remote.origin.url", push_urls[0]]
        )
        for push_url in push_urls:
            self._git_output(
                [
                    "--git-dir",
                    str(git_dir),
                    "config",
                    "--add",
                    "remote.origin.pushurl",
                    push_url,
                ]
            )
        return (
            {
                "GIT_DIR": str(git_dir),
                "GIT_WORK_TREE": str(workdir.resolve()),
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
            objects,
        )

    def _validated_push_urls(self, task: Task, workdir: Path) -> list[str]:
        output = self._git_output(
            ["remote", "get-url", "--push", "--all", "origin"],
            cwd=workdir,
            required=False,
        )
        push_urls = [url.strip() for url in output.splitlines() if url.strip()]
        if not push_urls:
            raise LauncherError("Git remote 'origin' has no push destination")
        trusted_config = self._trusted_config(self.config)
        trusted_proxy_hosts = trusted_config.governance.get("git", {}).get(
            "trusted_github_proxy_hosts", []
        )
        governance = Governance(trusted_config)
        for push_url in push_urls:
            repo = github_repo_slug(
                push_url,
                trusted_proxy_hosts=trusted_proxy_hosts,
            )
            if repo is None:
                raise LauncherError("Git remote 'origin' has an unrecognized push destination")
            decision = governance.push_allowed(repo=repo, branch=str(task.branch))
            if not decision.allowed:
                raise LauncherError("; ".join(decision.reasons))
        return push_urls

    @staticmethod
    def _git_output(
        args: list[str],
        *,
        cwd: Path | None = None,
        required: bool = True,
    ) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            if not required:
                return ""
            raise LauncherError(
                f"could not prepare isolated Git metadata: {result.stderr.strip()}"
            )
        return result.stdout.strip()

    def _validated_workdir(self, task: Task) -> Path:
        if not task.branch:
            raise LauncherError(f"task {task.id} has no attached branch")
        if not task.worktree:
            raise LauncherError(f"task {task.id} has no attached worktree")
        workdir = Path(task.worktree)
        if workdir.resolve() == self.config.root.resolve():
            raise LauncherError(f"task {task.id} cannot launch in the main checkout")
        if not workdir.is_dir():
            raise LauncherError(f"task worktree does not exist: {workdir}")
        registration = subprocess.run(  # noqa: S603 - fixed executable and arguments
            ["git", "worktree", "list", "--porcelain", "-z"],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            check=False,
        )
        if registration.returncode != 0:
            raise LauncherError(f"task worktree is not a Git worktree: {workdir}")
        registered = [
            Path(line.removeprefix("worktree ")).resolve()
            for line in registration.stdout.split("\0")
            if line.startswith("worktree ")
        ]
        resolved_workdir = workdir.resolve()
        if not registered or resolved_workdir not in registered:
            raise LauncherError(f"task worktree is not registered with Git: {workdir}")
        if resolved_workdir == registered[0]:
            raise LauncherError(f"task {task.id} cannot launch in a repository's main checkout")
        current = subprocess.run(  # noqa: S603 - fixed executable, arguments are not shell-parsed
            ["git", "branch", "--show-current"],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            check=False,
        )
        if current.returncode != 0 or current.stdout.strip() != task.branch:
            raise LauncherError(
                f"task worktree {workdir} is not checked out on branch {task.branch}"
            )
        return workdir

    def _worker_config(self, workdir: Path) -> Config:
        candidate = Config(workdir)
        if candidate.data_root.resolve() == self.config.data_root.resolve():
            return Config(candidate.data_root)
        return self._trusted_config(self.config)

    @staticmethod
    def _trusted_config(config: Config) -> Config:
        if config.root == config.data_root:
            return config
        return Config(config.data_root)

    def _worker_environment(
        self,
        config: Config,
        contract: AgentContract,
        *,
        task: Task,
        workdir: Path,
    ) -> dict[str, str]:
        environment = {
            name: value
            for name in self._worker_env_allowlist()
            if (value := os.environ.get(name)) is not None
        }
        trusted_config = self._trusted_config(config)
        home = self._isolated_home(task.id)
        environment["HOME"] = str(home)
        environment["XDG_CONFIG_HOME"] = str(home / ".config")
        environment["XDG_CACHE_HOME"] = str(home / ".cache")
        environment["XDG_DATA_HOME"] = str(home / ".local" / "share")
        environment["SATURNIN_HOME"] = str(trusted_config.root)
        environment["SATURNIN_WORKTREE"] = str(workdir)
        attestation_settings = trusted_config.governance.get("review", {}).get(
            "attestation", {}
        )
        key_env = str(attestation_settings.get("key_env", "SATURNIN_REVIEW_ATTESTATION_KEY"))
        previous_key_env = str(
            attestation_settings.get(
                "previous_key_env",
                "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY",
            )
        )
        scope_env = str(
            attestation_settings.get("key_scope_env", "SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE")
        )
        role_env = str(attestation_settings.get("role_env", "SATURNIN_AGENT_ROLE"))
        for protected_name in (
            key_env,
            previous_key_env,
            scope_env,
            role_env,
        ):
            environment.pop(protected_name, None)
        environment[role_env] = contract.role
        source = str(config.root / "src")
        environment["PYTHONPATH"] = source
        if contract.role in self._review_attestation_roles(trusted_config):
            master_key = os.environ.get(key_env, "")
            if not master_key:
                raise LauncherError(
                    f"reviewer role {contract.role!r} requires {key_env} in the launcher environment"
                )
            environment[key_env] = role_scoped_review_attestation_key(
                master_key,
                contract.role,
            )
            environment[scope_env] = "role"
        if "github" in contract.mcp:
            token_name = str(
                self.policy.get("github_read_token_env", "SATURNIN_GITHUB_MCP_TOKEN")
            )
            token = os.environ.get(token_name, "")
            if token:
                environment["GITHUB_PERSONAL_ACCESS_TOKEN"] = token
        return environment

    @staticmethod
    def _review_attestation_roles(config: Config) -> set[str]:
        review = config.governance.get("review", {})
        roles: set[str] = set()
        for kind in ("pr", "issue"):
            configured = review.get(kind, {}).get("allowed_reviewer_roles", [])
            if isinstance(configured, list):
                roles.update(str(role).strip().lower() for role in configured if str(role).strip())
        return roles

    def _isolated_home(self, task_id: str) -> Path:
        root = self.dir / f"{task_id}.home"
        for path in (
            root,
            root / ".config",
            root / ".cache",
            root / ".local" / "share",
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        destinations: set[Path] = set()
        for entry in self.policy.get("approved_home_config", []) or []:
            source, destination = self._approved_home_copy_paths(entry, root)
            if not source.exists():
                continue
            if destination in destinations:
                raise LauncherError(f"duplicate approved_home_config destination: {destination}")
            destinations.add(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                if destination.exists():
                    if not destination.is_dir():
                        raise LauncherError(
                            f"approved_home_config destination collides with a file: {destination}"
                        )
                    shutil.rmtree(destination)
                shutil.copytree(source, destination, symlinks=False)
            else:
                if destination.is_dir():
                    raise LauncherError(
                        f"approved_home_config destination collides with a directory: {destination}"
                    )
                shutil.copy2(source, destination)
        return root

    @staticmethod
    def _approved_home_copy_paths(entry: Any, isolated_home: Path) -> tuple[Path, Path]:
        if isinstance(entry, dict):
            source_value = entry.get("source")
            destination_value = entry.get("destination", entry.get("dest"))
            if not isinstance(source_value, str) or not source_value.strip():
                raise LauncherError("approved_home_config mapping entries require source")
        else:
            source_value = str(entry)
            destination_value = None
        source = Path(source_value).expanduser()
        if not source.is_absolute():
            raise LauncherError("approved_home_config entries must be absolute paths")
        if destination_value is None:
            home = Path.home().resolve(strict=False)
            resolved_source = source.resolve(strict=False)
            try:
                relative_destination = resolved_source.relative_to(home)
            except ValueError:
                relative_destination = Path(resolved_source.name)
        else:
            relative_destination = Path(str(destination_value)).expanduser()
            if relative_destination.is_absolute():
                raise LauncherError("approved_home_config destinations must be relative paths")
        if ".." in relative_destination.parts or not relative_destination.parts:
            raise LauncherError("approved_home_config destination must stay inside isolated HOME")
        destination = (isolated_home / relative_destination).resolve(strict=False)
        isolated = isolated_home.resolve(strict=False)
        if destination == isolated or not destination.is_relative_to(isolated):
            raise LauncherError("approved_home_config destination must stay inside isolated HOME")
        return source, destination

    def _worker_env_allowlist(self) -> tuple[str, ...]:
        configured = self.policy.get("env_allowlist")
        if configured is None:
            return (
                "PATH",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "TERM",
                "TMPDIR",
                "USER",
                "LOGNAME",
                "SHELL",
            )
        if not isinstance(configured, list) or not all(
            isinstance(name, str) and name.strip() for name in configured
        ):
            raise LauncherError("mcp.launcher.env_allowlist must be a non-empty list of env names")
        return tuple(dict.fromkeys(name.strip() for name in configured))

    def _contract(self, task: Task, config: Config | None = None) -> AgentContract:
        if not task.role:
            raise LauncherError(f"task {task.id} has no routed role")
        config = self._trusted_config(config or self.config)
        contracts = {contract.role: contract for contract in load_contracts(config)}
        if task.worktree:
            contracts.update(self._project_contracts(Path(task.worktree), config))
        try:
            return contracts[task.role]
        except KeyError as exc:
            raise LauncherError(f"no agent contract for routed role {task.role!r}") from exc

    def _project_contracts(
        self, worktree: Path, config: Config | None = None
    ) -> dict[str, AgentContract]:
        config = self._trusted_config(config or self.config)
        worktree_root = worktree.resolve(strict=False)
        manifest_path = (worktree_root / ".saturnin" / "repo.yaml").resolve(strict=False)
        if not manifest_path.is_relative_to(worktree_root):
            raise LauncherError("managed repository manifest must stay inside the worktree")
        if not manifest_path.is_file():
            return {}
        try:
            manifest = load_yaml(manifest_path)
        except (OSError, ValueError, YAMLError) as exc:
            raise LauncherError(f"invalid managed repository manifest: {exc}") from exc
        contracts: dict[str, AgentContract] = {}
        entries = manifest.get("agents") or []
        if not isinstance(entries, list):
            raise LauncherError("managed repository agents must be a list")
        global_roles = {contract.role for contract in load_contracts(config)}
        for entry in entries:
            relative = Path(str(entry))
            try:
                path = project_agent_path(worktree, entry, ".saturnin/agents")
            except ValueError as exc:
                raise LauncherError(f"invalid project agent path: {exc}") from exc
            if not path.is_file():
                raise LauncherError(f"project agent contract does not exist: {entry}")
            match = FRONT_MATTER.match(path.read_text(encoding="utf-8"))
            if not match:
                raise LauncherError(f"project agent contract lacks front matter: {entry}")
            data = load_yaml_front_matter(match.group(1), path)
            role = str(data.get("role", ""))
            if not role or role != relative.stem:
                raise LauncherError(f"project agent role must match its filename: {entry}")
            if role in global_roles:
                raise LauncherError(f"project agent shadows global role {role!r}")
            contract = AgentContract(role=role, path=path, front_matter=data)
            skills = {
                skill_path.stem
                for skill_path in (config.root / "skills").glob("*.md")
                if skill_path.name != "README.md"
            }
            for skill in contract.skills:
                if skill not in skills:
                    raise LauncherError(f"project agent {role!r} names unknown skill {skill!r}")
            for server in contract.mcp:
                authorization_problem = mcp_authorization_problem(
                    role,
                    server,
                    config.policy("mcp"),
                    executes=contract.executes,
                )
                if authorization_problem:
                    raise LauncherError(
                        f"MCP server {server!r} is not authorized for project role "
                        f"{role!r}: {authorization_problem}"
                    )
            contracts[role] = contract
        return contracts

    def _write_mcp_config(
        self,
        task: Task,
        contract: AgentContract,
        *,
        config: Config | None = None,
        worktree_scope: Path | None = None,
    ) -> Path:
        config = config or self.config
        trusted_config = self._trusted_config(config)
        trusted_definitions = trusted_config.policy("mcp").get("servers", {})
        source_definitions = config.policy("mcp").get("servers", {})
        if task.worktree:
            source_policy_path = Path(task.worktree) / "policies" / "mcp.yaml"
            if source_policy_path.is_file():
                source_definitions = load_yaml(source_policy_path).get("servers", {})
        if not isinstance(source_definitions, dict) or not isinstance(
            trusted_definitions, dict
        ):
            raise LauncherError("MCP server catalog must be a mapping")
        unknown = sorted(set(source_definitions) - set(trusted_definitions))
        if unknown:
            raise LauncherError(
                "branch-local policy defines untrusted MCP server(s): "
                + ", ".join(unknown)
            )
        altered = sorted(
            name
            for name, definition in source_definitions.items()
            if definition != trusted_definitions[name]
        )
        if altered:
            raise LauncherError(
                "branch-local policy alters trusted MCP server(s): "
                + ", ".join(altered)
            )
        definitions = {
            name: trusted_definitions[name] for name in source_definitions
        }
        servers: dict[str, dict[str, Any]] = {}
        allowed = list(contract.mcp)
        if task.worktree:
            worktree_root = Path(task.worktree).resolve(strict=False)
            manifest_path = (worktree_root / ".saturnin" / "repo.yaml").resolve(strict=False)
            if not manifest_path.is_relative_to(worktree_root):
                raise LauncherError("managed repository manifest must stay inside the worktree")
            if manifest_path.is_file():
                try:
                    manifest = load_yaml(manifest_path)
                except (OSError, ValueError, YAMLError) as exc:
                    raise LauncherError(f"invalid managed repository manifest: {exc}") from exc
                project_mcp = manifest.get("mcp")
                if project_mcp is not None:
                    if not isinstance(project_mcp, list) or not all(
                        isinstance(name, str) for name in project_mcp
                    ):
                        raise LauncherError("managed repository mcp must be a list of server ids")
                    unknown = sorted(set(project_mcp) - set(definitions))
                    if unknown:
                        raise LauncherError(
                            f"managed repository names unknown MCP server(s): {', '.join(unknown)}"
                        )
                    project_allowlist = set(project_mcp)
                    allowed = [name for name in allowed if name in project_allowlist]
        for name in allowed:
            definition = definitions.get(name)
            if not isinstance(definition, dict):
                raise LauncherError(f"unknown MCP server {name!r} for role {contract.role}")
            authorization_problem = mcp_authorization_problem(
                contract.role,
                name,
                trusted_config.policy("mcp"),
                executes=contract.executes,
            )
            if authorization_problem:
                raise LauncherError(
                    f"MCP server {name!r} is not authorized for role "
                    f"{contract.role!r}: {authorization_problem}"
                )
            command, args = server_process(
                name,
                definition,
                trusted_config,
                worktree_scope=worktree_scope,
            )
            canonical_github = (
                config.var_dir / "bin" / "github-mcp-server"
            ).resolve(strict=False)
            if Path(command).resolve(strict=False) == canonical_github:
                verified = verify_github_binary(trusted_config).resolve()
                if verified != canonical_github:
                    raise LauncherError(
                        "verified GitHub MCP executable does not match canonical path"
                    )
            servers[name] = {
                "type": definition.get("transport", "stdio"),
                "command": command,
                "args": args,
            }
        path = self.dir / f"{task.id}.mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n", encoding="utf-8")
        return path

    def _prompt(
        self,
        task: Task,
        contract: AgentContract,
        *,
        config: Config | None = None,
        checkpoint: Checkpoint | None = None,
    ) -> str:
        config = config or self.config
        sections = [
            f"Complete Saturnin task {task.id}.",
            json.dumps(task.to_dict(), indent=2),
            contract.path.read_text(encoding="utf-8"),
        ]
        if task.worktree:
            worktree_root = Path(task.worktree).resolve(strict=False)
            manifest_path = (worktree_root / ".saturnin" / "repo.yaml").resolve(strict=False)
            if not manifest_path.is_relative_to(worktree_root):
                raise LauncherError("managed repository manifest must stay inside the worktree")
            if manifest_path.is_file():
                sections.append(
                    "Managed repository manifest (.saturnin/repo.yaml):\n"
                    + manifest_path.read_text(encoding="utf-8")
                )
        for skill in contract.skills:
            path = config.root / "skills" / f"{skill}.md"
            sections.append(path.read_text(encoding="utf-8"))
        if checkpoint is not None:
            sections.append(checkpoint.render())
        return "\n\n---\n\n".join(sections)


def load_yaml_front_matter(value: str, path: Path) -> dict[str, Any]:
    import yaml

    try:
        data = yaml.safe_load(value) or {}
    except YAMLError as exc:
        raise LauncherError(f"invalid project agent contract {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LauncherError(f"project agent contract {path} must contain a mapping")
    return data
