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
from .locking import file_lock
from .mcp import MCPError, server_process, verify_github_binary
from .review import ReviewError, role_scoped_review_attestation_key, slugify as review_slugify
from .worker_callbacks import (
    CALLBACKS_FILE,
    ENV_CALLBACK_DIR,
    ENV_CALLBACK_TASK_ID,
    apply_queued,
)
from .worktrees import GitError, validated_task_worktree


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
        callback_path = (
            self.dir
            / f"{task.id}.home"
            / ".saturnin-callbacks"
            / CALLBACKS_FILE
        )
        if metadata_path.exists() or callback_path.exists():
            self.reconcile_exited_launches()
        with file_lock(metadata_path):
            if metadata_path.exists() or callback_path.exists():
                raise LauncherError(
                    f"task {task.id} already has an active or unrecoverable launch"
                )
            task = self.board.get(task_id)
            return self._launch_locked(task, resumed_checkpoint=resumed_checkpoint)

    def _launch_locked(
        self,
        task: Task,
        *,
        resumed_checkpoint: str | None,
    ) -> LaunchResult | None:
        metadata_path = self.dir / f"{task.id}.json"
        checkpoint = CheckpointStore(self.config, self.board).latest(task.id)
        executable = str(self.policy.get("command", "copilot"))
        executable_path = shutil.which(executable)
        if executable_path is None:
            raise LauncherError(f"agent launcher executable not found: {executable}")
        executable_path = str(Path(executable_path).resolve())
        sandbox_path = self._sandbox_executable()
        network_sandbox_path = self._network_sandbox_executable()
        mcp_path: Path | None = None
        log_path = self.dir / f"{task.id}.log"
        launch_error: LauncherError | None = None
        process: subprocess.Popen[bytes] | None = None
        workdir: Path | None = None
        metadata: dict[str, Any] | None = None
        metadata_attempted = False
        completed_during_grace = False
        completed_persistence_problem: str | None = None
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
                if stored.state == "in_progress":
                    if self._poller_is_waiting(stored):
                        stored.launch_deferred_at = None
                        stored.launch_deferred_reason = None
                        return None
                    if resumed_checkpoint:
                        if stored.checkpoint_resumed_at == resumed_checkpoint:
                            raise LauncherError(
                                f"checkpoint {resumed_checkpoint} already resumed "
                                f"for task {stored.id}"
                            )
                    elif stored.launch_deferred_at is None:
                        raise LauncherError(
                            f"task {stored.id} cannot launch from state {stored.state}"
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
                    self._stage_worker_board_context(claimed, home, worker_config)
                    command = self._sandbox_command(
                        sandbox_path,
                        network_sandbox_path,
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
                        process_start_time = self._process_start_time(process.pid)
                        if process_start_time is None:
                            raise LauncherError(
                                f"could not read process identity for agent pid {process.pid}"
                            )
                        immediate_status = self._immediate_exit_status(process)
                        if immediate_status not in (None, 0):
                            raise LauncherError(
                                "agent launcher exited immediately with "
                                f"status {immediate_status}; see {log_path}"
                            )
                        completed_during_grace = immediate_status == 0
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
                        "callback_dir": environment.get(ENV_CALLBACK_DIR),
                        "completed": completed_during_grace,
                    }
                    metadata_attempted = True
                    atomic_replace_text(
                        metadata_path, json.dumps(metadata, indent=2) + "\n"
                    )
                except (LauncherError, MCPError, OSError) as exc:
                    reason = str(exc)
                    if not completed_during_grace:
                        exit_status, failure_cleanup_problem = (
                            self._settle_failed_process(process)
                        )
                        completed_during_grace = exit_status == 0
                    if completed_during_grace and metadata is not None:
                        metadata["completed"] = True
                    if completed_during_grace:
                        completed_persistence_problem = reason
                        stored.log(
                            "agent:launch_recovery_pending",
                            actor="launcher",
                            reason=reason,
                        )
                    else:
                        if previous_state in ("routed", "in_progress"):
                            stored.state = previous_state
                        stored.checkpoint_resumed_at = previous_checkpoint_resumed_at
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
                    if previous_state == "routed":
                        stored.log(
                            "state:in_progress",
                            actor=stored.role or "launcher",
                            note=f"agent pid={process.pid}",
                        )
                    task = Task.from_dict(stored.to_dict())
        except OSError as exc:
            reason = f"could not persist launch state: {exc}"
            termination_problem: str | None = None
            if not completed_during_grace:
                exit_status, termination_problem = self._settle_failed_process(process)
                completed_during_grace = exit_status == 0
            if completed_during_grace and metadata is not None:
                metadata["completed"] = True
            if completed_during_grace:
                completed_persistence_problem = reason
            else:
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
                raise LauncherError(
                    f"agent launcher failed for task {task.id}: {reason}"
                ) from exc
        if launch_error is not None:
            if not failure_cleanup_problem and metadata_attempted:
                removal_problem = self._remove_launch_metadata(metadata_path)
                if removal_problem:
                    raise LauncherError(f"{launch_error}; {removal_problem}") from launch_error
            raise launch_error
        if process is None or workdir is None or mcp_path is None:  # pragma: no cover
            raise LauncherError(f"agent launcher failed for task {task.id}")
        if completed_during_grace:
            metadata_ready = metadata_path.exists() and completed_persistence_problem is None
            if completed_persistence_problem and metadata is not None:
                try:
                    atomic_replace_text(
                        metadata_path, json.dumps(metadata, indent=2) + "\n"
                    )
                except OSError as exc:
                    metadata_ready = False
                    completed_persistence_problem = (
                        f"{completed_persistence_problem}; {exc}"
                        if completed_persistence_problem
                        else str(exc)
                    )
                else:
                    metadata_ready = True
            if metadata_ready:
                _, callbacks_complete, recovery_reason = (
                    self._reconcile_exited_launch(metadata)
                )
                if callbacks_complete:
                    completed_persistence_problem = self._remove_launch_metadata(
                        metadata_path
                    )
                else:
                    completed_persistence_problem = (
                        f"{completed_persistence_problem}; {recovery_reason}"
                        if completed_persistence_problem
                        else recovery_reason
                    )
            elif metadata is not None:
                _, callbacks_complete, recovery_reason = (
                    self._reconcile_exited_launch(metadata)
                )
                if callbacks_complete:
                    removal_problem = self._remove_launch_metadata(metadata_path)
                    completed_persistence_problem = removal_problem
                else:
                    completed_persistence_problem = (
                        f"{completed_persistence_problem}; {recovery_reason}"
                        if completed_persistence_problem
                        else recovery_reason
                    )
        if completed_persistence_problem:
            raise LauncherError(
                f"agent launcher completed for task {task.id}, but recovery remains "
                f"pending: {completed_persistence_problem}"
            )
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
            with file_lock(metadata_path):
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
                    metadata.get("completed") is not True
                    and isinstance(process_start_time, int)
                    and not isinstance(process_start_time, bool)
                    and self._process_start_time(pid) == process_start_time
                ):
                    self._recover_launch_metadata(metadata)
                    continue
                recovery_pending, callbacks_complete, _ = (
                    self._reconcile_exited_launch(metadata)
                )
                if recovery_pending:
                    resumed.append(task_id)
                if not callbacks_complete:
                    continue
                try:
                    metadata_path.unlink()
                except OSError:
                    pass
        for queue_path in sorted(
            self.dir.glob(f"*.home/.saturnin-callbacks/{CALLBACKS_FILE}")
        ):
            task_id = queue_path.parent.parent.name.removesuffix(".home")
            if not task_id:
                continue
            metadata_path = self.dir / f"{task_id}.json"
            if metadata_path.exists():
                continue
            with file_lock(metadata_path):
                if metadata_path.exists() or not queue_path.is_file():
                    continue
                recovery_pending, callbacks_complete, _ = self._reconcile_exited_launch(
                    {
                        "task_id": task_id,
                        "pid": 0,
                        "callback_dir": str(queue_path.parent),
                        "completed": True,
                    }
                )
                if recovery_pending:
                    resumed.append(task_id)
        return resumed

    def _reconcile_exited_launch(
        self,
        metadata: dict[str, Any],
    ) -> tuple[bool, bool, str]:
        task_id = str(metadata["task_id"])
        pid = int(metadata["pid"])
        reason = f"agent process exited or identity changed after launch with pid {pid}"
        if metadata.get("completed") is True:
            recovery_problem = self._recover_launch_metadata(metadata)
            if recovery_problem:
                return False, False, f"{reason}; {recovery_problem}"
        callbacks_complete = True
        try:
            apply_queued(
                self.config,
                self.board,
                task_id=task_id,
                callback_dir=metadata.get("callback_dir")
                if isinstance(metadata.get("callback_dir"), str)
                else None,
            )
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            callbacks_complete = False
            reason = f"{reason}; worker callbacks failed: {exc}"
        recovery_pending = False
        try:
            with self.board.edit(task_id) as task:
                if not callbacks_complete:
                    task.log("agent:callback_failed", actor="launcher", reason=reason)
                elif task.state == "in_progress":
                    if self._poller_is_waiting(task):
                        task.log(
                            "agent:poller_waiting",
                            actor="launcher",
                            reason=reason,
                        )
                    else:
                        task.launch_deferred_at = utcnow()
                        task.launch_deferred_reason = reason
                        task.log("agent:launch_failed", actor="launcher", reason=reason)
                        recovery_pending = True
        except OSError as exc:
            return False, False, f"{reason}; launch reconciliation failed: {exc}"
        except BoardError:
            pass
        return recovery_pending, callbacks_complete, reason

    def _recover_launch_metadata(self, metadata: dict[str, Any]) -> str | None:
        task_id = str(metadata["task_id"])
        pid = int(metadata["pid"])
        resumed_checkpoint = metadata.get("resumed_checkpoint")
        try:
            with self.board.edit(task_id) as task:
                recover_state = task.state == "routed"
                recover_checkpoint = (
                    isinstance(resumed_checkpoint, str)
                    and bool(resumed_checkpoint)
                    and task.checkpoint_resumed_at != resumed_checkpoint
                )
                if not recover_state and not recover_checkpoint:
                    return None
                task.log("agent:launch_recovered", actor="launcher", pid=pid)
                if recover_state:
                    self.board._apply_transition(  # noqa: SLF001 - atomic recovery
                        task,
                        "in_progress",
                        actor=task.role or "launcher",
                        note=f"recovered agent pid={pid}",
                    )
                    task.launch_deferred_at = None
                    task.launch_deferred_reason = None
                if recover_checkpoint:
                    task.checkpoint_resumed_at = resumed_checkpoint
        except (BoardError, OSError) as exc:
            return f"launch recovery failed: {exc}"
        return None

    def has_active_launch(self, task_id: str) -> bool:
        metadata_path = self.dir / f"{task_id}.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        pid = metadata.get("pid")
        started = metadata.get("process_start_time_ticks")
        return (
            metadata.get("task_id") == task_id
            and metadata.get("completed") is not True
            and isinstance(pid, int)
            and not isinstance(pid, bool)
            and isinstance(started, int)
            and not isinstance(started, bool)
            and self._process_start_time(pid) == started
        )

    def _poller_is_waiting(self, task: Task) -> bool:
        if task.result_contract != "poller":
            return False
        return (self.config.var_dir / "pollers" / f"{task.id}.json").is_file()

    @staticmethod
    def _remove_launch_metadata(metadata_path: Path) -> str | None:
        try:
            metadata_path.unlink(missing_ok=True)
        except OSError as exc:
            return f"could not remove launch metadata: {exc}"
        return None

    def _settle_failed_process(
        self,
        process: subprocess.Popen[bytes] | None,
    ) -> tuple[int | None, str | None]:
        exit_status = self._reap_exit_status(process)
        if exit_status is not None:
            return exit_status, None
        return self._terminate_process(process)

    def _terminate_process(
        self,
        process: subprocess.Popen[bytes] | None,
    ) -> tuple[int | None, str | None]:
        if process is None:
            return None, None
        try:
            process.terminate()
        except ProcessLookupError:
            return self._reap_exit_status(process), None
        except (AttributeError, OSError) as exc:
            exit_status = self._reap_exit_status(process)
            if exit_status is not None:
                return exit_status, None
            return None, f"could not terminate spawned agent pid {process.pid}: {exc}"
        wait = getattr(process, "wait", None)
        if wait is None:
            return None, None
        try:
            return (
                wait(timeout=float(self.policy.get("termination_grace_seconds", 5))),
                None,
            )
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
            return (
                wait(timeout=float(self.policy.get("termination_grace_seconds", 5))),
                None,
            )
        except ProcessLookupError:
            return self._reap_exit_status(process), None
        except (AttributeError, OSError, subprocess.TimeoutExpired) as exc:
            exit_status = self._reap_exit_status(process)
            if exit_status is not None:
                return exit_status, None
            return None, f"could not terminate spawned agent pid {process.pid}: {exc}"

    @staticmethod
    def _reap_exit_status(
        process: subprocess.Popen[bytes] | None,
    ) -> int | None:
        if process is None:
            return None
        wait = getattr(process, "wait", None)
        if wait is None:
            return None
        try:
            return wait(timeout=0)
        except (AttributeError, OSError, subprocess.TimeoutExpired):
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
                task.checkpoint_resumed_at = previous_checkpoint_resumed_at
                if task.state == previous_state:
                    task.launch_deferred_at = previous_launch_deferred_at
                    task.launch_deferred_reason = previous_launch_deferred_reason
                else:
                    task.launch_deferred_at = utcnow()
                    task.launch_deferred_reason = reason
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

    def _network_sandbox_executable(self) -> str:
        sandbox = self.policy.get("sandbox", {})
        if not isinstance(sandbox, dict):
            raise LauncherError("mcp.launcher.sandbox must be a mapping")
        network = sandbox.get("network", {})
        if not isinstance(network, dict):
            raise LauncherError("mcp.launcher.sandbox.network must be a mapping")
        executable = str(network.get("command", "pasta")).strip()
        path = shutil.which(executable)
        if path is None:
            raise LauncherError(
                f"required worker network sandbox executable not found: {executable}"
            )
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
        network_sandbox: str,
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
        network_policy = sandbox_policy.get("network", {})
        if not isinstance(network_policy, dict):
            raise LauncherError("mcp.launcher.sandbox.network must be a mapping")
        network_args = network_policy.get(
            "args",
            [
                "--quiet",
                "--foreground",
                "--no-map-gw",
                "--tcp-ports=none",
                "--udp-ports=none",
            ],
        )
        if not isinstance(network_args, list) or not all(
            isinstance(argument, str) and argument for argument in network_args
        ):
            raise LauncherError(
                "mcp.launcher.sandbox.network.args must be a list of nonempty strings"
            )
        required_network_args = {
            "--no-map-gw",
            "--tcp-ports=none",
            "--udp-ports=none",
        }
        missing_network_args = sorted(required_network_args - set(network_args))
        if missing_network_args:
            raise LauncherError(
                "mcp.launcher.sandbox.network.args must disable host gateway and "
                f"inbound port mappings (missing: {', '.join(missing_network_args)})"
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
            network_sandbox,
            *network_args,
            "--",
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
            (Path(path), Path(path)) for path in read_only_paths if Path(path).exists()
        ]
        read_only_mounts.extend((path, path) for path in trusted_paths if path.exists())
        read_only_mounts.extend(
            (path, path) for path in (Path(executable), git_objects, mcp_config)
        )
        staged_board = isolated_home / ".saturnin-board"
        if staged_board.exists():
            read_only_mounts.append((staged_board, trusted_config.board_dir))
        mounts = [
            *[
                ("--ro-bind", source, target)
                for source, target in dict.fromkeys(read_only_mounts)
            ],
            ("--bind", workdir.resolve(), workdir.resolve()),
            ("--bind", isolated_home.resolve(), isolated_home.resolve()),
        ]
        created: set[Path] = set()
        for _, _, target in mounts:
            parent = target if target.is_dir() else target.parent
            for directory in reversed(parent.parents):
                if directory != Path("/") and directory not in created:
                    command.extend(("--dir", str(directory)))
                    created.add(directory)
            if parent != Path("/") and parent not in created:
                command.extend(("--dir", str(parent)))
                created.add(parent)
        for operation, source, target in mounts:
            command.extend((operation, str(source), str(target)))
        command.extend(("--chdir", str(workdir.resolve()), "--", executable, *args))
        return command

    def _stage_worker_board_context(
        self,
        task: Task,
        isolated_home: Path,
        config: Config,
    ) -> Path:
        """Stage the minimum board data this worker may read."""
        trusted_config = self._trusted_config(config)
        staged = isolated_home / ".saturnin-board"
        if staged.exists():
            shutil.rmtree(staged)
        for name in ("tasks", "checkpoints", "reviews"):
            (staged / name).mkdir(parents=True, exist_ok=True)
        for source, destination in (
            (
                trusted_config.tasks_dir / f"{task.id}.json",
                staged / "tasks" / f"{task.id}.json",
            ),
            (
                trusted_config.checkpoints_dir / f"{task.id}.jsonl",
                staged / "checkpoints" / f"{task.id}.jsonl",
            ),
        ):
            if source.is_file():
                shutil.copy2(source, destination)
        if task.review_subject and task.kind in {"pr-review", "issue-review"}:
            review_kind = task.kind.removesuffix("-review")
            try:
                review_name = f"{review_kind}-{review_slugify(task.review_subject)}.jsonl"
            except ReviewError:
                review_name = ""
            source = trusted_config.board_dir / "reviews" / review_name
            if review_name and source.is_file():
                shutil.copy2(source, staged / "reviews" / review_name)
        readme = trusted_config.board_dir / "README.md"
        if readme.is_file():
            shutil.copy2(readme, staged / "README.md")
        return staged

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
        self._validated_push_urls(task, workdir)
        self._git_output(
            ["--git-dir", str(git_dir), "config", "--unset-all", "remote.origin.url"],
            required=False,
        )
        self._git_output(
            ["--git-dir", str(git_dir), "config", "--unset-all", "remote.origin.pushurl"],
            required=False,
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
        try:
            return validated_task_worktree(task)
        except GitError as exc:
            raise LauncherError(str(exc)) from exc

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
        trusted_config = self._trusted_config(config)
        token_name = str(
            trusted_config.policy("mcp")
            .get("launcher", {})
            .get("github_read_token_env", "SATURNIN_GITHUB_MCP_TOKEN")
        )
        environment = {
            name: value
            for name in self._worker_env_allowlist()
            if (value := os.environ.get(name)) is not None
        }
        home = self._isolated_home(task.id)
        environment["HOME"] = str(home)
        environment["XDG_CONFIG_HOME"] = str(home / ".config")
        environment["XDG_CACHE_HOME"] = str(home / ".cache")
        environment["XDG_DATA_HOME"] = str(home / ".local" / "share")
        environment["SATURNIN_HOME"] = str(trusted_config.root)
        environment["SATURNIN_WORKTREE"] = str(workdir)
        environment[ENV_CALLBACK_TASK_ID] = task.id
        environment[ENV_CALLBACK_DIR] = str(home / ".saturnin-callbacks")
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
            token_name,
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GITHUB_PERSONAL_ACCESS_TOKEN",
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
            server: dict[str, Any] = {
                "type": definition.get("transport", "stdio"),
                "command": command,
                "args": args,
            }
            if name == "github":
                token_name = str(
                    trusted_config.policy("mcp")
                    .get("launcher", {})
                    .get("github_read_token_env", "SATURNIN_GITHUB_MCP_TOKEN")
                )
                token = os.environ.get(token_name, "")
                if token:
                    server["env"] = {"GITHUB_PERSONAL_ACCESS_TOKEN": token}
            servers[name] = server
        path = self.dir / f"{task.id}.mcp.json"
        atomic_replace_text(
            path,
            json.dumps({"mcpServers": servers}, indent=2) + "\n",
            mode=PRIVATE_FILE_MODE,
        )
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
