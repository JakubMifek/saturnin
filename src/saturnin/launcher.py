"""Non-blocking, contract-aware agent process launcher."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from yaml import YAMLError

from .board import Board, Task, utcnow
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config, default_config, load_yaml
from .contracts import (
    FRONT_MATTER,
    AgentContract,
    load_contracts,
    mcp_authorization_problem,
    project_agent_path,
)
from .mcp import server_process


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
        self.policy = self.config.policy("mcp").get("launcher", {})
        self.dir = self.config.var_dir / "launches"
        self.dir.mkdir(parents=True, exist_ok=True)

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
        contract = self._contract(task)
        checkpoint = CheckpointStore(self.config, self.board).latest(task.id)
        executable = str(self.policy.get("command", "copilot"))
        if shutil.which(executable) is None:
            raise LauncherError(f"agent launcher executable not found: {executable}")
        mcp_path: Path | None = None
        log_path = self.dir / f"{task.id}.log"
        launch_error: LauncherError | None = None
        process: subprocess.Popen[bytes] | None = None
        workdir: Path | None = None
        with self.board.edit(task.id) as stored:
            previous_state = stored.state
            previous_checkpoint_resumed_at = stored.checkpoint_resumed_at
            if stored.state == "in_progress" and resumed_checkpoint:
                if stored.checkpoint_resumed_at == resumed_checkpoint:
                    raise LauncherError(
                        f"checkpoint {resumed_checkpoint} already resumed for task {stored.id}"
                    )
            elif stored.state != "routed":
                raise LauncherError(f"task {stored.id} cannot launch from state {stored.state}")
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
                mcp_path = self._write_mcp_config(claimed, contract, worktree_scope=workdir)
                prompt = self._prompt(claimed, contract, checkpoint=checkpoint)
                args = [
                    str(value).format(mcp_config=str(mcp_path), prompt=prompt, task_id=claimed.id)
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
                with log_path.open("ab") as output:
                    process = subprocess.Popen(
                        [executable, *args],
                        cwd=workdir,
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
            except (LauncherError, OSError) as exc:
                if previous_state in ("routed", "in_progress"):
                    stored.state = previous_state
                stored.checkpoint_resumed_at = previous_checkpoint_resumed_at
                stored.log("agent:launch_failed", actor="launcher", reason=str(exc))
                launch_error = LauncherError(f"agent launcher failed for task {task.id}: {exc}")
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
        if launch_error is not None:
            raise launch_error
        if process is None or workdir is None or mcp_path is None:  # pragma: no cover
            raise LauncherError(f"agent launcher failed for task {task.id}")
        metadata = {
            "task_id": task.id,
            "role": contract.role,
            "pid": process.pid,
            "started_at": utcnow(),
            "cwd": str(workdir),
            "mcp_config": str(mcp_path),
            "log": str(log_path),
        }
        (self.dir / f"{task.id}.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
        )
        return LaunchResult(
            task_id=task.id,
            role=contract.role,
            pid=process.pid,
            log=str(log_path),
            mcp_config=str(mcp_path),
        )

    def _immediate_exit_status(self, process: subprocess.Popen[bytes]) -> int | None:
        wait = getattr(process, "wait", None)
        if wait is None:
            return None
        try:
            return wait(timeout=float(self.policy.get("failure_grace_seconds", 0.05)))
        except subprocess.TimeoutExpired:
            return None

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

    def _contract(self, task: Task) -> AgentContract:
        if not task.role:
            raise LauncherError(f"task {task.id} has no routed role")
        contracts = {contract.role: contract for contract in load_contracts(self.config)}
        if task.worktree:
            contracts.update(self._project_contracts(Path(task.worktree)))
        try:
            return contracts[task.role]
        except KeyError as exc:
            raise LauncherError(f"no agent contract for routed role {task.role!r}") from exc

    def _project_contracts(self, worktree: Path) -> dict[str, AgentContract]:
        manifest_path = worktree / ".saturnin" / "repo.yaml"
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
        global_roles = {contract.role for contract in load_contracts(self.config)}
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
            contracts[role] = AgentContract(role=role, path=path, front_matter=data)
        return contracts

    def _write_mcp_config(
        self,
        task: Task,
        contract: AgentContract,
        *,
        worktree_scope: Path | None = None,
    ) -> Path:
        definitions = self.config.policy("mcp").get("servers", {})
        servers: dict[str, dict[str, Any]] = {}
        allowed = list(contract.mcp)
        if task.worktree:
            manifest_path = Path(task.worktree) / ".saturnin" / "repo.yaml"
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
                self.config.policy("mcp"),
                executes=contract.executes,
            )
            if authorization_problem:
                raise LauncherError(
                    f"MCP server {name!r} is not authorized for role "
                    f"{contract.role!r}: {authorization_problem}"
                )
            command, args = server_process(
                definition,
                self.config,
                worktree_scope=worktree_scope,
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
        checkpoint: Checkpoint | None = None,
    ) -> str:
        sections = [
            f"Complete Saturnin task {task.id}.",
            json.dumps(task.to_dict(), indent=2),
            contract.path.read_text(encoding="utf-8"),
        ]
        if task.worktree:
            manifest_path = Path(task.worktree) / ".saturnin" / "repo.yaml"
            if manifest_path.is_file():
                sections.append(
                    "Managed repository manifest (.saturnin/repo.yaml):\n"
                    + manifest_path.read_text(encoding="utf-8")
                )
        for skill in contract.skills:
            path = self.config.root / "skills" / f"{skill}.md"
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
