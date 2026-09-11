"""Non-blocking, contract-aware agent process launcher."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .board import Board, Task, utcnow
from .checkpoints import CheckpointStore
from .config import Config, default_config
from .contracts import AgentContract, load_contracts


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
        if task.state not in ("routed", "in_progress"):
            raise LauncherError(f"task {task.id} cannot launch from state {task.state}")
        contract = self._contract(task)
        mcp_path = self._write_mcp_config(task, contract)
        prompt = self._prompt(task, contract)
        executable = str(self.policy.get("command", "copilot"))
        if shutil.which(executable) is None:
            raise LauncherError(f"agent launcher executable not found: {executable}")
        args = [
            str(value).format(mcp_config=str(mcp_path), prompt=prompt, task_id=task.id)
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
        workdir = Path(task.worktree) if task.worktree else self.config.root
        if not workdir.is_dir():
            raise LauncherError(f"task worktree does not exist: {workdir}")
        log_path = self.dir / f"{task.id}.log"
        with log_path.open("ab") as output:
            process = subprocess.Popen(
                [executable, *args],
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        with self.board.edit(task.id) as stored:
            if stored.state == "routed":
                Board._apply_transition(
                    stored,
                    "in_progress",
                    actor=stored.role or "launcher",
                    note=f"agent pid={process.pid}",
                )
            stored.log(
                "agent:launched",
                actor="launcher",
                role=contract.role,
                pid=process.pid,
            )
            if resumed_checkpoint:
                stored.checkpoint_resumed_at = resumed_checkpoint
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

    def _contract(self, task: Task) -> AgentContract:
        if not task.role:
            raise LauncherError(f"task {task.id} has no routed role")
        contracts = {contract.role: contract for contract in load_contracts(self.config)}
        try:
            return contracts[task.role]
        except KeyError as exc:
            raise LauncherError(f"no agent contract for routed role {task.role!r}") from exc

    def _write_mcp_config(self, task: Task, contract: AgentContract) -> Path:
        definitions = self.config.policy("mcp").get("servers", {})
        servers: dict[str, dict[str, Any]] = {}
        for name in contract.mcp:
            definition = definitions.get(name)
            if not isinstance(definition, dict):
                raise LauncherError(f"unknown MCP server {name!r} for role {contract.role}")
            servers[name] = {
                "type": definition.get("transport", "stdio"),
                "command": definition["command"],
                "args": [
                    str(value).format(worktrees=str(self.config.var_dir / "worktrees"))
                    for value in definition.get("args", [])
                ],
            }
        path = self.dir / f"{task.id}.mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n", encoding="utf-8")
        return path

    def _prompt(self, task: Task, contract: AgentContract) -> str:
        sections = [
            f"Complete Saturnin task {task.id}.",
            json.dumps(task.to_dict(), indent=2),
            contract.path.read_text(encoding="utf-8"),
        ]
        for skill in contract.skills:
            path = self.config.root / "skills" / f"{skill}.md"
            sections.append(path.read_text(encoding="utf-8"))
        checkpoint = CheckpointStore(self.config, self.board).latest(task.id)
        if checkpoint is not None:
            sections.append(checkpoint.render())
        return "\n\n---\n\n".join(sections)
