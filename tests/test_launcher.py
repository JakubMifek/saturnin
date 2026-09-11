from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from saturnin.board import Board
from saturnin.config import Config
from saturnin.launcher import AgentLauncher
from saturnin.routing import Router


def test_launcher_starts_routed_role_with_filtered_mcp(
    config: Config, board: Board, monkeypatch
) -> None:
    config.policy("mcp")["launcher"]["enabled"] = True
    task = board.create("Implement a small fix")
    Router(config).dispatch(board, task)
    calls: list[tuple[list[str], dict]] = []

    monkeypatch.setattr("saturnin.launcher.shutil.which", lambda _: "/usr/bin/copilot")

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr("saturnin.launcher.subprocess.Popen", fake_popen)

    result = AgentLauncher(config, board).launch(task.id)

    assert result is not None
    assert result.pid == 4242
    assert board.get(task.id).state == "in_progress"
    mcp = json.loads((config.var_dir / "launches" / f"{task.id}.mcp.json").read_text())
    assert set(mcp["mcpServers"]) == {"github", "filesystem"}
    assert mcp["mcpServers"]["filesystem"]["args"][-1] == str(config.var_dir / "worktrees")
    command = calls[0][0]
    assert "--no-ask-user" in command
    assert "Implement a small fix" in command[-1]
    assert "role: code-worker" in command[-1]


def test_root_mcp_config_has_no_blanket_grants() -> None:
    config = json.loads((Path(__file__).parents[1] / ".mcp.json").read_text())
    assert config["mcpServers"] == {}
