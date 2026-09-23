from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from saturnin.cli import main
from saturnin.config import Config
from saturnin.launcher import AgentLauncher
from saturnin.launcher_host import (
    LauncherHostError,
    host_config_path,
    host_launcher_enabled,
    launcher_health,
)
from saturnin.mcp import MCPError


def _healthy_prerequisites(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    for name in ("bwrap", "pasta", "copilot", "npx", "uvx"):
        path = binary_dir / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir))
    monkeypatch.setattr(
        "saturnin.launcher_host.resolve_trusted_executable",
        lambda _, name, **kwargs: binary_dir / name,
    )
    github = config.var_dir / "bin" / "github-mcp-server"
    monkeypatch.setattr(
        "saturnin.launcher_host.verify_github_binary", lambda _: github
    )
    return github


def test_launcher_enable_is_host_local_and_keeps_policy_default(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _healthy_prerequisites(config, tmp_path, monkeypatch)

    assert main(["--json", "launcher", "enable"]) == 0
    payload = json.loads(capsys.readouterr().out)
    path = host_config_path(config)

    assert payload["enabled"] is True
    assert payload["source"] == "host-local"
    assert payload["healthy"] is True
    assert config.policy("mcp")["launcher"]["enabled"] is False
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": 1,
        "launcher": {"enabled": True},
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert AgentLauncher(config).enabled is True

    assert main(["--json", "launcher", "disable"]) == 0
    disabled = json.loads(capsys.readouterr().out)
    assert disabled["enabled"] is False
    assert disabled["source"] == "safe-default"
    assert not path.exists()


def test_launcher_enable_reports_every_failed_prerequisite(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(
        "saturnin.launcher_host.verify_github_binary",
        lambda _: (_ for _ in ()).throw(
            MCPError("pinned GitHub MCP server is unavailable")
        ),
    )

    assert main(["launcher", "enable"]) == 1

    error = capsys.readouterr().err
    assert "bwrap, pasta, copilot, npx, uvx, github-mcp-server" in error
    assert not host_config_path(config).exists()


def test_launcher_rejects_host_configuration_with_extra_data(config: Config) -> None:
    path = host_config_path(config)
    path.parent.mkdir(parents=True)
    path.write_text(
        '{"version": 1, "launcher": {"enabled": true}, "token": "forbidden"}\n',
        encoding="utf-8",
    )

    with pytest.raises(LauncherHostError, match="must contain only"):
        host_launcher_enabled(config)


def test_launcher_health_does_not_execute_untrusted_path_entries(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree_bin = tmp_path / "worktree" / "bin"
    worktree_bin.mkdir(parents=True)
    for name in ("bwrap", "pasta", "copilot", "npx", "uvx"):
        path = worktree_bin / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", str(worktree_bin))
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "saturnin.launcher_host.subprocess.run",
        lambda command, **kwargs: calls.append(command),
    )
    monkeypatch.setattr(
        "saturnin.launcher_host.verify_github_binary",
        lambda _: config.var_dir / "bin" / "github-mcp-server",
    )

    checks = launcher_health(config)

    assert all(not check["healthy"] for check in checks[:5])
    assert all(
        "outside trusted system executable roots" in check["detail"]
        for check in checks[:5]
    )
    assert calls == []
