from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.cli import main
from saturnin.config import Config
from saturnin.launcher import AgentLauncher
from saturnin.launcher_host import (
    LauncherHostError,
    host_config_path,
    host_launcher_enabled,
    launcher_health,
    set_host_launcher_enabled,
)
from saturnin.mcp import MCPError


def _secure_host_config_parents(config: Config) -> None:
    config.data_root.chmod(0o755)
    config.var_dir.chmod(0o700)


def _healthy_prerequisites(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    _secure_host_config_parents(config)
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
    monkeypatch.setattr(
        "saturnin.launcher_host.prerequisite_invocation",
        lambda _, executable, arguments, definition: (
            ["/bin/sh", str(executable), *arguments],
            "/usr/bin:/bin",
        ),
    )
    github = config.var_dir / "bin" / "github-mcp-server"
    monkeypatch.setattr(
        "saturnin.launcher_host.verify_github_binary",
        lambda _, **kwargs: github,
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
        lambda _, **kwargs: (_ for _ in ()).throw(
            MCPError("pinned GitHub MCP server is unavailable")
        ),
    )

    assert main(["launcher", "enable"]) == 1

    error = capsys.readouterr().err
    assert "bwrap, pasta, copilot, npx, uvx, github-mcp-server" in error
    assert not host_config_path(config).exists()


def test_launcher_rejects_host_configuration_with_extra_data(config: Config) -> None:
    _secure_host_config_parents(config)
    path = host_config_path(config)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_text(
        '{"version": 1, "launcher": {"enabled": true}, "token": "forbidden"}\n',
        encoding="utf-8",
    )
    path.chmod(0o600)

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
        lambda _, **kwargs: config.var_dir / "bin" / "github-mcp-server",
    )

    checks = launcher_health(config)

    assert all(not check["healthy"] for check in checks[:5])
    assert all(
        "outside trusted system executable roots" in check["detail"]
        for check in checks[:5]
    )
    assert calls == []


def test_launcher_health_is_derived_from_typed_policy(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custom = tmp_path / "custom-check"
    custom.write_bytes(b"\x7fELF")
    custom.chmod(0o755)
    config.server_scope["prerequisite_checks"] = {
        "custom-check": {
            "type": "system-executable",
            "args": ["--health"],
            "target_roots": [],
            "script_interpreters": [],
        },
        "github-mcp-server": {
            "type": "pinned-github-mcp",
            "args": ["--release"],
        },
    }
    calls: list[list[str]] = []
    pinned_arguments: list[list[str]] = []
    monkeypatch.setattr(
        "saturnin.launcher_host.resolve_trusted_executable",
        lambda config, name, **kwargs: custom,
    )
    monkeypatch.setattr(
        "saturnin.launcher_host.subprocess.run",
        lambda command, **kwargs: (
            calls.append(command) or SimpleNamespace(returncode=0)
        ),
    )
    monkeypatch.setattr(
        "saturnin.launcher_host.verify_github_binary",
        lambda config, **kwargs: (
            pinned_arguments.append(kwargs["version_args"])
            or config.var_dir / "bin" / "github-mcp-server"
        ),
    )

    checks = launcher_health(config)

    assert [check["name"] for check in checks] == [
        "custom-check",
        "github-mcp-server",
    ]
    assert calls == [[str(custom), "--health"]]
    assert pinned_arguments == [["--release"]]


def test_launcher_health_uses_trusted_interpreter_not_ambient_path(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "npx-cli.js"
    script.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    script.chmod(0o755)
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    attacker_node = shadow / "node"
    attacker_node.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    attacker_node.chmod(0o755)
    monkeypatch.setenv("PATH", str(shadow))
    monkeypatch.setattr(
        "saturnin.launcher_host.resolve_trusted_executable",
        lambda *_args, **_kwargs: script,
    )
    trusted_interpreter = Path("/bin/sh").resolve(strict=True)
    monkeypatch.setattr(
        "saturnin.launcher_host.shutil.which",
        lambda _name, *, path: str(trusted_interpreter),
    )
    calls: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(
        "saturnin.launcher_host.subprocess.run",
        lambda command, **kwargs: (
            calls.append((command, kwargs["env"]))
            or SimpleNamespace(returncode=0)
        ),
    )
    check = launcher_health(config)[3]

    assert check["healthy"]
    command, environment = calls[0]
    assert command[0] != str(attacker_node)
    assert command[0] == str(trusted_interpreter)
    assert command[1:] == [str(script), "--version"]
    assert str(shadow) not in environment["PATH"]


def test_launcher_health_rejects_unauthorized_script_interpreter(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "npx-cli.js"
    script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setattr(
        "saturnin.launcher_host.resolve_trusted_executable",
        lambda *_args, **_kwargs: script,
    )
    monkeypatch.setattr(
        "saturnin.launcher_host.verify_github_binary",
        lambda *_args, **_kwargs: config.var_dir / "bin" / "github-mcp-server",
    )

    check = launcher_health(config)[3]

    assert not check["healthy"]
    assert "not authorized" in check["detail"]


def test_launcher_host_config_rejects_symlink(
    config: Config, tmp_path: Path
) -> None:
    _secure_host_config_parents(config)
    path = host_config_path(config)
    path.parent.mkdir(parents=True, mode=0o700)
    target = tmp_path / "launcher.json"
    target.write_text(
        '{"version": 1, "launcher": {"enabled": true}}\n',
        encoding="utf-8",
    )
    target.chmod(0o600)
    path.symlink_to(target)

    with pytest.raises(LauncherHostError, match="invalid launcher host configuration"):
        host_launcher_enabled(config)


def test_launcher_host_config_rejects_group_access(config: Config) -> None:
    _secure_host_config_parents(config)
    path = set_host_launcher_enabled(config, True)
    path.chmod(0o640)

    with pytest.raises(LauncherHostError, match="group/other access"):
        host_launcher_enabled(config)


def test_launcher_host_config_rejects_unsafe_parent(config: Config) -> None:
    _secure_host_config_parents(config)
    path = set_host_launcher_enabled(config, True)
    path.parent.chmod(0o770)

    with pytest.raises(LauncherHostError, match="group/world-writable"):
        host_launcher_enabled(config)


def test_launcher_host_config_rejects_wrong_owner(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    _secure_host_config_parents(config)
    set_host_launcher_enabled(config, True)
    real_fstat = os.fstat

    def wrong_owner(descriptor: int) -> os.stat_result:
        values = list(real_fstat(descriptor))
        values[4] = os.geteuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr("saturnin.launcher_host.os.fstat", wrong_owner)

    with pytest.raises(LauncherHostError, match="must be owned by uid"):
        host_launcher_enabled(config)


def test_launcher_disable_uses_open_parent_when_ancestor_is_replaced(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _secure_host_config_parents(config)
    original = set_host_launcher_enabled(config, True)
    outside = config.root / "outside-var"
    outside_config = outside / "config"
    outside_config.mkdir(parents=True)
    outside_target = outside_config / "launcher.json"
    outside_target.write_text("must survive\n", encoding="utf-8")
    outside_target.chmod(0o600)
    moved_var = config.root / "original-var"
    real_open = os.open
    swapped = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "launcher.json" and dir_fd is not None and not swapped:
            swapped = True
            config.var_dir.rename(moved_var)
            config.var_dir.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("saturnin.launcher_host.os.open", racing_open)

    set_host_launcher_enabled(config, False)

    assert swapped
    assert not (moved_var / "config" / original.name).exists()
    assert outside_target.read_text() == "must survive\n"
