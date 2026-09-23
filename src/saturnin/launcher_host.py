"""Host-local launcher enablement and prerequisite checks."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .config import Config
from .governance import ExecutableTrustError, resolve_trusted_executable
from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text
from .mcp import MCPError, verify_github_binary

HOST_CONFIG = Path("var/config/launcher.json")
REQUIRED_EXECUTABLES = ("bwrap", "pasta", "copilot", "npx", "uvx")


class LauncherHostError(RuntimeError):
    pass


def host_config_path(config: Config) -> Path:
    return config.shared_path(HOST_CONFIG)


def host_launcher_enabled(config: Config) -> bool:
    path = host_config_path(config)
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file():
        raise LauncherHostError(f"launcher host configuration is not a regular file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LauncherHostError(f"invalid launcher host configuration {path}: {exc}") from exc
    expected = {"version": 1, "launcher": {"enabled": True}}
    if data != expected:
        raise LauncherHostError(
            f"launcher host configuration {path} must contain only {expected!r}"
        )
    return True


def set_host_launcher_enabled(config: Config, enabled: bool) -> Path:
    path = host_config_path(config)
    if not enabled:
        path.unlink(missing_ok=True)
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_replace_text(
        path,
        json.dumps({"version": 1, "launcher": {"enabled": True}}, indent=2) + "\n",
        mode=PRIVATE_FILE_MODE,
    )
    return path


def launcher_health(config: Config) -> list[dict[str, Any]]:
    config = _trusted_config(config)
    checks = [_executable_health(config, name) for name in REQUIRED_EXECUTABLES]
    try:
        path = verify_github_binary(config)
    except (MCPError, OSError, subprocess.SubprocessError) as exc:
        checks.append(
            {
                "name": "github-mcp-server",
                "healthy": False,
                "path": str(config.var_dir / "bin" / "github-mcp-server"),
                "detail": str(exc),
            }
        )
    else:
        checks.append(
            {
                "name": "github-mcp-server",
                "healthy": True,
                "path": str(path),
                "detail": "pinned release and checksum verified",
            }
        )
    return checks


def launcher_status(config: Config) -> dict[str, Any]:
    config = _trusted_config(config)
    repository_enabled = bool(
        config.policy("mcp").get("launcher", {}).get("enabled", False)
    )
    local_enabled = host_launcher_enabled(config)
    checks = launcher_health(config)
    return {
        "enabled": repository_enabled or local_enabled,
        "source": (
            "repository-policy"
            if repository_enabled
            else "host-local"
            if local_enabled
            else "safe-default"
        ),
        "host_config": str(host_config_path(config)),
        "healthy": all(check["healthy"] for check in checks),
        "checks": checks,
    }


def _trusted_config(config: Config) -> Config:
    return config if config.root == config.data_root else Config(config.data_root)


def _executable_health(config: Config, name: str) -> dict[str, Any]:
    try:
        executable = resolve_trusted_executable(
            config,
            name,
            expected_binary=name,
        )
    except ExecutableTrustError as exc:
        return {
            "name": name,
            "healthy": False,
            "path": None,
            "detail": str(exc),
        }
    path = str(executable)
    try:
        result = subprocess.run(
            [path, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env={
                key: value
                for key, value in os.environ.items()
                if key in {"PATH", "LANG", "LC_ALL", "LC_CTYPE"}
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "name": name,
            "healthy": False,
            "path": path,
            "detail": f"version check failed: {exc}",
        }
    return {
        "name": name,
        "healthy": result.returncode == 0,
        "path": path,
        "detail": (
            "version check passed"
            if result.returncode == 0
            else f"version check exited {result.returncode}"
        ),
    }
