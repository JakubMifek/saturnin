"""Host-local launcher enablement and prerequisite checks."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from .config import Config
from .governance import (
    ExecutableTrustError,
    _containing_root,
    _trusted_path_requirements,
    _trusted_system_path,
    _trusted_system_path_problem,
    resolve_trusted_executable,
)
from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text
from .mcp import MCPError, verify_github_binary

HOST_CONFIG = Path("var/config/launcher.json")


class LauncherHostError(RuntimeError):
    pass


def host_config_path(config: Config) -> Path:
    return config.shared_path(HOST_CONFIG)


def host_launcher_enabled(config: Config) -> bool:
    path = host_config_path(config)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise LauncherHostError(f"invalid launcher host configuration {path}: {exc}") from exc
    try:
        parent_problem = _host_config_parent_problem(config, path)
        if parent_problem:
            raise LauncherHostError(parent_problem)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LauncherHostError(
                f"launcher host configuration is not a regular file: {path}"
            )
        if metadata.st_uid != os.geteuid():
            raise LauncherHostError(
                f"launcher host configuration must be owned by uid {os.geteuid()}: {path}"
            )
        if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise LauncherHostError(
                f"launcher host configuration permissions must not grant group/other access: {path}"
            )
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            content = handle.read(4097)
        if len(content) > 4096:
            raise LauncherHostError(f"launcher host configuration is too large: {path}")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise LauncherHostError(f"invalid launcher host configuration {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    expected = {"version": 1, "launcher": {"enabled": True}}
    if data != expected:
        raise LauncherHostError(
            f"launcher host configuration {path} must contain only {expected!r}"
        )
    return True


def set_host_launcher_enabled(config: Config, enabled: bool) -> Path:
    path = host_config_path(config)
    if not enabled:
        _secure_unlink_host_config(config, path)
        return path
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_problem = _host_config_parent_problem(config, path)
    if parent_problem:
        raise LauncherHostError(parent_problem)
    atomic_replace_text(
        path,
        json.dumps({"version": 1, "launcher": {"enabled": True}}, indent=2) + "\n",
        mode=PRIVATE_FILE_MODE,
    )
    return path


def _secure_unlink_host_config(config: Config, path: Path) -> None:
    parent = _open_host_config_parent(config, path)
    if parent is None:
        return
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
        except FileNotFoundError:
            return
        metadata = os.fstat(descriptor)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise LauncherHostError(
                f"launcher host configuration cannot be safely removed: {path}"
            )
        os.unlink(path.name, dir_fd=parent)
    except OSError as exc:
        raise LauncherHostError(
            f"launcher host configuration cannot be safely removed: {path}: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _open_host_config_parent(config: Config, path: Path) -> int | None:
    data_root = Path(os.path.abspath(config.data_root))
    parent_path = Path(os.path.abspath(path.parent))
    if not parent_path.is_relative_to(data_root):
        raise LauncherHostError(f"launcher host configuration escapes data root: {path}")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = Path("/")
    try:
        for component in parent_path.parts[1:]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.close(descriptor)
                return None
            metadata = os.fstat(child)
            current /= component
            sticky_root = (
                metadata.st_uid == 0
                and bool(metadata.st_mode & stat.S_ISVTX)
            )
            if (
                metadata.st_uid not in {0, os.geteuid()}
                or (
                    metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    and not sticky_root
                )
            ):
                os.close(child)
                raise LauncherHostError(
                    f"launcher host configuration parent is unsafe: {current}"
                )
            os.close(descriptor)
            descriptor = child
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def launcher_health(config: Config) -> list[dict[str, Any]]:
    config = _trusted_config(config)
    definitions = config.server_scope.get("prerequisite_checks", {})
    if not isinstance(definitions, dict):
        raise LauncherHostError("server prerequisite_checks must be a mapping")
    checks = []
    for name, definition in definitions.items():
        if not isinstance(definition, dict):
            raise LauncherHostError(f"invalid prerequisite definition for {name!r}")
        arguments = definition.get("args")
        if not isinstance(arguments, list) or not all(
            isinstance(value, str) for value in arguments
        ):
            raise LauncherHostError(f"invalid prerequisite arguments for {name!r}")
        if definition.get("type") == "pinned-github-mcp":
            checks.append(_github_mcp_health(config, name, arguments))
        elif definition.get("type") == "system-executable":
            checks.append(_executable_health(config, name, arguments, definition))
        else:
            raise LauncherHostError(f"invalid prerequisite type for {name!r}")
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


def _host_config_parent_problem(config: Config, path: Path) -> str | None:
    data_root = config.data_root.resolve()
    current = path.parent
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            return f"launcher host configuration parent cannot be inspected: {current}: {exc}"
        if not stat.S_ISDIR(metadata.st_mode):
            return f"launcher host configuration parent is not a directory: {current}"
        if metadata.st_uid not in {0, os.geteuid()}:
            return (
                f"launcher host configuration parent has unexpected owner "
                f"uid {metadata.st_uid}: {current}"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return (
                f"launcher host configuration parent must not be group/world-writable: "
                f"{current}"
            )
        if current == data_root:
            return None
        if current.parent == current or not current.is_relative_to(data_root):
            return f"launcher host configuration escapes data root: {path}"
        current = current.parent


def _github_mcp_health(
    config: Config, name: str, arguments: list[str]
) -> dict[str, Any]:
    try:
        path = verify_github_binary(config, version_args=arguments)
    except (MCPError, OSError, subprocess.SubprocessError) as exc:
        return {
            "name": name,
            "healthy": False,
            "path": str(config.var_dir / "bin" / "github-mcp-server"),
            "detail": str(exc),
        }
    return {
        "name": name,
        "healthy": True,
        "path": str(path),
        "detail": "pinned release and checksum verified",
    }


def _executable_health(
    config: Config,
    name: str,
    arguments: list[str],
    definition: dict[str, Any],
) -> dict[str, Any]:
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
        command, system_path = _prerequisite_command(
            config, executable, arguments, definition
        )
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env={
                **{
                    key: value
                    for key, value in os.environ.items()
                    if key in {"LANG", "LC_ALL", "LC_CTYPE"}
                },
                "PATH": system_path,
            },
        )
    except (ExecutableTrustError, OSError, subprocess.SubprocessError) as exc:
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


def _prerequisite_command(
    config: Config,
    executable: Path,
    arguments: list[str],
    definition: dict[str, Any],
) -> tuple[list[str], str]:
    roots = _trusted_system_path(config.server_scope.get("filesystem", {}))
    system_path = os.pathsep.join(str(root) for root in roots)
    try:
        with executable.open("rb") as handle:
            first_line = handle.readline(512)
    except OSError as exc:
        raise ExecutableTrustError(
            f"trusted executable script header cannot be read: {exc}"
        ) from exc
    if not first_line.startswith(b"#!"):
        return [str(executable), *arguments], system_path
    try:
        shebang = shlex.split(first_line[2:].decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExecutableTrustError(f"invalid trusted executable shebang: {exc}") from exc
    allowed = definition.get("script_interpreters")
    if not isinstance(allowed, list):
        raise ExecutableTrustError("script_interpreters policy must be a list")
    if len(shebang) == 2 and shebang[0] == "/usr/bin/env":
        interpreter_name = shebang[1]
    elif len(shebang) == 1 and Path(shebang[0]).is_absolute():
        interpreter_name = Path(shebang[0]).name
    else:
        raise ExecutableTrustError("trusted executable has an unsupported shebang")
    if interpreter_name not in allowed:
        raise ExecutableTrustError(
            f"script interpreter {interpreter_name!r} is not authorized for this prerequisite"
        )
    found = shutil.which(interpreter_name, path=system_path)
    if found is None:
        raise ExecutableTrustError(
            f"required script interpreter not found in trusted system PATH: {interpreter_name}"
        )
    interpreter = Path(found).resolve(strict=True)
    if _containing_root(interpreter, roots) is None:
        raise ExecutableTrustError(
            f"script interpreter {str(interpreter)!r} is outside trusted system PATH"
        )
    requirements = _trusted_path_requirements(
        config.server_scope.get("filesystem", {})
    )
    problem = _trusted_system_path_problem(interpreter, requirements)
    if problem:
        raise ExecutableTrustError(problem)
    return [str(interpreter), str(executable), *arguments], system_path
