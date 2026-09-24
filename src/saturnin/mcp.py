"""Pinned MCP server installation and startup validation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from .config import Config, default_config


class MCPError(RuntimeError):
    pass


@dataclass
class StagedGithubBinary:
    path: Path
    descriptor: int
    device: int
    inode: int
    runtime_device: int
    runtime_inode: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def metadata(self) -> dict[str, Any]:
        return {
            "directory": str(self.path.parent),
            "directory_device": self.runtime_device,
            "directory_inode": self.runtime_inode,
            "file": self.path.name,
            "file_device": self.device,
            "file_inode": self.inode,
        }


def _validate_github_read_only(args: Sequence[str]) -> None:
    values: list[str] = []
    for argument in args:
        if argument == "--":
            break
        option, separator, value = argument.partition("=")
        if option.replace("_", "-") != "--read-only":
            continue
        values.append(value.casefold() if separator else "true")
    if not values:
        raise MCPError("GitHub MCP server must be configured with effective --read-only")
    if len(values) != 1 or values[0] != "true":
        raise MCPError(
            "GitHub MCP --read-only must be true and specified exactly once"
        )


def server_process(
    name: str,
    definition: dict[str, Any],
    config: Config,
    *,
    worktree_scope: Path | None = None,
) -> tuple[str, list[str]]:
    values = {
        "data_root": str(config.data_root),
        "root": str(config.root),
        "var": str(config.var_dir),
        "worktrees": str(worktree_scope or (config.var_dir / "worktrees")),
        "worktree": str(worktree_scope or (config.var_dir / "worktrees")),
    }
    command = str(definition["command"]).format(**values)
    args = [str(value).format(**values) for value in definition.get("args", [])]
    canonical_github = (config.var_dir / "bin" / "github-mcp-server").resolve(strict=False)
    configured = Path(command).expanduser().resolve(strict=False)
    if name == "github" and configured != canonical_github:
        raise MCPError(f"GitHub MCP server must use canonical executable {canonical_github}")
    if name != "github" and configured == canonical_github:
        raise MCPError("canonical GitHub MCP executable may only use server id 'github'")
    if name == "github":
        _validate_github_read_only(args)
    return command, args


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _asset_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    architectures = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    architecture = architectures.get(machine)
    if system != "linux" or architecture is None:
        raise MCPError(f"unsupported GitHub MCP platform: {system}-{machine}")
    return f"linux-{architecture}"


def _github_definition(config: Config) -> dict[str, Any]:
    definition = config.policy("mcp").get("servers", {}).get("github")
    if not isinstance(definition, dict):
        raise MCPError("GitHub MCP server is not configured")
    return definition


def _expected_binary(config: Config) -> tuple[Path, dict[str, str], dict[str, Any]]:
    definition = _github_definition(config)
    install = definition.get("install")
    if not isinstance(install, dict):
        raise MCPError("GitHub MCP install metadata is missing")
    assets = install.get("assets", {})
    asset = assets.get(_asset_key()) if isinstance(assets, dict) else None
    if not isinstance(asset, dict):
        raise MCPError(f"GitHub MCP has no asset for {_asset_key()}")
    command, _ = server_process("github", definition, config)
    return Path(command), {str(key): str(value) for key, value in asset.items()}, install


@contextmanager
def _verified_github_descriptor(
    config: Config,
) -> Iterator[tuple[int, Path, dict[str, Any]]]:
    target, asset, install = _expected_binary(config)
    try:
        descriptor = os.open(
            target,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise MCPError(f"GitHub MCP server cannot be securely opened: {target}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise MCPError(f"GitHub MCP server is not a regular file: {target}")
        if metadata.st_uid != os.geteuid():
            raise MCPError(
                f"GitHub MCP server must be owned by uid {os.geteuid()}: {target}"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise MCPError(
                f"GitHub MCP server must not be group/world-writable: {target}"
            )
        parent_problem = _private_runtime_path_problem(target.parent)
        if parent_problem:
            raise MCPError(parent_problem)
        if _sha256_descriptor(descriptor) != asset.get("binary_sha256"):
            raise MCPError("installed GitHub MCP server checksum does not match policy")
        yield descriptor, target, install
    finally:
        os.close(descriptor)


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _private_runtime_path_problem(path: Path) -> str | None:
    current = path
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as exc:
            return f"GitHub MCP runtime path cannot be inspected: {current}: {exc}"
        if not stat.S_ISDIR(metadata.st_mode):
            return f"GitHub MCP runtime path is not a directory: {current}"
        if metadata.st_uid not in {0, os.geteuid()}:
            return f"GitHub MCP runtime path has unexpected owner uid {metadata.st_uid}: {current}"
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            sticky_root = (
                metadata.st_uid == 0
                and bool(metadata.st_mode & stat.S_ISVTX)
            )
            if not sticky_root:
                return f"GitHub MCP runtime path must not be group/world-writable: {current}"
        if current.parent == current:
            return None
        current = current.parent


def _github_version_args(config: Config) -> list[str]:
    definition = config.server_scope.get("prerequisite_checks", {}).get(
        "github-mcp-server"
    )
    if (
        not isinstance(definition, dict)
        or definition.get("type") != "pinned-github-mcp"
        or not isinstance(definition.get("args"), list)
        or not all(isinstance(value, str) for value in definition["args"])
    ):
        raise MCPError("pinned GitHub MCP prerequisite policy is invalid")
    return list(definition["args"])


def _verify_github_version(
    descriptor: int,
    install: dict[str, Any],
    arguments: Sequence[str],
) -> None:
    version = subprocess.run(
        [f"/proc/self/fd/{descriptor}", *arguments],
        pass_fds=(descriptor,),
        capture_output=True,
        text=True,
        check=False,
    )
    expected = str(install.get("tag", "")).removeprefix("v")
    if version.returncode or f"Version: {expected}" not in version.stdout:
        raise MCPError(f"installed GitHub MCP server is not release {expected}")


def verify_github_binary(
    config: Config | None = None,
    *,
    version_args: Sequence[str] | None = None,
) -> Path:
    config = config or default_config()
    arguments = list(version_args) if version_args is not None else _github_version_args(config)
    with _verified_github_descriptor(config) as (descriptor, target, install):
        _verify_github_version(descriptor, install, arguments)
        return target


def stage_github_binary(config: Config, destination: Path) -> StagedGithubBinary:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _prepare_private_runtime_path(destination.parent)
    expected_runtime = destination.parent.stat(follow_symlinks=False)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    staged = -1
    runtime = os.open(
        destination.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        runtime_metadata = os.fstat(runtime)
        if (
            runtime_metadata.st_dev,
            runtime_metadata.st_ino,
        ) != (
            expected_runtime.st_dev,
            expected_runtime.st_ino,
        ):
            raise MCPError("private GitHub MCP runtime directory identity changed")
        if (
            runtime_metadata.st_uid != os.geteuid()
            or runtime_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise MCPError("private GitHub MCP runtime directory is unsafe")
        with _verified_github_descriptor(config) as (source, _, install):
            try:
                staged = os.open(destination.name, flags, 0o500, dir_fd=runtime)
            except OSError as exc:
                raise MCPError(
                    f"private GitHub MCP stage cannot be created: {destination}: {exc}"
                ) from exc
            try:
                os.fchmod(staged, 0o500)
                while chunk := os.read(source, 1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(staged, view)
                        view = view[written:]
                os.fsync(staged)
                written_metadata = os.fstat(staged)
                os.close(staged)
                staged = os.open(
                    destination.name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=runtime,
                )
                reopened_metadata = os.fstat(staged)
                if (
                    written_metadata.st_dev,
                    written_metadata.st_ino,
                ) != (
                    reopened_metadata.st_dev,
                    reopened_metadata.st_ino,
                ):
                    raise MCPError("private GitHub MCP staged inode changed")
            except Exception:
                if staged >= 0:
                    os.close(staged)
                staged = -1
                os.unlink(destination.name, dir_fd=runtime)
                raise
        try:
            staged_metadata = os.fstat(staged)
            _verify_github_version(
                staged,
                install,
                _github_version_args(config),
            )
        except Exception:
            os.close(staged)
            staged = -1
            os.unlink(destination.name, dir_fd=runtime)
            raise
    finally:
        os.close(runtime)
    return StagedGithubBinary(
        path=destination,
        descriptor=staged,
        device=staged_metadata.st_dev,
        inode=staged_metadata.st_ino,
        runtime_device=runtime_metadata.st_dev,
        runtime_inode=runtime_metadata.st_ino,
    )


def _prepare_private_runtime_path(path: Path) -> None:
    current = path
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as exc:
            raise MCPError(
                f"GitHub MCP runtime path cannot be inspected: {current}: {exc}"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise MCPError(f"GitHub MCP runtime path is not a directory: {current}")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise MCPError(
                f"GitHub MCP runtime path has unexpected owner uid {metadata.st_uid}: {current}"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
            if sticky_root:
                pass
            elif metadata.st_uid == os.geteuid():
                current.chmod(stat.S_IMODE(metadata.st_mode) & ~0o022)
            else:
                raise MCPError(
                    f"GitHub MCP runtime path must not be group/world-writable: {current}"
                )
        if current.parent == current:
            return
        current = current.parent


def probe_github_stdio(config: Config | None = None, *, timeout: float = 10) -> None:
    config = config or default_config()
    definition = _github_definition(config)
    _, args = server_process("github", definition, config)
    environment = dict(os.environ)
    environment.setdefault("GITHUB_PERSONAL_ACCESS_TOKEN", "saturnin-startup-check")
    with _verified_github_descriptor(config) as (descriptor, _, install):
        _verify_github_version(descriptor, install, _github_version_args(config))
        process = subprocess.Popen(
            [f"/proc/self/fd/{descriptor}", *args],
            pass_fds=(descriptor,),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "saturnin-startup-check", "version": "1"},
            },
        }
        try:
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            ready, _, _ = select.select([process.stdout], [], [], timeout)
            if not ready:
                raise MCPError("GitHub MCP server did not answer the stdio initialize request")
            response = json.loads(process.stdout.readline())
            if response.get("id") != 1 or not isinstance(response.get("result"), dict):
                raise MCPError("GitHub MCP server returned an invalid initialize response")
        except (BrokenPipeError, json.JSONDecodeError) as exc:
            raise MCPError(f"GitHub MCP stdio handshake failed: {exc}") from exc
        finally:
            process.terminate()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


def install_github(config: Config | None = None) -> Path:
    config = config or default_config()
    target, asset, install = _expected_binary(config)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _prepare_private_runtime_path(target.parent)
    if target.is_file():
        try:
            probe_github_stdio(config)
            return target
        except MCPError:
            pass
    repository = str(install.get("repository", ""))
    tag = str(install.get("tag", ""))
    archive_name = asset.get("archive", "")
    if not repository or not tag or not archive_name:
        raise MCPError("GitHub MCP release metadata is incomplete")
    download_dir = config.var_dir / "downloads"
    download_dir.mkdir(parents=True, exist_ok=True)
    archive = download_dir / archive_name
    partial = archive.with_suffix(archive.suffix + ".download")
    url = f"https://github.com/{repository}/releases/download/{tag}/{archive_name}"
    request = urllib.request.Request(url, headers={"User-Agent": "saturnin-bootstrap"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output)
        if _sha256(partial) != asset.get("archive_sha256"):
            raise MCPError("downloaded GitHub MCP archive checksum does not match policy")
        partial.replace(archive)
    finally:
        partial.unlink(missing_ok=True)

    staged = target.with_suffix(".installing")
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            member = bundle.getmember("github-mcp-server")
            if not member.isfile():
                raise MCPError("GitHub MCP archive does not contain a regular executable")
            source = bundle.extractfile(member)
            if source is None:
                raise MCPError("GitHub MCP executable could not be read")
            with source, staged.open("wb") as output:
                shutil.copyfileobj(source, output)
        if _sha256(staged) != asset.get("binary_sha256"):
            raise MCPError("GitHub MCP executable checksum does not match policy")
        staged.chmod(0o755)
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)
    probe_github_stdio(config)
    return target


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args == ["install", "github"]:
        target = install_github()
        print(f"Installed and verified GitHub MCP server: {target}")
        return 0
    if args == ["check", "github"]:
        probe_github_stdio()
        print("GitHub MCP server passed the stdio startup check.")
        return 0
    print("usage: python -m saturnin.mcp <install|check> github", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
