"""Pinned MCP server installation and startup validation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import select
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any, Sequence

from .config import Config, default_config


class MCPError(RuntimeError):
    pass


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
    if name == "github" and "--read-only" not in args:
        raise MCPError("GitHub MCP server must be configured with --read-only")
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


def verify_github_binary(config: Config | None = None) -> Path:
    config = config or default_config()
    target, asset, install = _expected_binary(config)
    if not target.is_file():
        raise MCPError(f"GitHub MCP server is not installed: {target}")
    if _sha256(target) != asset.get("binary_sha256"):
        raise MCPError("installed GitHub MCP server checksum does not match policy")
    version = subprocess.run(
        [str(target), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    expected = str(install.get("tag", "")).removeprefix("v")
    if version.returncode or f"Version: {expected}" not in version.stdout:
        raise MCPError(f"installed GitHub MCP server is not release {expected}")
    return target


def probe_github_stdio(config: Config | None = None, *, timeout: float = 10) -> None:
    config = config or default_config()
    definition = _github_definition(config)
    target = verify_github_binary(config)
    _, args = server_process("github", definition, config)
    environment = dict(os.environ)
    environment.setdefault("GITHUB_PERSONAL_ACCESS_TOKEN", "saturnin-startup-check")
    process = subprocess.Popen(
        [str(target), *args],
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
    target.parent.mkdir(parents=True, exist_ok=True)
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
