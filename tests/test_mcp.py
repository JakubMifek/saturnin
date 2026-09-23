from __future__ import annotations

import hashlib
import io
import stat
import tarfile
from pathlib import Path

import pytest

from saturnin.config import Config
from saturnin.mcp import (
    MCPError,
    install_github,
    probe_github_stdio,
    server_process,
    stage_github_binary,
    verify_github_binary,
)


def _fake_server(path: Path) -> str:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('GitHub MCP Server\\nVersion: 1.0')\n"
        "    raise SystemExit(0)\n"
        "request = json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], "
        "'result': {'protocolVersion': request['params']['protocolVersion'], "
        "'capabilities': {}}}), flush=True)\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _secure_runtime_path(config: Config) -> None:
    config.data_root.chmod(0o755)
    config.var_dir.chmod(0o700)
    (config.var_dir / "bin").chmod(0o700)


def test_github_mcp_uses_pinned_local_official_binary(config: Config) -> None:
    definition = config.policy("mcp")["servers"]["github"]
    command, args = server_process("github", definition, config)
    install = definition["install"]

    assert command == str(config.data_root / "var/bin/github-mcp-server")
    assert args == ["stdio", "--read-only"]
    assert install["repository"] == "github/github-mcp-server"
    assert install["tag"] == "v1.12.1"
    assert install["commit"] == "7d13a7ad6f2a17f351a6d77ce280c85ae1821f4d"
    assert all(
        len(asset[key]) == 64
        for asset in install["assets"].values()
        for key in ("archive_sha256", "binary_sha256")
    )


def test_registry_mcp_servers_use_pinned_packages(config: Config) -> None:
    servers = config.policy("mcp")["servers"]

    assert servers["fetch"]["args"] == ["mcp-server-fetch@2026.8.18"]
    assert servers["filesystem"]["args"] == [
        "-y",
        "@modelcontextprotocol/server-filesystem@2026.8.31",
        "{worktrees}",
    ]


@pytest.mark.parametrize(
    ("server_id", "args"),
    [
        ("github", ["stdio"]),
        ("github", ["stdio", "--read-only=false"]),
        ("github", ["stdio", "--read_only=false"]),
        ("github", ["stdio", "--read-only=invalid"]),
        ("github", ["stdio", "--read-only", "--read-only=false"]),
        ("github", ["stdio", "--read-only=false", "--read-only"]),
        ("github", ["stdio", "--read-only", "--read_only=true"]),
        ("github", ["stdio", "--", "--read-only"]),
    ],
)
def test_github_mcp_rejects_write_capable_configuration(
    config: Config, server_id: str, args: list[str]
) -> None:
    definition = config.policy("mcp")["servers"]["github"]
    definition["args"] = args

    with pytest.raises(MCPError, match="read-only"):
        server_process(server_id, definition, config)


def test_github_server_id_rejects_replacement_executable(config: Config) -> None:
    definition = config.policy("mcp")["servers"]["github"]
    definition["command"] = "/bin/echo"

    with pytest.raises(MCPError, match="canonical executable"):
        server_process("github", definition, config)


def test_canonical_github_executable_rejects_alias_id(config: Config) -> None:
    definition = config.policy("mcp")["servers"]["github"]

    with pytest.raises(MCPError, match="only use server id 'github'"):
        server_process("renamed-server", definition, config)


@pytest.mark.parametrize(
    "flag", ["--read-only", "--read-only=true", "--read-only=TRUE", "--read_only=true"]
)
def test_github_mcp_accepts_effective_read_only_forms(config: Config, flag: str) -> None:
    definition = config.policy("mcp")["servers"]["github"]
    definition["args"] = ["stdio", flag]

    assert server_process("github", definition, config)[1] == ["stdio", flag]


def test_github_mcp_stdio_startup_handshake(config: Config) -> None:
    script = config.var_dir / "bin" / "github-mcp-server"
    script.parent.mkdir(parents=True)
    checksum = _fake_server(script)
    definition = config.policy("mcp")["servers"]["github"]
    definition["command"] = str(script)
    definition["args"] = ["--read-only"]
    definition["install"]["tag"] = "v1.0"
    for asset in definition["install"]["assets"].values():
        asset["binary_sha256"] = checksum
    _secure_runtime_path(config)

    probe_github_stdio(config, timeout=2)


def test_github_mcp_stdio_rejects_non_server_executable(config: Config) -> None:
    script = config.var_dir / "bin" / "github-mcp-server"
    script.parent.mkdir(parents=True)
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('Version: 1.0')\n"
        "else:\n"
        "    sys.stdin.readline()\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    definition = config.policy("mcp")["servers"]["github"]
    definition["command"] = str(script)
    definition["args"] = ["--read-only"]
    definition["install"]["tag"] = "v1.0"
    checksum = hashlib.sha256(script.read_bytes()).hexdigest()
    for asset in definition["install"]["assets"].values():
        asset["binary_sha256"] = checksum
    _secure_runtime_path(config)

    with pytest.raises(MCPError, match="stdio handshake"):
        probe_github_stdio(config, timeout=1)


@pytest.mark.parametrize("unsafe", ["file", "parent"])
def test_github_mcp_rejects_writable_runtime_paths(
    config: Config,
    unsafe: str,
) -> None:
    script = config.var_dir / "bin" / "github-mcp-server"
    script.parent.mkdir(parents=True)
    checksum = _fake_server(script)
    definition = config.policy("mcp")["servers"]["github"]
    definition["install"]["tag"] = "v1.0"
    for asset in definition["install"]["assets"].values():
        asset["binary_sha256"] = checksum
    _secure_runtime_path(config)
    target = script if unsafe == "file" else script.parent
    target.chmod(stat.S_IMODE(target.stat().st_mode) | stat.S_IWGRP)

    with pytest.raises(MCPError, match="group/world-writable"):
        verify_github_binary(config)


def test_github_mcp_rejects_symlink(config: Config, tmp_path: Path) -> None:
    script = config.var_dir / "bin" / "github-mcp-server"
    script.parent.mkdir(parents=True)
    target = tmp_path / "github-mcp-server"
    _fake_server(target)
    script.symlink_to(target)
    _secure_runtime_path(config)

    with pytest.raises(MCPError, match="securely opened"):
        verify_github_binary(config)


def test_github_mcp_stages_verified_inode_before_path_replacement(
    config: Config,
) -> None:
    script = config.var_dir / "bin" / "github-mcp-server"
    script.parent.mkdir(parents=True)
    checksum = _fake_server(script)
    definition = config.policy("mcp")["servers"]["github"]
    definition["install"]["tag"] = "v1.0"
    for asset in definition["install"]["assets"].values():
        asset["binary_sha256"] = checksum
    _secure_runtime_path(config)
    destination = config.var_dir / "launches" / "task.runtime" / "github-mcp-server"

    staged = stage_github_binary(config, destination)
    original = staged.read_bytes()
    script.write_text("replacement\n", encoding="utf-8")

    assert staged.read_bytes() == original
    assert stat.S_IMODE(staged.stat().st_mode) == 0o500
    assert staged.stat().st_ino != script.stat().st_ino


def test_github_mcp_installer_verifies_archive_and_handshake(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = config.root / "fake-release-server"
    binary_sha256 = _fake_server(source)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
        info = tarfile.TarInfo("github-mcp-server")
        payload = source.read_bytes()
        info.size = len(payload)
        info.mode = 0o755
        bundle.addfile(info, io.BytesIO(payload))
    archive_bytes = archive.getvalue()
    definition = config.policy("mcp")["servers"]["github"]
    definition["install"]["repository"] = "github/example"
    definition["install"]["tag"] = "v1.0"
    for asset in definition["install"]["assets"].values():
        asset["archive"] = "github-mcp-server.tar.gz"
        asset["archive_sha256"] = hashlib.sha256(archive_bytes).hexdigest()
        asset["binary_sha256"] = binary_sha256
    monkeypatch.setattr(
        "saturnin.mcp.urllib.request.urlopen",
        lambda request, timeout: io.BytesIO(archive_bytes),
    )

    target = install_github(config)

    assert target == config.var_dir / "bin" / "github-mcp-server"
    assert hashlib.sha256(target.read_bytes()).hexdigest() == binary_sha256
    monkeypatch.setattr(
        "saturnin.mcp.urllib.request.urlopen",
        lambda request, timeout: pytest.fail("verified installation was downloaded again"),
    )
    assert install_github(config) == target


def test_bootstrap_installs_server_before_doctor() -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "scripts/bootstrap.sh").read_text(encoding="utf-8")

    assert bootstrap.index("python -m saturnin.mcp install github") < bootstrap.index(
        "saturnin doctor"
    )
    assert "Configured companion repositories:" in bootstrap
    assert "gh repo create" in bootstrap
