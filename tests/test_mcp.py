from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from saturnin.config import Config
from saturnin.mcp import MCPError, install_github, probe_github_stdio, server_process


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


def test_github_mcp_rejects_write_capable_configuration(config: Config) -> None:
    definition = config.policy("mcp")["servers"]["github"]
    definition["args"] = ["stdio"]

    with pytest.raises(MCPError, match="must be configured with --read-only"):
        server_process("github", definition, config)


def test_github_mcp_stdio_startup_handshake(config: Config) -> None:
    script = config.var_dir / "bin" / "fake-github-mcp.py"
    script.parent.mkdir(parents=True)
    checksum = _fake_server(script)
    definition = config.policy("mcp")["servers"]["github"]
    definition["command"] = str(script)
    definition["args"] = ["--read-only"]
    definition["install"]["tag"] = "v1.0"
    for asset in definition["install"]["assets"].values():
        asset["binary_sha256"] = checksum

    probe_github_stdio(config, timeout=2)


def test_github_mcp_stdio_rejects_non_server_executable(config: Config) -> None:
    script = config.var_dir / "bin" / "not-an-mcp.py"
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

    with pytest.raises(MCPError, match="stdio handshake"):
        probe_github_stdio(config, timeout=1)


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
