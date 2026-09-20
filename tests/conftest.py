"""Shared fixtures: every test runs against a throwaway Saturnin home."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from saturnin.board import Board
from saturnin.config import Config

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "saturnin-home"
    (root / "policies").mkdir(parents=True)
    for policy in (REPO_ROOT / "policies").glob("*.yaml"):
        shutil.copy(policy, root / "policies" / policy.name)
    mcp_path = root / "policies" / "mcp.yaml"
    mcp_policy = yaml.safe_load(mcp_path.read_text(encoding="utf-8"))
    mcp_policy["launcher"]["enabled"] = False
    mcp_path.write_text(yaml.safe_dump(mcp_policy), encoding="utf-8")
    shutil.copytree(REPO_ROOT / "automation", root / "automation")
    shutil.copytree(REPO_ROOT / "scripts", root / "scripts")
    shutil.copytree(REPO_ROOT / "agents", root / "agents")
    shutil.copytree(REPO_ROOT / "skills", root / "skills")
    monkeypatch.setenv("SATURNIN_HOME", str(root))
    monkeypatch.setenv("SATURNIN_REVIEW_ATTESTATION_KEY", "test-review-attestation-key")
    return root


@pytest.fixture()
def config(home: Path) -> Config:
    config = Config.load(home)
    config.ensure_dirs()
    return config


@pytest.fixture()
def board(config: Config) -> Board:
    return Board(config)


def git(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture()
def git_repo(config: Config) -> Path:
    """A real git repository rooted at the Saturnin home."""
    root = config.root
    git(["init", "-b", "main"], root)
    git(["config", "user.email", "saturnin@example.com"], root)
    git(["config", "user.name", "Saturnin"], root)
    (root / "README.md").write_text("test repo\n", encoding="utf-8")
    git(["add", "."], root)
    git(["commit", "-m", "initial"], root)
    git(
        [
            "remote",
            "add",
            "origin",
            "http://localhost:26831/JakubMifek/saturnin",
        ],
        root,
    )
    return root
