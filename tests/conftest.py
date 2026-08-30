"""Shared fixtures: every test runs against a throwaway Saturnin home."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from saturnin.board import Board
from saturnin.config import Config

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "saturnin-home"
    (root / "policies").mkdir(parents=True)
    for policy in (REPO_ROOT / "policies").glob("*.yaml"):
        shutil.copy(policy, root / "policies" / policy.name)
    shutil.copytree(REPO_ROOT / "automation", root / "automation")
    monkeypatch.setenv("SATURNIN_HOME", str(root))
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
    return root
