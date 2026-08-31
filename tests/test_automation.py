from __future__ import annotations

import os
import subprocess
import sys

from saturnin.automation import AutomationLibrary
from saturnin.board import Board
from saturnin.config import Config


def test_registry_files_exist(config: Config) -> None:
    library = AutomationLibrary(config)
    assert library.list()
    assert library.audit() == []


def test_find_prevents_reinvention(config: Config) -> None:
    library = AutomationLibrary(config)
    matches = library.find("clean up stale worktrees")
    assert matches and matches[0].id == "janitor-cleanup"
    assert library.find("brew coffee for the narrator") == []


def test_detect_repeats(config: Config, board: Board) -> None:
    for _ in range(3):
        board.create("Rotate the deploy keys")
    board.create("Something else entirely")
    candidates = AutomationLibrary(config).detect_repeats(board, threshold=3)
    assert len(candidates) == 1
    assert candidates[0].count == 3
    assert candidates[0].existing is None


def test_detect_repeats_normalises_punctuated_titles(config: Config, board: Board) -> None:
    board.create("Clean worktree/branch for e2e")
    board.create("Clean worktree branch for e 2 e")
    board.create("Clean worktree-branch for e2e")
    candidates = AutomationLibrary(config).detect_repeats(board, threshold=3)
    assert len(candidates) == 1
    assert candidates[0].count == 3


def test_propose_files_one_task_only(config: Config, board: Board) -> None:
    library = AutomationLibrary(config)
    for _ in range(3):
        board.create("Rotate the deploy keys")
    first = library.propose(board, threshold=3)
    assert len(first) == 1
    assert "automation" in first[0].labels
    assert library.propose(board, threshold=3) == []


def test_covered_repeats_are_not_proposed(config: Config, board: Board) -> None:
    for _ in range(4):
        board.create("cleanup stale worktrees")
    assert AutomationLibrary(config).propose(board, threshold=3) == []


def test_monitors_use_project_virtualenv_python(config: Config) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: health\n"
        "    url: https://example.test/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    marker = config.root / "python-used"
    venv_bin = config.root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text(
        f"#!/bin/sh\nprintf used >> {marker}\nexec {sys.executable} \"$@\"\n",
        encoding="utf-8",
    )
    python.chmod(0o755)
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nprintf 200\n", encoding="utf-8")
    curl.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert "used" in marker.read_text(encoding="utf-8")


def test_monitor_escalations_are_pushed_and_not_silenced(config: Config) -> None:
    script = (config.root / "automation/library/run_monitors.sh").read_text(
        encoding="utf-8"
    )
    escalation = script.split("saturnin escalate", 1)[1].split("else", 1)[0]
    assert "--push" in escalation
    assert "|| true" not in escalation
