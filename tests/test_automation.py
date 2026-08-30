from __future__ import annotations

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
