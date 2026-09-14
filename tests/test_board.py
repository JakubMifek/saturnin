from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from saturnin.board import Board, BoardError
from saturnin.config import Config


def test_create_and_reload(board: Board) -> None:
    task = board.create("Fix the flaky login test", labels=["test", " "], priority="P1")
    assert task.id.startswith("T-")
    assert task.state == "intake"
    assert task.labels == ["test"]
    assert board.get(task.id).title == "Fix the flaky login test"
    assert task.history[0]["event"] == "intake"


def test_empty_title_rejected(board: Board) -> None:
    with pytest.raises(BoardError):
        board.create("   ")


def test_unknown_priority_rejected(board: Board) -> None:
    with pytest.raises(BoardError):
        board.create("something", priority="P9")


def test_transitions_are_validated(board: Board) -> None:
    task = board.create("Implement widget")
    with pytest.raises(BoardError):
        board.transition(task, "done")
    board.transition(task, "routed")
    board.transition(task, "in_progress")
    board.transition(task, "review")
    board.transition(task, "done")
    assert board.get(task.id).closed_at is not None
    with pytest.raises(BoardError):
        board.transition(task, "in_progress")


def test_transition_default_actor_uses_configured_ceo_role(board: Board) -> None:
    """transition()/transition_id() must stamp the configured ceo_role, not a hardcoded literal."""
    delegation = board.config.governance.setdefault("delegation", {})
    had_role = "ceo_role" in delegation
    original_role = delegation.get("ceo_role")
    delegation["ceo_role"] = "chief"
    try:
        task = board.create("Implement widget")
        updated = board.transition(task, "routed")
        assert updated.history[-1]["actor"] == "chief"
    finally:
        if had_role:
            delegation["ceo_role"] = original_role
        else:
            delegation.pop("ceo_role", None)


@pytest.mark.parametrize("terminal_state", ["done", "cancelled"])
def test_noop_terminal_transition_preserves_closed_at(
    board: Board, terminal_state: str
) -> None:
    task = board.create("Preserve terminal timestamp")
    if terminal_state == "done":
        for state in ("routed", "in_progress", "review", "done"):
            task = board.transition(task, state)
    else:
        task = board.transition(task, "cancelled")
    closed_at = task.closed_at

    repeated = board.transition(task, terminal_state)

    assert repeated.closed_at == closed_at


def test_transition_id_is_read_modify_write_under_lock(board: Board) -> None:
    task = board.create("Implement widget")
    updated = board.transition_id(task.id, "routed", actor="router", note="dispatched")
    assert updated.state == "routed"
    assert updated.history[-1]["event"] == "state:routed"
    assert updated.history[-1]["actor"] == "router"
    assert board.get(task.id).state == "routed"
    with pytest.raises(BoardError):
        board.transition_id(task.id, "done")


def test_transition_to_blocked_requires_escalation_reference(board: Board) -> None:
    task = board.create("Escalate blocker")
    board.transition(task, "routed")
    with pytest.raises(BoardError):
        board.transition(task, "blocked")
    blocked = board.transition(task, "blocked", note="escalated: https://example.test/issues/1")
    assert blocked.state == "blocked"


def test_listing_orders_by_priority(board: Board) -> None:
    low = board.create("low", priority="P3")
    high = board.create("high", priority="P0")
    assert [t.id for t in board.list()] == [high.id, low.id]
    assert board.list(state="intake") == board.list()
    board.transition(low, "cancelled")
    assert [t.id for t in board.list(open_only=True)] == [high.id]


def test_open_tasks_for_branch(board: Board) -> None:
    task = board.create("branchy")
    with board.edit(task.id) as stored:
        stored.branch = "feature/x"
    assert [t.id for t in board.open_tasks_for_branch("feature/x")] == [task.id]
    board.transition(task, "cancelled")
    assert board.open_tasks_for_branch("feature/x") == []


def test_invalid_task_id_rejected(board: Board) -> None:
    with pytest.raises(BoardError):
        board.get("../../etc/passwd")


def test_signature_is_normalised(board: Board) -> None:
    a = board.create("Rotate the backup keys")
    b = board.create("rotate backup the keys")
    assert a.signature == b.signature


def test_signature_extracts_words_from_punctuated_tokens(board: Board) -> None:
    punctuated = board.create("Clean worktree/branch for e2e")
    spaced = board.create("clean worktree branch for e 2 e")
    assert punctuated.signature == spaced.signature
    assert "café" in board.create("Réparer café/db").signature


def test_concurrent_processes_do_not_overwrite_colliding_task_ids(
    board: Board,
    config: Config,
) -> None:
    ready = config.root / "creator-ready"
    ready.mkdir()
    start = config.root / "start-creators"
    child = """
import os
import sys
import time
import saturnin.board as board_module
from saturnin.board import Board
from saturnin.config import Config

root, suffix, title = sys.argv[1:]
ids = iter(("T-20000101-c0ffee", f"T-20000101-{suffix}"))
board_module.new_task_id = lambda now=None: next(ids)
original_write = Board._write
def delayed_write(self, path, task):
    time.sleep(0.25)
    original_write(self, path, task)
Board._write = delayed_write
open(os.path.join(root, "creator-ready", suffix), "w").close()
while not os.path.exists(os.path.join(root, "start-creators")):
    time.sleep(0.01)
Board(Config.load(root)).create(title)
"""
    env = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        "SATURNIN_HOME": str(config.root),
    }
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", child, str(config.root), suffix, title],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for suffix, title in (("aaaaaa", "first creator"), ("bbbbbb", "second creator"))
    ]
    deadline = time.monotonic() + 5
    while len(list(ready.iterdir())) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(list(ready.iterdir())) == 2
    start.touch()
    results = [process.communicate(timeout=10) for process in processes]

    assert [process.returncode for process in processes] == [0, 0], results
    tasks = list(board)
    assert {task.title for task in tasks} == {"first creator", "second creator"}
    assert len({task.id for task in tasks}) == 2
