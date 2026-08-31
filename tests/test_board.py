from __future__ import annotations

import pytest

from saturnin.board import Board, BoardError


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


def test_transition_id_is_read_modify_write_under_lock(board: Board) -> None:
    task = board.create("Implement widget")
    updated = board.transition_id(task.id, "routed", actor="router", note="dispatched")
    assert updated.state == "routed"
    assert updated.history[-1]["event"] == "state:routed"
    assert updated.history[-1]["actor"] == "router"
    assert board.get(task.id).state == "routed"
    with pytest.raises(BoardError):
        board.transition_id(task.id, "done")


def test_listing_orders_by_priority(board: Board) -> None:
    low = board.create("low", priority="P3")
    high = board.create("high", priority="P0")
    assert [t.id for t in board.list()] == [high.id, low.id]
    assert board.list(state="intake") == board.list()
    board.transition(low, "cancelled")
    assert [t.id for t in board.list(open_only=True)] == [high.id]


def test_open_tasks_for_branch(board: Board) -> None:
    task = board.create("branchy")
    task.branch = "feature/x"
    board.save(task)
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
