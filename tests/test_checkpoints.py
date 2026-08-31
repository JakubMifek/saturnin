from __future__ import annotations

import pytest

from saturnin.board import Board
from saturnin.checkpoints import Checkpoint, CheckpointError, CheckpointStore
from saturnin.config import Config


def test_save_and_resume(config: Config, board: Board) -> None:
    task = board.create("Long migration")
    store = CheckpointStore(config, board)
    store.save(
        Checkpoint(
            task_id=task.id,
            role="code-worker",
            summary="Migrated 3 of 7 tables.",
            next_steps=["migrate table 4", "run the smoke suite"],
            branch="feature/migration",
            blockers=["needs a maintenance window"],
            resume_after="2026-09-01T06:00:00+00:00",
        )
    )
    note = store.resume(task.id)
    assert "Migrated 3 of 7 tables." in note
    assert "- [ ] migrate table 4" in note
    assert "Do not resume before" in note
    assert board.get(task.id).checkpoint is not None


def test_latest_wins(config: Config, board: Board) -> None:
    task = board.create("Iterative work")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="first", next_steps=["a"]))
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="second", next_steps=["b"]))
    assert store.latest(task.id).summary == "second"
    assert len(store.history(task.id)) == 2
    assert [c.summary for c in store] == ["second"]


def test_incomplete_trailing_checkpoint_is_ignored(config: Config, board: Board) -> None:
    task = board.create("Interrupted checkpoint")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write('{"task_id":')

    assert store.latest(task.id).summary == "safe"
    assert [checkpoint.summary for checkpoint in store.history(task.id)] == ["safe"]


def test_corrupt_checkpoint_before_latest_is_reported(config: Config, board: Board) -> None:
    task = board.create("Corrupt checkpoint")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="first", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
        handle.write('{"task_id":"later"}\n')

    with pytest.raises(CheckpointError, match=r"line 2"):
        store.history(task.id)


def test_save_uses_locked_board_edit(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Parallel work")
    with board.edit(task.id) as current:
        current.body = "updated by another squad"

    def reject_save(*args: object, **kwargs: object) -> None:
        raise AssertionError("checkpoint mutation must not use Board.save()")

    monkeypatch.setattr(board, "save", reject_save)
    CheckpointStore(config, board).save(
        Checkpoint(task_id=task.id, role="scribe", summary="saved", next_steps=["continue"])
    )

    stored = board.get(task.id)
    assert stored.body == "updated by another squad"
    assert stored.history[-1]["event"] == "checkpoint"


def test_incomplete_checkpoint_rejected(config: Config, board: Board) -> None:
    task = board.create("Work")
    store = CheckpointStore(config, board)
    with pytest.raises(CheckpointError):
        store.save(Checkpoint(task_id=task.id, role="scribe", summary="", next_steps=["x"]))
    with pytest.raises(CheckpointError):
        store.save(Checkpoint(task_id=task.id, role="scribe", summary="s", next_steps=[]))


def test_resume_without_checkpoint(config: Config, board: Board) -> None:
    with pytest.raises(CheckpointError):
        CheckpointStore(config, board).resume("T-does-not-exist")
