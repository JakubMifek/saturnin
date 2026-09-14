from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

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


def test_complete_checkpoint_append_uses_durable_atomic_replace(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Durable checkpoint")
    store = CheckpointStore(config, board)
    writes: list[str] = []

    def tracked_replace(path: Path, text: str) -> None:
        writes.append(text)
        path.write_text(text, encoding="utf-8")

    monkeypatch.setattr("saturnin.checkpoints.atomic_replace_text", tracked_replace)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safer", next_steps=["b"]))

    assert len(writes) == 2
    assert writes[-1].count("\n") == 2


def test_incomplete_trailing_checkpoint_is_ignored(config: Config, board: Board) -> None:
    task = board.create("Interrupted checkpoint")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write('{"task_id":')

    assert store.latest(task.id).summary == "safe"
    assert [checkpoint.summary for checkpoint in store.history(task.id)] == ["safe"]


def test_save_truncates_incomplete_trailing_checkpoint(config: Config, board: Board) -> None:
    task = board.create("Interrupted checkpoint")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write('{"task_id":')

    store.save(Checkpoint(task_id=task.id, role="scribe", summary="after", next_steps=["b"]))

    assert [checkpoint.summary for checkpoint in store.history(task.id)] == ["safe", "after"]


def test_save_preserves_complete_unterminated_tail(config: Config, board: Board) -> None:
    task = board.create("Interrupted checkpoint")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write(
            '{"task_id":"'
            + task.id
            + '","role":"scribe","summary":"complete-tail","next_steps":["b"]}'
        )

    store.save(Checkpoint(task_id=task.id, role="scribe", summary="after", next_steps=["c"]))

    assert [checkpoint.summary for checkpoint in store.history(task.id)] == [
        "safe",
        "complete-tail",
        "after",
    ]


def test_save_repairs_unterminated_tail_with_atomic_replace(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Atomic tail repair")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write(
            '{"task_id":"'
            + task.id
            + '","role":"scribe","summary":"complete-tail","next_steps":["b"]}'
        )

    replaced: list[str] = []

    def tracked_replace(path: Path, text: str) -> None:
        replaced.append(text)
        path.write_text(text, encoding="utf-8")

    monkeypatch.setattr("saturnin.checkpoints.atomic_replace_text", tracked_replace)

    store.save(Checkpoint(task_id=task.id, role="scribe", summary="after", next_steps=["c"]))

    assert len(replaced) == 1
    assert replaced[0].endswith("\n")
    assert '"summary":"complete-tail"' in replaced[0]
    assert [checkpoint.summary for checkpoint in store.history(task.id)] == [
        "safe",
        "complete-tail",
        "after",
    ]


def test_newline_terminated_trailing_corruption_is_reported(
    config: Config, board: Board
) -> None:
    task = board.create("Terminated corrupt checkpoint")
    store = CheckpointStore(config, board)
    store.save(Checkpoint(task_id=task.id, role="scribe", summary="safe", next_steps=["a"]))
    with store.path_for(task.id).open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")

    with pytest.raises(CheckpointError, match=r"line 2"):
        store.latest(task.id)


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


def test_checkpoint_store_locks_jsonl_access(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Parallel checkpoints")
    calls: list[tuple[str, bool]] = []

    @contextmanager
    def fake_file_lock(path: Path, *, exclusive: bool = True) -> Iterator[None]:
        calls.append((path.name, exclusive))
        yield

    monkeypatch.setattr("saturnin.checkpoints.file_lock", fake_file_lock)
    store = CheckpointStore(config, board)
    store.save(
        Checkpoint(task_id=task.id, role="scribe", summary="saved", next_steps=["resume"])
    )

    assert (f"{task.id}.jsonl", True) in calls

    calls.clear()
    assert store.history(task.id)
    assert calls == [(f"{task.id}.jsonl", False)]


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


def test_due_returns_only_elapsed_unresumed_checkpoints(config: Config, board: Board) -> None:
    due_task = board.create("Resume now")
    future_task = board.create("Resume later")
    store = CheckpointStore(config, board)
    due = store.save(
        Checkpoint(
            task_id=due_task.id,
            role="code-worker",
            summary="paused",
            next_steps=["continue"],
            resume_after="2026-09-11T19:00:00+00:00",
        )
    )
    store.save(
        Checkpoint(
            task_id=future_task.id,
            role="code-worker",
            summary="waiting",
            next_steps=["continue"],
            resume_after="2026-09-12T19:00:00+00:00",
        )
    )

    assert [item.task_id for item in store.due(
        now=datetime(2026, 9, 11, 20, tzinfo=timezone.utc)
    )] == [due_task.id]

    with board.edit(due_task.id) as task:
        task.checkpoint_resumed_at = due.created_at
    assert store.due(now=datetime(2026, 9, 11, 20, tzinfo=timezone.utc)) == []
