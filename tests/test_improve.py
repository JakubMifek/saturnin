from __future__ import annotations

from datetime import datetime, timedelta, timezone

from saturnin import telemetry
from saturnin.board import Board
from saturnin.config import Config
from saturnin.improve import ImprovementLoop
from saturnin.routing import Router


def test_median_ignores_missing_values() -> None:
    assert telemetry._median(value for value in [None, 1.0, 3.0]) == 2.0
    assert telemetry._median([None]) is None


def test_metrics_reflect_the_board(config: Config, board: Board) -> None:
    router = Router(config)
    done = board.create("Implement a widget")
    router.dispatch(board, done)
    board.transition(done, "in_progress")
    board.transition(done, "done")
    board.create("Waiting in intake")

    metrics = telemetry.collect(board)
    assert metrics["total"] == 2
    assert metrics["open"] == 1
    assert metrics["undispatched"] == 1
    assert metrics["by_state"]["done"] == 1
    assert metrics["median_dispatch_latency_s"] is not None
    assert metrics["median_cycle_time_s"] is not None


def test_bottleneck_detection(config: Config, board: Board) -> None:
    loop = ImprovementLoop(config, board)
    findings = {
        f.id
        for f in loop.detect(
            {
                "open": 10,
                "blocked": 6,
                "undispatched": 9,
                "wip_by_role": {"code-worker": 12},
                "median_dispatch_latency_s": 900,
                "median_cycle_time_s": 10,
                "oldest_open_age_days": 40,
            }
        )
    }
    assert findings == {
        "slow-dispatch",
        "intake-backlog",
        "overloaded-code-worker",
        "blocked-heavy",
        "stale-work",
    }


def test_healthy_board_has_no_findings(config: Config, board: Board) -> None:
    loop = ImprovementLoop(config, board)
    assert loop.detect(telemetry.collect(board)) == []


def test_run_files_tasks_and_report(config: Config, board: Board) -> None:
    for index in range(5):
        board.create(f"Idle task {index}")
    loop = ImprovementLoop(config, board)
    report = loop.run(now=datetime.now(timezone.utc) + timedelta(days=1))
    assert report.proposed_tasks
    assert any(task.kind == "improvement" for task in board)
    assert list((config.root / "var" / "reports").glob("improvement-*.json"))

    # Running again must not duplicate the same improvement task.
    before = len(list(board))
    loop.run(now=datetime.now(timezone.utc) + timedelta(days=1))
    assert len(list(board)) == before


def test_run_can_report_only(config: Config, board: Board) -> None:
    for index in range(5):
        board.create(f"Idle task {index}")
    report = ImprovementLoop(config, board).run(create_tasks=False)
    assert report.findings
    assert report.proposed_tasks == []
