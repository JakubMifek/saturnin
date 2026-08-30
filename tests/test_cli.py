from __future__ import annotations

import json
from pathlib import Path

import pytest

from saturnin.board import Board
from saturnin.cli import main


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


def test_doctor_is_healthy(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "doctor")
    assert code == 0
    assert "in order" in out


def test_task_intake_and_dispatch(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(
        capsys, "--json", "task", "add", "Fix the failing deploy", "--dispatch"
    )
    assert code == 0
    task = json.loads(out)
    assert task["state"] == "routed"
    assert task["role"] == "code-worker"

    code, out = run(capsys, "task", "list", "--open")
    assert task["id"] in out


def test_dispatch_all_and_dry_run(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run(capsys, "task", "add", "Write the runbook documentation")
    code, out = run(capsys, "--json", "dispatch", "--all", "--dry-run")
    assert json.loads(out)[0]["role"] == "scribe"
    assert json.loads(run(capsys, "--json", "task", "list", "--state", "intake")[1])

    run(capsys, "dispatch", "--all")
    assert not json.loads(run(capsys, "--json", "task", "list", "--state", "intake")[1])


def test_branch_and_command_checks(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "check", "branch", "feature/x")[0] == 0
    assert run(capsys, "check", "branch", "main")[0] == 2
    assert run(capsys, "check", "command", "systemctl --user restart saturnin-janitor.timer")[0] == 0
    assert run(capsys, "check", "command", "sudo rm -rf /")[0] == 2


def test_review_gate_flow(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    subject = "JakubMifek/saturnin#42"
    assert (
        run(
            capsys,
            "review",
            "gate",
            subject,
            "--kind",
            "pr",
            "--repo",
            "JakubMifek/saturnin",
            "--author",
            "code-worker",
        )[0]
        == 2
    )
    run(
        capsys,
        "review",
        "record",
        subject,
        "--kind",
        "pr",
        "--author",
        "code-worker",
        "--reviewer",
        "pr-reviewer",
        "--verdict",
        "approved",
    )
    code, out = run(
        capsys,
        "review",
        "gate",
        subject,
        "--kind",
        "pr",
        "--repo",
        "JakubMifek/saturnin",
        "--author",
        "code-worker",
    )
    assert code == 0
    assert "ALLOWED" in out


def test_checkpoint_roundtrip(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    task = json.loads(run(capsys, "--json", "task", "add", "Long job")[1])
    run(
        capsys,
        "checkpoint",
        "save",
        task["id"],
        "--role",
        "code-worker",
        "--summary",
        "Half done",
        "--next",
        "finish the other half",
    )
    code, out = run(capsys, "checkpoint", "resume", task["id"])
    assert code == 0
    assert "finish the other half" in out


def test_escalation_body_is_complete(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(
        capsys,
        "escalate",
        "Need production credentials",
        "--context",
        "Deploy blocked",
        "--item",
        "Provide a scoped token",
        "--unblock",
        "Token available in the vault",
        "--urgency",
        "high",
    )
    assert code == 0
    assert "@jakubmifek" in out
    assert "## Checklist" in out
    assert "## Unblock criteria" in out


def test_escalation_rejects_unknown_urgency(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "escalate", "Help", "--urgency", "apocalyptic")[0] == 2


def test_automation_and_improve(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for _ in range(3):
        run(capsys, "task", "add", "Rotate the deploy keys")
    code, out = run(capsys, "automation", "detect", "--propose")
    assert code == 0
    assert "3x" in out
    assert "Automate repeated work" in run(capsys, "task", "list")[1]

    code, out = run(capsys, "--json", "improve", "--no-tasks")
    assert code == 0
    assert json.loads(out)["metrics"]["total"] >= 4

    assert "janitor-cleanup" in run(capsys, "automation", "find", "stale", "worktrees")[1]


def test_board_metrics_and_roles(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert "median_dispatch_latency_s" in run(capsys, "board", "metrics")[1]
    roles = run(capsys, "board", "roles")[1]
    assert "DELEGATES ONLY" in roles


def test_unknown_task_returns_error(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["task", "show", "T-nope"]) == 1


def test_attach_rejects_protected_branch(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    task = json.loads(run(capsys, "--json", "task", "add", "Attach me")[1])
    assert main(["task", "attach", task["id"], "--branch", "main"]) == 2
    assert main(["task", "attach", task["id"], "--branch", "feature/ok"]) == 0
    board = Board()
    assert board.get(task["id"]).branch == "feature/ok"
