from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.board import Board
from saturnin.cli import main
from saturnin.worktrees import WorktreeManager


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


def test_dispatch_launches_the_selected_agent(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = json.loads(run(capsys, "--json", "task", "add", "Implement launcher check")[1])
    launched: list[str] = []
    monkeypatch.setattr(
        "saturnin.cli.AgentLauncher.launch",
        lambda self, task_id, **kwargs: launched.append(task_id),
    )

    assert run(capsys, "dispatch", task["id"])[0] == 0
    assert launched == [task["id"]]


@pytest.mark.parametrize(
    ("squad", "error"),
    [("ghost", "unknown squad members"), ("ceo", "CEO never executes")],
)
def test_dry_run_dispatch_rejects_an_invalid_squad(
    home: Path, capsys: pytest.CaptureFixture[str], squad: str, error: str
) -> None:
    task = json.loads(run(capsys, "--json", "task", "add", "Preview dispatch")[1])

    assert main(["dispatch", task["id"], "--dry-run", "--squad", squad]) == 1
    assert error in capsys.readouterr().err
    assert Board().get(task["id"]).state == "intake"


def test_branch_and_command_checks(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "check", "branch", "feature/x")[0] == 0
    assert run(capsys, "check", "branch", "main")[0] == 2
    assert run(capsys, "check", "command", "systemctl --user restart saturnin-janitor.timer")[0] == 0
    assert run(capsys, "check", "command", "sudo rm -rf /")[0] == 2
    assert run(capsys, "check", "command", "rm -rf /etc")[0] == 2
    assert run(capsys, "check", "command", "apt install ripgrep")[0] == 2
    assert (
        run(
            capsys,
            "check",
            "command",
            "apt install ripgrep",
            "--service",
            "saturnin-discovery.service",
        )[0]
        == 0
    )


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
        "--head-sha",
        "abc123",
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
        "--head-sha",
        "abc123",
    )
    assert code == 0
    assert "ALLOWED" in out


def test_issue_review_gate_requires_matching_digest(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    subject = "draft-for-managed-repo"
    digest = "reviewed-digest"
    run(
        capsys,
        "review",
        "record",
        subject,
        "--kind",
        "issue",
        "--author",
        "researcher",
        "--reviewer",
        "issue-reviewer",
        "--verdict",
        "approved",
        "--issue-digest",
        digest,
    )

    code, out = run(
        capsys,
        "review",
        "gate",
        subject,
        "--kind",
        "issue",
        "--repo",
        "JakubMifek/saturnin-ops",
        "--author",
        "researcher",
        "--issue-digest",
        digest,
    )

    assert code == 0
    assert "ALLOWED" in out


def test_escalation_returns_nonzero_when_submitted_task_cannot_be_blocked(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    done = Board().create("already done")
    Board().transition(done, "routed")
    Board().transition(done, "in_progress")
    Board().transition(done, "review")
    Board().transition(done, "done")
    monkeypatch.setattr(
        "saturnin.escalation.submit",
        lambda **kwargs: "https://github.com/JakubMifek/saturnin-ops/issues/9",
    )

    code, out = run(capsys, "escalate", "Need help", "--push", "--task", done.id)

    assert code == 2
    assert out.splitlines()[0].endswith("/issues/9")
    assert "not blocked" in out


def test_cleanup_apply_reports_plan_errors(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from saturnin.worktrees import CleanupPlan, WorktreeManager

    monkeypatch.setattr(
        WorktreeManager,
        "plan_cleanup",
        lambda self, now: CleanupPlan(errors=["could not remove stale worktree"]),
    )
    assert run(capsys, "worktree", "cleanup", "--apply")[0] == 1


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


def test_escalation_push_submits_safely_to_board_repo(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        stdout = (
            "[]"
            if args[1:3] == ["label", "list"]
            else "https://github.com/JakubMifek/saturnin-ops/issues/7\n"
        )
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)
    title = "Need help; echo not-a-command"

    code, out = run(capsys, "escalate", title, "--urgency", "high", "--push")

    assert code == 0
    assert out.strip().endswith("/issues/7")
    create = next(call for call in calls if call[1:3] == ["issue", "create"])
    assert create[create.index("--repo") + 1] == "JakubMifek/saturnin-ops"
    assert create[create.index("--title") + 1] == title
    assert create[create.index("--label") + 1] == "saturnin:escalation"
    provision = next(call for call in calls if call[1:3] == ["label", "create"])
    assert provision[3] == "saturnin:escalation"


def test_escalation_push_failure_is_reported(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(
        "saturnin.issues.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 1, "", "authentication failed"
        ),
    )

    assert main(["escalate", "Need help", "--push"]) == 1
    assert "authentication failed" in capsys.readouterr().err


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


def test_attach_uses_locked_edit(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Attach atomically")

    def reject_save(*args: object, **kwargs: object) -> None:
        raise AssertionError("attach must not use Board.save()")

    monkeypatch.setattr(Board, "save", reject_save)
    assert (
        main(
            [
                "task",
                "attach",
                task.id,
                "--branch",
                "feature/atomic",
                "--actor",
                "code-worker",
            ]
        )
        == 0
    )
    stored = Board().get(task.id)
    assert stored.branch == "feature/atomic"
    assert stored.history[-1]["actor"] == "code-worker"


def test_task_move_uses_locked_edit(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Move atomically")

    def reject_save(*args: object, **kwargs: object) -> None:
        raise AssertionError("task move must not use Board.save()")

    monkeypatch.setattr(Board, "save", reject_save)
    assert main(["task", "move", task.id, "routed", "--actor", "router"]) == 0
    stored = Board().get(task.id)
    assert stored.state == "routed"
    assert stored.history[-1]["actor"] == "router"


def test_worktree_task_attachment_uses_locked_edit(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Create worktree atomically")
    worktree_path = home / "worktree"
    monkeypatch.setattr(
        WorktreeManager,
        "create",
        lambda *args, **kwargs: SimpleNamespace(
            branch="feature/atomic-worktree", path=worktree_path
        ),
    )

    def reject_save(*args: object, **kwargs: object) -> None:
        raise AssertionError("worktree attachment must not use Board.save()")

    monkeypatch.setattr(Board, "save", reject_save)
    assert (
        main(
            [
                "worktree",
                "create",
                "feature/atomic-worktree",
                "--task",
                task.id,
                "--actor",
                "code-worker",
            ]
        )
        == 0
    )
    stored = Board().get(task.id)
    assert stored.branch == "feature/atomic-worktree"
    assert stored.worktree == str(worktree_path)
    assert stored.history[-1]["actor"] == "code-worker"
