from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from saturnin.board import Board
from saturnin.checkpoints import Checkpoint, CheckpointStore
from saturnin.cli import main
from saturnin.config import Config
from saturnin.discovery import InboundIssue, IssueDiscovery
from saturnin.launcher import AgentLauncher
from saturnin.review import (
    issue_content_digest,
    review_attestation_signing_key,
    sign_review_attestation,
)
from saturnin.routing import Router
from saturnin.worktrees import WorktreeManager


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


def review_attestation_args(**kwargs: str) -> tuple[str, str]:
    attestation = sign_review_attestation(
        key=review_attestation_signing_key(Config.load(), kwargs["reviewer"]),
        subject=kwargs["subject"],
        kind=kwargs["kind"],
        author=kwargs["author"],
        reviewer=kwargs["reviewer"],
        verdict=kwargs["verdict"],
        head_sha=kwargs.get("head_sha", ""),
        issue_digest=kwargs.get("issue_digest", ""),
    )
    return ("--attestation", attestation)


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
    run(capsys, "task", "add", "Roadmap", "--kind", "objective")
    code, out = run(capsys, "--json", "dispatch", "--all", "--dry-run")
    assert json.loads(out)[0]["role"] == "scribe"
    assert len(json.loads(run(capsys, "--json", "task", "list", "--state", "intake")[1])) == 2

    run(capsys, "dispatch", "--all")
    intake = json.loads(run(capsys, "--json", "task", "list", "--state", "intake")[1])
    assert [task["kind"] for task in intake] == ["objective"]


def test_dispatch_launches_the_selected_agent(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = json.loads(run(capsys, "--json", "task", "add", "Implement launcher check")[1])
    launched: list[str] = []
    monkeypatch.setattr(
        "saturnin.cli.AgentLauncher.launch",
        lambda self, task_id, **kwargs: launched.append(task_id),
    )
    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))
    worktree = home / "var" / "worktrees" / "feature"
    worktree.mkdir(parents=True)
    monkeypatch.setattr(
        WorktreeManager,
        "create",
        lambda self, branch, base=None: SimpleNamespace(path=worktree, branch=branch),
    )

    assert run(capsys, "dispatch", task["id"])[0] == 0
    assert launched == [task["id"]]


def test_task_add_provisions_worktree_before_launch(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = home / "var" / "worktrees" / "auto"
    worktree.mkdir(parents=True)
    launched: list[dict] = []
    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))
    monkeypatch.setattr(
        WorktreeManager,
        "create",
        lambda self, branch, base=None: SimpleNamespace(path=worktree, branch=branch),
    )

    def launch(self, task_id, **kwargs):
        launched.append(self.board.get(task_id).to_dict())
        return None

    monkeypatch.setattr(AgentLauncher, "launch", launch)

    code, out = run(
        capsys, "--json", "task", "add", "Provision before launch", "--dispatch"
    )

    task = json.loads(out)
    assert code == 0
    assert task["worktree"] == str(worktree)
    assert task["branch"].startswith("feature/")
    assert launched[0]["worktree"] == str(worktree)


def test_auto_provision_rolls_back_created_worktree_when_attach_fails(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    created = SimpleNamespace(
        branch="feature/rollback-auto",
        path=home / "var" / "worktrees" / "rollback-auto",
    )
    rollbacks: list[object] = []
    original_edit = Board.edit

    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))
    monkeypatch.setattr(WorktreeManager, "create", lambda self, branch, base=None: created)
    monkeypatch.setattr(
        WorktreeManager, "rollback_create", lambda self, worktree: rollbacks.append(worktree)
    )
    failed = False

    def fail_attach_once(self, task_id):
        nonlocal failed
        task = self.get(task_id)
        if (
            not failed
            and task.state == "routed"
            and task.branch is None
            and task.worktree is None
        ):
            failed = True
            raise OSError("task write failed")
        return original_edit(self, task_id)

    monkeypatch.setattr(Board, "edit", fail_attach_once)

    code, out = run(capsys, "--json", "task", "add", "Rollback auto provision", "--dispatch")

    task = json.loads(out)
    assert code == 0
    assert rollbacks == [created]
    assert task["branch"] is None
    assert task["worktree"] is None
    assert "worktree provisioning failed: task write failed" in task["launch_deferred_reason"]


def test_deferred_external_discovery_provisions_configured_checkout_on_retry(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = home / "policies" / "repos.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["discovery"]["sources"].append({"slug": "JakubMifek/widget-api"})
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    issue = InboundIssue(
        repo="JakubMifek/widget-api",
        number=7,
        title="Fix widget failure",
        url="https://github.com/JakubMifek/widget-api/issues/7",
        labels=["incident"],
    )
    launched: list[dict] = []
    monkeypatch.setattr(IssueDiscovery, "poll", lambda self: [issue])
    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))

    def launch(self, task_id, **kwargs):
        launched.append(self.board.get(task_id).to_dict())
        with self.board.edit(task_id) as stored:
            stored.launch_deferred_at = None
            stored.launch_deferred_reason = None

    monkeypatch.setattr(AgentLauncher, "launch", launch)

    assert run(capsys, "discover")[0] == 0
    task = next(iter(Board()))
    assert task.state == "routed"
    assert task.launch_deferred_reason == (
        "configure a checkout for managed repository JakubMifek/widget-api"
    )
    assert launched == []

    checkout = home / "projects" / "widget-api"
    worktree = home / "var" / "worktrees" / "widget"
    (worktree / ".saturnin" / "agents").mkdir(parents=True)
    checkout.mkdir(parents=True)
    (worktree / ".saturnin" / "agents" / "widget-worker.md").write_text(
        "---\nrole: widget-worker\nunit: engineering\nskills: []\nmcp: []\n---\n"
    )
    (worktree / ".saturnin" / "repo.yaml").write_text(
        "project: Widget\ncontext: python\nconventions: pytest\n"
        "lead: widget-worker\nsquad: [widget-worker]\n"
        "agents: [.saturnin/agents/widget-worker.md]\n"
    )
    policy["discovery"]["sources"][-1]["checkout"] = str(checkout)
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    provisioned_from: list[Path] = []

    def create(manager, branch, base=None):
        provisioned_from.append(manager.repo)
        return SimpleNamespace(path=worktree, branch=branch)

    monkeypatch.setattr(WorktreeManager, "create", create)

    assert run(capsys, "dispatch", "--all")[0] == 0
    stored = Board().get(task.id)
    assert provisioned_from == [checkout]
    assert launched[0]["role"] == "widget-worker"
    assert launched[0]["worktree"] == str(worktree)
    assert stored.launch_deferred_at is None
    assert stored.launch_deferred_reason is None


def test_deferred_external_discovery_applies_project_squad_without_lead(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = home / "policies" / "repos.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["discovery"]["sources"].append({"slug": "JakubMifek/widget-api"})
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    issue = InboundIssue(
        repo="JakubMifek/widget-api",
        number=9,
        title="Fix widget retry flow",
        url="https://github.com/JakubMifek/widget-api/issues/9",
        labels=["incident"],
    )
    launched: list[dict] = []
    monkeypatch.setattr(IssueDiscovery, "poll", lambda self: [issue])
    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))

    def launch(self, task_id, **kwargs):
        launched.append(self.board.get(task_id).to_dict())
        with self.board.edit(task_id) as stored:
            stored.launch_deferred_at = None
            stored.launch_deferred_reason = None

    monkeypatch.setattr(AgentLauncher, "launch", launch)

    assert run(capsys, "discover")[0] == 0
    task = next(iter(Board()))
    assert task.state == "routed"
    assert launched == []

    checkout = home / "projects" / "widget-api"
    worktree = home / "var" / "worktrees" / "widget-retry"
    (worktree / ".saturnin").mkdir(parents=True)
    checkout.mkdir(parents=True)
    (worktree / ".saturnin" / "repo.yaml").write_text(
        "project: Widget\ncontext: python\nconventions: pytest\n"
        "squad: [code-worker, scribe]\n"
    )
    policy["discovery"]["sources"][-1]["checkout"] = str(checkout)
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    monkeypatch.setattr(
        WorktreeManager,
        "create",
        lambda self, branch, base=None: SimpleNamespace(path=worktree, branch=branch),
    )

    assert run(capsys, "dispatch", "--all")[0] == 0
    stored = Board().get(task.id)
    assert launched[0]["role"] == "code-worker"
    assert launched[0]["squad"] == ["code-worker", "scribe"]
    assert stored.squad == ["code-worker", "scribe"]


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


def test_governed_push_uses_remote_repo_and_destination_branch(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["symbolic-ref", "--quiet"]:
            return subprocess.CompletedProcess(args, 0, "feature/safe\n", "")
        if args[1:] == ["remote", "get-url", "--push", "--all", "origin"]:
            return subprocess.CompletedProcess(
                args, 0, "http://localhost:26831/JakubMifek/saturnin\n", ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.cli.subprocess.run", fake_run)

    assert run(capsys, "push")[0] == 0
    assert calls[-1] == [
        "git",
        "push",
        "--",
        "origin",
        "HEAD:refs/heads/feature/safe",
    ]


def test_governed_push_refuses_protected_branch_before_push(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:] == ["remote", "get-url", "--push", "--all", "origin"]:
            return subprocess.CompletedProcess(
                args, 0, "https://github.com/JakubMifek/saturnin.git\n", ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.cli.subprocess.run", fake_run)

    code, out = run(capsys, "push", "--branch", "main")

    assert code == 2
    assert "protected" in out
    assert not any(call[1:2] == ["push"] for call in calls)


def test_governed_push_rejects_unconfigured_loopback_proxy(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:] == ["remote", "get-url", "--push", "--all", "origin"]:
            return subprocess.CompletedProcess(
                args, 0, "http://127.0.0.1:26831/JakubMifek/saturnin\n", ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.cli.subprocess.run", fake_run)

    code = main(["push", "--branch", "feature/safe"])
    error = capsys.readouterr().err

    assert code == 1
    assert "unrecognized push destination" in error
    assert not any(call[1:2] == ["push"] for call in calls)


def test_governed_push_authorizes_pushurl_not_fetch_url(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    fetch_url = "https://github.com/JakubMifek/saturnin.git"
    push_url = "https://github.com/other/project.git"

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:] == ["remote", "get-url", "--push", "--all", "origin"]:
            return subprocess.CompletedProcess(args, 0, push_url + "\n", "")
        if args[1:] == ["remote", "get-url", "origin"]:
            return subprocess.CompletedProcess(args, 0, fetch_url + "\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.cli.subprocess.run", fake_run)

    code, out = run(capsys, "push", "--branch", "feature/safe")

    assert code == 2
    assert "managed repos are not allowed" in out
    assert ["git", "remote", "get-url", "--push", "--all", "origin"] in calls
    assert ["git", "remote", "get-url", "origin"] not in calls
    assert not any(call[1:2] == ["push"] for call in calls)


def test_review_gate_flow(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    subject = "JakubMifek/saturnin#42"
    head_sha = "a" * 40
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
            "--head-sha",
            head_sha,
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
        head_sha,
        *review_attestation_args(
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=head_sha,
        ),
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
        head_sha,
    )
    assert code == 0
    assert "ALLOWED" in out


def test_review_cli_resolves_omitted_pr_head(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = "JakubMifek/saturnin#42"
    head_sha = "a" * 40
    monkeypatch.setattr(
        "saturnin.cli.run_gh",
        lambda args: json.dumps({"head": {"sha": head_sha}}),
    )

    assert run(
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
        *review_attestation_args(
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=head_sha,
        ),
    )[0] == 0
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


def test_review_attest_refuses_to_sign_for_another_role(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SATURNIN_AGENT_ROLE", "code-worker")

    code, _ = run(
        capsys,
        "review",
        "attest",
        "JakubMifek/saturnin#forged",
        "--kind",
        "pr",
        "--author",
        "code-worker",
        "--reviewer",
        "pr-reviewer",
        "--verdict",
        "approved",
        "--head-sha",
        "d" * 40,
    )

    assert code == 1


def test_dispatch_all_defers_one_launch_failure_and_continues(
    config: Config, board: Board, capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = board.create("First launch")
    second = board.create("Second launch")
    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))
    worktree = config.root / "var" / "worktrees" / "queued"
    worktree.mkdir(parents=True)
    monkeypatch.setattr(
        WorktreeManager,
        "create",
        lambda self, branch, base=None: SimpleNamespace(path=worktree, branch=branch),
    )
    launched: list[str] = []

    def launch(self, task_id, **kwargs):
        launched.append(task_id)
        if task_id == first.id:
            from saturnin.launcher import LauncherError

            raise LauncherError("cannot spawn")
        return SimpleNamespace(to_dict=lambda: {"task_id": task_id, "pid": 42})

    monkeypatch.setattr(AgentLauncher, "launch", launch)

    code, out = run(capsys, "--json", "dispatch", "--all")

    assert code == 0
    assert launched == [first.id, second.id]
    assert "agent launch failed: cannot spawn" in board.get(first.id).launch_deferred_reason
    assert json.loads(out)[1]["launch"]["task_id"] == second.id


def test_invalid_project_manifest_is_reported_as_a_routing_error(
    config: Config, board: Board, capsys: pytest.CaptureFixture[str]
) -> None:
    task = board.create("Malformed project")
    worktree = config.root / "malformed-project"
    (worktree / ".saturnin").mkdir(parents=True)
    (worktree / ".saturnin" / "repo.yaml").write_text("squad: [\n", encoding="utf-8")
    with board.edit(task.id) as stored:
        stored.worktree = str(worktree)

    assert main(["dispatch", task.id, "--dry-run"]) == 1
    assert "invalid managed repository manifest" in capsys.readouterr().err


def test_issue_review_gate_requires_matching_digest(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    subject = "draft-for-managed-repo"
    digest = "b" * 64
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
        *review_attestation_args(
            subject=subject,
            kind="issue",
            author="researcher",
            reviewer="issue-reviewer",
            verdict="approved",
            issue_digest=digest,
        ),
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


def test_review_merge_blocks_when_pr_head_changed_after_approval(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = "JakubMifek/saturnin#7"
    reviewed_head = "a" * 40
    current_head = "b" * 40
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
        reviewed_head,
        *review_attestation_args(
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=reviewed_head,
        ),
    )
    calls: list[list[str]] = []

    def fake_run_gh(args: list[str]) -> str:
        calls.append(args)
        if args[:2] == ["api", f"repos/JakubMifek/saturnin/pulls/7"]:
            return json.dumps({"head": {"sha": current_head}})
        raise AssertionError(f"unexpected gh call: {args}")

    monkeypatch.setattr("saturnin.cli.run_gh", fake_run_gh)

    code, out = run(
        capsys,
        "review",
        "merge",
        subject,
        "--repo",
        "JakubMifek/saturnin",
        "--author",
        "code-worker",
    )

    assert code == 2
    assert "no review records match the current head SHA" in out
    assert calls == [["api", "repos/JakubMifek/saturnin/pulls/7"]]


def test_review_merge_uses_expected_head_precondition(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = "JakubMifek/saturnin#8"
    head_sha = "c" * 40
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
        head_sha,
        *review_attestation_args(
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=head_sha,
        ),
    )
    calls: list[list[str]] = []

    def fake_run_gh(args: list[str]) -> str:
        calls.append(args)
        if args[:2] == ["api", f"repos/JakubMifek/saturnin/pulls/8"]:
            return json.dumps({"head": {"sha": head_sha}})
        if args[:4] == ["api", "--method", "PUT", "repos/JakubMifek/saturnin/pulls/8/merge"]:
            assert f"sha={head_sha}" in args
            return json.dumps({"merged": True, "message": "Pull Request successfully merged", "sha": "d" * 40})
        raise AssertionError(f"unexpected gh call: {args}")

    monkeypatch.setattr("saturnin.cli.run_gh", fake_run_gh)

    code, out = run(
        capsys,
        "review",
        "merge",
        subject,
        "--repo",
        "JakubMifek/saturnin",
        "--author",
        "code-worker",
        "--method",
        "squash",
    )

    assert code == 0
    assert "successfully merged" in out
    assert calls[1][:4] == ["api", "--method", "PUT", "repos/JakubMifek/saturnin/pulls/8/merge"]


def test_review_submit_issue_uses_reviewed_title_and_body_digest(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = "managed-issue-draft"
    title = "Need safer rollout guardrails"
    body = "Gate deployments on verified backup snapshots."
    digest = issue_content_digest(title, body)
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
        *review_attestation_args(
            subject=subject,
            kind="issue",
            author="researcher",
            reviewer="issue-reviewer",
            verdict="approved",
            issue_digest=digest,
        ),
    )
    calls: list[list[str]] = []

    def fake_run_gh(args: list[str]) -> str:
        calls.append(args)
        if args[:2] == ["issue", "create"]:
            assert args[args.index("--title") + 1] == title
            assert args[args.index("--body") + 1] == body
            return "https://github.com/JakubMifek/saturnin-ops/issues/77\n"
        raise AssertionError(f"unexpected gh call: {args}")

    monkeypatch.setattr("saturnin.cli.run_gh", fake_run_gh)

    code, out = run(
        capsys,
        "review",
        "submit-issue",
        subject,
        "--repo",
        "JakubMifek/saturnin-ops",
        "--author",
        "researcher",
        "--title",
        title,
        "--body",
        body,
        "--label",
        "incident",
    )

    assert code == 0
    assert out.strip().endswith("/issues/77")
    assert calls == [
        [
            "issue",
            "create",
            "--repo",
            "JakubMifek/saturnin-ops",
            "--title",
            title,
            "--body",
            body,
            "--label",
            "incident",
        ]
    ]


def test_review_submit_issue_blocks_when_reviewed_content_differs(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = "content-mismatch-draft"
    reviewed_digest = "e" * 64
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
        reviewed_digest,
        *review_attestation_args(
            subject=subject,
            kind="issue",
            author="researcher",
            reviewer="issue-reviewer",
            verdict="approved",
            issue_digest=reviewed_digest,
        ),
    )
    monkeypatch.setattr("saturnin.cli.run_gh", lambda args: (_ for _ in ()).throw(AssertionError(args)))

    code, out = run(
        capsys,
        "review",
        "submit-issue",
        subject,
        "--repo",
        "JakubMifek/saturnin-ops",
        "--author",
        "researcher",
        "--title",
        "Reviewed title",
        "--body",
        "Different body than the reviewed draft",
    )

    assert code == 2
    assert "no issue review records match the current issue-content digest" in out


def test_checkpoint_sweep_does_not_mutate_when_launcher_is_disabled(
    config: Config, board: Board, capsys: pytest.CaptureFixture[str]
) -> None:
    task = board.create("Resume after dependency")
    Router(config).dispatch(board, task)
    board.transition(task, "blocked", note="escalated: https://example.test/escalations/42")
    CheckpointStore(config, board).save(
        Checkpoint(
            task_id=task.id,
            role="code-worker",
            summary="Waiting for dependency.",
            next_steps=["Continue implementation."],
            resume_after=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        )
    )
    before = board.get(task.id)

    code, out = run(capsys, "--json", "checkpoint", "sweep")

    after = board.get(task.id)
    assert code == 0
    assert json.loads(out) == [{"task_id": task.id, "disabled": True}]
    assert after.state == "blocked"
    assert after.history == before.history


def test_checkpoint_sweep_continues_after_launch_failure(
    config: Config, board: Board, capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = board.create("Malformed checkpoint task")
    second = board.create("Healthy checkpoint task")
    Router(config).dispatch(board, first)
    Router(config).dispatch(board, second)
    checkpoints = [
        Checkpoint(task_id=first.id, role="code-worker", summary="first"),
        Checkpoint(task_id=second.id, role="code-worker", summary="second"),
    ]
    monkeypatch.setattr(CheckpointStore, "due", lambda self: checkpoints)
    monkeypatch.setattr(AgentLauncher, "enabled", property(lambda self: True))

    def launch(self, task_id, **kwargs):
        if task_id == first.id:
            raise RuntimeError("invalid checkpoint")
        return SimpleNamespace(to_dict=lambda: {"task_id": task_id, "pid": 42})

    monkeypatch.setattr("saturnin.cli.AgentLauncher.launch", launch)

    code, out = run(capsys, "--json", "checkpoint", "sweep")

    assert code == 1
    assert json.loads(out) == [
        {"task_id": first.id, "error": "invalid checkpoint"},
        {"task_id": second.id, "pid": 42},
    ]


def test_escalation_validates_task_before_submission(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    done = Board().create("already done")
    Board().transition(done, "routed")
    Board().transition(done, "in_progress")
    Board().transition(done, "review")
    Board().transition(done, "done")
    submitted: list[str] = []
    monkeypatch.setattr("saturnin.escalation.submit", lambda **kwargs: submitted.append("called"))

    code, out = run(capsys, "escalate", "Need help", "--push", "--task", done.id)

    assert code == 1
    assert out == ""
    assert submitted == []


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


def test_worktree_start_attaches_and_transitions_in_one_lifecycle(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Start work session")
    Board().transition(task, "routed")
    worktree_path = home / "worktree"
    monkeypatch.setattr(
        WorktreeManager,
        "create",
        lambda *args, **kwargs: SimpleNamespace(
            branch="feature/start-session", path=worktree_path
        ),
    )

    assert (
        main(
            [
                "worktree",
                "create",
                "feature/start-session",
                "--task",
                task.id,
                "--actor",
                "code-worker",
                "--start",
            ]
        )
        == 0
    )

    stored = Board().get(task.id)
    assert stored.state == "in_progress"
    assert stored.branch == "feature/start-session"
    assert stored.worktree == str(worktree_path)
    assert stored.history[-1]["actor"] == "code-worker"


def test_worktree_start_rejects_an_unstartable_task_before_creation(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Unrouted task")
    calls: list[str] = []
    monkeypatch.setattr(WorktreeManager, "create", lambda *args, **kwargs: calls.append("create"))

    assert main(["worktree", "create", "feature/unrouted", "--task", task.id, "--start"]) == 1
    assert calls == []
    assert Board().get(task.id).worktree is None


def test_worktree_start_rolls_back_when_final_transition_fails(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Rollback failed start")
    Board().transition(task, "routed")
    worktree = SimpleNamespace(branch="feature/rollback", path=home / "worktree")
    rollback: list[object] = []
    monkeypatch.setattr(WorktreeManager, "create", lambda *args, **kwargs: worktree)
    monkeypatch.setattr(WorktreeManager, "rollback_create", lambda _self, item: rollback.append(item))

    def fail_transition(*args: object, **kwargs: object) -> None:
        raise RuntimeError("state write failed")

    monkeypatch.setattr(Board, "_apply_transition", fail_transition)

    assert (
        main(["worktree", "create", "feature/rollback", "--task", task.id, "--start"]) == 1
    )
    assert rollback == [worktree]
    stored = Board().get(task.id)
    assert stored.state == "routed"
    assert stored.worktree is None


def test_worktree_create_rejects_already_attached_task(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    task = Board().create("Already attached")
    with Board().edit(task.id) as stored:
        stored.branch = "feature/existing"
        stored.worktree = "/tmp/existing-worktree"

    calls: list[str] = []

    def fake_create(*args, **kwargs):
        calls.append("called")
        return SimpleNamespace(branch="feature/new", path=Path("/tmp/new-worktree"))

    monkeypatch.setattr(WorktreeManager, "create", fake_create)

    assert main(["worktree", "create", "feature/new", "--task", task.id]) == 1
    assert calls == []
