from __future__ import annotations

import pytest

from saturnin.config import Config
from saturnin.governance import Governance
from saturnin.review import ReviewLedger, ReviewError

SELF_REPO = "JakubMifek/saturnin"
OTHER_REPO = "JakubMifek/some-project"


@pytest.fixture()
def governance(config: Config) -> Governance:
    return Governance(config)


def test_policies_audit_clean(governance: Governance) -> None:
    assert governance.audit() == []


@pytest.mark.parametrize("branch", ["main", "master", "release"])
def test_default_branch_is_never_writable(governance: Governance, branch: str) -> None:
    assert not governance.check_branch(branch).allowed


@pytest.mark.parametrize("branch", ["feature/board-ui", "fix/login-500", "automation/janitor"])
def test_feature_branches_allowed(governance: Governance, branch: str) -> None:
    assert governance.check_branch(branch).allowed


def test_branch_without_prefix_rejected(governance: Governance) -> None:
    decision = governance.check_branch("my-random-branch")
    assert not decision.allowed
    assert "feature/" in decision.reasons[0]


def test_merge_requires_independent_zero_context_review(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#7"
    assert not governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr")
    ).allowed

    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="changes_requested",
    )
    assert not governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr")
    ).allowed

    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
    )
    assert governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr")
    ).allowed


def test_reviewer_with_context_does_not_satisfy_gate(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#8"
    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="test-worker",
        verdict="approved",
        zero_context=False,
    )
    decision = governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr")
    )
    assert not decision.allowed
    assert "zero-context" in decision.reasons[0]


def test_self_review_is_impossible(config: Config) -> None:
    ledger = ReviewLedger(config)
    with pytest.raises(ReviewError):
        ledger.record(
            subject="x#1",
            kind="pr",
            author="code-worker",
            reviewer="code-worker",
            verdict="approved",
        )


def test_corrupt_review_ledger_reports_file_and_line(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#corrupt"
    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
    )
    path = next(ledger.dir.glob("*.jsonl"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")

    with pytest.raises(ReviewError, match=rf"{path} at line 2"):
        ledger.for_subject(subject, "pr")
    with pytest.raises(ReviewError, match=rf"{path} at line 2"):
        list(ledger)


def test_merge_in_managed_repo_is_never_autonomous(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = f"{OTHER_REPO}#3"
    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
    )
    decision = governance.merge_allowed(
        repo=OTHER_REPO, author="code-worker", records=ledger.for_subject(subject, "pr")
    )
    assert not decision.allowed


def test_issue_submission_requires_review_in_managed_repos(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "draft-improve-ci"
    assert not governance.issue_submission_allowed(
        repo=OTHER_REPO, author="researcher", records=ledger.for_subject(subject, "issue")
    ).allowed
    ledger.record(
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="issue-reviewer",
        verdict="approved",
    )
    assert governance.issue_submission_allowed(
        repo=OTHER_REPO, author="researcher", records=ledger.for_subject(subject, "issue")
    ).allowed


def test_issue_in_own_repo_needs_no_review(governance: Governance) -> None:
    assert governance.issue_submission_allowed(
        repo=SELF_REPO, author="researcher", records=[]
    ).allowed


def test_push_rules(governance: Governance) -> None:
    assert governance.push_allowed(repo=SELF_REPO, branch="feature/x").allowed
    assert not governance.push_allowed(repo=SELF_REPO, branch="main").allowed
    assert not governance.push_allowed(repo=OTHER_REPO, branch="feature/x").allowed


@pytest.mark.parametrize(
    "command",
    [
        "sudo systemctl restart nginx",
        "systemctl restart nginx",
        "systemctl restart",
        "apt remove python3",
        "apt install ripgrep",
        "su - root",
        "/usr/bin/sudo systemctl --user restart saturnin-janitor.timer",
        "bash -c 'sudo systemctl --user restart saturnin-janitor.timer'",
        "sh -c '/usr/bin/doas systemctl --user restart saturnin-janitor.timer'",
        "env sudo systemctl --user restart saturnin-janitor.timer",
        "env /usr/local/bin/pkexec systemctl --user restart saturnin-janitor.timer",
        "systemctl --user --system restart saturnin-janitor.timer",
    ],
)
def test_out_of_scope_server_commands(governance: Governance, command: str) -> None:
    assert not governance.check_server_command(command).allowed


@pytest.mark.parametrize(
    "command",
    [
        "systemctl --user restart saturnin-janitor.timer",
        "systemctl --user status saturnin-improve.service",
        "python3 -m saturnin doctor",
    ],
)
def test_in_scope_server_commands(governance: Governance, command: str) -> None:
    assert governance.check_server_command(command).allowed


def test_server_commands_are_rejected_when_running_as_root(
    governance: Governance, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("saturnin.governance.os.geteuid", lambda: 0)

    decision = governance.check_server_command("python3 -m saturnin doctor")

    assert not decision.allowed
    assert decision.reasons == ["server commands may not run as root"]


def test_apt_requires_a_saturnin_dedicated_service(governance: Governance) -> None:
    assert governance.check_server_command(
        "apt install ripgrep", dedicated_service="saturnin-discovery.service"
    ).allowed
    assert not governance.check_server_command(
        "apt install ripgrep", dedicated_service="unrelated.service"
    ).allowed


def test_escalation_body_must_be_complete(governance: Governance) -> None:
    assert not governance.check_escalation("please help", urgency="normal").allowed
