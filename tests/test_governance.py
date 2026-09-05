from __future__ import annotations

import pytest

from saturnin.config import Config
from saturnin.governance import Governance, _curl_targets
from saturnin.review import ReviewLedger, ReviewError

SELF_REPO = "JakubMifek/saturnin"
OTHER_REPO = "JakubMifek/some-project"
TEST_HEAD_SHA = "abc1234567890"


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
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
    ).allowed

    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="changes_requested",
        head_sha=TEST_HEAD_SHA,
    )
    assert not governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
    ).allowed

    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    assert governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
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
        head_sha=TEST_HEAD_SHA,
    )
    decision = governance.merge_allowed(
        repo=SELF_REPO, author="code-worker", records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
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


def test_review_subjects_are_exact_and_roles_are_valid(config: Config) -> None:
    ledger = ReviewLedger(config)
    first = "owner/repo#1"
    second = "owner-repo-1"
    ledger.record(subject=first, kind="pr", author="code-worker", reviewer="pr-reviewer", verdict="approved")
    ledger.record(subject=second, kind="pr", author="code-worker", reviewer="pr-reviewer", verdict="approved")
    assert {record.subject for record in ledger.for_subject(first, "pr")} == {first}
    assert {record.subject for record in ledger.for_subject(second, "pr")} == {second}

    with pytest.raises(ReviewError, match="unknown reviewer role"):
        ledger.record(subject="x#2", kind="pr", author="code-worker", reviewer="ghost", verdict="approved")


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
        head_sha=TEST_HEAD_SHA,
    )
    decision = governance.merge_allowed(
        repo=OTHER_REPO, author="code-worker", records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
    )
    assert not decision.allowed


def test_issue_submission_requires_review_in_managed_repos(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "draft-improve-ci"
    managed_repo = "JakubMifek/saturnin-ops"
    assert not governance.issue_submission_allowed(
        repo=managed_repo, author="researcher", records=ledger.for_subject(subject, "issue")
    ).allowed
    ledger.record(
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="issue-reviewer",
        verdict="approved",
    )
    assert governance.issue_submission_allowed(
        repo=managed_repo, author="researcher", records=ledger.for_subject(subject, "issue")
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
        "systemctl --user daemon-reload",
        "systemctl --user enable --now saturnin-janitor.timer",
        "curl -o /home/saturnin/response.txt https://example.test/ok",
        "curl --output /home/saturnin/response.txt https://example.test/ok",
        "curl -D /home/saturnin/headers.txt https://example.test/ok",
        "python3 -m saturnin doctor",
    ],
)
def test_in_scope_server_commands(governance: Governance, command: str) -> None:
    assert governance.check_server_command(command).allowed


def test_curl_output_flags_are_parsed() -> None:
    assert _curl_targets([
        "-o",
        "/home/saturnin/response.txt",
        "--output",
        "/home/saturnin/other.txt",
        "-D",
        "/home/saturnin/headers.txt",
        "-O",
        "--silent",
        "https://example.test/download.tar.gz",
        "--remote-name-all",
        "https://example.test/second.tar.gz",
    ]) == [
        "/home/saturnin/response.txt",
        "/home/saturnin/other.txt",
        "/home/saturnin/headers.txt",
        "download.tar.gz",
        "second.tar.gz",
    ]


@pytest.mark.parametrize(
    "command",
    [
        "SATURNIN_HOME=/tmp python3 -m saturnin task add x",
        "env SATURNIN_HOME=/tmp python3 -m saturnin task add x",
    ],
)
def test_shell_assignments_cannot_change_policy_home(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "assignments are not allowed" in decision.reasons[0]


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("rm -rf /etc", "forbidden root"),
        ("touch /usr/local/unsafe", "forbidden root"),
        ("mkdir /var/lib/saturnin", "forbidden root"),
        ("curl -o /etc/headers.txt https://example.test/ok", "forbidden root"),
        ("rm -rf /home/saturnin-other", "outside writable roots"),
        ("rm -- -outside-writable-roots", "outside writable roots"),
        ("cp --target-directory /opt source", "outside writable roots"),
        ("curl --output /opt/response.txt https://example.test/ok", "outside writable roots"),
        ("sed -i s/foo/bar/ /opt/status", "outside writable roots"),
    ],
)
def test_filesystem_writes_outside_policy_are_rejected(
    governance: Governance, command: str, reason: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert reason in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /home/saturnin/worktrees/stale",
        "touch /home/saturnin/status",
        "cp source /home/saturnin/worktrees/destination",
        "sed -i s/foo/bar/ /home/saturnin/status",
    ],
)
def test_filesystem_writes_within_writable_roots_are_allowed(
    governance: Governance, command: str
) -> None:
    assert governance.check_server_command(command).allowed


@pytest.mark.parametrize("binary", ["cp", "install", "ln", "mv", "rsync"])
def test_single_destination_operand_is_checked(
    governance: Governance, binary: str
) -> None:
    decision = governance.check_server_command(f"{binary} /opt/destination")

    assert not decision.allowed
    assert "outside writable roots" in decision.reasons[0]


@pytest.mark.parametrize("binary", ["cp", "install", "ln", "mv", "rsync"])
def test_only_final_operand_is_destination_for_multiple_operands(
    governance: Governance, binary: str
) -> None:
    decision = governance.check_server_command(
        f"{binary} /opt/source /home/saturnin/destination"
    )

    assert decision.allowed


def test_forbidden_roots_override_writable_roots(
    governance: Governance, config: Config
) -> None:
    config.server_scope["filesystem"]["writable_roots"] = ["/"]

    decision = governance.check_server_command("rm -rf /etc")

    assert not decision.allowed
    assert "forbidden root '/etc'" in decision.reasons[0]


def test_forbidden_roots_remain_readable(governance: Governance) -> None:
    decision = governance.check_server_command("cat /etc/passwd")

    assert decision.allowed


@pytest.mark.parametrize(
    "command",
    [
        "true && apt remove python3",
        "! systemctl --user restart saturnin-janitor.timer",
        "time apt install ripgrep",
        "true; xargs apt remove",
        "true | systemctl restart nginx",
        "true > result.txt",
        "cat < input.txt",
        "echo $(apt remove python3)",
        "echo `apt remove python3`",
        "echo ${COMMAND}",
        'exec "$CMD" remove python3',
        "env CMD=apt exec $CMD remove python3",
        "/usr/bin/a* remove python3",
        "a\\\npt remove python3",
        "a\\\r\npt remove python3",
        "su\\\ndo systemctl restart nginx",
    ],
)
def test_top_level_dynamic_shell_syntax_fails_closed(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)
    assert not decision.allowed
    assert "not allowed" in decision.reasons[0]


def test_quoted_shell_metacharacters_are_literal(governance: Governance) -> None:
    assert governance.check_server_command(
        "printf '%s' '&& $HOME > file * {one,two}'"
    ).allowed


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


@pytest.mark.parametrize(
    "command",
    [
        "env nice -n 5 /usr/bin/apt remove ripgrep",
        "env - apt remove ripgrep",
        "env -a harmless apt remove ripgrep",
        "env --argv0 harmless apt remove ripgrep",
        "timeout 10 bash -c 'ionice -c 3 apt remove ripgrep'",
        "stdbuf -oL /usr/bin/systemctl --user restart nginx.service",
        "xargs sh -c 'systemctl --user restart nginx.service'",
        "xargs -I{} apt remove {}",
        "bash -c 'echo ready && /usr/bin/apt remove python3'",
        "bash -c 'exec apt remove python3'",
        "bash -c 'command systemctl --user restart saturnin-janitor.timer'",
        "bash -c '$(printf apt) remove python3'",
        "bash -c 'f(){ apt remove python3; }; f'",
        "/bin/dash -c 'apt remove python3'",
        "/bin/hush -c 'apt remove python3'",
        "/usr/bin/zsh -c 'apt remove python3'",
        "busybox sh -c 'apt remove python3'",
        "/bin/busybox ash -c 'apt remove python3'",
        "toybox sh -c 'apt remove python3'",
        "exec apt remove python3",
        "command systemctl --user restart nginx.service",
    ],
)
def test_wrapped_elevated_commands_remain_restricted(
    governance: Governance, command: str
) -> None:
    assert not governance.check_server_command(
        command, dedicated_service="saturnin-discovery.service"
    ).allowed


def test_wrapped_apt_still_requires_dedicated_service(governance: Governance) -> None:
    assert not governance.check_server_command(
        "env timeout 10 apt install ripgrep"
    ).allowed


@pytest.mark.parametrize(
    "command",
    [
        "env nice -n 5 /usr/bin/apt install ripgrep",
        "env - apt install ripgrep",
        "env -a apt apt install ripgrep",
        "env --argv0=apt apt install ripgrep",
        "env --default-signal= apt install ripgrep",
        "timeout 10 ionice -c 3 apt install ripgrep",
        "stdbuf -oL /usr/bin/systemctl --user restart saturnin-janitor.timer",
        "exec apt install ripgrep",
        "command /usr/bin/systemctl --user status saturnin-improve.service",
        "exec -a apt apt install ripgrep",
        "command -p /usr/bin/systemctl --user status saturnin-improve.service",
        "env printf '%s' -S",
    ],
)
def test_allowed_elevated_commands_survive_nested_wrappers(
    governance: Governance, command: str
) -> None:
    assert governance.check_server_command(
        command, dedicated_service="saturnin-discovery.service"
    ).allowed


@pytest.mark.parametrize(
    "command",
    [
        "env -u",
        "env -",
        "env -a",
        "env --argv0",
        "env --argv0=",
        "env -x apt install ripgrep",
        "env --unknown apt install ripgrep",
        "env -S 'apt install ripgrep'",
        "nice --unknown apt install ripgrep",
        "nice --adjustment",
        "ionice --unknown apt install ripgrep",
        "ionice --class",
        "stdbuf --unknown apt install ripgrep",
        "stdbuf --output",
        "timeout --unknown 10 apt install ripgrep",
        "timeout --signal",
        "exec --unknown apt install ripgrep",
        "exec -a",
        "command --unknown apt install ripgrep",
        "nice -n",
        "stdbuf -oL",
        "timeout 10",
        "xargs",
        "ionice -c 3",
        "bash -c",
        "sh -c 'apt install",
        "sh -c 'echo ok ;'",
        "dash",
        "busybox",
        "toybox",
    ],
)
def test_malformed_wrappers_fail_closed(governance: Governance, command: str) -> None:
    assert not governance.check_server_command(command).allowed


def test_escalation_body_must_be_complete(governance: Governance) -> None:
    assert not governance.check_escalation("please help", urgency="normal").allowed
