from __future__ import annotations

import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from saturnin.config import Config
from saturnin.governance import Governance, _curl_targets, _git_targets
from saturnin.jsonlines import durable_append_text
from saturnin.review import (
    ReviewLedger,
    ReviewError,
    issue_content_digest,
    review_attestation_signing_key,
    sign_review_attestation,
)

SELF_REPO = "JakubMifek/saturnin"
OTHER_REPO = "JakubMifek/some-project"
TEST_HEAD_SHA = "a" * 40


def record_review(ledger: ReviewLedger, **kwargs):
    attestation = sign_review_attestation(
        key=review_attestation_signing_key(ledger.config, kwargs["reviewer"]),
        subject=kwargs["subject"],
        kind=kwargs["kind"],
        author=kwargs["author"],
        reviewer=kwargs["reviewer"],
        verdict=kwargs["verdict"],
        zero_context=kwargs.get("zero_context", True),
        head_sha=kwargs.get("head_sha", ""),
        issue_digest=kwargs.get("issue_digest", ""),
    )
    return ledger.record(attestation=attestation, **kwargs)


@pytest.fixture()
def governance(config: Config) -> Governance:
    return Governance(config)


def test_policies_audit_clean(governance: Governance) -> None:
    assert governance.audit() == []


@pytest.mark.parametrize(
    ("setting", "value", "problem"),
    [
        ("github_reviewer_logins", [], "non-empty list of GitHub reviewer logins"),
        ("allowed_reviewer_roles", [1], "non-empty list of reviewer roles"),
    ],
)
def test_audit_rejects_unusable_pr_reviewer_policy(
    config: Config, setting: str, value: object, problem: str
) -> None:
    config.governance["review"]["pr"][setting] = value

    assert any(problem in item for item in Governance(config).audit())


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

    record_review(ledger,
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

    record_review(ledger,
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


def test_dismissed_review_blocks_merge(governance: Governance, config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#dismissed"
    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="dismissed",
        head_sha=TEST_HEAD_SHA,
    )
    decision = governance.merge_allowed(
        repo=SELF_REPO,
        author="code-worker",
        records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
    )
    assert not decision.allowed
    assert "dismissed" in decision.reasons[0]


def test_unauthorized_reviewer_cannot_veto_pr(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#unauthorized-veto"
    record_review(
        ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    record_review(
        ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="issue-reviewer",
        verdict="changes_requested",
        head_sha=TEST_HEAD_SHA,
    )

    decision = governance.merge_allowed(
        repo=SELF_REPO,
        author="code-worker",
        records=ledger.for_subject(subject, "pr"),
        head_sha=TEST_HEAD_SHA,
    )

    assert decision.allowed


def test_reviewer_with_context_does_not_satisfy_gate(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#8"
    record_review(ledger,
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
        record_review(ledger,
            subject="x#1",
            kind="pr",
            author="code-worker",
            reviewer="code-worker",
            verdict="approved",
        )


def test_review_record_requires_valid_signed_attestation(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#signed"
    attestation = sign_review_attestation(
        key=review_attestation_signing_key(config, "pr-reviewer"),
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    forged = attestation.replace("code-worker", "chief-of-staff")

    with pytest.raises(ReviewError, match="signature does not match"):
        ledger.record(
            subject=subject,
            kind="pr",
            author="chief-of-staff",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=TEST_HEAD_SHA,
            attestation=forged,
        )

    ledger.record(
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
        attestation=attestation,
    )
    with pytest.raises(ReviewError, match="already been recorded"):
        ledger.record(
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=TEST_HEAD_SHA,
            attestation=attestation,
        )


def test_attestation_key_is_scoped_to_reviewer_role(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#role-scoped"
    pr_reviewer_key = review_attestation_signing_key(config, "pr-reviewer")
    forged = sign_review_attestation(
        key=pr_reviewer_key,
        subject=subject,
        kind="issue",
        author="code-worker",
        reviewer="issue-reviewer",
        verdict="approved",
        issue_digest="b" * 64,
    )

    with pytest.raises(ReviewError, match="signature does not match"):
        ledger.record(
            subject=subject,
            kind="issue",
            author="code-worker",
            reviewer="issue-reviewer",
            verdict="approved",
            issue_digest="b" * 64,
            attestation=forged,
        )


def test_role_scoped_attestation_verification_rejects_cross_role_impersonation(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#role-impersonation"
    issue_key = review_attestation_signing_key(config, "issue-reviewer")
    forged = sign_review_attestation(
        key=issue_key,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    monkeypatch.setenv("SATURNIN_REVIEW_ATTESTATION_KEY", issue_key)
    monkeypatch.setenv("SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE", "role")
    monkeypatch.setenv("SATURNIN_AGENT_ROLE", "issue-reviewer")

    with pytest.raises(ReviewError, match="may not verify reviewer pr-reviewer"):
        ledger.record(
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha=TEST_HEAD_SHA,
            attestation=forged,
        )


def test_role_scoped_attestation_signing_requires_agent_role(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE", "role")
    monkeypatch.delenv("SATURNIN_AGENT_ROLE", raising=False)

    with pytest.raises(ReviewError, match="SATURNIN_AGENT_ROLE is required"):
        review_attestation_signing_key(config, "pr-reviewer")


def test_review_gate_rejects_tampered_attestation(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#tampered"
    record = record_review(
        ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    path = next(ledger.dir.glob("*.jsonl"))
    data = record.to_dict()
    data["author"] = "chief-of-staff"
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")

    with pytest.raises(ReviewError, match="invalid review attestation"):
        ledger.for_subject(subject, "pr")


def test_review_subjects_are_exact_and_roles_are_valid(config: Config) -> None:
    ledger = ReviewLedger(config)
    first = "owner/repo#1"
    second = "owner-repo-1"
    record_review(ledger,
        subject=first,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    record_review(ledger,
        subject=second,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    assert {record.subject for record in ledger.for_subject(first, "pr")} == {first}
    assert {record.subject for record in ledger.for_subject(second, "pr")} == {second}

    with pytest.raises(ReviewError, match="unknown reviewer role"):
        record_review(ledger,
            subject="x#2",
            kind="pr",
            author="code-worker",
            reviewer="ghost",
            verdict="approved",
            head_sha=TEST_HEAD_SHA,
        )


def test_pr_review_requires_head_sha(config: Config) -> None:
    with pytest.raises(ReviewError, match="--head-sha"):
        ReviewLedger(config).record(
            subject="owner/repo#2",
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
        )


def test_pr_review_requires_a_full_commit_sha(config: Config) -> None:
    with pytest.raises(ReviewError, match="40-character"):
        ReviewLedger(config).record(
            subject="owner/repo#2",
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            head_sha="abc123",
        )


def test_issue_review_requires_sha256_issue_digest(config: Config) -> None:
    with pytest.raises(ReviewError, match="64-character"):
        ReviewLedger(config).record(
            subject="owner/repo#2",
            kind="issue",
            author="code-worker",
            reviewer="issue-reviewer",
            verdict="approved",
            issue_digest="not-a-digest",
        )


def test_python_allowlist_is_limited_to_configured_modules(
    governance: Governance, config: Config
) -> None:
    filesystem = config.server_scope["filesystem"]

    assert "python3" not in filesystem["executable_allowlist"]
    assert filesystem["python_module_allowlist"] == ["saturnin"]
    assert governance.check_server_command("python3 -m saturnin doctor").allowed
    assert not governance.check_server_command(
        "python3 -c 'open(\"/home/saturnin/out\", \"w\")'"
    ).allowed


def test_corrupt_review_ledger_reports_file_and_line(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#corrupt"
    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    path = next(ledger.dir.glob("*.jsonl"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")

    with pytest.raises(ReviewError, match=rf"{path} at line 2"):
        ledger.for_subject(subject, "pr")
    with pytest.raises(ReviewError, match=rf"{path} at line 2"):
        list(ledger)


def test_review_ledger_recovers_from_unterminated_tail(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#interrupted"
    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    path = next(ledger.dir.glob("*.jsonl"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            '{"subject":"'
            + subject
            + '","kind":"pr","verdict":"changes_requested"'
        )

    with pytest.raises(ReviewError, match=r"corrupt review ledger .* at line 2"):
        ledger.for_subject(subject, "pr")
    replacements: list[tuple[Path, Path]] = []
    original_replace = os.replace

    def tracked_replace(source: Path, destination: Path) -> None:
        replacements.append((Path(source), Path(destination)))
        original_replace(source, destination)

    monkeypatch.setattr("saturnin.jsonlines.os.replace", tracked_replace)
    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="changes_requested",
        head_sha=TEST_HEAD_SHA,
    )
    assert ledger.for_subject(subject, "pr")[0].verdict == "changes_requested"
    assert replacements and replacements[0][1] == path
    assert replacements[0][0].parent == path.parent


def test_review_record_validates_entry_before_append(config: Config) -> None:
    ledger = ReviewLedger(config)

    with pytest.raises(ReviewError, match="zero_context.*(boolean|wrong type)"):
        record_review(ledger,
            subject="JakubMifek/saturnin#invalid-write",
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="approved",
            zero_context="true",
            head_sha=TEST_HEAD_SHA,
        )

    assert list(ledger.dir.glob("*.jsonl")) == []


def test_review_ledger_preserves_complete_unterminated_record(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#complete-tail"
    first = record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    path = next(ledger.dir.glob("*.jsonl"))
    path.write_text(
        json.dumps(first.to_dict()) + "\n" + json.dumps(first.to_dict()),
        encoding="utf-8",
    )

    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="changes_requested",
        head_sha=TEST_HEAD_SHA,
    )

    assert [record.verdict for record in ledger] == [
        "approved",
        "approved",
        "changes_requested",
    ]


@pytest.mark.parametrize("payload", ["not-json\n", "[]\n", "{}\nnot-json\n"])
def test_review_ledger_rejects_terminated_malformed_records(
    config: Config, payload: str
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#malformed"
    record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    path = next(ledger.dir.glob("*.jsonl"))
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ReviewError, match=r"corrupt review ledger .* at line"):
        list(ledger)
    with pytest.raises(ReviewError, match=r"corrupt review ledger .* at line"):
        record_review(ledger,
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="changes_requested",
            head_sha=TEST_HEAD_SHA,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject", 7),
        ("kind", "pull_request"),
        ("verdict", "allow"),
        ("zero_context", "false"),
        ("head_sha", "a" * 39),
        ("issue_digest", "not-a-digest"),
        ("notes", []),
        ("created_at", "yesterday"),
        ("created_at", "2026-09-13T17:00:00"),
    ],
)
def test_review_ledger_rejects_invalid_record_values_before_gate(
    config: Config, field: str, value: object
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#invalid-values"
    record = record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    data = record.to_dict()
    data[field] = value
    path = next(ledger.dir.glob("*.jsonl"))
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")

    with pytest.raises(ReviewError, match=r"corrupt review ledger .* at line 1"):
        ledger.for_subject(subject, "pr")
    with pytest.raises(ReviewError, match=r"corrupt review ledger .* at line 1"):
        record_review(ledger,
            subject=subject,
            kind="pr",
            author="code-worker",
            reviewer="pr-reviewer",
            verdict="changes_requested",
            head_sha=TEST_HEAD_SHA,
        )


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_review_ledger_rejects_invalid_record_shape(
    config: Config, mutation: str
) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#invalid-shape"
    record = record_review(ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    data = record.to_dict()
    if mutation == "missing":
        del data["zero_context"]
    else:
        data["zeroContext"] = True
    path = next(ledger.dir.glob("*.jsonl"))
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")

    with pytest.raises(ReviewError, match=r"corrupt review ledger .* at line 1"):
        ledger.for_subject(subject, "pr")


def test_review_ledger_serializes_concurrent_records(config: Config) -> None:
    ledger = ReviewLedger(config)
    subject = "JakubMifek/saturnin#concurrent"

    def record(index: int) -> None:
        record_review(ledger,
            subject=subject,
            kind="pr",
            author="chief-of-staff",
            reviewer="code-worker" if index % 2 else "test-worker",
            verdict="approved",
            zero_context=False,
            head_sha=TEST_HEAD_SHA,
            notes=str(index),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, range(32)))

    assert len(list(ledger)) == 32


def test_review_ledger_normal_append_uses_durable_append(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = ReviewLedger(config)
    appended: list[Path] = []

    def tracked_append(path: Path, text: str) -> None:
        durable_append_text(path, text)
        appended.append(path)

    monkeypatch.setattr("saturnin.review.durable_append_text", tracked_append)

    record_review(
        ledger,
        subject="JakubMifek/saturnin#durable-append",
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )

    assert appended == [next(ledger.dir.glob("*.jsonl"))]


def test_merge_in_managed_repo_is_never_autonomous(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = f"{OTHER_REPO}#3"
    record_review(ledger,
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
    digest = issue_content_digest("Improve CI", "Add the missing gate.")
    assert not governance.issue_submission_allowed(
        repo=managed_repo,
        author="researcher",
        records=ledger.for_subject(subject, "issue"),
        issue_digest=digest,
    ).allowed
    record_review(ledger,
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="issue-reviewer",
        verdict="approved",
        issue_digest=digest,
    )
    assert governance.issue_submission_allowed(
        repo=managed_repo,
        author="researcher",
        records=ledger.for_subject(subject, "issue"),
        issue_digest=digest,
    ).allowed


def test_unauthorized_reviewer_cannot_veto_issue(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "draft-unauthorized-veto"
    managed_repo = "JakubMifek/saturnin-ops"
    digest = issue_content_digest("Improve CI", "Add the missing gate.")
    record_review(
        ledger,
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="issue-reviewer",
        verdict="approved",
        issue_digest=digest,
    )
    record_review(
        ledger,
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="pr-reviewer",
        verdict="rejected",
        issue_digest=digest,
    )

    decision = governance.issue_submission_allowed(
        repo=managed_repo,
        author="researcher",
        records=ledger.for_subject(subject, "issue"),
        issue_digest=digest,
    )

    assert decision.allowed


def test_issue_review_is_bound_to_the_reviewed_draft(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "draft-changing"
    managed_repo = "JakubMifek/saturnin-ops"
    reviewed = issue_content_digest("Original", "Reviewed body")
    changed = issue_content_digest("Original", "Changed body")
    record_review(ledger,
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="issue-reviewer",
        verdict="approved",
        issue_digest=reviewed,
    )

    missing = governance.issue_submission_allowed(
        repo=managed_repo,
        author="researcher",
        records=ledger.for_subject(subject, "issue"),
    )
    changed_decision = governance.issue_submission_allowed(
        repo=managed_repo,
        author="researcher",
        records=ledger.for_subject(subject, "issue"),
        issue_digest=changed,
    )

    assert not missing.allowed
    assert "issue_digest is required" in missing.reasons[0]
    assert not changed_decision.allowed
    assert "current issue-content digest" in changed_decision.reasons[0]


def test_issue_in_own_repo_needs_no_review(governance: Governance) -> None:
    assert governance.issue_submission_allowed(
        repo=SELF_REPO, author="researcher", records=[]
    ).allowed


def test_github_repository_matching_is_case_insensitive(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = f"{SELF_REPO}#case"
    record_review(
        ledger,
        subject=subject,
        kind="pr",
        author="code-worker",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=TEST_HEAD_SHA,
    )
    records = ledger.for_subject(subject, "pr")

    assert governance.merge_allowed(
        repo=SELF_REPO.lower(),
        author="code-worker",
        records=records,
        head_sha=TEST_HEAD_SHA,
    ).allowed
    assert governance.issue_submission_allowed(
        repo=SELF_REPO.upper(), author="researcher", records=[]
    ).allowed
    assert governance.push_allowed(
        repo=SELF_REPO.swapcase(), branch="feature/case"
    ).allowed


def test_managed_repository_issue_matching_is_case_insensitive(
    governance: Governance, config: Config
) -> None:
    ledger = ReviewLedger(config)
    subject = "draft-case-insensitive-repo"
    digest = issue_content_digest("Improve CI", "Add the missing gate.")
    record_review(
        ledger,
        subject=subject,
        kind="issue",
        author="researcher",
        reviewer="issue-reviewer",
        verdict="approved",
        issue_digest=digest,
    )

    assert governance.issue_submission_allowed(
        repo="jakubmifek/SATURNIN-OPS",
        author="researcher",
        records=ledger.for_subject(subject, "issue"),
        issue_digest=digest,
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
        "journalctl -u saturnin-janitor.service -n 100",
        "journalctl --user -u nginx.service -n 100",
        "journalctl --user --system -u saturnin-janitor.service",
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
        "systemctl --user list-timers --all",
        "systemctl --user status --failed saturnin-improve.service",
        "journalctl --user -u saturnin-janitor.service -n 100",
        "curl -q -o /home/saturnin/response.txt https://example.test/ok",
        "curl -q --output /home/saturnin/response.txt https://example.test/ok",
        "curl -q --output-dir /home/saturnin https://example.test/ok",
        "curl -q -D /home/saturnin/headers.txt https://example.test/ok",
        "python3 -m saturnin doctor",
    ],
)
def test_in_scope_server_commands(governance: Governance, command: str) -> None:
    assert governance.check_server_command(command).allowed


def test_bootstrap_runtime_saturnin_executable_is_trusted(
    governance: Governance,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = config.data_root / ".venv" / "bin"
    runtime.mkdir(parents=True)
    executable = runtime / "saturnin"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", f"{runtime}:{os.environ['PATH']}")

    assert governance.check_server_command("saturnin doctor").allowed
    assert governance.check_server_command(f"{executable} doctor").allowed


def test_worktree_saturnin_executable_cannot_spoof_trusted_runtime(
    governance: Governance,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = config.data_root / ".venv" / "bin"
    runtime.mkdir(parents=True)
    trusted = runtime / "saturnin"
    trusted.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    trusted.chmod(0o755)
    worktree_bin = config.root / "var" / "worktrees" / "spoof" / ".venv" / "bin"
    worktree_bin.mkdir(parents=True)
    spoof = worktree_bin / "saturnin"
    spoof.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    spoof.chmod(0o755)
    monkeypatch.setenv("PATH", f"{worktree_bin}:{runtime}:{os.environ['PATH']}")

    decision = governance.check_server_command("saturnin doctor")

    assert not decision.allowed
    assert str(spoof) in decision.reasons[0]


def test_trusted_runtime_executable_must_not_be_a_symlink(
    governance: Governance,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = config.data_root / ".venv" / "bin"
    runtime.mkdir(parents=True)
    outside = config.root / "spoofed-saturnin"
    outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    outside.chmod(0o755)
    (runtime / "saturnin").symlink_to(outside)
    monkeypatch.setenv("PATH", f"{runtime}:{os.environ['PATH']}")

    decision = governance.check_server_command("saturnin doctor")

    assert not decision.allowed
    assert "must not be a symlink" in decision.reasons[0]


@pytest.mark.parametrize(
    "runtime",
    [None, "", "/opt/saturnin", "../bin/saturnin", ".venv/bin/not-saturnin"],
)
def test_audit_rejects_invalid_trusted_runtime_executable(
    config: Config, runtime: object
) -> None:
    config.server_scope["filesystem"]["trusted_runtime_executable"] = runtime

    assert any("trusted_runtime_executable" in problem for problem in Governance(config).audit())


@pytest.mark.parametrize("binary", ["git", "systemctl", "rm", "env"])
def test_path_resolved_classified_executables_must_come_from_trusted_roots(
    governance: Governance,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    binary: str,
) -> None:
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    fake = fake_bin / binary
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")

    decision = governance.check_server_command(f"{binary} status")

    assert not decision.allowed
    assert str(fake) in decision.reasons[0]
    assert "outside trusted system executable roots" in decision.reasons[0]


def test_path_qualified_allowlisted_executable_is_not_classified_by_basename(
    governance: Governance,
    config: Config,
) -> None:
    fake = config.root / "git"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)

    decision = governance.check_server_command(f"{fake} status")

    assert not decision.allowed
    assert str(fake) in decision.reasons[0]
    assert "outside trusted system executable roots" in decision.reasons[0]


def test_path_qualified_classified_executable_must_exist(
    governance: Governance,
    config: Config,
) -> None:
    trusted = config.root / "trusted-bin"
    trusted.mkdir()
    config.server_scope["filesystem"]["trusted_executable_roots"] = [str(trusted)]
    missing = trusted / "git"

    decision = governance.check_server_command(f"{missing} status")

    assert not decision.allowed
    assert "does not resolve to an existing file" in decision.reasons[0]


@pytest.mark.parametrize("kind", ["directory", "non-executable"])
def test_path_qualified_classified_executable_must_be_executable_regular_file(
    governance: Governance,
    config: Config,
    kind: str,
) -> None:
    trusted = config.root / "trusted-bin"
    trusted.mkdir()
    fake = trusted / "git"
    if kind == "directory":
        fake.mkdir()
    else:
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o644)
    config.server_scope["filesystem"]["trusted_executable_roots"] = [str(trusted)]

    decision = governance.check_server_command(f"{fake} status")

    assert not decision.allowed
    expected = "not a regular file" if kind == "directory" else "not executable"
    assert expected in decision.reasons[0]


def test_symlink_in_trusted_root_cannot_authorize_outside_executable(
    governance: Governance,
    config: Config,
) -> None:
    trusted = config.root / "trusted-bin"
    trusted.mkdir()
    outside = config.root / "outside-git"
    outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    outside.chmod(0o755)
    fake = trusted / "git"
    fake.symlink_to(outside)
    config.server_scope["filesystem"]["trusted_executable_roots"] = [str(trusted)]

    decision = governance.check_server_command(f"{fake} status")

    assert not decision.allowed
    assert str(outside) in decision.reasons[0]
    assert "outside trusted system executable roots" in decision.reasons[0]


@pytest.mark.parametrize("path_qualified", [False, True])
def test_executable_selected_outside_trusted_roots_cannot_gain_a_trusted_basename(
    governance: Governance,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    path_qualified: bool,
) -> None:
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    fake = fake_bin / "git"
    system_git = shutil.which("git")
    assert system_git is not None
    fake.symlink_to(Path(system_git).resolve())
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    executable = str(fake) if path_qualified else "git"

    decision = governance.check_server_command(f"{executable} status")

    assert not decision.allowed
    assert str(fake) in decision.reasons[0]
    assert "outside trusted system executable roots" in decision.reasons[0]


@pytest.mark.parametrize("binary", ["sudo", "su", "doas", "pkexec"])
def test_path_qualified_privilege_tools_are_location_checked_before_basename_denial(
    governance: Governance,
    config: Config,
    binary: str,
) -> None:
    fake = config.root / binary
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)

    decision = governance.check_server_command(f"{fake} true")

    assert not decision.allowed
    assert str(fake) in decision.reasons[0]
    assert "outside trusted system executable roots" in decision.reasons[0]


@pytest.mark.parametrize("binary", ["git", "systemctl", "saturnin"])
def test_unresolvable_classified_executables_fail_closed(
    governance: Governance,
    monkeypatch: pytest.MonkeyPatch,
    binary: str,
) -> None:
    monkeypatch.setattr("saturnin.governance.shutil.which", lambda _: None)

    decision = governance.check_server_command(f"{binary} status")

    assert not decision.allowed
    assert f"classified executable {binary!r} could not be resolved from PATH" in (
        decision.reasons[0]
    )


@pytest.mark.parametrize(
    "roots",
    [
        "/usr/bin",
        {"bin": "/usr/bin"},
        [],
        ["/usr/bin", ""],
        ["/usr/bin", "relative/bin"],
        ["/usr/bin", "~/bin"],
    ],
)
def test_invalid_trusted_executable_roots_fail_closed(
    governance: Governance,
    config: Config,
    roots: object,
) -> None:
    config.server_scope["filesystem"]["trusted_executable_roots"] = roots

    decision = governance.check_server_command("/usr/bin/git status")

    assert not decision.allowed
    assert "invalid executable trust policy" in decision.reasons[0]


def test_curl_output_flags_are_parsed() -> None:
    assert _curl_targets([
        "-q",
        "-o",
        "/home/saturnin/response.txt",
        "--output",
        "/home/saturnin/other.txt",
        "--output-dir",
        "/home/saturnin/downloads",
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
        "/home/saturnin/downloads",
        "/home/saturnin/headers.txt",
        "/home/saturnin/downloads/download.tar.gz",
        "/home/saturnin/downloads/second.tar.gz",
    ]


def test_curl_output_dir_applies_even_when_url_comes_first() -> None:
    assert _curl_targets([
        "-q",
        "-O",
        "https://example.test/download.tar.gz",
        "--output-dir",
        "/home/saturnin/downloads",
    ]) == [
        "/home/saturnin/downloads/download.tar.gz",
        "/home/saturnin/downloads",
    ]


def test_curl_cookie_and_trace_outputs_are_checked() -> None:
    assert _curl_targets([
        "-q",
        "--cookie-jar",
        "/home/saturnin/cookies.txt",
        "--trace=/home/saturnin/trace.log",
        "--trace-ascii",
        "/home/saturnin/trace-ascii.log",
        "https://example.test/ok",
    ]) == [
        "/home/saturnin/cookies.txt",
        "/home/saturnin/trace.log",
        "/home/saturnin/trace-ascii.log",
    ]


@pytest.mark.parametrize(
    "command",
    [
        "curl data:,ok",
        "curl -s -q data:,ok",
        "curl -sq data:,ok",
    ],
)
def test_curl_requires_config_suppression_as_first_argument(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "first argument" in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "curl -q data:,ok",
        "curl --disable data:,ok",
        "curl -qO https://example.test/file --output-dir /home/saturnin",
    ],
)
def test_curl_accepts_leading_config_suppression(
    governance: Governance, command: str
) -> None:
    assert governance.check_server_command(command).allowed


@pytest.mark.parametrize(
    "option",
    ["--stderr", "--etag-save", "--libcurl", "--alt-svc", "--hsts"],
)
def test_curl_long_file_options_are_scope_checked(
    governance: Governance, option: str
) -> None:
    denied = governance.check_server_command(f"curl -q {option} /etc/curl-state data:,ok")
    allowed = governance.check_server_command(
        f"curl -q {option} /home/saturnin/curl-state data:,ok"
    )

    assert not denied.allowed
    assert "forbidden root" in denied.reasons[0]
    assert allowed.allowed


@pytest.mark.parametrize(
    "option",
    [
        "'-w%output{/etc/curl-report}'",
        "'-sw%output{/etc/curl-report}'",
        "'--write-out=%output{/etc/curl-report}'",
        "--write-out '%output{/etc/curl-report}'",
    ],
)
def test_curl_write_out_destinations_are_scope_checked(
    governance: Governance, option: str
) -> None:
    decision = governance.check_server_command(f"curl -q {option} data:,ok")

    assert not decision.allowed
    assert "forbidden root" in decision.reasons[0]


@pytest.mark.parametrize(
    "option",
    [
        "'-w%output{/home/saturnin/curl-report}'",
        "'-sw%output{/home/saturnin/curl-report}'",
        "'--write-out=%output{/home/saturnin/curl-report}'",
    ],
)
def test_curl_write_out_destinations_within_scope_are_allowed(
    governance: Governance, option: str
) -> None:
    assert governance.check_server_command(f"curl -q {option} data:,ok").allowed


def test_curl_odd_percent_run_keeps_write_out_directive_active(
    governance: Governance,
) -> None:
    decision = governance.check_server_command(
        "curl -q '-w%%%output{/tmp/file}' data:,ok"
    )

    assert not decision.allowed
    assert "outside writable roots" in decision.reasons[0]


@pytest.mark.parametrize(
    "format_string",
    [
        "%%",
        "%%output{/tmp/file}",
        "%%%%output{/tmp/file}",
        "%{http_code}",
    ],
)
def test_curl_even_percent_runs_and_variables_do_not_open_output_files(
    governance: Governance, format_string: str
) -> None:
    assert governance.check_server_command(
        f"curl -q '-w{format_string}' data:,ok"
    ).allowed


@pytest.mark.parametrize("format_string", ["%output{}", "%output{/tmp/file"])
def test_curl_malformed_write_out_directives_fail_closed(
    governance: Governance, format_string: str
) -> None:
    decision = governance.check_server_command(
        f"curl -q '-w{format_string}' data:,ok"
    )

    assert not decision.allowed
    assert "curl --write-out %output" in decision.reasons[0]


@pytest.mark.parametrize(
    "option",
    [
        "-w @file",
        "-w@file",
        "-sw@file",
        "--write-out @-",
        "--write-out=@file",
    ],
)
def test_curl_external_write_out_formats_fail_closed(
    governance: Governance, option: str
) -> None:
    decision = governance.check_server_command(f"curl -q {option} data:,ok")

    assert not decision.allowed
    assert "external curl --write-out formats are unsupported" in decision.reasons[0]


def test_curl_literal_write_out_format_remains_allowed(
    governance: Governance,
) -> None:
    assert governance.check_server_command(
        "curl -q -w '%{http_code}' data:,ok"
    ).allowed


@pytest.mark.parametrize(
    ("argument", "target"),
    [
        ("-o/etc/response", "/etc/response"),
        ("-D/etc/headers", "/etc/headers"),
        ("-c/etc/cookies", "/etc/cookies"),
        ("-so/etc/response", "/etc/response"),
        ("-sD/etc/headers", "/etc/headers"),
        ("-sc/etc/cookies", "/etc/cookies"),
    ],
)
def test_curl_attached_short_output_options_are_parsed(
    argument: str, target: str
) -> None:
    assert _curl_targets(["-q", argument, "https://example.test/ok"]) == [target]


@pytest.mark.parametrize(
    "option", ["-K/etc/curlrc", "-sK/etc/curlrc", "-OsK/etc/curlrc"]
)
def test_curl_attached_short_config_is_rejected(
    governance: Governance, option: str
) -> None:
    decision = governance.check_server_command(f"curl -q {option} data:,ok")

    assert not decision.allowed
    assert "unsupported curl option '--config'" in decision.reasons[0]


@pytest.mark.parametrize(
    ("option", "target"),
    [
        ("-OD/etc/headers", "/etc/headers"),
        ("-Oo/etc/body", "/etc/body"),
    ],
)
def test_curl_write_options_after_bundled_remote_name_are_parsed(
    option: str, target: str
) -> None:
    assert target in _curl_targets(["-q", option, "data:,ok"])


@pytest.mark.parametrize("option", ["-OD/etc/headers", "-Oo/etc/body"])
def test_curl_write_options_after_bundled_remote_name_are_rejected(
    governance: Governance, option: str
) -> None:
    decision = governance.check_server_command(f"curl -q {option} data:,ok")

    assert not decision.allowed
    assert "forbidden root" in decision.reasons[0]


def test_curl_bundled_remote_name_uses_output_directory() -> None:
    assert _curl_targets([
        "-q",
        "-sO",
        "https://example.test/download.tar.gz",
        "--output-dir",
        "/home/saturnin/downloads",
    ]) == [
        "/home/saturnin/downloads/download.tar.gz",
        "/home/saturnin/downloads",
    ]


@pytest.mark.parametrize("next_option", ["--next", "-:", "-s:"])
def test_curl_output_dir_resets_between_operations(next_option: str) -> None:
    assert _curl_targets([
        "-q",
        "-O",
        "https://example.test/first.tar.gz",
        "--output-dir",
        "/home/saturnin/downloads",
        next_option,
        "-O",
        "https://example.test/second.tar.gz",
    ]) == [
        "/home/saturnin/downloads/first.tar.gz",
        "/home/saturnin/downloads",
        "second.tar.gz",
    ]


@pytest.mark.parametrize("next_option", ["--next", "-:", "-s:"])
def test_curl_remote_name_requires_output_dir_in_each_operation(
    governance: Governance, next_option: str
) -> None:
    decision = governance.check_server_command(
        "curl -q -O https://example.test/first.tar.gz "
        f"--output-dir /home/saturnin/downloads {next_option} "
        "-O https://example.test/second.tar.gz"
    )

    assert not decision.allowed
    assert "outside writable roots" in decision.reasons[0]


@pytest.mark.parametrize("next_option", ["--next", "-:", "-s:"])
def test_curl_each_operation_can_set_a_valid_output_dir(
    governance: Governance, next_option: str
) -> None:
    decision = governance.check_server_command(
        "curl -q -O https://example.test/first.tar.gz "
        f"--output-dir /home/saturnin/first {next_option} "
        "-O https://example.test/second.tar.gz "
        "--output-dir /home/saturnin/second"
    )

    assert decision.allowed


def test_curl_flags_after_bundled_short_next_apply_to_new_operation(
    governance: Governance,
) -> None:
    decision = governance.check_server_command(
        "curl -q -O https://example.test/first.tar.gz "
        "--output-dir /home/saturnin/first "
        "-s:O https://example.test/second.tar.gz "
        "--output-dir /home/saturnin/second"
    )

    assert decision.allowed


def test_curl_bundled_remote_name_outside_writable_root_is_rejected(
    governance: Governance,
) -> None:
    decision = governance.check_server_command(
        "curl -q -sO https://example.test/download.tar.gz"
    )

    assert not decision.allowed
    assert "outside writable roots" in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "curl -q --config /tmp/curlrc https://example.test/ok",
        "curl -q --config=/tmp/curlrc https://example.test/ok",
    ],
)
def test_curl_config_is_rejected(governance: Governance, command: str) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "unsupported curl option '--config'" in decision.reasons[0]


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
        ("curl -q -o /etc/headers.txt https://example.test/ok", "forbidden root"),
        ("curl -q -o/etc/response https://example.test/ok", "forbidden root"),
        ("curl -q -D/etc/headers https://example.test/ok", "forbidden root"),
        ("curl -q -c/etc/cookies https://example.test/ok", "forbidden root"),
        ("curl -q -so/etc/response data:,ok", "forbidden root"),
        ("curl -q -sD/etc/headers data:,ok", "forbidden root"),
        ("curl -q -sc/etc/cookies data:,ok", "forbidden root"),
        ("curl -q --output-dir /opt https://example.test/ok", "outside writable roots"),
        ("rm -rf /home/saturnin-other", "outside writable roots"),
        ("rm -- -outside-writable-roots", "outside writable roots"),
        ("cp --target-directory /opt source", "outside writable roots"),
        ("curl -q --output /opt/response.txt https://example.test/ok", "outside writable roots"),
        ("sed -i s/foo/bar/ /opt/status", "outside writable roots"),
        ("python3 -m saturnin --home /tmp task add x", "outside writable roots"),
        ("git -C /tmp init", "outside writable roots"),
        ("git --git-dir=/tmp/repo.git status", "outside writable roots"),
        ("git --work-tree /tmp/repo checkout -- file", "outside writable roots"),
        ("git init /tmp/repo", "outside writable roots"),
        ("git worktree add /tmp/worktree feature/test", "outside writable roots"),
        ("git worktree add -b feature/test /tmp/worktree", "outside writable roots"),
        ("git diff --output=/etc/result HEAD", "outside writable roots"),
        ("git diff --output /opt/result HEAD", "outside writable roots"),
        ("find /tmp/job -delete", "outside writable roots"),
        ("find /home/saturnin -fprint /opt/results", "outside writable roots"),
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
        "find /tmp/job -exec rm ITEM +",
        "find /home/saturnin -execdir ./cleanup ITEM +",
    ],
)
def test_find_exec_actions_fail_closed(governance: Governance, command: str) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "unsupported find action" in decision.reasons[0]


@pytest.mark.parametrize(
    ("arguments", "target"),
    [
        (["-C", "/tmp", "init"], "/tmp"),
        (["--git-dir=/tmp/repo.git", "status"], "/tmp/repo.git"),
        (["--work-tree", "/tmp/repo", "checkout", "--", "file"], "/tmp/repo"),
        (["init", "/tmp/repo"], "/tmp/repo"),
        (["worktree", "add", "/tmp/worktree", "feature/test"], "/tmp/worktree"),
        (
            ["worktree", "add", "-b", "feature/test", "--lock", "/tmp/worktree"],
            "/tmp/worktree",
        ),
        (
            ["worktree", "add", "--reason=review-fix", "/tmp/worktree", "HEAD"],
            "/tmp/worktree",
        ),
    ],
)
def test_git_control_paths_and_mutation_destinations_are_write_targets(
    arguments: list[str], target: str
) -> None:
    assert target in _git_targets(arguments)


@pytest.mark.parametrize(
    ("arguments", "target"),
    [
        (["diff", "--output=/etc/result", "HEAD"], "/etc/result"),
        (["diff", "--output", "/opt/result", "HEAD"], "/opt/result"),
    ],
)
def test_git_write_bearing_options_are_write_targets(
    arguments: list[str], target: str
) -> None:
    assert target in _git_targets(arguments)


@pytest.mark.parametrize(
    "command",
    [
        "git clone ext::sh -c id /home/saturnin/worktrees/repo",
        "git fetch origin main",
        "git pull origin main",
        "git push origin HEAD:main",
        "git remote update",
        "git remote show origin",
        "git clone --upload-pack=/bin/sh https://example.test/repo.git repo",
        "git push --receive-pack=/bin/sh origin HEAD",
    ],
)
def test_git_network_subcommands_require_governed_wrappers(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "governed wrapper" in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "cp source /etc/target --suffix .bak",
        "mv source /etc/target --suffix .bak",
        "install source /etc/target --mode 600",
        "ln source /etc/target --suffix .bak",
        "rsync source /etc/target --suffix .bak",
    ],
)
def test_destination_commands_reject_options_after_operands(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "option after operands" in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "git -c alias.pwn='!touch /etc/out' pwn",
        "git -calias.pwn='!touch /etc/out' pwn",
    ],
)
def test_git_configuration_overrides_fail_closed(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "configuration overrides are unsupported" in decision.reasons[0]


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("git config alias.pwn '!touch /etc/out'", "git config is unsupported"),
        ("git pwn", "unsupported git subcommand"),
        ("git --exec-path=/home/saturnin/helpers status", "executable dispatch options"),
        ("git --config-env=alias.pwn=GIT_ALIAS pwn", "configuration overrides"),
    ],
)
def test_git_executable_dispatch_fails_closed(
    governance: Governance, command: str, reason: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert reason in decision.reasons[0]


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        (
            "git worktree add --porcelain /home/saturnin/worktrees/test",
            "unsupported git worktree add option",
        ),
        ("git worktree add -b", "requires a value"),
        ("git worktree add --lock", "requires an explicit destination"),
    ],
)
def test_unsupported_git_worktree_add_forms_fail_closed(
    governance: Governance, command: str, reason: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert reason in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "git worktree remove --force /home/saturnin/worktrees/stale",
        "git worktree remove --force /etc/stale",
        "git worktree move /home/saturnin/worktrees/a /home/saturnin/worktrees/b",
        "git worktree prune",
        "git worktree repair /home/saturnin/worktrees/stale",
    ],
)
def test_destructive_raw_git_worktree_commands_fail_closed(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "saturnin worktree lifecycle commands" in decision.reasons[0]


def test_git_worktree_add_target_is_checked_after_global_options(
    governance: Governance,
) -> None:
    decision = governance.check_server_command("git worktree --verbose add /etc/stale")

    assert not decision.allowed
    assert "outside writable roots" in decision.reasons[0]


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


@pytest.mark.parametrize(
    "command",
    [
        'saturnin check command "git reflog show --all --date=iso"',
        "git reflog show --all --date=iso",
        "git reflog --all",
        'saturnin check command "git fsck --unreachable"',
        "git fsck --unreachable",
        f"git branch feature/recovered {'a' * 40}",
        "saturnin worktree cleanup --apply",
        "saturnin task move TASK_ID ready --actor chief-of-staff",
        "saturnin task attach TASK_ID --branch feature/recovered --actor chief-of-staff",
        "systemctl --user stop 'saturnin-*.timer'",
        "saturnin task list --open",
        'saturnin escalate "Recovery requires human intervention" --urgency critical --push',
    ],
)
def test_documented_recovery_commands_are_allowed(
    governance: Governance,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    trusted = config.root / "trusted-recovery-bin"
    trusted.mkdir()
    for binary in ("git", "systemctl"):
        executable = trusted / binary
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
    runtime = config.data_root / ".venv" / "bin"
    runtime.mkdir(parents=True)
    executable = runtime / "saturnin"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    config.server_scope["filesystem"]["trusted_executable_roots"] = [str(trusted)]
    monkeypatch.setenv("PATH", f"{trusted}:{runtime}")
    monkeypatch.setattr("os.getcwd", lambda: "/home/saturnin")

    assert governance.check_server_command(command).allowed


@pytest.mark.parametrize(
    "command",
    [
        "git fsck",
        "git fsck --lost-found",
        "git fsck --unreachable --lost-found",
        "git fsck --no-reflogs --unreachable",
        "git fsck --unreachable HEAD",
    ],
)
def test_git_fsck_rejects_undocumented_or_mutating_variants(
    governance: Governance,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    monkeypatch.setattr("os.getcwd", lambda: "/home/saturnin")

    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "limited to the read-only" in decision.reasons[0]


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
        "apt update -o APT::Update::Pre-Invoke::=/usr/bin/touch /tmp/outside",
        "apt -o APT::Update::Pre-Invoke::=/usr/bin/touch update",
        "apt install ripgrep --option=Dpkg::Pre-Invoke::=/bin/sh",
        "apt install ripgrep -c /home/saturnin/hook.conf",
        "apt install ripgrep --config-file=/home/saturnin/hook.conf",
    ],
)
def test_apt_configuration_hooks_fail_closed(
    governance: Governance, command: str
) -> None:
    decision = governance.check_server_command(
        command, dedicated_service="saturnin-discovery.service"
    )

    assert not decision.allowed
    assert "configuration" in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "gh pr merge 123 --admin --repo JakubMifek/saturnin",
        "gh repo edit JakubMifek/saturnin --visibility private",
        "gh api --method DELETE repos/JakubMifek/saturnin",
        "gh api -XPATCH -fstate=closed repos/JakubMifek/saturnin/pulls/1",
        "gh api -iXDELETE repos/JakubMifek/saturnin/pulls/1",
        "gh api -ifstate=closed repos/JakubMifek/saturnin/pulls/1",
        "gh api graphql -f query='mutation { x }'",
        "gh issue create --repo JakubMifek/saturnin --title t --body b",
        "gh issue edit 1 --repo JakubMifek/saturnin --title t",
        "gh issue close 1 --repo JakubMifek/saturnin",
        "gh label create incident --repo JakubMifek/saturnin",
    ],
)
def test_gh_admin_commands_fail_closed(governance: Governance, command: str) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "unsupported" in decision.reasons[0]


@pytest.mark.parametrize(
    "command",
    [
        "gh api repos/JakubMifek/saturnin/pulls/1",
        "gh issue list --repo JakubMifek/saturnin",
        "gh issue view 1 --repo JakubMifek/saturnin",
        "gh label list --repo JakubMifek/saturnin",
    ],
)
def test_gh_read_only_issue_label_and_api_helpers_are_allowed(
    governance: Governance, command: str
) -> None:
    assert governance.check_server_command(command).allowed


@pytest.mark.parametrize("command", ["env --chdir /tmp touch status", "env -C/tmp touch status"])
def test_env_chdir_fails_closed(governance: Governance, command: str) -> None:
    decision = governance.check_server_command(command)

    assert not decision.allowed
    assert "env wrapper" in decision.reasons[0]


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
