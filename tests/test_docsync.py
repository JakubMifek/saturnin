from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from saturnin import docsync
from saturnin.cli import main
from saturnin.config import Config
from saturnin.review import (
    ReviewLedger,
    review_attestation_signing_key,
    sign_review_attestation,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def docs_home(config: Config) -> Config:
    for name in ("docs", ".github"):
        shutil.copytree(REPO_ROOT / name, config.root / name)
    return config


def test_checked_in_docs_match_policy() -> None:
    """The repository itself must never be stale."""
    assert docsync.render(Config.load(REPO_ROOT), write=False) == []
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    capability_block = next(
        match
        for match in docsync.MARKER.finditer(readme)
        if match.group("name") == "capabilities"
    )
    rows = capability_block.group("body").splitlines()
    assert rows[:2] == ["| Capability | Command |", "| --- | --- |"]
    assert all(row.startswith("| ") and row.endswith(" |") for row in rows)
    assert sum("Governance gates" in row for row in rows) == 1
    runtime_block = next(
        match
        for match in docsync.MARKER.finditer(readme)
        if match.group("name") == "runtime-summary"
    )
    assert ".github/workflows/governance.yml" in runtime_block.group("body")
    assert "independently enforces the review gate" in runtime_block.group("body")
    topology = (REPO_ROOT / "docs" / "adr" / "0002-repository-topology.md").read_text(
        encoding="utf-8"
    )
    assert "Status: **Accepted**" in topology
    assert "<!-- generated:notes-governance -->" in topology


def test_cleanup_guidance_references_policy_without_copying_configurable_facts() -> None:
    janitor = (REPO_ROOT / "agents" / "janitor.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs" / "runbooks" / "ops-safety.md").read_text(
        encoding="utf-8"
    )
    startup = (REPO_ROOT / "docs" / "runbooks" / "day-1-startup.md").read_text(
        encoding="utf-8"
    )
    skill = (REPO_ROOT / "skills" / "worktree-session.md").read_text(
        encoding="utf-8"
    )
    service = (REPO_ROOT / "systemd" / "saturnin-janitor.service").read_text(
        encoding="utf-8"
    )
    installer = (REPO_ROOT / "scripts" / "install_user_units.sh").read_text(
        encoding="utf-8"
    )

    assert "policies/cleanup.yaml" in janitor
    assert "policies/cleanup.yaml:safety.keep_reflog_days" in runbook
    assert "policies/cleanup.yaml" in startup
    for duplicated_fact in (
        "old *and* dirty",
        "repeated over-cap",
        "unmerged branch",
        "never touches a dirty",
        "keep_reflog_days` (90)",
        "APPLY=1",
    ):
        assert duplicated_fact not in "\n".join(
            (janitor, runbook, startup, service, installer)
        )
    assert "saturnin worktree create <branch> [--task <id>]" in skill
    assert "--base main" not in skill


def test_generated_blocks_are_found(docs_home: Config) -> None:
    names = {p.name for p in docsync.documents(docs_home)}
    assert {
        "operating-model.md",
        "delegation-policy.md",
        "copilot-instructions.md",
        "review-ledger.md",
    } <= names


def test_policy_change_makes_docs_stale(docs_home: Config) -> None:
    policy = docs_home.root / "policies" / "governance.yaml"
    policy.write_text(
        policy.read_text().replace("Never push to the default branch", "Push wherever you like")
    )
    docs_home._cache.clear()
    stale = docsync.render(docs_home, write=False)
    assert stale
    assert docsync.audit(docs_home)

    assert main(["--home", str(docs_home.root), "docs", "render", "--check"]) == 2
    assert main(["--home", str(docs_home.root), "docs", "render"]) == 0
    assert docsync.render(Config.load(docs_home.root), write=False) == []


def test_review_flow_blocks_are_policy_rendered(docs_home: Config) -> None:
    policy = docs_home.root / "policies" / "governance.yaml"
    policy.write_text(
        policy.read_text().replace(
            "allowed_reviewer_roles: [pr-reviewer]",
            "allowed_reviewer_roles: [review-bot]",
        )
    )
    docs_home._cache.clear()

    stale = docsync.render(docs_home, write=False)

    assert docs_home.root / "skills" / "review-ledger.md" in stale
    assert docs_home.root / "agents" / "pr-reviewer.md" in stale
    docsync.render(docs_home)
    rendered = (docs_home.root / "skills" / "review-ledger.md").read_text(encoding="utf-8")
    assert "--reviewer review-bot" in rendered


def test_generated_notes_review_flow_matches_ledger_contract(config: Config) -> None:
    notes = config.policy("repos")["repos"]["notes"]
    review = notes["change_review"]
    repo = notes["slug"]
    flow = docsync._notes_review_flow(config)
    for option in (
        f"--repo {repo}",
        f"--profile {review['profile']}",
        f"--method {review['method']}",
        *(f"--check {check}" for check in review["required_checks"]),
    ):
        assert flow.count(option) >= 2

    subject = f"{repo}#42"
    head_sha = "d" * 40
    attestation = sign_review_attestation(
        key=review_attestation_signing_key(config, "pr-reviewer"),
        subject=subject,
        kind="pr",
        author="scribe",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=head_sha,
        destination_repo=repo,
        review_profile=review["profile"],
        review_method=review["method"],
        review_checks=review["required_checks"],
    )
    record = ReviewLedger(config).record(
        subject=subject,
        kind="pr",
        author="scribe",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=head_sha,
        destination_repo=repo,
        review_profile=review["profile"],
        review_method=review["method"],
        review_checks=review["required_checks"],
        attestation=attestation,
    )

    assert record.review_profile == review["profile"]


def test_audit_checks_generated_blocks_in_skills(docs_home: Config) -> None:
    skill = docs_home.root / "skills" / "review-ledger.md"
    skill.write_text(
        "<!-- generated:pr-review-flow -->\nstale\n<!-- /generated:pr-review-flow -->",
        encoding="utf-8",
    )

    errors = docsync.audit(docs_home)

    assert errors == [
        "documentation has drifted from policy (skills/review-ledger.md); run: saturnin docs render"
    ]


def test_unknown_block_is_rejected(docs_home: Config) -> None:
    with pytest.raises(KeyError):
        docsync.render_text(
            "<!-- generated:nonsense -->\n\n<!-- /generated:nonsense -->", docs_home
        )


def test_audit_reports_unknown_generated_blocks(docs_home: Config, capsys) -> None:
    (docs_home.root / "docs" / "bad.md").write_text(
        "<!-- generated:nonsense -->\n\n<!-- /generated:nonsense -->",
        encoding="utf-8",
    )

    assert docsync.audit(docs_home) == ["unknown generated block: nonsense"]
    assert main(["--home", str(docs_home.root), "doctor"]) == 2
    assert "unknown generated block: nonsense" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("closing", "problem"),
    [
        ("", "has no closing marker"),
        ("<!-- /generated:routing -->", "is closed as 'routing'"),
    ],
)
def test_audit_reports_malformed_generated_blocks(
    docs_home: Config,
    capsys: pytest.CaptureFixture[str],
    closing: str,
    problem: str,
) -> None:
    path = docs_home.root / "docs" / "bad.md"
    path.write_text(f"<!-- generated:rules -->\nstale policy text\n{closing}", encoding="utf-8")

    errors = docsync.audit(docs_home)

    assert len(errors) == 1
    assert "docs/bad.md:" in errors[0]
    assert problem in errors[0]
    assert main(["--home", str(docs_home.root), "doctor"]) == 2
    assert problem in capsys.readouterr().out


def test_audit_rejects_paired_markers_without_required_newlines(
    docs_home: Config, capsys: pytest.CaptureFixture[str]
) -> None:
    path = docs_home.root / "docs" / "bad.md"
    path.write_text(
        "<!-- generated:rules -->stale<!-- /generated:rules -->",
        encoding="utf-8",
    )

    errors = docsync.audit(docs_home)

    assert len(errors) == 1
    assert "malformed generated marker" in errors[0]
    assert main(["--home", str(docs_home.root), "doctor"]) == 2
    assert "malformed generated marker" in capsys.readouterr().out


def test_audit_detects_malformed_marker_candidates(docs_home: Config) -> None:
    path = docs_home.root / "docs" / "bad.md"
    path.write_text(
        "<!-- generated:rules-->\nstale\n<!-- /generated:rules -->",
        encoding="utf-8",
    )

    errors = docsync.audit(docs_home)

    assert any("malformed generated marker" in error for error in errors)
    assert any("has no opening marker" in error for error in errors)


@pytest.mark.parametrize(
    "content",
    [
        "<!-- generated:rules\nstale",
        "<!-- generated rules -->\nstale\n<!-- /generated:rules -->",
        "<!-- generated :rules -->\nstale\n<!-- /generated:rules -->",
        "<!-- generated : rules -->\nstale\n<!-- /generated : rules -->",
        "<!-- generated: -->\nstale\n<!-- /generated: -->",
        "prefix <!-- generated:rules -->\nstale\n<!-- /generated:rules --> suffix",
        "<!-- generated:RULES -->\nstale\n<!-- /generated:RULES -->",
    ],
)
def test_audit_rejects_empty_nonlowercase_or_embedded_markers(
    docs_home: Config, content: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (docs_home.root / "docs" / "bad.md").write_text(content, encoding="utf-8")

    errors = docsync.audit(docs_home)

    assert errors
    assert any("malformed generated marker" in error for error in errors)
    assert main(["--home", str(docs_home.root), "doctor"]) == 2
    assert "malformed generated marker" in capsys.readouterr().out


def test_documents_ignores_unrelated_generated_prose(docs_home: Config) -> None:
    path = docs_home.root / "docs" / "notes.md"
    path.write_text(
        "This generated documentation stays outside marker comments.\n"
        "<!-- generated by tooling, not a marker -->\n",
        encoding="utf-8",
    )

    assert path not in docsync.documents(docs_home)


def test_documented_pr_review_flow_records_attested_head() -> None:
    runbook = (REPO_ROOT / "docs" / "runbooks" / "day-1-startup.md").read_text(
        encoding="utf-8"
    )
    template = (REPO_ROOT / ".github" / "pull_request_template.md").read_text(
        encoding="utf-8"
    )

    assert "HEAD_SHA=\"$(gh pr view" in runbook
    assert "VERDICT=approved" in runbook
    assert "--head-sha \"$HEAD_SHA\")" in runbook
    assert "--head-sha \"$HEAD_SHA\" --attestation \"$attestation\"" in runbook
    assert "Review attestation created for that revision" in template
    assert "--head-sha \"$HEAD_SHA\" --attestation \"$attestation\"" in template


def test_generated_pr_review_flows_pass_same_head_sha() -> None:
    for path in [
        REPO_ROOT / "docs" / "runbooks" / "day-1-startup.md",
        REPO_ROOT / "agents" / "pr-reviewer.md",
        REPO_ROOT / "skills" / "review-ledger.md",
    ]:
        text = path.read_text(encoding="utf-8")
        blocks = [
            match.group("body")
            for match in docsync.MARKER.finditer(text)
            if match.group("name") == "pr-review-flow"
        ]
        assert blocks, path
        for block in blocks:
            assert 'HEAD_SHA="$(gh pr view' in block
            assert block.count('--head-sha "$HEAD_SHA"') == 3
            assert "--reviewer pr-reviewer" in block
