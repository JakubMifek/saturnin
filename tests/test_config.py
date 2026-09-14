from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from saturnin.config import find_root

REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_find_root_keeps_the_worktree_as_the_source_root(
    tmp_path: Path, monkeypatch
) -> None:
    main = tmp_path / "main"
    main.mkdir()
    (main / "policies").mkdir()
    (main / "policies" / "governance.yaml").write_text("{}\n", encoding="utf-8")
    _git(main, "init", "-b", "main")
    _git(main, "config", "user.email", "test@example.com")
    _git(main, "config", "user.name", "Test")
    _git(main, "add", ".")
    _git(main, "commit", "-m", "initial")
    linked = tmp_path / "linked"
    _git(main, "worktree", "add", "-b", "feature/linked", str(linked))
    monkeypatch.delenv("SATURNIN_HOME", raising=False)

    assert find_root(linked) == linked
    assert find_root(linked / "policies") == linked


def test_find_root_preserves_saturnin_home_precedence(
    tmp_path: Path, monkeypatch
) -> None:
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    monkeypatch.setenv("SATURNIN_HOME", str(explicit))

    assert find_root(tmp_path) == explicit


def test_ci_runs_untrusted_tests_only_for_push_and_pull_request() -> None:
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "branches-ignore" not in workflow
    assert "pull_request:" in workflow
    assert "pull_request_target:" not in workflow
    assert "review_gate.sh" not in workflow


def test_ci_review_gate_does_not_claim_a_fixed_author_role() -> None:
    workflow = (REPO_ROOT / ".github/workflows/governance.yml").read_text(
        encoding="utf-8"
    )

    gate_line = next(line for line in workflow.splitlines() if "review_gate.sh pr" in line)
    assert "code-worker" not in gate_line
    assert "github.event.pull_request.base.repo.full_name" in gate_line


def test_ci_governance_uses_base_controlled_workflow_and_code() -> None:
    workflow = (REPO_ROOT / ".github/workflows/governance.yml").read_text(
        encoding="utf-8"
    )

    assert "pull_request_target:" in workflow
    assert "\n  pull_request:\n" not in workflow
    assert "github.event.pull_request.base.sha" in workflow
    assert "persist-credentials: false" in workflow
    assert "ref: ${{ github.event.pull_request.head.sha }}" not in workflow
    assert "TRUSTED_BOOTSTRAP_BASE_SHA" not in workflow
    assert "Detect initial governance bootstrap" in workflow
    assert "steps.bootstrap.outputs.initial != 'true'" in workflow
    assert "Repository-native bootstrap approval" in workflow
    assert "github.paginate(" in workflow
    assert "listReviews" in workflow
    assert "const {data: reviews}" not in workflow
    assert "bootstrapReviewer = \"copilot-pull-request-reviewer[bot]\"" in workflow
    assert "review.user.type === \"Bot\"" in workflow
    assert "review.user.login === bootstrapReviewer" in workflow
    assert "review.commit_id === head" in workflow


def test_public_task_template_matches_discovery_source_labels() -> None:
    policy = yaml.safe_load((REPO_ROOT / "policies/repos.yaml").read_text(encoding="utf-8"))
    template = yaml.safe_load(
        (REPO_ROOT / ".github/ISSUE_TEMPLATE/task.yml").read_text(encoding="utf-8")
    )
    engine = policy["repos"]["engine"]["slug"]
    source = next(item for item in policy["discovery"]["sources"] if item["slug"] == engine)

    assert set(template["labels"]) & set(source["labels"])
    assert "saturnin:trusted" in source["require_labels"]
    assert "saturnin:trusted" in template["body"][0]["attributes"]["value"]


def test_ceo_instructions_require_backups_until_mirroring_is_enabled() -> None:
    instructions = (REPO_ROOT / ".github/copilot-instructions.md").read_text(
        encoding="utf-8"
    )
    policy = yaml.safe_load(
        (REPO_ROOT / "policies/governance.yaml").read_text(encoding="utf-8")
    )

    assert policy["tracking"]["mirror_tasks_as_issues"] is False
    assert "while `tracking.mirror_tasks_as_issues` is false" in instructions
    assert "configured backups of `board/` and `var/`" in instructions


def test_public_task_template_matches_discovery_policy() -> None:
    template = yaml.safe_load(
        (REPO_ROOT / ".github/ISSUE_TEMPLATE/task.yml").read_text(encoding="utf-8")
    )
    repos = yaml.safe_load(
        (REPO_ROOT / "policies/repos.yaml").read_text(encoding="utf-8")
    )
    source = next(
        entry
        for entry in repos["discovery"]["sources"]
        if entry["slug"] == repos["repos"]["engine"]["slug"]
    )

    assert template["labels"] == source["labels"]
    assert not set(source.get("require_labels", [])) <= set(template["labels"])
