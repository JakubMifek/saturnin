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


def test_ci_runs_on_default_branch_pushes_without_branch_gating_them() -> None:
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "branches-ignore" not in workflow
    assert "if: github.event_name == 'pull_request'" in workflow


def test_ci_review_gate_does_not_claim_a_fixed_author_role() -> None:
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    gate_line = next(line for line in workflow.splitlines() if "review_gate.sh pr" in line)
    assert "code-worker" not in gate_line


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
