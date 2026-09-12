from __future__ import annotations

import hashlib
import os
import subprocess
import sys

from saturnin.automation import AutomationLibrary
from saturnin.board import Board
from saturnin.config import Config


def test_registry_files_exist(config: Config) -> None:
    library = AutomationLibrary(config)
    assert library.list()
    assert library.audit() == []


def test_find_prevents_reinvention(config: Config) -> None:
    library = AutomationLibrary(config)
    matches = library.find("clean up stale worktrees")
    assert matches and matches[0].id == "janitor-cleanup"
    assert library.find("brew coffee for the narrator") == []


def test_detect_repeats(config: Config, board: Board) -> None:
    for _ in range(3):
        board.create("Rotate the deploy keys")
    board.create("Something else entirely")
    candidates = AutomationLibrary(config).detect_repeats(board, threshold=3)
    assert len(candidates) == 1
    assert candidates[0].count == 3
    assert candidates[0].existing is None


def test_detect_repeats_normalises_punctuated_titles(config: Config, board: Board) -> None:
    board.create("Clean worktree/branch for e2e")
    board.create("Clean worktree branch for e 2 e")
    board.create("Clean worktree-branch for e2e")
    candidates = AutomationLibrary(config).detect_repeats(board, threshold=3)
    assert len(candidates) == 1
    assert candidates[0].count == 3


def test_propose_files_one_task_only(config: Config, board: Board) -> None:
    library = AutomationLibrary(config)
    for _ in range(3):
        board.create("Rotate the deploy keys")
    first = library.propose(board, threshold=3)
    assert len(first) == 1
    assert "automation" in first[0].labels
    assert library.propose(board, threshold=3) == []


def test_covered_repeats_are_not_proposed(config: Config, board: Board) -> None:
    for _ in range(4):
        board.create("cleanup stale worktrees")
    assert AutomationLibrary(config).propose(board, threshold=3) == []


def test_monitors_use_project_virtualenv_python(config: Config) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: health\n"
        "    url: https://example.test/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    marker = config.root / "python-used"
    venv_bin = config.root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text(
        f"#!/bin/sh\nprintf used >> {marker}\nexec {sys.executable} \"$@\"\n",
        encoding="utf-8",
    )
    python.chmod(0o755)
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nprintf 200\n", encoding="utf-8")
    curl.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert "used" in marker.read_text(encoding="utf-8")


def test_monitor_escalations_are_pushed_and_not_silenced(config: Config) -> None:
    script = (config.root / "automation/library/run_monitors.sh").read_text(
        encoding="utf-8"
    )
    escalation = script.split("saturnin escalate", 1)[1].split("else", 1)[0]
    assert "--push" in escalation
    assert '--task "$incident_task"' in escalation
    assert '.task"' in script
    assert "|| true" not in escalation


def test_monitor_recovery_closes_recorded_incident_task(config: Config, board: Board) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: health\n"
        "    url: https://example.test/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    task = board.create("Monitor managed-app/health failed")
    (config.var_dir / "monitors").mkdir(parents=True)
    repo_key = f"managed-app-{hashlib.sha256(str(repo.resolve()).encode()).hexdigest()[:12]}"
    marker = config.var_dir / "monitors" / f"{repo_key}_health.task"
    marker.write_text(task.id, encoding="utf-8")
    escalated = config.var_dir / "monitors" / f"{repo_key}_health.escalated"
    escalated.write_text("", encoding="utf-8")
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nprintf 200\n", encoding="utf-8")
    curl.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.path.dirname(sys.executable)}:{os.environ['PATH']}",
        },
    )

    assert board.get(task.id).state == "cancelled"
    assert not marker.exists()
    assert not escalated.exists()


def test_monitors_validate_manifest_name_and_url_before_curl(config: Config) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: ../escape\n"
        "    url: https://example.test/health\n"
        "  - name: option-url\n"
        "    url: --config=/tmp/curlrc\n",
        encoding="utf-8",
    )
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    curl.chmod(0o755)

    result = subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert "unsafe name" in result.stdout
    assert "unsupported monitor URL" in result.stdout
    assert not list((config.root / "var" / "monitors").glob("*escape*"))


def test_monitor_state_is_namespaced_by_repository_path(config: Config) -> None:
    repos = [config.root / parent / "managed-app" for parent in ("one", "two")]
    for repo in repos:
        (repo / ".saturnin").mkdir(parents=True)
        (repo / ".saturnin" / "repo.yaml").write_text(
            "monitors:\n"
            "  - name: health\n"
            "    url: https://example.test/health\n",
            encoding="utf-8",
        )
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nprintf 200\n", encoding="utf-8")
    curl.chmod(0o755)

    subprocess.run(
        [
            "bash",
            str(config.root / "automation/library/run_monitors.sh"),
            *(str(repo) for repo in repos),
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    result_files = list((config.var_dir / "monitors").glob("managed-app-*.jsonl"))
    repository_logs = [path for path in result_files if not path.stem.endswith("_health")]
    assert len(repository_logs) == 2
    assert repository_logs[0].name != repository_logs[1].name


def test_review_gate_rejects_pr_subject_for_another_repo(config: Config) -> None:
    result = subprocess.run(
        [
            "bash",
            str(config.root / "automation/library/review_gate.sh"),
            "pr",
            "other/repo#42",
            "owner/repo",
            "code-worker",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "SATURNIN_HOME": str(config.root)},
    )

    assert result.returncode == 2
    assert "expected owner/repo#number" in result.stderr


def test_review_gate_passes_issue_digest_to_gate(config: Config) -> None:
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    args_log = config.root / "saturnin-args"
    saturnin = fake_bin / "saturnin"
    saturnin.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {args_log}\n",
        encoding="utf-8",
    )
    saturnin.chmod(0o755)

    subprocess.run(
        [
            "bash",
            str(config.root / "automation/library/review_gate.sh"),
            "issue",
            "draft-42",
            "owner/repo",
            "researcher",
            "reviewed-digest",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    args = args_log.read_text(encoding="utf-8").splitlines()
    assert args[:2] == ["review", "gate"]
    assert args[-2:] == ["--issue-digest", "reviewed-digest"]


def test_review_gate_imports_only_the_designated_reviewer(config: Config) -> None:
    script = (config.root / "automation/library/review_gate.sh").read_text(
        encoding="utf-8"
    )

    assert "user.casefold() != reviewer_login.casefold()" in script
    assert 'elif latest == "dismissed":' in script
    assert 'print(f"dismissed\\t{reviewer_login}")' in script
    assert "Imported from GitHub reviewer ${github_reviewer}" in script
