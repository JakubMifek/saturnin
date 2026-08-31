from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest

from saturnin.board import Board, BoardError
from saturnin.cli import check_managed_repo, main
from saturnin.config import Config
from saturnin.governance import Governance
from saturnin.issues import IssueMirror, MirrorError


def test_hierarchy_rollup(board: Board) -> None:
    epic = board.create("Widget platform", kind="epic")
    feature = board.create("Widget API", kind="feature", parent=epic.id)
    one = board.create("Endpoint", parent=feature.id)
    board.create("Docs", parent=feature.id)
    board.transition(one, "cancelled")
    assert [t.id for t in board.children(epic.id)] == [feature.id]
    assert len(board.descendants(epic.id)) == 3
    roll = board.rollup(epic.id)
    assert roll == {"id": epic.id, "leaves": 2, "done": 0, "open": 1, "percent": 0.0}


def test_a_task_cannot_parent_another_task(board: Board) -> None:
    parent = board.create("Endpoint")
    with pytest.raises(BoardError):
        board.create("Sub work", parent=parent.id)


def test_unknown_kind_is_rejected(board: Board) -> None:
    with pytest.raises(BoardError):
        board.create("Something", kind="wishful-thinking")


def test_concurrent_edits_do_not_lose_updates(board: Board) -> None:
    task = board.create("Busy task")

    def append(index: int) -> None:
        with board.edit(task.id) as stored:
            stored.log("touch", actor=f"worker-{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(24)))

    touches = [entry for entry in board.get(task.id).history if entry["event"] == "touch"]
    assert len(touches) == 24


def test_mirror_renders_issue_payload(config: Config, board: Board) -> None:
    epic = board.create("Widget platform", kind="epic")
    board.create("Endpoint", parent=epic.id)
    mirror = IssueMirror(config, board)
    payload = mirror.render(board.get(epic.id))
    assert payload.repo == "JakubMifek/saturnin-ops"
    assert payload.title == "[epic] Widget platform"
    assert f"saturnin:task:{epic.id}" in payload.body
    assert "### Children" in payload.body
    assert "saturnin:kind/epic" in payload.labels
    assert "saturnin:state/intake" in payload.labels


def test_unmirrored_lists_open_tasks_without_an_issue(config: Config, board: Board) -> None:
    task = board.create("Endpoint")
    mirror = IssueMirror(config, board)
    assert [t.id for t in mirror.unmirrored()] == [task.id]
    with board.edit(task.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
    assert mirror.unmirrored() == []


def test_syncable_revisits_existing_open_mirrors(config: Config, board: Board) -> None:
    existing = board.create("Existing")
    fresh = board.create("Fresh")
    closed = board.create("Closed")
    with board.edit(existing.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
    board.transition(closed, "cancelled")

    assert {task.id for task in IssueMirror(config, board).syncable()} == {
        existing.id,
        fresh.id,
    }


def test_existing_mirror_updates_content_and_reconciles_metadata_labels(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Old title", labels=["incident"])
    with board.edit(task.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
        stored.title = "New title"
        stored.body = "New body"
        stored.state = "in_progress"
        stored.priority = "P0"
        stored.role = "code-worker"
    calls: list[list[str]] = []

    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        stdout = ""
        if args[1:3] == ["issue", "view"]:
            stdout = json.dumps(
                {
                    "labels": [
                        {"name": "saturnin:state/intake"},
                        {"name": "saturnin:priority/P2"},
                        {"name": "keep-me"},
                    ]
                }
            )
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    IssueMirror(config, board).sync(board.get(task.id), push=True)

    edit = next(call for call in calls if call[1:3] == ["issue", "edit"])
    assert edit[edit.index("--title") + 1] == "[task] New title"
    assert "New body" in edit[edit.index("--body") + 1]
    removed = [edit[index + 1] for index, arg in enumerate(edit) if arg == "--remove-label"]
    assert removed == ["saturnin:priority/P2", "saturnin:state/intake"]
    assert "keep-me" not in removed
    assert "saturnin:state/in_progress" in edit
    stored = board.get(task.id)
    assert stored.issue_synced_at is not None
    assert stored.history[-1]["event"] == "issue:synced"


def test_labels_are_provisioned_before_create(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Fresh", labels=["dynamic"])
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        stdout = (
            "https://github.com/JakubMifek/saturnin-ops/issues/2\n"
            if args[1:3] == ["issue", "create"]
            else ""
        )
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    IssueMirror(config, board).sync(task, push=True)

    create_index = next(i for i, call in enumerate(calls) if call[1:3] == ["issue", "create"])
    provisioned = {
        call[3]
        for call in calls[:create_index]
        if call[1:3] == ["label", "create"]
    }
    assert provisioned == set(IssueMirror(config, board).labels_for(task))
    assert all("--force" in call for call in calls[:create_index])


def test_label_provisioning_failure_stops_issue_creation(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Fresh")
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "permission denied")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    with pytest.raises(MirrorError, match="permission denied"):
        IssueMirror(config, board).sync(task, push=True)
    assert not any(call[1:3] == ["issue", "create"] for call in calls)
    assert board.get(task.id).issue is None


def test_review_kinds_are_not_mirrored(config: Config, board: Board) -> None:
    task = board.create("Review the diff", kind="pr-review")
    mirror = IssueMirror(config, board)
    assert not mirror.mirrors(task)
    with pytest.raises(MirrorError):
        mirror.render(task)


def test_result_contract_gate(config: Config) -> None:
    governance = Governance(config)
    assert not governance.check_result_contract(None)
    assert not governance.check_result_contract("telepathy")
    assert governance.check_result_contract("poller")


def test_doctor_flags_unmirrored_tasks(config: Config, board: Board, capsys) -> None:
    board.create("Endpoint")
    assert main(["--home", str(config.root), "doctor"]) == 2
    assert "not mirrored" in capsys.readouterr().out


def test_managed_repo_contract(tmp_path, config: Config) -> None:
    repo = tmp_path / "project"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".github").mkdir()
    problems = check_managed_repo(repo, config)
    assert any("repo.yaml" in problem for problem in problems)

    (repo / ".github" / "copilot-instructions.md").write_text("see AGENTS.md\n")
    (repo / ".saturnin" / "repo.yaml").write_text(
        "project: Demo\ncontext: python service\nsquad: [code-worker, nonesuch]\n"
        "conventions: pytest\n"
    )
    problems = check_managed_repo(repo, config)
    assert any("nonesuch" in problem for problem in problems)
    assert not any("conventions" in problem for problem in problems)

    (repo / ".saturnin" / "repo.yaml").write_text(
        "project: Demo\ncontext: python service\nsquad: [code-worker]\nconventions: pytest\n"
    )
    assert check_managed_repo(repo, config) == []


def test_cli_task_tree_and_sync_preview(config: Config, board: Board, capsys) -> None:
    epic = board.create("Widget platform", kind="epic")
    endpoint = board.create("Endpoint", parent=epic.id)
    with board.edit(endpoint.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
    assert main(["--home", str(config.root), "task", "tree"]) == 0
    out = capsys.readouterr().out
    assert "(epic)" in out and "Endpoint" in out

    assert main(["--home", str(config.root), "--json", "task", "sync", "--all"]) == 0
    payloads = json.loads(capsys.readouterr().out)
    assert len(payloads) == 2
    # A preview never touches the board.
    assert board.get(epic.id).issue is None
    assert board.get(endpoint.id).issue == stored.issue
