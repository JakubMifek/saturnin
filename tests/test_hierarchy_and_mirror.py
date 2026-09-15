from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from saturnin.board import Board, BoardError
from saturnin.cli import check_managed_repo, main
from saturnin.config import Config
from saturnin.escalation import submit
from saturnin.governance import Governance
from saturnin.issues import IssueMirror, MirrorError, run_gh


def _set_issue_mirror(config: Config, *, repos: bool = True, mandatory: bool = False) -> None:
    repos_path = config.root / "policies" / "repos.yaml"
    repos_policy = yaml.safe_load(repos_path.read_text(encoding="utf-8"))
    repos_policy["tracking"]["mirror_tasks_as_issues"] = repos
    repos_path.write_text(yaml.safe_dump(repos_policy), encoding="utf-8")

    governance_path = config.root / "policies" / "governance.yaml"
    governance_policy = yaml.safe_load(governance_path.read_text(encoding="utf-8"))
    governance_policy["tracking"]["mirror_tasks_as_issues"] = mandatory
    governance_path.write_text(yaml.safe_dump(governance_policy), encoding="utf-8")
    config._cache.clear()


@pytest.fixture(autouse=True)
def issue_mirror_enabled(config: Config) -> None:
    _set_issue_mirror(config)


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
    current = board.create("Current")
    fresh = board.create("Fresh")
    closed = board.create("Closed")
    with board.edit(existing.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
    with board.edit(current.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/2"
        stored.log("issue:synced", actor="chief-of-staff", note=stored.issue)
        stored.issue_synced_at = stored.updated_at
    board.transition(closed, "cancelled")

    assert {task.id for task in IssueMirror(config, board).syncable()} == {
        existing.id,
        fresh.id,
        closed.id,
    }


def test_syncable_revisits_parent_when_child_changes(config: Config, board: Board) -> None:
    parent = board.create("Parent", kind="epic")
    child = board.create("Child", parent=parent.id)
    with board.edit(parent.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
        stored.log("issue:synced", actor="chief-of-staff", note=stored.issue)
        stored.issue_synced_at = stored.updated_at
    board.transition(child, "routed")

    assert parent.id in {task.id for task in IssueMirror(config, board).syncable()}


def test_pushed_sync_all_revisits_unchanged_mirrors(
    config: Config,
    board: Board,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = board.create("Remote state may drift")
    with board.edit(task.id) as stored:
        stored.issue = "https://github.com/example/repo/issues/9"
    payload = IssueMirror(config, board).render(board.get(task.id))
    with board.edit(task.id) as stored:
        stored.issue_synced_digest = IssueMirror._payload_digest(payload)
    visited: list[str] = []

    def record_sync(self, tasks, *, push=False):
        visited.extend(candidate.id for candidate in tasks)
        return []

    monkeypatch.setattr(IssueMirror, "sync_all", record_sync)

    assert main(["--home", str(config.root), "task", "sync", "--all", "--push"]) == 0
    assert visited == [task.id]
    assert capsys.readouterr().out.strip() == "(nothing to mirror)"


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
        if args[1:3] == ["label", "list"]:
            stdout = "[]"
        elif args[1:3] == ["issue", "view"]:
            stdout = json.dumps(
                {
                    "labels": [
                        {"name": "saturnin:state/intake"},
                        {"name": "saturnin:priority/P2"},
                        {"name": "keep-me"},
                    ],
                    "state": "OPEN",
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
    assert stored.issue_synced_digest is not None
    assert stored.history[-1]["event"] == "issue:synced"


def test_concurrent_change_is_left_pending_after_mirror_push(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Concurrent mirror")
    with board.edit(task.id) as stored:
        stored.issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
    monkeypatch.setattr("saturnin.issues.ensure_labels", lambda *args: None)

    def concurrent_push(current, payload):
        with board.edit(current.id) as stored:
            stored.state = "done"
            stored.log("state:done", actor="code-worker")
        return current.issue

    mirror = IssueMirror(config, board)
    monkeypatch.setattr(mirror, "_push", concurrent_push)
    mirror.sync(board.get(task.id), push=True)

    stored = board.get(task.id)
    assert stored.state == "done"
    assert stored.issue_synced_at is None
    assert stored.id in {candidate.id for candidate in mirror.syncable()}


def test_child_change_during_push_keeps_parent_pending(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = board.create("Parent", kind="epic")
    child = board.create("Child", parent=parent.id)
    mirror = IssueMirror(config, board)

    def concurrent_push(current, payload):
        with board.edit(child.id) as stored:
            stored.state = "done"
            stored.log("state:done", actor="code-worker")
        return "https://github.com/example/repo/issues/8"

    monkeypatch.setattr(mirror, "_push", concurrent_push)
    mirror.sync(parent, push=True)

    assert parent.id in {candidate.id for candidate in mirror.syncable()}


def test_labels_are_provisioned_before_create(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Fresh", labels=["dynamic"])
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            stdout = json.dumps([{"name": "dynamic"}])
        elif args[1:3] == ["issue", "list"]:
            stdout = "[]"
        elif args[1:3] == ["issue", "create"]:
            stdout = "https://github.com/JakubMifek/saturnin-ops/issues/2\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    IssueMirror(config, board).sync(task, push=True)

    create_index = next(i for i, call in enumerate(calls) if call[1:3] == ["issue", "create"])
    provisioned = {
        call[3]
        for call in calls[:create_index]
        if call[1:3] == ["label", "create"]
    }
    expected = set(IssueMirror(config, board).labels_for(task))
    assert provisioned == expected - {"dynamic"}
    assert "dynamic" not in provisioned
    assert not any("--force" in call for call in calls[:create_index])


def test_long_internal_labels_are_encoded(config: Config, board: Board) -> None:
    task = board.create("Fresh", labels=["source:" + "x" * 100])

    labels = IssueMirror(config, board).labels_for(task)

    assert all(len(label) <= 50 for label in labels)
    assert any(label.startswith("saturnin:label/") for label in labels)


def test_label_provisioning_failure_stops_issue_creation(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Fresh")
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            if sum(call[1:3] == ["label", "list"] for call in calls) == 1:
                return subprocess.CompletedProcess(args, 0, "[]", "")
            return subprocess.CompletedProcess(args, 1, "", "network unavailable")
        return subprocess.CompletedProcess(args, 1, "", "permission denied")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    with pytest.raises(MirrorError, match="permission denied"):
        IssueMirror(config, board).sync(task, push=True)
    assert not any(call[1:3] == ["issue", "create"] for call in calls)
    assert board.get(task.id).issue is None


def test_new_terminal_issue_is_closed(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Already complete", kind="task")
    with board.edit(task.id) as stored:
        stored.state = "done"
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if args[1:3] == ["issue", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if args[1:3] == ["issue", "create"]:
            return subprocess.CompletedProcess(
                args, 0, "https://github.com/example/repo/issues/3\n", ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)
    IssueMirror(config, board).sync(task, push=True)
    assert ["gh", "issue", "close", "https://github.com/example/repo/issues/3"] in calls


@pytest.mark.parametrize(
    ("task_state", "issue_state", "expected_command"),
    [
        ("in_progress", "CLOSED", "reopen"),
        ("done", "OPEN", "close"),
    ],
)
def test_existing_mirror_reconciles_issue_state_bidirectionally(
    config: Config,
    board: Board,
    monkeypatch: pytest.MonkeyPatch,
    task_state: str,
    issue_state: str,
    expected_command: str,
) -> None:
    task = board.create("State reconciliation")
    issue = "https://github.com/example/repo/issues/10"
    with board.edit(task.id) as stored:
        stored.issue = issue
        stored.state = task_state
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if args[1:3] == ["issue", "view"]:
            metadata = {"labels": [], "state": issue_state}
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    IssueMirror(config, board).sync(board.get(task.id), push=True)

    assert ["gh", "issue", expected_command, issue] in calls
    opposite = "close" if expected_command == "reopen" else "reopen"
    assert ["gh", "issue", opposite, issue] not in calls


def test_recovered_terminal_issue_is_updated_and_closed(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Recovered", kind="task")
    with board.edit(task.id) as stored:
        stored.state = "done"
    calls: list[list[str]] = []
    recovered = "https://github.com/example/repo/issues/4"
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if args[1:3] == ["issue", "list"]:
            return subprocess.CompletedProcess(args, 0, json.dumps([{"url": recovered}]), "")
        if args[1:3] == ["issue", "view"]:
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"labels": [], "state": "OPEN"}), ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    IssueMirror(config, board).sync(task, push=True)

    search = next(call for call in calls if call[1:3] == ["issue", "list"])
    assert "--state" in search
    assert search[search.index("--state") + 1] == "all"
    assert next(call for call in calls if call[1:3] == ["issue", "edit"])[3] == recovered
    assert ["gh", "issue", "close", recovered] in calls
    assert not any(call[1:3] == ["issue", "create"] for call in calls)


def test_marker_lookup_failure_stops_issue_creation(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = board.create("Fresh")
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if args[1:3] == ["issue", "list"]:
            return subprocess.CompletedProcess(args, 1, "", "search unavailable")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    with pytest.raises(MirrorError, match="search unavailable"):
        IssueMirror(config, board).sync(task, push=True)
    assert not any(call[1:3] == ["issue", "create"] for call in calls)


@pytest.mark.parametrize("output", ["not-json", "{}", "[{}]", ""])
def test_malformed_marker_lookup_stops_issue_creation(
    config: Config, board: Board, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    task = board.create("Fresh")
    calls: list[list[str]] = []
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["label", "list"]:
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if args[1:3] == ["issue", "list"]:
            return subprocess.CompletedProcess(args, 0, output, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("saturnin.issues.subprocess.run", fake_run)

    with pytest.raises(MirrorError, match="invalid JSON or shape"):
        IssueMirror(config, board).sync(task, push=True)
    assert not any(call[1:3] == ["issue", "create"] for call in calls)


@pytest.mark.parametrize("output", ["not-json", "{}", "[{}]", ""])
def test_malformed_escalation_lookup_stops_issue_creation(
    config: Config, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(args)
        return output

    monkeypatch.setattr("saturnin.escalation.run_gh", fake_run)

    with pytest.raises(MirrorError, match="invalid JSON or shape"):
        submit(title="Need help", body="Context", config=config, task_id="T-retry")
    assert not any(call[:2] == ["issue", "create"] for call in calls)


def test_missing_gh_error_applies_to_all_integrations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("saturnin.issues.shutil.which", lambda _: None)

    with pytest.raises(MirrorError, match="GitHub integrations") as error:
        run_gh(["issue", "list"])

    assert "--push" not in str(error.value)


@pytest.mark.parametrize("kind", ["pr-review", "issue-review"])
def test_review_kinds_are_mirrored(config: Config, board: Board, kind: str) -> None:
    task = board.create("Review the diff", kind=kind)
    mirror = IssueMirror(config, board)
    assert mirror.mirrors(task)
    assert f"saturnin:kind/{kind}" in mirror.render(task).labels


def test_result_contract_gate(config: Config) -> None:
    governance = Governance(config)
    assert not governance.check_result_contract(None)
    assert not governance.check_result_contract("telepathy")
    assert governance.check_result_contract("poller")


def test_doctor_flags_unmirrored_tasks(config: Config, board: Board, capsys) -> None:
    _set_issue_mirror(config, mandatory=True)
    board.create("Endpoint")
    assert main(["--home", str(config.root), "doctor"]) == 2
    assert "not mirrored" in capsys.readouterr().out


def test_doctor_rejects_required_but_disabled_mirroring(
    config: Config, capsys
) -> None:
    _set_issue_mirror(config, repos=False, mandatory=True)

    assert main(["--home", str(config.root), "doctor"]) == 2
    assert "governance requires task mirroring" in capsys.readouterr().out


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
    issue = "https://github.com/JakubMifek/saturnin-ops/issues/1"
    with board.edit(endpoint.id) as stored:
        stored.issue = issue
    assert main(["--home", str(config.root), "task", "tree"]) == 0
    out = capsys.readouterr().out
    assert "(epic)" in out and "Endpoint" in out

    assert main(["--home", str(config.root), "--json", "task", "sync", "--all"]) == 0
    payloads = json.loads(capsys.readouterr().out)
    assert len(payloads) == 2
    # A preview never touches the board.
    assert board.get(epic.id).issue is None
    assert board.get(endpoint.id).issue == issue
