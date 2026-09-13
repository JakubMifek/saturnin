from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time

import yaml
from saturnin.automation import AutomationLibrary
from saturnin.board import Board
from saturnin.config import Config


def _register_monitor_repo(config: Config, repo, slug: str = "owner/managed-app") -> None:
    path = config.root / "policies" / "repos.yaml"
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    policy["discovery"]["sources"].append({"slug": slug, "checkout": str(repo)})
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")


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
        "    url: https://93.184.216.34/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    _register_monitor_repo(config, repo)
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
        "    url: https://93.184.216.34/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    _register_monitor_repo(config, repo)
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


def test_monitor_recreates_missing_incident_marker_before_escalating(config: Config) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: health\n"
        "    url: https://93.184.216.34/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    _register_monitor_repo(config, repo)
    repo_key = f"managed-app-{hashlib.sha256(str(repo.resolve()).encode()).hexdigest()[:12]}"
    monitor_log = config.var_dir / "monitors" / f"{repo_key}_health.jsonl"
    monitor_log.parent.mkdir(parents=True)
    monitor_log.write_text('{"ok":false}\n', encoding="utf-8")
    args_log = config.root / "saturnin-args"
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nprintf 500\n", encoding="utf-8")
    curl.chmod(0o755)
    saturnin = config.root / ".venv" / "bin" / "saturnin"
    saturnin.parent.mkdir(parents=True)
    saturnin.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {args_log}\n"
        "if [ \"$1\" = '--json' ] && [ \"$2\" = 'task' ] && [ \"$3\" = 'add' ]; then\n"
        "  printf '%s\\n' '{\"id\":\"T-monitor\"}'\n"
        "fi\n",
        encoding="utf-8",
    )
    saturnin.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert (config.var_dir / "monitors" / f"{repo_key}_health.task").read_text(
        encoding="utf-8"
    ) == "T-monitor"
    calls = args_log.read_text(encoding="utf-8")
    assert "--json task add" in calls
    assert "escalate Monitor managed-app/health failing repeatedly" in calls
    assert "--task T-monitor" in calls


def test_monitor_replaces_terminal_incident_marker_before_escalating(config: Config) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: health\n"
        "    url: https://93.184.216.34/health\n"
        "    expect_status: 200\n",
        encoding="utf-8",
    )
    _register_monitor_repo(config, repo)
    repo_key = f"managed-app-{hashlib.sha256(str(repo.resolve()).encode()).hexdigest()[:12]}"
    monitor_dir = config.var_dir / "monitors"
    monitor_dir.mkdir(parents=True)
    (monitor_dir / f"{repo_key}_health.jsonl").write_text('{"ok":false}\n', encoding="utf-8")
    (monitor_dir / f"{repo_key}_health.task").write_text("T-done", encoding="utf-8")
    (monitor_dir / f"{repo_key}_health.escalated").write_text("", encoding="utf-8")
    args_log = config.root / "saturnin-args"
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\nprintf 500\n", encoding="utf-8")
    curl.chmod(0o755)
    saturnin = config.root / ".venv" / "bin" / "saturnin"
    saturnin.parent.mkdir(parents=True)
    saturnin.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {args_log}\n"
        "if [ \"$1\" = '--json' ] && [ \"$2\" = 'task' ] && [ \"$3\" = 'show' ]; then\n"
        "  printf '%s\\n' '{\"state\":\"done\"}'\n"
        "elif [ \"$1\" = '--json' ] && [ \"$2\" = 'task' ] && [ \"$3\" = 'add' ]; then\n"
        "  printf '%s\\n' '{\"id\":\"T-new\"}'\n"
        "fi\n",
        encoding="utf-8",
    )
    saturnin.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert (monitor_dir / f"{repo_key}_health.task").read_text(encoding="utf-8") == "T-new"
    calls = args_log.read_text(encoding="utf-8")
    assert "--json task show T-done" in calls
    assert "--json task add" in calls
    assert "--task T-new" in calls


def test_monitors_validate_manifest_name_and_url_before_curl(config: Config) -> None:
    repo = config.root / "managed-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: ../escape\n"
        "    url: https://93.184.216.34/health\n"
        "  - name: option-url\n"
        "    url: --config=/tmp/curlrc\n"
        "  - name: loopback\n"
        "    url: http://127.0.0.1/health\n"
        "  - name: ipv6-loopback\n"
        "    url: http://[::1]/health\n"
        "  - name: metadata\n"
        "    url: http://169.254.169.254/latest/meta-data/\n"
        "  - name: cgnat\n"
        "    url: http://100.64.0.1/health\n"
        "  - name: dotted\n"
        "    url: https://93.184.216.34./health\n"
        "  - name: credentials\n"
        "    url: http://user@93.184.216.34/health\n"
        "  - name: missing-host\n"
        "    url: https:///health\n"
        "  - name: bad-port\n"
        "    url: https://93.184.216.34:not-a-port/health\n",
        encoding="utf-8",
    )
    _register_monitor_repo(config, repo)
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl_marker = config.root / "curl-called"
    curl.write_text(f"#!/bin/sh\nprintf called > {curl_marker}\nexit 99\n", encoding="utf-8")
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
    assert not curl_marker.exists()
    script = (config.root / "automation/library/run_monitors.sh").read_text(
        encoding="utf-8"
    )
    assert "-q -sS --noproxy '*'" in script


def test_result_poller_is_executable_for_systemd(config: Config) -> None:
    script = config.root / "automation/library/result_poller.sh"

    assert os.access(script, os.X_OK)


def test_monitor_state_is_namespaced_by_repository_path(config: Config) -> None:
    repos = [config.root / parent / "managed-app" for parent in ("one", "two")]
    for repo in repos:
        (repo / ".saturnin").mkdir(parents=True)
        (repo / ".saturnin" / "repo.yaml").write_text(
            "monitors:\n"
            "  - name: health\n"
            "    url: https://93.184.216.34/health\n",
            encoding="utf-8",
        )
        _register_monitor_repo(config, repo, f"owner/{repo.parent.name}-managed-app")
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


def test_monitors_fail_closed_for_an_unregistered_checkout(config: Config) -> None:
    repo = config.root / "unregistered-app"
    (repo / ".saturnin").mkdir(parents=True)
    (repo / ".saturnin" / "repo.yaml").write_text(
        "monitors:\n"
        "  - name: health\n"
        "    url: https://93.184.216.34/health\n",
        encoding="utf-8",
    )
    fake_bin = config.root / "fake-bin"
    fake_bin.mkdir()
    curl_marker = config.root / "curl-called"
    curl = fake_bin / "curl"
    curl.write_text(f"#!/bin/sh\nprintf called > {curl_marker}\n", encoding="utf-8")
    curl.chmod(0o755)

    result = subprocess.run(
        ["bash", str(config.root / "automation/library/run_monitors.sh"), str(repo)],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert result.returncode == 1
    assert "not registered as a managed discovery source" in result.stdout
    assert not curl_marker.exists()


def test_result_poller_serializes_overlapping_runs(config: Config) -> None:
    pollers = config.var_dir / "pollers"
    pollers.mkdir(parents=True)
    run_marker = config.root / "probe-runs"
    probe = pollers / "T-concurrent.sh"
    probe.write_text(
        f"#!/bin/bash\nprintf x >> {run_marker}\nsleep 0.4\nexit 2\n",
        encoding="utf-8",
    )
    script = config.root / "automation" / "library" / "result_poller.sh"
    env = {**os.environ, "SATURNIN_HOME": str(config.root)}
    first = subprocess.Popen(
        ["bash", str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    for _ in range(100):
        if run_marker.exists():
            break
        time.sleep(0.01)
    second = subprocess.run(
        ["bash", str(script)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    first_stdout, first_stderr = first.communicate(timeout=5)

    assert first.returncode == 0, first_stderr or first_stdout
    assert "another result-poller run is active" in second.stdout
    assert run_marker.read_text(encoding="utf-8") == "x"


def test_result_poller_persists_escalation_reference(config: Config) -> None:
    pollers = config.var_dir / "pollers"
    pollers.mkdir(parents=True)
    task_id = "T-persist"
    (pollers / f"{task_id}.sh").write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
    args_log = config.root / "saturnin-args"
    fake_saturin = config.root / ".venv" / "bin" / "saturnin"
    fake_saturin.parent.mkdir(parents=True)
    fake_saturin.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {args_log}\n"
        "if [ \"$1\" = '--json' ] && [ \"$2\" = 'escalate' ]; then\n"
        "  printf '%s\\n' '{\"url\":\"https://example.test/issues/42\"}'\n"
        "elif [ \"$1\" = '--json' ] && [ \"$2\" = 'task' ] && [ \"$3\" = 'show' ]; then\n"
        "  printf '%s\\n' '{\"state\":\"blocked\"}'\n"
        "fi\n",
        encoding="utf-8",
    )
    fake_saturin.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/result_poller.sh")],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "SATURNIN_HOME": str(config.root)},
    )

    assert (pollers / f"{task_id}.escalated").read_text(encoding="utf-8") == (
        "https://example.test/issues/42\n"
    )
    assert f"--json task show {task_id}" in args_log.read_text(encoding="utf-8")


def test_result_poller_reuses_escalation_reference_when_reblocking(config: Config) -> None:
    pollers = config.var_dir / "pollers"
    pollers.mkdir(parents=True)
    task_id = "T-retry"
    (pollers / f"{task_id}.sh").write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
    (pollers / f"{task_id}.escalated").write_text(
        "https://example.test/issues/42\n", encoding="utf-8"
    )
    args_log = config.root / "saturnin-args"
    fake_saturin = config.root / ".venv" / "bin" / "saturnin"
    fake_saturin.parent.mkdir(parents=True)
    fake_saturin.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {args_log}\n"
        "if [ \"$1\" = '--json' ] && [ \"$2\" = 'task' ] && [ \"$3\" = 'show' ]; then\n"
        "  printf '%s\\n' '{\"state\":\"in_progress\"}'\n"
        "elif [ \"$1\" = '--json' ] && [ \"$2\" = 'escalate' ]; then\n"
        "  exit 99\n"
        "fi\n",
        encoding="utf-8",
    )
    fake_saturin.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/result_poller.sh")],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "SATURNIN_HOME": str(config.root)},
    )

    calls = args_log.read_text(encoding="utf-8")
    assert f"--json task show {task_id}" in calls
    assert "escalate" not in calls
    assert (
        f"task move {task_id} blocked --actor result-poller --escalation "
        "https://example.test/issues/42"
    ) in calls


def test_result_poller_archives_terminal_tasks_before_probe_execution(config: Config) -> None:
    pollers = config.var_dir / "pollers"
    pollers.mkdir(parents=True)
    task_id = "T-done"
    run_marker = config.root / "probe-ran"
    probe = pollers / f"{task_id}.sh"
    probe.write_text(f"#!/bin/bash\nprintf ran > {run_marker}\n", encoding="utf-8")
    probe.chmod(0o755)
    (pollers / f"{task_id}.escalated").write_text(
        "https://example.test/issues/42\n", encoding="utf-8"
    )
    fake_saturin = config.root / ".venv" / "bin" / "saturnin"
    fake_saturin.parent.mkdir(parents=True)
    fake_saturin.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = '--json' ] && [ \"$2\" = 'task' ] && [ \"$3\" = 'show' ]; then\n"
        "  printf '%s\\n' '{\"state\":\"done\"}'\n"
        "fi\n",
        encoding="utf-8",
    )
    fake_saturin.chmod(0o755)

    subprocess.run(
        ["bash", str(config.root / "automation/library/result_poller.sh")],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "SATURNIN_HOME": str(config.root)},
    )

    assert not run_marker.exists()
    assert not probe.exists()
    assert (pollers / f"{task_id}.sh.done").exists()
    assert not (pollers / f"{task_id}.escalated").exists()


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

    assert config.governance["review"]["pr"]["github_reviewer_logins"] == [
        "copilot-pull-request-reviewer[bot]"
    ]
    assert 'review_user.get("type") != "Bot"' in script
    assert "user.casefold() not in reviewer_logins" in script
    assert '"changes_requested", "rejected", "dismissed"' in script
    assert "state not in" in script
    assert "Imported from GitHub reviewer ${github_reviewer}" in script
    assert 'author="github:${pr_author}"' in script
    assert "saturnin_python -c '" in script
    assert "import json, sys, yaml" in script
