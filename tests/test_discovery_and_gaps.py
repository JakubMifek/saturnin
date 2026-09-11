"""Inbound discovery, the declared gap backlog and project-local agents."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from saturnin.board import Board
from saturnin.cli import check_managed_repo, main
from saturnin.config import Config
from saturnin.discovery import InboundIssue, IssueDiscovery
from saturnin.improve import ImprovementLoop


def _issue(number: int, *, labels: list[str] | None = None) -> InboundIssue:
    return InboundIssue(
        repo="JakubMifek/widget-api",
        number=number,
        title=f"Alert: widget-api p99 over budget ({number})",
        url=f"https://github.com/JakubMifek/widget-api/issues/{number}",
        body="p99 latency above 800ms for 10 minutes.",
        labels=labels or ["alert"],
    )


def _discovery(config: Config, board: Board, issues: list[InboundIssue]) -> IssueDiscovery:
    config.policy("repos")["discovery"]["sources"] = ["JakubMifek/widget-api"]
    return IssueDiscovery(config, board, fetcher=lambda repo, labels: list(issues))


def test_inbound_issue_becomes_a_routed_task(config: Config, board: Board) -> None:
    discovery = _discovery(config, board, [_issue(7)])
    created = discovery.ingest(discovery.poll())
    assert len(created) == 1
    task = created[0]
    assert task.repo == "JakubMifek/widget-api"
    assert "source:jakubmifek/widget-api#7" in task.labels
    assert "alert" in task.labels
    assert task.priority == "P0"
    assert "issues/7" in task.body


def test_discovery_never_adopts_the_same_issue_twice(config: Config, board: Board) -> None:
    discovery = _discovery(config, board, [_issue(7), _issue(8)])
    assert len(discovery.run()) == 2
    assert discovery.run() == []
    assert len(list(board)) == 2


def test_concurrent_discovery_atomically_deduplicates(config: Config, board: Board) -> None:
    issue = _issue(77)

    def ingest(_: int):
        return _discovery(config, board, [issue]).ingest([issue])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(ingest, range(16)))

    assert sum(len(result) for result in results) == 1
    assert len(list(board)) == 1


def test_discovery_normalizes_source_markers(config: Config, board: Board) -> None:
    discovery = _discovery(config, board, [_issue(7)])
    discovery.run()
    case_variant = _issue(7)
    case_variant.repo = "jakubmifek/WIDGET-API"

    assert discovery.ingest([case_variant]) == []


def test_priority_falls_back_to_the_default(config: Config, board: Board) -> None:
    discovery = _discovery(config, board, [_issue(9, labels=["question"])])
    task = discovery.run()[0]
    assert task.priority == "P2"
    assert task.labels == ["source:jakubmifek/widget-api#9"]


def test_carried_labels_and_priority_match_regardless_of_case(config: Config, board: Board) -> None:
    discovery = _discovery(config, board, [_issue(11, labels=["Alert", "INCIDENT"])])
    task = discovery.run()[0]
    assert task.priority == "P0"
    assert "alert" in task.labels or "Alert" in task.labels
    assert any(label.casefold() == "alert" for label in task.labels)
    assert any(label.casefold() == "incident" for label in task.labels)


def test_discovery_respects_the_enabled_switch(config: Config, board: Board) -> None:
    policy = config.policy("repos")
    policy["discovery"]["enabled"] = False
    discovery = _discovery(config, board, [_issue(10)])
    assert discovery.poll() == []


def test_sources_accept_plain_slugs_and_mappings(config: Config, board: Board) -> None:
    policy = config.policy("repos")
    policy["discovery"]["sources"] = ["a/one", {"slug": "a/two", "labels": ["ops"]}]
    discovery = IssueDiscovery(config, board)
    sources = discovery.sources()
    assert [s["slug"] for s in sources] == ["a/one", "a/two"]
    assert sources[0]["labels"] == discovery.labels
    assert sources[1]["labels"] == ["ops"]


def test_public_task_intake_is_a_discovery_source(config: Config, board: Board) -> None:
    sources = IssueDiscovery(config, board).sources()
    assert {
        "slug": "JakubMifek/saturnin",
        "labels": ["saturnin:task"],
    } in sources


def test_discover_command_reports_when_there_is_nothing(config: Config, capsys) -> None:
    policy_path = config.policies / "repos.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["discovery"]["sources"] = []
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    assert main(["--home", str(config.root), "discover", "--dry-run"]) == 0
    assert "nothing new to adopt" in capsys.readouterr().out


def test_declared_gaps_become_board_tasks(config: Config, board: Board) -> None:
    loop = ImprovementLoop(config, board)
    gaps = loop.backlog()
    assert gaps, "the improvement policy declares no backlog"
    assert any(gap.id == "cost-accounting" for gap in gaps)

    report = loop.run()
    titles = {task.title for task in board}
    assert any(title.startswith("Gap: ") for title in titles)
    assert len(report.proposed_tasks) >= len(gaps)

    filed = [task for task in board if "gap" in task.labels]
    assert {f"finding:{gap.id}" for gap in gaps} <= {
        label for task in filed for label in task.labels
    }

    # Running the loop again must not duplicate a gap that is already filed.
    loop.run()
    assert len([task for task in board if "gap" in task.labels]) == len(gaps)


def test_gap_table_is_generated_from_policy(config: Config) -> None:
    from saturnin import docsync

    rendered = docsync.render_text(
        "<!-- generated:backlog -->\nstale\n<!-- /generated:backlog -->", config
    )
    assert "cost-accounting" in rendered
    assert "stale" not in rendered


@pytest.fixture()
def project(tmp_path):
    repo = tmp_path / "widget-api"
    (repo / ".saturnin" / "agents").mkdir(parents=True)
    (repo / ".github").mkdir(parents=True)
    (repo / ".github" / "copilot-instructions.md").write_text("see AGENTS.md\n")
    return repo


def _manifest(repo, agents: str) -> None:
    (repo / ".saturnin" / "repo.yaml").write_text(
        "project: Widget\ncontext: python service\nsquad: [code-worker]\n"
        f"conventions: pytest\nagents: [{agents}]\n"
    )


def test_project_agent_must_live_inside_the_project(project, config: Config) -> None:
    _manifest(project, "../../agents/code-worker.md")
    assert any("stay inside" in p for p in check_managed_repo(project, config))

    _manifest(project, "/etc/passwd")
    assert any("stay inside" in p for p in check_managed_repo(project, config))

    _manifest(project, "docs/db-migrator.md")
    assert any(".saturnin/agents/" in p for p in check_managed_repo(project, config))


def test_project_agent_must_exist_and_not_shadow_a_global_role(
    project, config: Config
) -> None:
    _manifest(project, ".saturnin/agents/db-migrator.md")
    assert any("missing" in p for p in check_managed_repo(project, config))

    (project / ".saturnin" / "agents" / "local-worker.md").write_text(
        "---\nrole: code-worker\nskills: []\nmcp: []\n---\n"
    )
    _manifest(project, ".saturnin/agents/local-worker.md")
    problems = check_managed_repo(project, config)
    assert any("shadows" in p for p in problems)
    assert any("must match its filename" in p for p in problems)

    (project / ".saturnin" / "agents" / "code-worker.md").write_text("# local\n")
    _manifest(project, ".saturnin/agents/code-worker.md")
    assert any("missing YAML front matter" in p for p in check_managed_repo(project, config))

    (project / ".saturnin" / "agents" / "db-migrator.md").write_text(
        "---\n"
        "role: db-migrator\n"
        "skills: [checkpointing]\n"
        "mcp: [github]\n"
        "---\n"
        "# Migrations\n"
    )
    _manifest(project, ".saturnin/agents/db-migrator.md")
    assert check_managed_repo(project, config) == []


def test_project_agent_validates_skill_and_mcp_declarations(
    project, config: Config
) -> None:
    agent = project / ".saturnin" / "agents" / "db-migrator.md"
    agent.write_text(
        "---\n"
        "role: db-migrator\n"
        "skills: [made-up-skill]\n"
        "mcp: [made-up-server]\n"
        "---\n"
    )
    _manifest(project, ".saturnin/agents/db-migrator.md")

    problems = check_managed_repo(project, config)
    assert any("unknown skill 'made-up-skill'" in p for p in problems)
    assert any("unknown MCP server 'made-up-server'" in p for p in problems)
