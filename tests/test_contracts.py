from __future__ import annotations

import pytest

from saturnin.config import Config
from saturnin.contracts import audit, load_contracts


def test_contracts_match_the_role_catalog(config: Config) -> None:
    assert audit(config) == []


def test_every_role_has_a_contract(config: Config) -> None:
    roles = set(config.routing["roles"])
    assert {c.role for c in load_contracts(config)} == roles


def test_drift_is_detected(config: Config) -> None:
    path = config.root / "agents" / "code-worker.md"
    path.write_text(path.read_text().replace("unit: engineering", "unit: catering"))
    problems = audit(config)
    assert any("catering" in problem for problem in problems)


def test_unknown_mcp_server_is_rejected(config: Config) -> None:
    path = config.root / "agents" / "researcher.md"
    path.write_text(path.read_text().replace("mcp: [fetch]", "mcp: [telepathy]"))
    assert any("telepathy" in problem for problem in audit(config))


def test_unknown_skill_in_orphan_contract_is_rejected(config: Config) -> None:
    path = config.root / "agents" / "researcher.md"
    path.write_text(
        path.read_text()
        .replace("role: researcher", "role: unrecognized-worker")
        .replace("skills: [board-ops]", "skills: [telepathy]")
    )
    assert any("unknown skill 'telepathy'" in problem for problem in audit(config))


def test_skills_readme_is_not_a_valid_skill(config: Config) -> None:
    path = config.root / "agents" / "researcher.md"
    path.write_text(path.read_text().replace("skills: [board-ops]", "skills: [README]"))
    assert any("unknown skill 'README'" in problem for problem in audit(config))


def test_ceo_gets_no_mcp_servers(config: Config) -> None:
    path = config.root / "agents" / "ceo.md"
    path.write_text(path.read_text().replace("mcp: []", "mcp: [github]"))
    assert any("non-executing" in problem for problem in audit(config))


def test_github_mcp_must_be_read_only(config: Config) -> None:
    config.policy("mcp")["servers"]["github"]["args"] = ["stdio"]

    assert any("effective --read-only" in problem for problem in audit(config))


def test_issue_reviewer_contract_declares_read_only_github_access(config: Config) -> None:
    issue_reviewer = next(contract for contract in load_contracts(config) if contract.role == "issue-reviewer")

    assert issue_reviewer.mcp == ["github"]
    assert audit(config) == []


def test_escalation_contracts_use_atomic_push_task_path(config: Config) -> None:
    chief = (config.root / "agents" / "chief-of-staff.md").read_text(encoding="utf-8")
    skill = (config.root / "skills" / "escalation.md").read_text(encoding="utf-8")

    assert "--task <task-id> --push" in chief
    assert "--task <id> --push" in skill


def test_duplicate_role_contracts_are_rejected(config: Config) -> None:
    duplicate = config.root / "agents" / "duplicate-code-worker.md"
    duplicate.write_text(
        "---\nrole: code-worker\nunit: engineering\nexecutes: true\nskills: []\nmcp: []\n---\n",
        encoding="utf-8",
    )
    assert any("duplicate agent contracts declare role 'code-worker'" in problem for problem in audit(config))


def test_private_notes_policy_has_one_writer_and_independent_review(
    config: Config,
) -> None:
    notes = config.policy("repos")["repos"]["notes"]

    assert notes["access"]["writer_roles"] == ["scribe"]
    assert notes["access"]["non_writer_access"] == "read-only"
    assert notes["change_review"]["allowed_reviewer_roles"] == ["pr-reviewer"]
    assert notes["change_review"]["independent"] is True
    assert audit(config) == []


def test_private_notes_non_scribe_writer_is_rejected(config: Config) -> None:
    config.policy("repos")["repos"]["notes"]["access"]["writer_roles"].append(
        "code-worker"
    )

    assert any("sole writer" in problem for problem in audit(config))


def test_public_bootstrap_cannot_authorize_non_scribe_application(
    config: Config,
) -> None:
    config.policy("repos")["repos"]["notes"]["curation"][
        "public_bootstrap_application_role"
    ] = "code-worker"

    assert any("bootstrap packages" in problem for problem in audit(config))


def test_notes_mcp_stays_disabled_read_only_and_write_free(config: Config) -> None:
    integration = config.policy("mcp")["future_integrations"]["notes"]

    assert integration == {
        "enabled": False,
        "repository": "notes",
        "non_scribe_access": "read-only",
        "write_roles": [],
    }
    integration["write_roles"] = ["scribe"]
    assert any("disabled and write-free" in problem for problem in audit(config))
