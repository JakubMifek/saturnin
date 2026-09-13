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


def test_duplicate_role_contracts_are_rejected(config: Config) -> None:
    duplicate = config.root / "agents" / "duplicate-code-worker.md"
    duplicate.write_text(
        "---\nrole: code-worker\nunit: engineering\nexecutes: true\nskills: []\nmcp: []\n---\n",
        encoding="utf-8",
    )
    assert any("duplicate agent contracts declare role 'code-worker'" in problem for problem in audit(config))
