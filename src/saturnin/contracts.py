"""Agent contract validation.

Every role exists twice on purpose: as prose in ``agents/<role>.md`` (what the
agent reads) and as data in ``policies/routing.yaml`` (what the router reads).
Two copies drift, so this module makes the two prove they agree and
``saturnin doctor`` fails when they do not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import Config, default_config

FRONT_MATTER = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


@dataclass(frozen=True)
class AgentContract:
    role: str
    path: Path
    front_matter: dict[str, Any]

    @property
    def unit(self) -> str | None:
        return self.front_matter.get("unit")

    @property
    def executes(self) -> bool:
        return bool(self.front_matter.get("executes", True))

    @property
    def skills(self) -> list[str]:
        return list(self.front_matter.get("skills", []))

    @property
    def mcp(self) -> list[str]:
        return list(self.front_matter.get("mcp", []))


def load_contracts(config: Config | None = None) -> list[AgentContract]:
    config = config or default_config()
    contracts: list[AgentContract] = []
    for path in sorted((config.root / "agents").glob("*.md")):
        match = FRONT_MATTER.match(path.read_text(encoding="utf-8"))
        if not match:
            continue
        data = yaml.safe_load(match.group(1)) or {}
        if not isinstance(data, dict) or "role" not in data:
            continue
        contracts.append(AgentContract(role=str(data["role"]), path=path, front_matter=data))
    return contracts


def audit(config: Config | None = None) -> list[str]:
    """Return every disagreement between contracts, routing and MCP policy."""
    config = config or default_config()
    problems: list[str] = []
    loaded_contracts = load_contracts(config)
    role_to_paths: dict[str, list[Path]] = {}
    for contract in loaded_contracts:
        role_to_paths.setdefault(contract.role, []).append(contract.path)
    for role, paths in sorted(role_to_paths.items()):
        if len(paths) > 1:
            problems.append(
                "duplicate agent contracts declare role "
                f"{role!r}: {', '.join(path.name for path in paths)}"
            )
    contracts = {c.role: c for c in loaded_contracts}
    roles: dict[str, dict[str, Any]] = config.routing.get("roles", {})

    missing_contract = sorted(set(roles) - set(contracts))
    if missing_contract:
        problems.append(
            "roles in policies/routing.yaml without an agents/<role>.md contract: "
            + ", ".join(missing_contract)
        )
    orphans = sorted(set(contracts) - set(roles))
    if orphans:
        problems.append(
            "agent contracts with no role in policies/routing.yaml: " + ", ".join(orphans)
        )

    skills = {
        path.stem
        for path in (config.root / "skills").glob("*.md")
        if path.name != "README.md"
    }
    mcp_policy = config.policy("mcp")
    servers = set(mcp_policy.get("servers", {}))
    denied: dict[str, list[str]] = mcp_policy.get("rules", {}).get("deny_for_roles", {})
    write_caps: dict[str, set[str]] = {
        server: set(server_def.get("write_roles", []))
        for server, server_def in mcp_policy.get("servers", {}).items()
        if isinstance(server_def, dict)
    }
    strict_non_executing = bool(
        mcp_policy.get("rules", {}).get("non_executing_roles_get_none", False)
    )

    for role, contract in contracts.items():
        catalog = roles.get(role)
        for skill in contract.skills:
            if skill not in skills:
                problems.append(f"{contract.path.name}: unknown skill {skill!r}")
        if catalog is None:
            continue
        if contract.unit != catalog.get("unit"):
            problems.append(
                f"{contract.path.name}: unit {contract.unit!r} != routing unit "
                f"{catalog.get('unit')!r}"
            )
        if contract.executes != bool(catalog.get("executes", True)):
            problems.append(f"{contract.path.name}: 'executes' disagrees with the role catalog")
        for server in contract.mcp:
            if server not in servers:
                problems.append(f"{contract.path.name}: unknown MCP server {server!r}")
            if server in denied.get(role, []):
                problems.append(
                    f"{contract.path.name}: MCP server {server!r} is denied for this role"
                )
            if server in write_caps and role not in write_caps[server] and write_caps[server]:
                problems.append(
                    f"{contract.path.name}: role {role!r} is not allowed write access to "
                    f"MCP server {server!r}"
                )
        if strict_non_executing and not contract.executes and contract.mcp:
            problems.append(
                f"{contract.path.name}: non-executing roles get no MCP servers "
                "(the CEO delegates, it does not act)"
            )
    return problems
