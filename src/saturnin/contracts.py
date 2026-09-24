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
from .mcp import MCPError, server_process

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


def project_agent_path(worktree: Path, entry: Any, agents_dir: str) -> Path:
    """Resolve a project-local agent path without following it out of scope."""
    relative = Path(str(entry))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"agent path must stay inside the repository: {entry}")
    worktree_root = worktree.resolve(strict=False)
    agents_root = (worktree_root / agents_dir).resolve(strict=False)
    if not agents_root.is_relative_to(worktree_root):
        raise ValueError(
            f"project agents directory must stay inside the repository: {agents_dir}"
        )
    if not str(relative).startswith(f"{agents_dir}/"):
        raise ValueError(f"project agents belong in {agents_dir}/: {entry}")
    candidate = (worktree_root / relative).resolve(strict=False)
    if not candidate.is_relative_to(agents_root):
        raise ValueError(f"agent path must stay inside {agents_dir}: {entry}")
    return candidate


def mcp_authorization_problem(
    role: str,
    server: str,
    mcp_policy: dict[str, Any],
    *,
    executes: bool = True,
) -> str | None:
    servers = mcp_policy.get("servers", {})
    if server not in servers:
        return f"unknown MCP server {server!r}"
    rules = mcp_policy.get("rules", {})
    if rules.get("non_executing_roles_get_none", False) and not executes:
        return "non-executing roles get no MCP servers (the CEO delegates, it does not act)"
    denied: dict[str, list[str]] = rules.get("deny_for_roles", {})
    if server in denied.get(role, []):
        return f"MCP server {server!r} is denied for this role"
    definition = servers.get(server, {})
    write_roles = set(definition.get("write_roles", [])) if isinstance(definition, dict) else set()
    if write_roles and role not in write_roles:
        return f"role {role!r} is not allowed write access to MCP server {server!r}"
    return None


def load_contracts(config: Config | None = None) -> list[AgentContract]:
    config = config or default_config()
    contracts: list[AgentContract] = []
    for path in sorted((config.root / "agents").glob("*.md")):
        contract = _load_contract(path)
        if contract is not None:
            contracts.append(contract)
    return contracts


def _load_contract(path: Path) -> AgentContract | None:
    text = path.read_text(encoding="utf-8")
    match = FRONT_MATTER.match(text)
    if not match:
        if text.startswith("---"):
            raise ValueError("malformed YAML front matter")
        return None
    data = yaml.safe_load(match.group(1)) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML front matter must contain a mapping")
    if "role" not in data:
        raise ValueError("YAML front matter has no role")
    return AgentContract(role=str(data["role"]), path=path, front_matter=data)


def _contract_load_problem(path: Path, error: Exception, config: Config) -> str:
    relative = path.relative_to(config.root)
    if isinstance(error, OSError):
        detail = error.strerror or str(error)
        return f"{relative}: cannot read agent contract: {detail}"
    return f"{relative}: invalid agent contract front matter: {error}"


def audit(config: Config | None = None) -> list[str]:
    """Return every disagreement between contracts, routing and MCP policy."""
    config = config or default_config()
    problems: list[str] = []
    loaded_contracts: list[AgentContract] = []
    for path in sorted((config.root / "agents").glob("*.md")):
        try:
            contract = _load_contract(path)
        except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
            problems.append(_contract_load_problem(path, error, config))
            continue
        if contract is not None:
            loaded_contracts.append(contract)
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
    for name, definition in mcp_policy.get("servers", {}).items():
        if not isinstance(definition, dict):
            problems.append(f"MCP server {name!r} must be a mapping")
            continue
        try:
            server_process(str(name), definition, config)
        except (KeyError, MCPError) as exc:
            problems.append(f"MCP server {name!r}: {exc}")

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
            problem = mcp_authorization_problem(
                role, server, mcp_policy, executes=contract.executes
            )
            if problem:
                problems.append(f"{contract.path.name}: {problem}")
    notes = config.policy("repos").get("repos", {}).get("notes", {})
    access = notes.get("access", {})
    writers = access.get("writer_roles", [])
    scribe = config.routing.get("knowledge", {}).get("scribe_role")
    if writers != [scribe]:
        problems.append("private notes repository must declare the scribe as its sole writer")
    if access.get("non_writer_access") != "read-only":
        problems.append("private notes access for non-scribe roles must be read-only")
    if access.get("secrets_allowed") is not False:
        problems.append("private notes repository must forbid secrets")
    curation = notes.get("curation", {})
    required_curation = {
        "search_before_create",
        "atomic_notes",
        "stable_ids",
        "stable_aliases",
        "canonical_notes",
        "redirects",
        "maps_of_content",
        "optimize_for_read_only_lookup",
    }
    if any(curation.get(key) is not True for key in required_curation):
        problems.append("private notes curation policy is incomplete")
    if curation.get("public_bootstrap_application_role") != scribe:
        problems.append("public notes bootstrap packages may only be applied by the scribe")
    review = notes.get("change_review", {})
    if not all(
        review.get(key) is True for key in ("required", "independent", "zero_context")
    ):
        problems.append("private notes changes require independent zero-context review")
    if review.get("method") != "rubber-duck":
        problems.append("private notes changes require the rubber-duck review method")
    reviewers = review.get("allowed_reviewer_roles", [])
    if not isinstance(reviewers, list) or not reviewers or any(
        reviewer not in roles for reviewer in reviewers
    ):
        problems.append("private notes reviewers must be known roles")
    if scribe in reviewers:
        problems.append("private notes reviewer must be independent from the scribe")
    integration = config.policy("mcp").get("future_integrations", {}).get("notes", {})
    if integration.get("enabled") is not False or integration.get("write_roles") != []:
        problems.append("private notes MCP integration must remain disabled and write-free")
    if integration.get("non_scribe_access") != "read-only":
        problems.append("future non-scribe notes MCP access must be read-only")
    return problems
