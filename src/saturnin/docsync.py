"""Generated documentation blocks.

The same rule written in two places becomes two different rules. Anything that
also exists in ``policies/*.yaml`` is therefore *generated* into the docs
between markers, and ``saturnin docs render --check`` (run by ``doctor`` and by
CI) fails when the checked-in text no longer matches the policy.

Markers::

    <!-- generated:rules -->
    ...anything here is overwritten...
    <!-- /generated:rules -->
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from .config import Config, default_config

MARKER = re.compile(
    r"(?P<open><!-- generated:(?P<name>[a-z-]+) -->\n)(?P<body>.*?)"
    r"(?P<close><!-- /generated:(?P=name) -->)",
    re.DOTALL,
)


def _rules_table(config: Config) -> str:
    rules = config.governance.get("rules", [])
    lines = ["| # | Rule | Enforced by |", "| --- | --- | --- |"]
    lines += [f"| {r['id']} | {r['summary']} | {r['enforced_by']} |" for r in rules]
    return "\n".join(lines)


def _rules_list(config: Config) -> str:
    rules = config.governance.get("rules", [])
    return "\n".join(f"{r['id']}. {r['summary']}." for r in rules)


def _roles_table(config: Config) -> str:
    roles: dict[str, dict[str, Any]] = config.routing.get("roles", {})
    lines = ["| Role | Unit | Executes | Purpose |", "| --- | --- | --- | --- |"]
    for role, meta in roles.items():
        executes = "yes" if meta.get("executes", True) else "**never**"
        description = " ".join(str(meta.get("description", "")).split())
        lines.append(f"| `{role}` | {meta.get('unit', '-')} | {executes} | {description} |")
    return "\n".join(lines)


def _routing_table(config: Config) -> str:
    rules = config.routing.get("rules", [])
    default = config.routing.get("default_route", {})
    lines = ["| Rule | Matches | Goes to | Priority | Results via |", "| --- | --- | --- | --- | --- |"]
    for rule in rules:
        when = rule.get("when", {})
        match = "; ".join(f"{key}: {', '.join(map(str, _aslist(value)))}" for key, value in when.items())
        route = rule.get("route", {})
        lines.append(
            f"| `{rule.get('id')}` | {match} | `{route.get('role')}` | "
            f"{route.get('priority', 'P2')} | "
            f"{route.get('result_contract', config.routing.get('default_result_contract', '-'))} |"
        )
    lines.append(
        f"| _default_ | anything else | `{default.get('role')}` | "
        f"{default.get('priority', 'P2')} | {default.get('result_contract', '-')} |"
    )
    return "\n".join(lines)


def _aslist(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


GENERATORS: dict[str, Callable[[Config], str]] = {
    "rules": _rules_table,
    "rules-list": _rules_list,
    "roles": _roles_table,
    "routing": _routing_table,
}


def render_text(text: str, config: Config) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        generator = GENERATORS.get(name)
        if generator is None:
            raise KeyError(f"unknown generated block: {name}")
        return match.group("open") + generator(config).rstrip() + "\n" + match.group("close")

    return MARKER.sub(replace, text)


def documents(config: Config) -> list[Path]:
    """Every tracked markdown file that contains a generated block."""
    roots = [config.root, config.root / "docs", config.root / "agents", config.root / ".github"]
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md") if root.name == "docs" else root.glob("*.md")):
            if MARKER.search(path.read_text(encoding="utf-8")):
                found.append(path)
    return found


def render(config: Config | None = None, *, write: bool = True) -> list[Path]:
    """Return the documents whose generated blocks were (or would be) updated."""
    config = config or default_config()
    stale: list[Path] = []
    for path in documents(config):
        current = path.read_text(encoding="utf-8")
        rendered = render_text(current, config)
        if rendered != current:
            stale.append(path)
            if write:
                path.write_text(rendered, encoding="utf-8")
    return stale


def audit(config: Config | None = None) -> list[str]:
    config = config or default_config()
    stale = render(config, write=False)
    if not stale:
        return []
    names = ", ".join(str(path.relative_to(config.root)) for path in stale)
    return [f"documentation has drifted from policy ({names}); run: saturnin docs render"]
