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
    r"^(?P<open><!-- generated:(?P<name>[a-z-]+) -->)\n(?P<body>.*?)"
    r"\n(?P<close><!-- /generated:(?P=name) -->)$",
    re.DOTALL | re.MULTILINE,
)
MARKER_TOKEN = re.compile(
    r"^<!-- (?P<close>/?)generated:(?P<name>[a-z-]+) -->$",
    re.MULTILINE,
)
MARKER_CANDIDATE = re.compile(
    r"<!--[ \t]*/?generated:[^\n]*(?:-->|$)",
    re.IGNORECASE,
)


class GeneratedBlockError(ValueError):
    pass


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


def _backlog_table(config: Config) -> str:
    items = config.policy("improvement").get("backlog", [])
    lines = ["| Gap | Severity | Fix |", "| --- | --- | --- |"]
    for item in items:
        title = " ".join(str(item.get("title") or item["id"]).split())
        fix = " ".join(str(item.get("recommendation", "")).split())
        lines.append(f"| `{item['id']}` - {title} | {item.get('severity', 'warn')} | {fix} |")
    return "\n".join(lines)


def _aslist(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


GENERATORS: dict[str, Callable[[Config], str]] = {
    "rules": _rules_table,
    "rules-list": _rules_list,
    "roles": _roles_table,
    "routing": _routing_table,
    "backlog": _backlog_table,
}


def render_text(text: str, config: Config) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        generator = GENERATORS.get(name)
        if generator is None:
            raise KeyError(f"unknown generated block: {name}")
        return match.group("open") + "\n" + generator(config).rstrip() + "\n" + match.group("close")

    return MARKER.sub(replace, text)


def _marker_problems(text: str, path: Path) -> list[str]:
    problems: list[str] = []
    tokens = list(MARKER_TOKEN.finditer(text))
    token_starts = {token.start() for token in tokens}
    for candidate in MARKER_CANDIDATE.finditer(text):
        if candidate.start() not in token_starts:
            line = text.count("\n", 0, candidate.start()) + 1
            problems.append(f"{path}:{line}: malformed generated marker")

    opened: tuple[str, int, int] | None = None
    for token in tokens:
        name = token.group("name")
        line = text.count("\n", 0, token.start()) + 1
        if not token.group("close"):
            if opened is not None:
                problems.append(
                    f"{path}:{line}: generated block {name!r} opens before "
                    f"{opened[0]!r} is closed"
                )
            else:
                opened = (name, line, token.start())
        elif opened is None:
            problems.append(
                f"{path}:{line}: generated block {name!r} has no opening marker"
            )
        elif opened[0] != name:
            problems.append(
                f"{path}:{line}: generated block {opened[0]!r} is closed as {name!r}"
            )
            opened = None
        else:
            block = text[opened[2] : token.end()]
            if MARKER.fullmatch(block) is None:
                problems.append(
                    f"{path}:{opened[1]}: generated block {name!r} does not match "
                    "the required newline-delimited grammar"
                )
            opened = None
    if opened is not None:
        problems.append(
            f"{path}:{opened[1]}: generated block {opened[0]!r} has no closing marker"
        )
    return problems


def documents(config: Config) -> list[Path]:
    """Every tracked markdown file that contains a generated marker."""
    roots = [config.root, config.root / "docs", config.root / "agents", config.root / ".github"]
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md") if root.name == "docs" else root.glob("*.md")):
            if MARKER_CANDIDATE.search(path.read_text(encoding="utf-8")):
                found.append(path)
    return found


def render(config: Config | None = None, *, write: bool = True) -> list[Path]:
    """Return the documents whose generated blocks were (or would be) updated."""
    config = config or default_config()
    stale: list[Path] = []
    for path in documents(config):
        current = path.read_text(encoding="utf-8")
        problems = _marker_problems(current, path.relative_to(config.root))
        if problems:
            raise GeneratedBlockError(problems[0])
        rendered = render_text(current, config)
        if rendered != current:
            stale.append(path)
            if write:
                path.write_text(rendered, encoding="utf-8")
    return stale


def audit(config: Config | None = None) -> list[str]:
    config = config or default_config()
    problems: list[str] = []
    for path in documents(config):
        problems.extend(
            _marker_problems(
                path.read_text(encoding="utf-8"),
                path.relative_to(config.root),
            )
        )
    if problems:
        return problems
    try:
        stale = render(config, write=False)
    except (GeneratedBlockError, KeyError) as error:
        return [str(error).strip("'")]
    if not stale:
        return []
    names = ", ".join(str(path.relative_to(config.root)) for path in stale)
    return [f"documentation has drifted from policy ({names}); run: saturnin docs render"]
