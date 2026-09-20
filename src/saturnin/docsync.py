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
    r"<!--[ \t]*/?[ \t]*generated(?:"
    r":[^\n]*(?:-->|(?=\n)|\Z)"
    r"|[ \t]+:?[ \t]*[a-z-]+[ \t]*-->)",
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


def _capabilities_table(config: Config) -> str:
    capability = config.governance.get("documentation", {}).get("capability")
    if not isinstance(capability, dict):
        raise GeneratedBlockError("governance documentation.capability must be a mapping")
    description = capability.get("description")
    command = capability.get("command")
    if not isinstance(description, str) or not description:
        raise GeneratedBlockError(
            "governance documentation.capability.description must be a non-empty string"
        )
    if not isinstance(command, str) or not command:
        raise GeneratedBlockError(
            "governance documentation.capability.command must be a non-empty string"
        )
    rows = [
        ("Task intake + centralised board", r"saturnin task add\|list\|show\|move\|attach"),
        ("Work hierarchy (objective/epic/feature/task)", "saturnin task tree`, `--parent"),
        (
            "Optional GitHub issue mirror; durable copy once mirroring is enabled",
            "saturnin task sync --all --push",
        ),
        ("Ultra-fast dispatch (table lookup, no deliberation)", r"saturnin dispatch <id> \| --all"),
        (description, command),
        (
            "Independent PR/issue review pipelines",
            r"saturnin review attest\|record\|gate\|merge\|submit-issue",
        ),
        ("Checkpoints, handoff and delayed resume", r"saturnin checkpoint save\|resume"),
        ("Worktree lifecycle + safe stale cleanup", r"saturnin worktree create\|list\|cleanup"),
        (
            "Reusable automation library + repeat detection",
            r"saturnin automation find\|list\|detect",
        ),
        ("Human escalation issues", "saturnin escalate"),
        ("Continuous self-improvement loop", "saturnin improve`, `saturnin board metrics"),
        ("Managed-repo contract validation", "saturnin repo check <path>"),
        ("Documentation generated from policy", "saturnin docs render [--check]"),
    ]
    lines = ["| Capability | Command |", "| --- | --- |"]
    lines.extend(f"| {name} | `{command}` |" for name, command in rows)
    return "\n".join(lines)


def _governance_documentation(config: Config, name: str) -> str:
    value = config.governance.get("documentation", {}).get(name)
    if not isinstance(value, str) or not value.strip():
        raise GeneratedBlockError(
            f"governance documentation.{name} must be a non-empty string"
        )
    return value


def _review_flow(config: Config, kind: str) -> str:
    review = config.governance.get("review", {}).get(kind)
    if not isinstance(review, dict):
        raise GeneratedBlockError(f"governance review.{kind} must be a mapping")
    roles = review.get("allowed_reviewer_roles")
    if not isinstance(roles, list) or not roles or not all(isinstance(role, str) for role in roles):
        raise GeneratedBlockError(
            f"governance review.{kind}.allowed_reviewer_roles must be a non-empty string list"
        )
    reviewer = roles[0]
    if kind == "pr":
        repo = config.governance.get("autonomy", {}).get("self_repo", "<owner/repo>")
        return "\n".join(
            [
                "```bash",
                f'HEAD_SHA="$(gh pr view <N> --repo {repo} --json headRefOid --jq .headRefOid)"',
                "VERDICT=approved",
                f'attestation="$(saturnin review attest {repo}#<N> --kind pr \\',
                f'  --author <author-role> --reviewer {reviewer} --verdict "$VERDICT" \\',
                '  --head-sha "$HEAD_SHA")"',
                f"saturnin review record {repo}#<N> --kind pr \\",
                f'  --author <author-role> --reviewer {reviewer} --verdict "$VERDICT" \\',
                '  --head-sha "$HEAD_SHA" --attestation "$attestation"',
                f"saturnin review gate {repo}#<N> --kind pr \\",
                f'  --repo {repo} --author <author-role> --head-sha "$HEAD_SHA"',
                "```",
                "",
                "Resolve the PR head once and pass that identical SHA through "
                "attest, record and gate.",
            ]
        )
    if kind == "issue":
        return "\n".join(
            [
                "```bash",
                "digest=\"$(python -c 'from saturnin.review import "
                "issue_content_digest; print(issue_content_digest(\"TITLE\", \"BODY\"))')\"",
                "VERDICT=approved",
                'attestation="$(saturnin review attest <draft-id> --kind issue \\',
                "  --repo <owner/repo> --author <author-role> \\",
                f'  --reviewer {reviewer} --verdict "$VERDICT" \\',
                '  --issue-digest "$digest")"',
                "saturnin review record <draft-id> --kind issue \\",
                "  --repo <owner/repo> --author <author-role> \\",
                f'  --reviewer {reviewer} --verdict "$VERDICT" \\',
                '  --issue-digest "$digest" --attestation "$attestation"',
                "saturnin review gate <draft-id> --kind issue \\",
                '  --repo <owner/repo> --author <author-role> --issue-digest "$digest"',
                "```",
                "",
                "Compute the digest from the exact title and body under review, "
                "then pass that identical digest through attest, record and gate.",
            ]
        )
    raise GeneratedBlockError(f"unknown review flow: {kind}")


def _pr_review_flow(config: Config) -> str:
    return _review_flow(config, "pr")


def _issue_review_flow(config: Config) -> str:
    return _review_flow(config, "issue")


def _runtime_summary(config: Config) -> str:
    return _governance_documentation(config, "runtime_summary")


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
    "capabilities": _capabilities_table,
    "runtime-summary": _runtime_summary,
    "pr-review-flow": _pr_review_flow,
    "issue-review-flow": _issue_review_flow,
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
    return [
        path
        for path in _document_candidates(config)
        if MARKER_CANDIDATE.search(path.read_text(encoding="utf-8"))
    ]


def _document_candidates(config: Config) -> list[Path]:
    roots = [
        config.root,
        config.root / "docs",
        config.root / "agents",
        config.root / "skills",
        config.root / ".github",
    ]
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md") if root.name == "docs" else root.glob("*.md")):
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
    readable_documents: list[tuple[Path, str]] = []
    for path in _document_candidates(config):
        relative = path.relative_to(config.root)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            detail = error.strerror if isinstance(error, OSError) else str(error)
            problems.append(f"{relative}: cannot read documentation: {detail}")
            continue
        if MARKER_CANDIDATE.search(text):
            readable_documents.append((path, text))

    for path, text in readable_documents:
        problems.extend(
            _marker_problems(
                text,
                path.relative_to(config.root),
            )
        )
    if problems:
        return problems
    try:
        stale = [
            path
            for path, text in readable_documents
            if render_text(text, config) != text
        ]
    except (GeneratedBlockError, KeyError) as error:
        return [str(error).strip("'")]
    if not stale:
        return []
    names = ", ".join(str(path.relative_to(config.root)) for path in stale)
    return [f"documentation has drifted from policy ({names}); run: saturnin docs render"]
