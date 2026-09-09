"""Command line interface - the only supported entry point for humans and agents.

Everything an agent needs to do (intake, dispatch, review gates, checkpoints,
cleanup, improvement) is available here so that agents stay thin and the rules
stay in one place.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import yaml

from . import escalation as escalation_mod
from . import telemetry
from .automation import AutomationLibrary
from .board import CONTAINER_KINDS, Board, BoardError, Task
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config
from .contracts import FRONT_MATTER, audit as audit_contracts
from .discovery import DiscoveryError, IssueDiscovery
from . import docsync
from .governance import Governance
from .improve import ImprovementLoop
from .issues import IssueMirror, MirrorError
from .review import ReviewLedger
from .routing import Router, RoutingError
from .worktrees import GitError, WorktreeManager


def _emit(data: Any, as_json: bool, text: str | None = None) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(text if text is not None else data)


def _task_line(task: Task) -> str:
    return (
        f"{task.id}  {task.priority}  {task.state:<11} "
        f"{(task.role or '-'):<16} {task.title}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="saturnin", description="Saturnin orchestrator CLI")
    parser.add_argument("--home", help="Saturnin home directory (default: autodetected)")
    parser.add_argument("--json", action="store_true", help="machine readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    # task ------------------------------------------------------------
    task = sub.add_parser("task", help="work board operations").add_subparsers(
        dest="task_command", required=True
    )
    add = task.add_parser("add", help="intake a new task")
    add.add_argument("title")
    add.add_argument("--body", default="")
    add.add_argument("--kind", default="task")
    add.add_argument("--label", action="append", default=[])
    add.add_argument("--repo")
    add.add_argument("--priority", default="P2")
    add.add_argument("--parent", help="objective/epic/feature this work belongs to")
    add.add_argument("--dispatch", action="store_true", help="route it immediately")

    listing = task.add_parser("list", help="list tasks")
    listing.add_argument("--state")
    listing.add_argument("--role")
    listing.add_argument("--priority")
    listing.add_argument("--open", action="store_true", dest="open_only")

    show = task.add_parser("show", help="show one task")
    show.add_argument("task_id")

    move = task.add_parser("move", help="change task state")
    move.add_argument("task_id")
    move.add_argument("state")
    move.add_argument("--actor", default=None, help="default: the configured CEO role")
    move.add_argument("--note", default="")

    tree = task.add_parser("tree", help="show the work hierarchy")
    tree.add_argument("task_id", nargs="?", help="root; default: every top level item")

    sync = task.add_parser("sync", help="mirror tasks as GitHub issues (rule 8)")
    sync.add_argument("task_id", nargs="?")
    sync.add_argument(
        "--all", action="store_true", help="every open task eligible for mirroring"
    )
    sync.add_argument("--push", action="store_true", help="actually call gh; default is a preview")

    attach = task.add_parser("attach", help="attach a branch/worktree to a task")
    attach.add_argument("task_id")
    attach.add_argument("--branch")
    attach.add_argument("--worktree")
    attach.add_argument("--actor")

    # dispatch ---------------------------------------------------------
    dispatch = sub.add_parser("dispatch", help="route tasks to executing roles")
    dispatch.add_argument("task_id", nargs="?")
    dispatch.add_argument("--all", action="store_true", help="dispatch everything in intake")
    dispatch.add_argument("--dry-run", action="store_true", help="show the route only")
    dispatch.add_argument(
        "--squad",
        action="append",
        default=[],
        help="assemble an ad-hoc squad for this task (repeatable)",
    )

    # discover ---------------------------------------------------------
    discover = sub.add_parser(
        "discover", help="adopt issues from managed repositories as board tasks"
    )
    discover.add_argument("--dry-run", action="store_true", help="list what would be adopted")
    discover.add_argument(
        "--no-dispatch", action="store_true", help="adopt without routing immediately"
    )

    # board ------------------------------------------------------------
    board_cmd = sub.add_parser("board", help="board overview").add_subparsers(
        dest="board_command", required=True
    )
    board_cmd.add_parser("metrics", help="throughput and bottleneck metrics")
    board_cmd.add_parser("roles", help="role catalog")

    # worktree ---------------------------------------------------------
    worktree = sub.add_parser("worktree", help="worktree lifecycle").add_subparsers(
        dest="worktree_command", required=True
    )
    create = worktree.add_parser("create", help="create a feature branch worktree")
    create.add_argument("branch")
    create.add_argument("--base")
    create.add_argument("--task")
    create.add_argument("--actor")
    worktree.add_parser("list", help="list worktrees")
    cleanup = worktree.add_parser("cleanup", help="plan (and optionally apply) stale cleanup")
    cleanup.add_argument("--apply", action="store_true", help="actually remove things")

    # checkpoint -------------------------------------------------------
    checkpoint = sub.add_parser("checkpoint", help="checkpoint / handoff").add_subparsers(
        dest="checkpoint_command", required=True
    )
    save = checkpoint.add_parser("save", help="store a handoff checkpoint")
    save.add_argument("task_id")
    save.add_argument("--role", required=True)
    save.add_argument("--summary", required=True)
    save.add_argument("--next", action="append", default=[], dest="next_steps")
    save.add_argument("--blocker", action="append", default=[], dest="blockers")
    save.add_argument("--artifact", action="append", default=[], dest="artifacts")
    save.add_argument("--branch")
    save.add_argument("--worktree")
    save.add_argument("--resume-after")
    resume = checkpoint.add_parser("resume", help="print the handoff note")
    resume.add_argument("task_id")

    # review -----------------------------------------------------------
    review = sub.add_parser("review", help="independent review pipelines").add_subparsers(
        dest="review_command", required=True
    )
    record = review.add_parser("record", help="record a review verdict")
    record.add_argument("subject", help="e.g. owner/repo#12 or issue draft id")
    record.add_argument("--kind", choices=["pr", "issue"], required=True)
    record.add_argument("--author", required=True)
    record.add_argument("--reviewer", required=True)
    record.add_argument("--verdict", required=True)
    record.add_argument("--notes", default="")
    record.add_argument(
        "--with-context",
        action="store_true",
        help="reviewer had prior context (fails the zero-context gate)",
    )
    record.add_argument("--head-sha", default="", help="reviewed commit SHA for PR reviews")
    gate = review.add_parser("gate", help="check whether merge/submission is allowed")
    gate.add_argument("subject")
    gate.add_argument("--kind", choices=["pr", "issue"], required=True)
    gate.add_argument("--repo", required=True)
    gate.add_argument("--author", required=True)
    gate.add_argument("--head-sha", default="", help="current PR head SHA to match reviews against")

    # governance -------------------------------------------------------
    gov = sub.add_parser("check", help="governance checks").add_subparsers(
        dest="check_command", required=True
    )
    branch = gov.add_parser("branch", help="is this branch acceptable?")
    branch.add_argument("branch")
    command = gov.add_parser("command", help="is this server command inside scope?")
    command.add_argument("cmdline", help="the shell command Saturnin wants to run")
    command.add_argument(
        "--service",
        help="Saturnin-dedicated service that requires an apt command",
    )

    # escalate ---------------------------------------------------------
    esc = sub.add_parser("escalate", help="render a human escalation issue body")
    esc.add_argument("title")
    esc.add_argument("--context", default="")
    esc.add_argument("--item", action="append", default=[], dest="checklist")
    esc.add_argument("--unblock", action="append", default=[], dest="unblock")
    esc.add_argument("--urgency", default="normal")
    esc.add_argument("--task")
    esc.add_argument("--actor", default="chief-of-staff", help="role performing the escalation")
    esc.add_argument("--push", action="store_true", help="submit to the configured board repo")

    # automation -------------------------------------------------------
    automation = sub.add_parser("automation", help="reusable automation library").add_subparsers(
        dest="automation_command", required=True
    )
    automation.add_parser("list", help="list registered automations")
    find = automation.add_parser("find", help="search before you build")
    find.add_argument("query", nargs="+")
    detect = automation.add_parser("detect", help="detect repeated work")
    detect.add_argument("--threshold", type=int, default=3)
    detect.add_argument("--propose", action="store_true", help="file automation tasks")

    # improve / doctor -------------------------------------------------
    improve = sub.add_parser("improve", help="run the self-improvement loop")
    improve.add_argument("--no-tasks", action="store_true", help="report only, file nothing")
    repo_cmd = sub.add_parser("repo", help="managed repository contract").add_subparsers(
        dest="repo_command", required=True
    )
    repo_check = repo_cmd.add_parser("check", help="validate a managed repo against the contract")
    repo_check.add_argument("path", nargs="?", default=".")

    docs_cmd = sub.add_parser("docs", help="generated documentation blocks").add_subparsers(
        dest="docs_command", required=True
    )
    docs_render = docs_cmd.add_parser("render", help="regenerate policy tables inside the docs")
    docs_render.add_argument(
        "--check", action="store_true", help="fail instead of writing when docs are stale"
    )

    sub.add_parser("doctor", help="validate policies and installation")

    return parser


def _tree_dict(board: Board, task: Task, lines: list[str], depth: int) -> dict[str, Any]:
    marker = {"done": "x", "cancelled": "-"}.get(task.state, " ")
    suffix = ""
    if task.kind in CONTAINER_KINDS:
        roll = board.rollup(task.id)
        suffix = f"  [{roll['done']}/{roll['leaves']} done, {roll['percent']}%]"
    lines.append(f"{'  ' * depth}[{marker}] {task.id} ({task.kind}) {task.title}{suffix}")
    node = task.to_dict()
    node["children"] = [_tree_dict(board, c, lines, depth + 1) for c in board.children(task.id)]
    return node


def _mirror_audit(config: Config, board: Board) -> list[str]:
    """Rule 8: warn when open work exists only on this machine."""
    mirror = IssueMirror(config, board)
    if not mirror.enabled:
        return []
    unmirrored = mirror.unmirrored()
    if not unmirrored:
        return []
    return [
        f"{len(unmirrored)} open task(s) are not mirrored as issues and would be lost with "
        f"this machine: {', '.join(t.id for t in unmirrored[:5])}"
        + (" ..." if len(unmirrored) > 5 else "")
        + " - run: saturnin task sync --all --push"
    ]


def check_managed_repo(path: Path, config: Config) -> list[str]:
    """Validate a Saturnin-managed repository against the contract.

    The contract lives in ``policies/repos.yaml``; it is what lets Saturnin
    dispatch into a project repository without first re-learning it.
    """
    contract = config.policy("repos").get("managed_repo_contract", {})
    problems: list[str] = []
    for required in contract.get("required_files", []):
        if not (path / required).is_file():
            problems.append(f"missing required file: {required}")
    manifest_path = path / ".saturnin" / "repo.yaml"
    if not manifest_path.is_file():
        return problems
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return problems + [f".saturnin/repo.yaml is not valid YAML: {exc}"]
    if not isinstance(manifest, dict):
        return problems + [".saturnin/repo.yaml must contain a mapping"]
    for key in contract.get("required_keys", []):
        if not manifest.get(key):
            problems.append(f".saturnin/repo.yaml is missing required key: {key}")
    roles = config.routing.get("roles", {})
    squad = manifest.get("squad") or []
    if isinstance(squad, list):
        unknown = [role for role in squad if role not in roles]
        if unknown:
            problems.append(f"squad names roles that are not in the catalog: {', '.join(unknown)}")
    else:
        problems.append("squad must be a list of role ids")
    problems += _check_project_agents(path, manifest, contract, roles, config)
    return problems


def _check_project_agents(
    path: Path,
    manifest: dict[str, Any],
    contract: dict[str, Any],
    roles: dict[str, Any],
    config: Config,
) -> list[str]:
    """A project-specific role must live inside the project it belongs to.

    Keeping it there means it is reviewed by the people who own the code it
    touches, travels with the repository, and cannot quietly become a
    dependency of the global catalog.
    """
    entries = manifest.get("agents") or []
    if not isinstance(entries, list):
        return ["agents must be a list of paths inside the repository"]
    agents_dir = str(contract.get("agents_dir", ".saturnin/agents"))
    known_skills = {
        skill.stem
        for skill in (config.root / "skills").glob("*.md")
        if skill.name != "README.md"
    }
    known_mcp = set(config.policy("mcp").get("servers", {}))
    problems: list[str] = []
    for entry in entries:
        rel = str(entry)
        if Path(rel).is_absolute() or ".." in Path(rel).parts:
            problems.append(f"agent path must stay inside the repository: {rel}")
            continue
        if not rel.startswith(f"{agents_dir}/"):
            problems.append(f"project agents belong in {agents_dir}/: {rel}")
            continue
        agent_path = path / rel
        if not agent_path.is_file():
            problems.append(f"agent contract declared but missing: {rel}")
            continue
        match = FRONT_MATTER.match(agent_path.read_text(encoding="utf-8"))
        if not match:
            problems.append(f"project agent {rel} is missing YAML front matter")
            continue
        try:
            front_matter = yaml.safe_load(match.group(1)) or {}
        except yaml.YAMLError as exc:
            problems.append(f"project agent {rel} has invalid YAML front matter: {exc}")
            continue
        if not isinstance(front_matter, dict):
            problems.append(f"project agent {rel} front matter must contain a mapping")
            continue
        role_id = front_matter.get("role")
        if not isinstance(role_id, str) or not role_id:
            problems.append(f"project agent {rel} must declare a role")
            continue
        if role_id != Path(rel).stem:
            problems.append(
                f"project agent {rel} declares role '{role_id}', which must match its filename"
            )
        if role_id in roles:
            problems.append(
                f"project agent {rel} shadows the global role '{role_id}'; "
                "give the project role its own id"
            )
        for field, known, description in (
            ("skills", known_skills, "skill"),
            ("mcp", known_mcp, "MCP server"),
        ):
            declarations = front_matter.get(field, [])
            if not isinstance(declarations, list) or not all(
                isinstance(value, str) for value in declarations
            ):
                problems.append(f"project agent {rel} {field} must be a list of ids")
                continue
            for value in declarations:
                if value not in known:
                    problems.append(f"project agent {rel}: unknown {description} {value!r}")
    return problems

def _config(args: argparse.Namespace) -> Config:
    return Config.load(Path(args.home) if args.home else None)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = _config(args)
    config.ensure_dirs()
    try:
        return _run(args, config)
    except (BoardError, RoutingError, GitError, MirrorError, RuntimeError) as exc:
        print(f"saturnin: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace, config: Config) -> int:  # noqa: C901 - flat command table
    board = Board(config)
    as_json = args.json

    if args.command == "task":
        return _run_task(args, config, board, as_json)
    if args.command == "dispatch":
        return _run_dispatch(args, config, board, as_json)
    if args.command == "board":
        if args.board_command == "metrics":
            metrics = telemetry.collect(board)
            _emit(
                metrics,
                as_json,
                "\n".join(f"{k}: {v}" for k, v in metrics.items()),
            )
            return 0
        roles = Router(config).roles
        _emit(
            roles,
            as_json,
            "\n".join(
                f"{rid:<16} {r.get('unit', '-'):<12} "
                f"{'executes' if r.get('executes', True) else 'DELEGATES ONLY':<14} "
                f"{r.get('description', '')}"
                for rid, r in roles.items()
            ),
        )
        return 0
    if args.command == "worktree":
        return _run_worktree(args, config, board, as_json)
    if args.command == "checkpoint":
        return _run_checkpoint(args, config, board, as_json)
    if args.command == "review":
        return _run_review(args, config, as_json)
    if args.command == "check":
        governance = Governance(config)
        decision = (
            governance.check_branch(args.branch)
            if args.check_command == "branch"
            else governance.check_server_command(args.cmdline, dedicated_service=args.service)
        )
        _emit(
            {"allowed": decision.allowed, "reasons": decision.reasons},
            as_json,
            ("ALLOWED: " if decision.allowed else "DENIED: ") + "; ".join(decision.reasons),
        )
        return 0 if decision.allowed else 2
    if args.command == "escalate":
        body = escalation_mod.render(
            title=args.title,
            context=args.context,
            checklist=args.checklist,
            urgency=args.urgency,
            unblock_criteria=args.unblock,
            task_id=args.task,
            config=config,
        )
        decision = escalation_mod.validate(body, urgency=args.urgency, config=config)
        if not decision.allowed:
            print("; ".join(decision.reasons), file=sys.stderr)
            return 2
        url = (
            escalation_mod.submit(title=args.title, body=body, config=config)
            if args.push
            else None
        )
        if url and args.task:
            escalation_actor = getattr(args, "actor", "chief-of-staff")
            try:
                board.transition_id(args.task, "blocked", actor=escalation_actor, note=f"escalated: {url}")
            except BoardError:
                try:
                    with board.edit(args.task) as etask:
                        etask.log("escalation", actor=escalation_actor, note=f"escalated: {url}")
                except BoardError:
                    print(f"warning: escalation submitted but task {args.task} not updated", file=sys.stderr)
        _emit({"body": body, "url": url}, as_json, url or body)
        return 0
    if args.command == "docs":
        stale = docsync.render(config, write=not args.check)
        names = [str(p.relative_to(config.root)) for p in stale]
        _emit(
            {"stale": names, "checked": True},
            as_json,
            (
                ("stale: " if args.check else "rewrote: ") + ", ".join(names)
                if names
                else "Documentation agrees with policy."
            ),
        )
        return 2 if (args.check and names) else 0
    if args.command == "repo":
        problems = check_managed_repo(Path(args.path), config)
        _emit(
            {"path": args.path, "compliant": not problems, "problems": problems},
            as_json,
            "\n".join(problems) if problems else "Repository satisfies the Saturnin contract.",
        )
        return 0 if not problems else 2
    if args.command == "discover":
        return _run_discover(args, config, board, as_json)
    if args.command == "automation":
        return _run_automation(args, config, board, as_json)
    if args.command == "improve":
        report = ImprovementLoop(config, board).run(create_tasks=not args.no_tasks)
        _emit(
            report.to_dict(),
            as_json,
            "\n".join(
                [f"metrics: {json.dumps(report.metrics)}"]
                + [f"[{f.severity}] {f.detail} -> {f.recommendation}" for f in report.findings]
                + ([f"filed: {', '.join(report.proposed_tasks)}"] if report.proposed_tasks else [])
            ),
        )
        return 0
    if args.command == "doctor":
        problems = (
            Governance(config).audit()
            + Router(config).validate_policy()
            + AutomationLibrary(config).audit()
            + audit_contracts(config)
            + docsync.audit(config)
            + _mirror_audit(config, board)
        )
        _emit(
            {"healthy": not problems, "problems": problems},
            as_json,
            "\n".join(problems) if problems else "Everything is in order, sir.",
        )
        return 0 if not problems else 2
    parser_error = f"unknown command {args.command}"  # pragma: no cover - argparse guards
    raise RuntimeError(parser_error)  # pragma: no cover


def _run_task(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    if args.task_command == "add":
        task = board.create(
            args.title,
            kind=args.kind,
            body=args.body,
            labels=args.label,
            repo=args.repo,
            priority=args.priority,
            parent=args.parent,
        )
        if args.dispatch:
            Router(config).dispatch(board, task)
            task = board.get(task.id)
        _emit(task.to_dict(), as_json, _task_line(task))
        return 0
    if args.task_command == "list":
        tasks = board.list(
            state=args.state,
            role=args.role,
            priority=args.priority,
            open_only=args.open_only,
        )
        _emit(
            [t.to_dict() for t in tasks],
            as_json,
            "\n".join(_task_line(t) for t in tasks) or "(board is empty)",
        )
        return 0
    if args.task_command == "show":
        task = board.get(args.task_id)
        _emit(task.to_dict(), as_json, json.dumps(task.to_dict(), indent=2))
        return 0
    if args.task_command == "tree":
        roots = (
            [board.get(args.task_id)]
            if args.task_id
            else [t for t in board.list() if t.parent is None]
        )
        lines: list[str] = []
        payload = [_tree_dict(board, root, lines, 0) for root in roots]
        _emit(payload, as_json, "\n".join(lines) or "(board is empty)")
        return 0
    if args.task_command == "sync":
        mirror = IssueMirror(config, board)
        if args.all:
            targets = mirror.syncable()
        elif args.task_id:
            targets = [board.get(args.task_id)]
        else:
            print("saturnin: give a task id or --all", file=sys.stderr)
            return 1
        payloads = mirror.sync_all(targets, push=args.push)
        _emit(
            [p.to_dict() for p in payloads],
            as_json,
            "\n".join(f"{p.repo}: {p.title}" for p in payloads) or "(nothing to mirror)",
        )
        return 0
    if args.task_command == "attach":
        if args.branch:
            decision = Governance(config).check_branch(args.branch)
            if not decision.allowed:
                print("; ".join(decision.reasons), file=sys.stderr)
                return 2
        with board.edit(args.task_id) as task:
            if args.branch:
                task.branch = args.branch
            if args.worktree:
                task.worktree = args.worktree
            task.log(
                "attach",
                actor=args.actor or task.role or "cli",
                branch=task.branch,
                worktree=task.worktree,
            )
        _emit(task.to_dict(), as_json, _task_line(task))
        return 0
    task = board.transition_id(args.task_id, args.state, actor=args.actor, note=args.note)
    _emit(task.to_dict(), as_json, _task_line(task))
    return 0


def _run_discover(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    discovery = IssueDiscovery(config, board)
    issues = discovery.poll()
    if args.dry_run:
        known = discovery.known_markers()
        pending = [i for i in issues if discovery.marker(i) not in known]
        _emit(
            {"found": len(issues), "adoptable": [i.ref for i in pending]},
            as_json,
            "\n".join(f"{i.ref}  {i.title}" for i in pending) or "(nothing new to adopt)",
        )
        return 0
    adopted = discovery.ingest(issues)
    router = Router(config)
    for task in adopted:
        if not args.no_dispatch:
            router.dispatch(board, task, actor="discovery")
    _emit(
        [task.to_dict() for task in adopted],
        as_json,
        "\n".join(f"{t.id}  {t.repo}  {t.title} -> {t.role or 'unrouted'}" for t in adopted)
        or "(nothing new to adopt)",
    )
    return 0


def _run_dispatch(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    router = Router(config)
    if args.dry_run and args.squad:
        router.validate_dispatch_squad(args.squad)
    if args.all:
        targets = board.list(state="intake")
    elif args.task_id:
        targets = [board.get(args.task_id)]
    else:
        print("saturnin: give a task id or --all", file=sys.stderr)
        return 1
    results = []
    for task in targets:
        route = (
            router.resolve(task)
            if args.dry_run
            else router.dispatch(board, task, squad=args.squad or None)
        )
        results.append({"task": task.id, "role": route.role, "rule": route.rule,
                        "priority": route.priority, "escalate": route.escalate,
                        "squad": list(args.squad or route.squad),
                        "result_contract": route.result_contract})
    _emit(
        results,
        as_json,
        "\n".join(
            f"{r['task']} -> {r['role']} ({r['priority']}, rule={r['rule']}, "
            f"results via {r['result_contract']})"
            for r in results
        )
        or "(nothing to dispatch)",
    )
    return 0


def _run_worktree(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    manager = WorktreeManager(config, board=board)
    if args.worktree_command == "create":
        worktree = manager.create(args.branch, base=args.base)
        if args.task:
            with board.edit(args.task) as task:
                task.branch = args.branch
                task.worktree = str(worktree.path)
                task.log(
                    "worktree",
                    actor=args.actor or task.role or "cli",
                    branch=args.branch,
                    worktree=str(worktree.path),
                )
        _emit(
            {"branch": worktree.branch, "path": str(worktree.path)},
            as_json,
            f"{worktree.branch} -> {worktree.path}",
        )
        return 0
    if args.worktree_command == "list":
        worktrees = [
            {"path": str(w.path), "branch": w.branch, "main": w.is_main} for w in manager.list()
        ]
        _emit(
            worktrees,
            as_json,
            "\n".join(f"{w['branch'] or '(detached)':<32} {w['path']}" for w in worktrees),
        )
        return 0
    plan = manager.plan_cleanup(now=datetime.now(timezone.utc))
    if args.apply:
        manager.apply(plan)
    else:
        manager.log_plan(plan)
    _emit(
        plan.to_dict(),
        as_json,
        "\n".join(
            [f"{'APPLIED' if plan.applied else 'DRY RUN'}: {len(plan.actions)} action(s)"]
            + [f"  - {a.kind} {a.target} :: {a.reason}" for a in plan.actions]
            + [f"  ~ skipped {a.kind} {a.target} :: {a.reason}" for a in plan.skipped]
            + [f"  ! {e}" for e in plan.errors]
        ),
    )
    return 1 if args.apply and plan.errors else 0


def _run_checkpoint(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    store = CheckpointStore(config, board)
    if args.checkpoint_command == "save":
        checkpoint = store.save(
            Checkpoint(
                task_id=args.task_id,
                role=args.role,
                summary=args.summary,
                next_steps=args.next_steps,
                blockers=args.blockers,
                artifacts=args.artifacts,
                branch=args.branch,
                worktree=args.worktree,
                resume_after=args.resume_after,
            )
        )
        _emit(checkpoint.to_dict(), as_json, checkpoint.render())
        return 0
    note = store.resume(args.task_id)
    _emit({"note": note}, as_json, note)
    return 0


def _run_review(args: argparse.Namespace, config: Config, as_json: bool) -> int:
    ledger = ReviewLedger(config)
    if args.review_command == "record":
        record = ledger.record(
            subject=args.subject,
            kind=args.kind,
            author=args.author,
            reviewer=args.reviewer,
            verdict=args.verdict,
            zero_context=not args.with_context,
            head_sha=getattr(args, "head_sha", ""),
            notes=args.notes,
        )
        _emit(
            record.to_dict(),
            as_json,
            f"recorded {record.verdict} for {record.subject} by {record.reviewer}",
        )
        return 0
    governance = Governance(config)
    records = ledger.for_subject(args.subject, args.kind)
    decision = (
        governance.merge_allowed(
            repo=args.repo, author=args.author, records=records,
            head_sha=getattr(args, "head_sha", ""),
        )
        if args.kind == "pr"
        else governance.issue_submission_allowed(
            repo=args.repo, author=args.author, records=records
        )
    )
    _emit(
        {"allowed": decision.allowed, "reasons": decision.reasons},
        as_json,
        ("ALLOWED: " if decision.allowed else "BLOCKED: ") + "; ".join(decision.reasons),
    )
    return 0 if decision.allowed else 2


def _run_automation(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    library = AutomationLibrary(config)
    if args.automation_command == "list":
        automations = [vars(a) for a in library.list()]
        _emit(
            automations,
            as_json,
            "\n".join(f"{a['id']:<28} {a['path']:<40} {a['description']}" for a in automations)
            or "(no automations registered)",
        )
        return 0
    if args.automation_command == "find":
        query = " ".join(args.query)
        matches = [vars(a) for a in library.find(query)]
        _emit(
            matches,
            as_json,
            "\n".join(f"{a['id']:<28} {a['path']}" for a in matches)
            or "(nothing found - safe to build it)",
        )
        return 0
    candidates = library.detect_repeats(board, threshold=args.threshold)
    filed = library.propose(board, threshold=args.threshold) if args.propose else []
    _emit(
        {
            "candidates": [c.to_dict() for c in candidates],
            "filed": [t.id for t in filed],
        },
        as_json,
        "\n".join(
            f"{c.count}x  {c.signature}  "
            + (f"(covered by {c.existing})" if c.existing else "(no automation yet)")
            for c in candidates
        )
        or "(no repeated work detected)",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
