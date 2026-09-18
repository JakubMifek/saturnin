"""Command line interface - the only supported entry point for humans and agents.

Everything an agent needs to do (intake, dispatch, review gates, checkpoints,
cleanup, improvement) is available here so that agents stay thin and the rules
stay in one place.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import yaml

from . import escalation as escalation_mod
from . import telemetry
from .automation import AutomationLibrary
from .board import CONTAINER_KINDS, TRANSITIONS, Board, BoardError, Task
from .checkpoints import Checkpoint, CheckpointStore
from .config import Config, ConfigError, find_root, load_yaml
from .contracts import (
    FRONT_MATTER,
    audit as audit_contracts,
    mcp_authorization_problem,
    project_agent_path,
)
from .discovery import DiscoveryError, IssueDiscovery
from . import docsync
from .governance import Governance, github_repo_slug
from .improve import ImprovementLoop
from .issues import IssueMirror, MirrorError, issue_search_url, run_gh
from .launcher import AgentLauncher, LauncherError, LaunchResult
from .locking import file_lock
from .review import (
    ReviewError,
    ReviewLedger,
    issue_content_digest,
    review_attestation_signing_key,
    sign_review_attestation,
)
from .routing import Router, RoutingError
from .worktrees import CleanupPlan, GitError, WorktreeManager
from .worker_callbacks import queue_from_args, register_poller, run_server_command


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
    add.add_argument("--no-launch", action="store_true", help="route without starting the worker")

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
    move.add_argument("--escalation", default="", help="escalation issue URL/ref for blocked tasks")

    reroute = task.add_parser("reroute", help="add labels and route a task atomically")
    reroute.add_argument("task_id")
    reroute.add_argument("--label", action="append", default=[], required=True)
    reroute.add_argument("--actor", default="chief-of-staff")

    tree = task.add_parser("tree", help="show the work hierarchy")
    tree.add_argument("task_id", nargs="?", help="root; default: every top level item")

    sync = task.add_parser("sync", help="preview or push the optional GitHub issue mirror")
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
    dispatch.add_argument("--no-launch", action="store_true", help="route without starting workers")
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
    discover.add_argument("--no-launch", action="store_true", help="route without starting workers")

    run_agent = sub.add_parser("run", help="start the routed agent without waiting")
    run_agent.add_argument("task_id")

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
    create.add_argument(
        "--start",
        action="store_true",
        help="atomically attach the worktree and move its task to in_progress",
    )
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
    sweep = checkpoint.add_parser("sweep", help="launch agents for due delayed checkpoints")
    sweep.add_argument("--dry-run", action="store_true")

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
        "--attestation",
        help="signed reviewer attestation JSON, or @path containing it",
    )
    record.add_argument(
        "--with-context",
        action="store_true",
        help="reviewer had prior context (fails the zero-context gate)",
    )
    record.add_argument("--head-sha", default="", help="reviewed commit SHA for PR reviews")
    record.add_argument(
        "--repo",
        default="",
        help="destination owner/repository slug (required for issue reviews)",
    )
    record.add_argument(
        "--issue-digest",
        default="",
        help="reviewed title/body digest for issue reviews",
    )
    attest = review.add_parser("attest", help="sign a review verdict as the reviewer")
    attest.add_argument("subject", help="e.g. owner/repo#12 or issue draft id")
    attest.add_argument("--kind", choices=["pr", "issue"], required=True)
    attest.add_argument("--author", required=True)
    attest.add_argument("--reviewer", required=True)
    attest.add_argument("--verdict", required=True)
    attest.add_argument(
        "--with-context",
        action="store_true",
        help="reviewer had prior context (fails the zero-context gate)",
    )
    attest.add_argument("--head-sha", default="", help="reviewed commit SHA for PR reviews")
    attest.add_argument(
        "--repo",
        default="",
        help="destination owner/repository slug (required for issue reviews)",
    )
    attest.add_argument(
        "--issue-digest",
        default="",
        help="reviewed title/body digest for issue reviews",
    )
    review.add_parser(
        "seal-rotation",
        help="seal retained previous-key attestations with the current master key",
    )
    gate = review.add_parser("gate", help="check whether merge/submission is allowed")
    gate.add_argument("subject")
    gate.add_argument("--kind", choices=["pr", "issue"], required=True)
    gate.add_argument("--repo", required=True)
    gate.add_argument("--author", required=True)
    gate.add_argument("--head-sha", default="", help="current PR head SHA to match reviews against")
    gate.add_argument(
        "--issue-digest",
        default="",
        help="current issue title/body digest to match reviews against",
    )
    merge = review.add_parser("merge", help="gate and merge a PR at the reviewed head")
    merge.add_argument("subject", help="owner/repo#number")
    merge.add_argument("--repo", required=True)
    merge.add_argument("--author", required=True)
    merge.add_argument(
        "--method",
        choices=["merge", "squash", "rebase"],
        default="squash",
        help="GitHub merge method",
    )
    issue_submit = review.add_parser(
        "submit-issue",
        help="gate and submit reviewed issue content to a managed repository",
    )
    issue_submit.add_argument("subject", help="review subject id used in review record")
    issue_submit.add_argument("--repo", required=True)
    issue_submit.add_argument("--author", required=True)
    issue_submit.add_argument("--title", required=True)
    issue_submit.add_argument("--body", required=True)
    issue_submit.add_argument("--label", action="append", default=[])

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
    command.add_argument(
        "--execute",
        action="store_true",
        help="execute an allowed host command; sandboxed workers queue a trusted callback",
    )
    command.add_argument("--task", help="board task associated with --execute")
    push = sub.add_parser("push", help="push the current commit through the branch policy")
    push.add_argument("--remote", default="origin")
    push.add_argument("--branch", help="destination branch; default: current branch")

    poller = sub.add_parser("poller", help="trusted result-poller registrations").add_subparsers(
        dest="poller_command", required=True
    )
    poller_register = poller.add_parser("register", help="register a declarative status-file probe")
    poller_register.add_argument("task_id")
    poller_register.add_argument(
        "--status-file",
        required=True,
        help="relative path under var/poller-signals containing status JSON",
    )
    poller_register.add_argument(
        "--pending-message",
        default="awaiting external signal",
    )
    poller_register.add_argument("--actor")

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
    """Warn when mandatory mirroring is enabled and open work is local-only."""
    if not Governance(config).mirror_required():
        return []
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
    local_roles = _project_agent_catalog(path, manifest, contract)
    known_roles = set(roles) | set(local_roles)
    squad = manifest.get("squad") or []
    if isinstance(squad, list):
        unknown = [role for role in squad if role not in known_roles]
        if unknown:
            problems.append(f"squad names roles that are not in the catalog: {', '.join(unknown)}")
    else:
        problems.append("squad must be a list of role ids")
    lead = manifest.get("lead")
    if lead is not None and lead not in known_roles:
        problems.append(f"lead names a role that is not in the catalog: {lead}")
    elif lead is not None:
        role = local_roles.get(lead) or roles.get(lead, {})
        if lead == config.ceo_role or not role.get("executes", True):
            problems.append(f"lead role does not execute work: {lead}")
    problems += _check_project_agents(path, manifest, contract, roles, config)
    return problems


def _project_agent_catalog(
    path: Path, manifest: dict[str, Any], contract: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    agents_dir = str(contract.get("agents_dir", ".saturnin/agents"))
    result: dict[str, dict[str, Any]] = {}
    entries = manifest.get("agents") or []
    if not isinstance(entries, list):
        return result
    for entry in entries:
        try:
            agent_path = project_agent_path(path, entry, agents_dir)
        except ValueError:
            continue
        if not agent_path.is_file():
            continue
        match = FRONT_MATTER.match(agent_path.read_text(encoding="utf-8"))
        if not match:
            continue
        try:
            data = yaml.safe_load(match.group(1)) or {}
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and isinstance(data.get("role"), str):
            result[data["role"]] = data
    return result


def _project_routing_context(
    task: Task, config: Config
) -> tuple[dict[str, dict[str, Any]], str | None, list[str] | None]:
    if not task.worktree:
        return {}, None, None
    worktree = Path(task.worktree)
    manifest_path = worktree / ".saturnin" / "repo.yaml"
    if not manifest_path.is_file():
        return {}, None, None
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RoutingError(f"invalid managed repository manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RoutingError("managed repository manifest must contain a mapping")
    local_roles = _project_agent_catalog(
        worktree,
        manifest,
        config.policy("repos").get("managed_repo_contract", {}),
    )
    lead = manifest.get("lead")
    if lead is not None and not isinstance(lead, str):
        raise RoutingError("managed repository lead must be a role id")
    squad = manifest.get("squad")
    if squad is not None and (
        not isinstance(squad, list) or not all(isinstance(role, str) for role in squad)
    ):
        raise RoutingError("managed repository squad must be a list of role ids")
    return local_roles, lead, squad


def _current_pr_head(subject: str, repo: str | None = None) -> str:
    subject_repo, number = _parse_pr_subject(subject, repo=repo)
    try:
        response = json.loads(run_gh(["api", f"repos/{subject_repo}/pulls/{number}"]))
        head_sha = str(response["head"]["sha"]).strip()
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReviewError(f"could not resolve current PR head for {subject}: {exc}") from exc
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
        raise ReviewError(f"GitHub returned an invalid head SHA for {subject}")
    return head_sha


def _parse_pr_subject(subject: str, *, repo: str | None = None) -> tuple[str, str]:
    subject_repo, separator, number = subject.rpartition("#")
    if (
        not separator
        or not number.isdigit()
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", subject_repo)
        or (repo is not None and subject_repo.casefold() != repo.casefold())
    ):
        raise ReviewError("PR subject must be owner/repo#number and match --repo")
    return subject_repo, number


def _review_attestation_key(config: Config, reviewer: str) -> str:
    settings = config.governance.get("review", {}).get("attestation", {})
    env_name = str(settings.get("key_env", "SATURNIN_REVIEW_ATTESTATION_KEY"))
    role_env = str(settings.get("role_env", "SATURNIN_AGENT_ROLE"))
    current_role = os.environ.get(role_env, "").strip().lower()
    reviewer_name = reviewer.strip().lower()
    if current_role and current_role != reviewer_name:
        raise ReviewError(
            f"{role_env}={current_role} may not sign as reviewer {reviewer_name}"
        )
    try:
        return review_attestation_signing_key(config, reviewer_name)
    except ReviewError as exc:
        if f"not configured in {env_name}" in str(exc):
            raise
        raise ReviewError(f"review attestation key is not configured in {env_name}") from exc


def _read_attestation_arg(value: str) -> str:
    if value.startswith("@"):
        return Path(value[1:]).read_text(encoding="utf-8").strip()
    return value


def _prepare_project_route(
    config: Config,
    board: Board,
    task_id: str,
    *,
    squad_override: Sequence[str] | None = None,
) -> Task:
    task = board.get(task_id)
    local_roles, lead, project_squad = _project_routing_context(task, config)
    if not lead and not project_squad and squad_override is None:
        return task
    router = Router(config)
    route = router.resolve(task, additional_roles=local_roles, lead_role=lead)
    squad = list(squad_override or project_squad or route.squad)
    if squad_override is None and lead and lead not in squad:
        squad.insert(0, lead)
    router.validate_dispatch_squad(squad, local_roles)
    with board.edit(task_id) as stored:
        if stored.state != "routed":
            raise BoardError(
                f"task {stored.id} cannot select project lead from state {stored.state}"
            )
        stored.role = route.role
        stored.unit = route.unit
        stored.squad = squad
        stored.log(
            "project-route",
            actor="worktree-provisioner",
            role=route.role,
            squad=",".join(squad),
        )
    return board.get(task_id)


def _governed_issue_marker(subject: str, repo: str, issue_digest: str) -> str:
    seed = json.dumps(
        {"digest": issue_digest, "repo": repo.casefold(), "subject": subject},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"saturnin:review-issue:{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


def _find_governed_issue(repo: str, marker: str) -> str | None:
    output = run_gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--search",
            marker,
            "--state",
            "all",
            "--json",
            "url",
            "--limit",
            "1",
        ]
    )
    return issue_search_url(output)


def _defer_launch(board: Board, task_id: str, reason: str) -> None:
    with board.edit(task_id) as task:
        if task.launch_deferred_reason == reason:
            return
        task.launch_deferred_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        task.launch_deferred_reason = reason
        task.log("agent:deferred", actor="worktree-provisioner", reason=reason)


def _configured_repo_checkout(config: Config, repo: str | None) -> tuple[Path | None, str]:
    policy = config.policy("repos")
    engine = policy.get("repos", {}).get("engine", {})
    engine_slug = str(engine.get("slug", ""))
    if not repo or repo.casefold() == engine_slug.casefold():
        return config.root, ""
    for source in policy.get("discovery", {}).get("sources", []) or []:
        if not isinstance(source, dict):
            continue
        if str(source.get("slug", "")).casefold() != repo.casefold():
            continue
        checkout = source.get("checkout")
        if not checkout:
            return None, f"configure a checkout for managed repository {repo}"
        path = Path(str(checkout)).expanduser()
        if not path.is_absolute():
            path = config.root / path
        path = path.resolve()
        if not path.is_dir():
            return None, f"configured checkout does not exist for managed repository {repo}: {path}"
        return path, ""
    return None, f"managed repository {repo} is not configured as a discovery source"


def _configured_repo_checkouts(config: Config) -> list[Path]:
    checkouts = [config.root.resolve()]
    sources = config.policy("repos").get("discovery", {}).get("sources", []) or []
    if not isinstance(sources, list):
        raise BoardError("configured discovery sources must be a list")
    for source in sources:
        if isinstance(source, str):
            source = {"slug": source}
        if not isinstance(source, dict) or not str(source.get("slug", "")).strip():
            raise BoardError("each configured discovery source must be a mapping with a slug")
        if not source.get("checkout"):
            continue
        checkout, reason = _configured_repo_checkout(config, str(source["slug"]))
        if checkout is None:
            raise BoardError(reason)
        resolved = checkout.resolve()
        if resolved not in checkouts:
            checkouts.append(resolved)
    return checkouts


def _provision_and_launch(
    config: Config,
    board: Board,
    task_id: str,
    *,
    squad_override: Sequence[str] | None = None,
) -> LaunchResult | None:
    launcher = AgentLauncher(config, board)
    if not launcher.enabled:
        _defer_launch(board, task_id, "agent launcher is disabled")
        return None
    task = board.get(task_id)
    if not task.worktree:
        checkout, reason = _configured_repo_checkout(config, task.repo)
        if checkout is None:
            _defer_launch(board, task.id, reason)
            return None
        branch = f"feature/{task.id.lower()}"
        manager = WorktreeManager(config, repo=checkout, board=board)
        worktree = None
        try:
            with manager.lifecycle_lock():
                worktree = manager.create(branch)
                with board.edit(task.id) as stored:
                    stored.branch = branch
                    stored.worktree = str(worktree.path)
                    stored.log(
                        "worktree",
                        actor="worktree-provisioner",
                        branch=branch,
                        worktree=str(worktree.path),
                    )
        except (BoardError, GitError, OSError) as exc:
            if worktree is not None:
                manager.rollback_create(worktree)
            _defer_launch(board, task.id, f"worktree provisioning failed: {exc}")
            return None
        except Exception:
            if worktree is not None:
                manager.rollback_create(worktree)
            raise
    _prepare_project_route(config, board, task.id, squad_override=squad_override)
    try:
        return launcher.launch(task.id)
    except LauncherError as exc:
        _defer_launch(board, task.id, f"agent launch failed: {exc}")
        return None


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
    mcp_policy = config.policy("mcp")
    known_mcp = set(mcp_policy.get("servers", {}))
    problems: list[str] = []
    for entry in entries:
        rel = str(entry)
        try:
            agent_path = project_agent_path(path, rel, agents_dir)
        except ValueError as exc:
            problems.append(str(exc))
            continue
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
                elif field == "mcp":
                    authorization_problem = mcp_authorization_problem(
                        role_id,
                        value,
                        mcp_policy,
                        executes=bool(front_matter.get("executes", True)),
                    )
                    if authorization_problem:
                        problems.append(f"project agent {rel}: {authorization_problem}")
    return problems

def _config(args: argparse.Namespace) -> Config:
    return Config.load(Path(args.home) if args.home else None)


def _git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        queued_callback = queue_from_args(args)
        if queued_callback is not None:
            _emit(
                queued_callback,
                args.json,
                f"queued worker callback: {queued_callback['type']} {queued_callback['task_id']}",
            )
            return 0
        config = _config(args)
        config.ensure_dirs()
        return _run(args, config)
    except Exception as exc:
        if args.command == "doctor":
            fallback = _doctor_config_path(args)
            problem = _doctor_exception(fallback, exc)
            _emit(
                {"healthy": False, "problems": [problem]},
                args.json,
                problem,
            )
            return 2
        if not isinstance(
            exc,
            (
                BoardError,
                RoutingError,
                GitError,
                MirrorError,
                docsync.GeneratedBlockError,
                ConfigError,
                yaml.YAMLError,
                RuntimeError,
            ),
        ):
            raise
        print(f"saturnin: {exc}", file=sys.stderr)
        return 1


def _doctor_config_path(args: argparse.Namespace) -> Path:
    try:
        if args.home:
            root = Path(args.home).expanduser().resolve(strict=False)
        else:
            root = find_root()
    except (OSError, RuntimeError):
        root = Path(args.home).expanduser() if args.home else Path.cwd()
    return root / "policies" / "governance.yaml"


def _run(args: argparse.Namespace, config: Config) -> int:  # noqa: C901 - flat command table
    as_json = args.json
    if args.command == "doctor":
        return _run_doctor(config, as_json)
    board = Board(config)

    if args.command == "task":
        return _run_task(args, config, board, as_json)
    if args.command == "dispatch":
        return _run_dispatch(args, config, board, as_json)
    if args.command == "run":
        _prepare_project_route(config, board, args.task_id)
        launched = AgentLauncher(config, board).launch(args.task_id)
        payload = launched.to_dict() if launched else {"task_id": args.task_id, "disabled": True}
        _emit(payload, as_json, json.dumps(payload, indent=2))
        return 0
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
    if args.command == "poller":
        registration = register_poller(
            config,
            board,
            task_id=args.task_id,
            status_file=args.status_file,
            pending_message=args.pending_message,
            actor=args.actor,
        )
        _emit(
            registration,
            as_json,
            f"registered poller for {args.task_id}: {registration['probe']['path']}",
        )
        return 0
    if args.command == "check":
        governance = Governance(config)
        decision = (
            governance.check_branch(args.branch)
            if args.check_command == "branch"
            else governance.check_server_command(args.cmdline, dedicated_service=args.service)
        )
        if args.check_command == "command" and args.execute:
            if not decision.allowed:
                _emit(
                    {"allowed": False, "reasons": decision.reasons},
                    as_json,
                    "DENIED: " + "; ".join(decision.reasons),
                )
                return 2
            if not args.task:
                raise RuntimeError("check command --execute requires --task")
            result = run_server_command(
                config,
                board,
                task_id=args.task,
                cmdline=args.cmdline,
                service=args.service,
                actor="ops-worker",
            )
            _emit(result, as_json, f"executed host command: {result['command']}")
            return 0
        _emit(
            {"allowed": decision.allowed, "reasons": decision.reasons},
            as_json,
            ("ALLOWED: " if decision.allowed else "DENIED: ") + "; ".join(decision.reasons),
        )
        return 0 if decision.allowed else 2
    if args.command == "push":
        if not re.fullmatch(r"[A-Za-z0-9._-]+", args.remote):
            raise RuntimeError(f"invalid git remote name: {args.remote!r}")
        current_branch = _git_output(
            config.root, "symbolic-ref", "--quiet", "--short", "HEAD"
        )
        branch = args.branch or current_branch
        if branch != current_branch:
            reason = (
                f"destination branch {branch!r} does not match "
                f"current branch {current_branch!r}"
            )
            _emit(
                {
                    "allowed": False,
                    "reasons": [reason],
                },
                as_json,
                f"DENIED: {reason}",
            )
            return 2
        push_urls = _git_output(
            config.root, "remote", "get-url", "--push", "--all", args.remote
        ).splitlines()
        if not push_urls:
            raise RuntimeError(f"remote {args.remote!r} has no push destination")
        trusted_proxy_hosts = config.governance.get("git", {}).get(
            "trusted_github_proxy_hosts", []
        )
        for remote_url in push_urls:
            repo = github_repo_slug(
                remote_url,
                trusted_proxy_hosts=trusted_proxy_hosts,
            )
            if repo is None:
                raise RuntimeError(
                    f"remote {args.remote!r} has an unrecognized push destination"
                )
            decision = Governance(config).push_allowed(repo=repo, branch=branch)
            if not decision.allowed:
                _emit(
                    {"allowed": False, "reasons": decision.reasons},
                    as_json,
                    "DENIED: " + "; ".join(decision.reasons),
                )
                return 2
        result = subprocess.run(
            ["git", "push", "--", args.remote, f"HEAD:refs/heads/{branch}"],
            cwd=config.root,
            check=False,
        )
        return result.returncode
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
        if args.push and args.task:
            url = escalation_mod.submit_task_escalation(
                config=config,
                board=board,
                task_id=args.task,
                title=args.title,
                body=body,
                urgency=args.urgency,
                actor=getattr(args, "actor", "chief-of-staff"),
            )
        elif args.push:
            url = escalation_mod.submit(
                title=args.title,
                body=body,
                urgency=args.urgency,
                config=config,
            )
        else:
            url = None
        payload = {"body": body, "url": url}
        _emit(
            payload,
            as_json,
            url or body,
        )
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
    parser_error = f"unknown command {args.command}"  # pragma: no cover - argparse guards
    raise RuntimeError(parser_error)  # pragma: no cover


def _doctor_exception(fallback: Path, error: Exception) -> str:
    filename = getattr(error, "filename", None)
    mark = getattr(error, "problem_mark", None)
    marked_name = getattr(mark, "name", "")
    path = (
        Path(filename)
        if filename
        else Path(marked_name)
        if marked_name and not marked_name.startswith("<")
        else fallback
    )
    detail = str(error).strip() or error.__class__.__name__
    path_text = str(path)
    return detail if detail.startswith(f"{path_text}:") else f"{path_text}: {detail}"


def _doctor_check(path: Path, check: Any) -> list[str]:
    try:
        return list(check())
    except Exception as error:
        return [_doctor_exception(path, error)]


def _run_doctor(config: Config, as_json: bool) -> int:
    problems: list[str] = []
    board: Board | None = None

    def construct_board() -> list[str]:
        nonlocal board
        board = Board(config)
        return []

    policy_names = {
        "cleanup.yaml",
        "governance.yaml",
        "improvement.yaml",
        "mcp.yaml",
        "repos.yaml",
        "routing.yaml",
        "server_scope.yaml",
    }
    configuration_paths = {
        *(config.policies / name for name in policy_names),
        *config.policies.glob("*.yaml"),
        config.automation_dir / "registry.yaml",
    }
    for path in sorted(configuration_paths):
        problems += _doctor_check(
            path, lambda path=path: _audit_configuration_file(path)
        )

    problems += _doctor_check(config.tasks_dir, construct_board)
    checks = [
        (
            config.policies / "governance.yaml",
            lambda: Governance(config).audit(),
        ),
        (
            config.policies / "routing.yaml",
            lambda: Router(config).validate_policy(),
        ),
        (
            config.policies / "cleanup.yaml",
            lambda: WorktreeManager(config).audit(),
        ),
        (
            config.automation_dir / "registry.yaml",
            lambda: AutomationLibrary(config).audit(),
        ),
        (
            config.policies / "repos.yaml",
            lambda: IssueDiscovery(config, board).audit(),
        ),
        (
            config.root / "agents",
            lambda: audit_contracts(config),
        ),
        (
            config.root / "docs",
            lambda: docsync.audit(config),
        ),
    ]
    for path, check in checks:
        problems += _doctor_check(path, check)
    if board is not None:
        problems += _doctor_check(
            config.policies / "repos.yaml",
            lambda: _mirror_audit(config, board),
        )

    _emit(
        {"healthy": not problems, "problems": problems},
        as_json,
        "\n".join(problems) if problems else "Everything is in order, sir.",
    )
    return 0 if not problems else 2


def _audit_configuration_file(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError("required configuration file does not exist")
    load_yaml(path)
    return []


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
            if not args.no_launch:
                _provision_and_launch(config, board, task.id)
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
    if args.task_command == "reroute":
        route = Router(config).relabel_and_reroute(
            board,
            args.task_id,
            labels=args.label,
            actor=args.actor,
        )
        task = board.get(args.task_id)
        payload = task.to_dict()
        payload["route"] = {
            "role": route.role,
            "rule": route.rule,
            "result_contract": route.result_contract,
        }
        _emit(payload, as_json, _task_line(task))
        return 0
    if args.task_command == "sync":
        mirror = IssueMirror(config, board)
        if args.all:
            # A pushed periodic sweep must reconcile remote issue state even
            # when the rendered board payload itself has not changed.
            targets = list(board) if args.push else mirror.syncable()
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
        manager = WorktreeManager(config, board=board)
        with manager.lifecycle_lock():
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
    note = args.note
    if args.state == "blocked" and args.escalation.strip():
        escalation_ref = args.escalation.strip()
        note = f"escalated: {escalation_ref}" if not note else f"escalated: {escalation_ref}; {note}"
    task = board.transition_id(args.task_id, args.state, actor=args.actor, note=note)
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
            if not args.no_launch:
                _provision_and_launch(config, board, task.id)
            task.__dict__.update(board.get(task.id).__dict__)
    _emit(
        [task.to_dict() for task in adopted],
        as_json,
        "\n".join(f"{t.id}  {t.repo}  {t.title} -> {t.role or 'unrouted'}" for t in adopted)
        or "(nothing new to adopt)",
    )
    return 0


def _run_dispatch(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    router = Router(config)
    launcher = AgentLauncher(config, board)
    if args.all and launcher.enabled:
        launcher.reconcile_exited_launches()
    if args.all:
        targets = [
            task
            for task in board.list(open_only=True)
            if (
                task.state == "intake"
                and task.kind not in CONTAINER_KINDS
            )
            or (task.state == "routed" and task.launch_deferred_at is not None)
        ]
    elif args.task_id:
        targets = [board.get(args.task_id)]
    else:
        print("saturnin: give a task id or --all", file=sys.stderr)
        return 1
    results = []
    for task in targets:
        try:
            local_roles, project_lead, project_squad = _project_routing_context(task, config)
            squad = args.squad or project_squad
            if squad:
                router.validate_dispatch_squad(squad, local_roles)
            if task.state == "routed":
                route = router.resolve(
                    task,
                    additional_roles=local_roles,
                    lead_role=project_lead,
                )
                if not args.dry_run:
                    task = _prepare_project_route(
                        config,
                        board,
                        task.id,
                        squad_override=args.squad or None,
                    )
            else:
                route = (
                    router.resolve(
                        task,
                        additional_roles=local_roles,
                        lead_role=project_lead,
                    )
                    if args.dry_run
                    else router.dispatch(
                        board,
                        task,
                        squad=squad or None,
                        additional_roles=local_roles,
                        lead_role=project_lead,
                    )
                )
            results.append({"task": task.id, "role": route.role, "rule": route.rule,
                            "priority": route.priority, "escalate": route.escalate,
                            "squad": list(squad or route.squad),
                            "result_contract": route.result_contract})
            if not args.dry_run and not args.no_launch:
                launched = _provision_and_launch(
                    config,
                    board,
                    task.id,
                    squad_override=args.squad or None,
                )
                if launched:
                    results[-1]["launch"] = launched.to_dict()
                else:
                    deferred = board.get(task.id)
                    if deferred.launch_deferred_reason:
                        results[-1]["launch_deferred"] = deferred.launch_deferred_reason
        except RuntimeError as exc:
            if not args.all:
                raise
            if not args.dry_run:
                _defer_launch(board, task.id, f"dispatch failed: {exc}")
                deferred_reason = board.get(task.id).launch_deferred_reason
            else:
                deferred_reason = None
            result = {"task": task.id, "error": str(exc)}
            if deferred_reason:
                result["launch_deferred"] = deferred_reason
            results.append(result)
    _emit(
        results,
        as_json,
        "\n".join(
            f"{r['task']} deferred: {r['error']}"
            if "error" in r
            else f"{r['task']} -> {r['role']} ({r['priority']}, rule={r['rule']}, "
            f"results via {r['result_contract']})"
            for r in results
        )
        or "(nothing to dispatch)",
    )
    return 0


def _run_worktree(args: argparse.Namespace, config: Config, board: Board, as_json: bool) -> int:
    if args.worktree_command == "create":
        if args.start and not args.task:
            raise BoardError("--start requires --task")
        checkout = config.root
        if args.task:
            task = board.get(args.task)
            checkout, reason = _configured_repo_checkout(config, task.repo)
            if checkout is None:
                raise BoardError(reason)
        manager = WorktreeManager(config, repo=checkout, board=board)
        with manager.lifecycle_lock():
            attachment_error = "already has an attached branch/worktree"
            actor = args.actor or "cli"
            worktree = None
            if args.task:
                try:
                    with board.edit(args.task) as task:
                        if task.branch or task.worktree:
                            raise BoardError(f"task {task.id} {attachment_error}")
                        if args.start and "in_progress" not in TRANSITIONS[task.state]:
                            raise BoardError(
                                f"illegal transition {task.state} -> in_progress "
                                f"(allowed: {', '.join(TRANSITIONS[task.state]) or 'none'})"
                            )
                        actor = args.actor or task.role or "cli"
                        worktree = manager.create(args.branch, base=args.base)
                        task.branch = args.branch
                        task.worktree = str(worktree.path)
                        task.log(
                            "worktree",
                            actor=actor,
                            branch=args.branch,
                            worktree=str(worktree.path),
                        )
                        if args.start:
                            board._apply_transition(  # noqa: SLF001 - same atomic lifecycle
                                task,
                                "in_progress",
                                actor=actor,
                                note=f"work session started on {args.branch}",
                            )
                except Exception:
                    if worktree is not None:
                        manager.rollback_create(worktree)
                    raise
            else:
                worktree = manager.create(args.branch, base=args.base)
        _emit(
            {"branch": worktree.branch, "path": str(worktree.path)},
            as_json,
            f"{worktree.branch} -> {worktree.path}",
        )
        return 0
    if args.worktree_command == "list":
        manager = WorktreeManager(config, board=board)
        worktrees = [
            {"path": str(w.path), "branch": w.branch, "main": w.is_main} for w in manager.list()
        ]
        _emit(
            worktrees,
            as_json,
            "\n".join(f"{w['branch'] or '(detached)':<32} {w['path']}" for w in worktrees),
        )
        return 0
    now = datetime.now(timezone.utc)
    managers = [
        WorktreeManager(config, repo=checkout, board=board)
        for checkout in _configured_repo_checkouts(config)
    ]
    plans = [manager.plan_cleanup(now=now) for manager in managers]
    global_cap = int(config.cleanup.get("safety", {}).get("max_removals_per_run", 10))
    remaining = global_cap
    for plan in plans:
        overflow = plan.actions[remaining:]
        plan.actions = plan.actions[:remaining]
        for action in overflow:
            action.reason += f" (deferred: over global cap of {global_cap} per run)"
        plan.skipped.extend(overflow)
        remaining -= len(plan.actions)
    for manager, plan in zip(managers, plans, strict=True):
        if args.apply:
            manager.apply(plan, now=now)
        else:
            manager.log_plan(plan)
    plan = CleanupPlan(
        actions=[action for item in plans for action in item.actions],
        skipped=[action for item in plans for action in item.skipped],
        applied=bool(args.apply),
        errors=[error for item in plans for error in item.errors],
    )
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
    if args.checkpoint_command == "sweep":
        due = store.due()
        if args.dry_run:
            payload = [checkpoint.to_dict() for checkpoint in due]
            had_errors = False
        else:
            router = Router(config)
            launcher = AgentLauncher(config, board)
            launcher.reconcile_exited_launches()
            due = store.due()
            payload = []
            had_errors = False
            if not launcher.enabled:
                payload = [
                    {"task_id": checkpoint.task_id, "disabled": True}
                    for checkpoint in due
                ]
            else:
                for checkpoint in due:
                    try:
                        task = board.get(checkpoint.task_id)
                        if task.state == "in_progress":
                            payload.append(
                                {
                                    "task_id": checkpoint.task_id,
                                    "active": True,
                                }
                            )
                            continue
                        if task.state in ("intake", "blocked"):
                            router.dispatch(board, task, actor="checkpoint-sweeper")
                        launched = launcher.launch(
                            checkpoint.task_id,
                            resumed_checkpoint=checkpoint.created_at,
                        )
                        payload.append(launched.to_dict())
                    except RuntimeError as exc:
                        had_errors = True
                        payload.append(
                            {"task_id": checkpoint.task_id, "error": str(exc)}
                        )
        _emit(
            payload,
            as_json,
            "\n".join(item["task_id"] for item in payload) or "(no checkpoints due)",
        )
        return 1 if had_errors else 0
    note = store.resume(args.task_id)
    _emit({"note": note}, as_json, note)
    return 0


def _run_review(args: argparse.Namespace, config: Config, as_json: bool) -> int:
    ledger = ReviewLedger(config)
    if args.review_command == "seal-rotation":
        path = ledger.seal_rotation_manifest()
        data = json.loads(path.read_text(encoding="utf-8"))
        _emit(
            {"path": str(path), "attestations": len(data["attestations"])},
            as_json,
            f"sealed {len(data['attestations'])} attestation(s) in {path}",
        )
        return 0
    if args.review_command == "attest":
        attestation = sign_review_attestation(
            key=_review_attestation_key(config, args.reviewer),
            subject=args.subject,
            kind=args.kind,
            author=args.author,
            reviewer=args.reviewer,
            verdict=args.verdict,
            zero_context=not args.with_context,
            head_sha=args.head_sha,
            issue_digest=args.issue_digest,
            destination_repo=args.repo,
        )
        _emit({"attestation": attestation}, as_json, attestation)
        return 0
    if args.review_command == "record":
        head_sha = getattr(args, "head_sha", "")
        if args.kind == "pr" and not head_sha:
            head_sha = _current_pr_head(
                args.subject,
                getattr(args, "repo", None) or None,
            )
        attestation = _read_attestation_arg(args.attestation) if args.attestation else ""
        record = ledger.record(
            subject=args.subject,
            kind=args.kind,
            author=args.author,
            reviewer=args.reviewer,
            verdict=args.verdict,
            zero_context=not args.with_context,
            head_sha=head_sha,
            issue_digest=getattr(args, "issue_digest", ""),
            destination_repo=getattr(args, "repo", ""),
            notes=args.notes,
            attestation=attestation,
        )
        _emit(
            record.to_dict(),
            as_json,
            f"recorded {record.verdict} for {record.subject} by {record.reviewer}",
        )
        return 0
    if args.review_command == "merge":
        subject_repo, number = _parse_pr_subject(args.subject, repo=args.repo)
        head_sha = _current_pr_head(args.subject, args.repo)
        governance = Governance(config)
        records = ledger.for_subject(args.subject, "pr")
        decision = governance.merge_allowed(
            repo=args.repo,
            author=args.author,
            records=records,
            head_sha=head_sha,
        )
        if not decision.allowed:
            _emit(
                {"allowed": False, "reasons": decision.reasons, "head_sha": head_sha},
                as_json,
                "BLOCKED: " + "; ".join(decision.reasons),
            )
            return 2
        try:
            response = json.loads(
                run_gh(
                    [
                        "api",
                        "--method",
                        "PUT",
                        f"repos/{subject_repo}/pulls/{number}/merge",
                        "-f",
                        f"sha={head_sha}",
                        "-f",
                        f"merge_method={args.method}",
                    ]
                )
            )
        except (MirrorError, json.JSONDecodeError) as exc:
            raise ReviewError(f"governed merge failed for {args.subject}: {exc}") from exc
        _emit(
            {
                "allowed": True,
                "reasons": decision.reasons,
                "head_sha": head_sha,
                "merged": bool(response.get("merged")),
                "message": str(response.get("message", "")),
                "sha": str(response.get("sha", "")),
            },
            as_json,
            str(response.get("message", "merge attempted")),
        )
        return 0 if response.get("merged") else 2
    if args.review_command == "submit-issue":
        digest = issue_content_digest(args.title, args.body)
        governance = Governance(config)
        records = ledger.for_subject(args.subject, "issue")
        decision = governance.issue_submission_allowed(
            repo=args.repo,
            author=args.author,
            records=records,
            issue_digest=digest,
        )
        if not decision.allowed:
            _emit(
                {"allowed": False, "reasons": decision.reasons, "issue_digest": digest},
                as_json,
                "BLOCKED: " + "; ".join(decision.reasons),
            )
            return 2
        marker = _governed_issue_marker(args.subject, args.repo, digest)
        marker_comment = f"<!-- {marker} -->"
        body = args.body if marker_comment in args.body else f"{marker_comment}\n\n{args.body}"
        lock_id = hashlib.sha256(marker.encode("utf-8")).hexdigest()
        submission_lock = config.var_dir / "locks" / f"governed-issue-{lock_id}"
        try:
            with file_lock(submission_lock):
                url = _find_governed_issue(args.repo, marker)
                if not url:
                    create_args = [
                        "issue",
                        "create",
                        "--repo",
                        args.repo,
                        "--title",
                        args.title,
                        "--body",
                        body,
                    ]
                    for label in args.label:
                        create_args.extend(["--label", label])
                    output = run_gh(create_args)
                    url = output.strip().splitlines()[-1].strip() if output.strip() else ""
        except MirrorError as exc:
            raise ReviewError(f"governed issue submission failed for {args.subject}: {exc}") from exc
        if not url:
            raise ReviewError("governed issue submission returned no issue URL")
        _emit(
            {
                "allowed": True,
                "reasons": decision.reasons,
                "issue_digest": digest,
                "url": url,
            },
            as_json,
            url,
        )
        return 0
    head_sha = getattr(args, "head_sha", "")
    if args.kind == "pr" and not head_sha:
        head_sha = _current_pr_head(
            args.subject,
            getattr(args, "repo", None),
        )
    governance = Governance(config)
    records = ledger.for_subject(args.subject, args.kind)
    decision = (
        governance.merge_allowed(
            repo=args.repo, author=args.author, records=records,
            head_sha=head_sha,
        )
        if args.kind == "pr"
        else governance.issue_submission_allowed(
            repo=args.repo, author=args.author, records=records,
            issue_digest=getattr(args, "issue_digest", ""),
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
