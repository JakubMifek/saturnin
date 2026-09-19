"""Governance gates.

Every irreversible action (push, merge, issue submission, server command) has to
pass through here first. The rules themselves live in
``policies/governance.yaml`` and ``policies/server_scope.yaml``.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from .config import Config, default_config
from .review import ReviewRecord

_MAX_COMMAND_DEPTH = 8
_WRAPPERS = {"env", "nice", "ionice", "stdbuf", "timeout", "exec", "command"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.DOTALL)
_SHELL_RESERVED = {
    "!", "case", "coproc", "do", "done", "elif", "else", "esac", "fi",
    "for", "function", "if", "in", "select", "then", "time", "until",
    "while", "{", "}",
}
_DYNAMIC_COMMANDS = {".", "eval", "source"}
_SHELL_BINARIES = {
    "ash", "bash", "csh", "dash", "fish", "hush", "ksh", "ksh93", "mksh", "nu",
    "osh", "posh", "powershell", "pwsh", "rbash", "sh", "tcsh", "xonsh",
    "yash", "zsh",
}
_MULTICALL_BINARIES = {"busybox", "toybox"}
_ALL_OPERANDS_WRITABLE = {
    "chmod",
    "chgrp",
    "chown",
    "mkdir",
    "mkfifo",
    "mknod",
    "rm",
    "rmdir",
    "setfacl",
    "tee",
    "touch",
    "truncate",
    "unlink",
}
_DESTINATION_WRITABLE = {"cp", "install", "ln", "mv", "rsync"}
_SPECIAL_EXECUTABLES = (
    _WRAPPERS
    | _SHELL_RESERVED
    | _DYNAMIC_COMMANDS
    | _SHELL_BINARIES
    | _MULTICALL_BINARIES
    | _ALL_OPERANDS_WRITABLE
    | _DESTINATION_WRITABLE
    | {
        "curl",
        "dd",
        "find",
        "gh",
        "git",
        "journalctl",
        "node",
        "perl",
        "python",
        "python3",
        "ruby",
        "saturnin",
        "sed",
        "systemctl",
        "xargs",
    }
)


def _repo_slug_key(repo: object) -> str:
    return str(repo or "").strip().casefold()


def github_repo_slug(
    remote_url: str, *, trusted_proxy_hosts: Sequence[str] = ()
) -> str | None:
    remote_url = remote_url.strip()
    scp = re.fullmatch(
        r"git@github\.com:(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        remote_url,
    )
    if scp:
        return scp.group("slug")

    try:
        parsed = urlsplit(remote_url)
        host = (parsed.hostname or "").casefold()
        port = parsed.port
    except ValueError:
        return None
    if parsed.query or parsed.fragment or parsed.password:
        return None
    if host == "github.com":
        if parsed.scheme == "https" and parsed.username:
            return None
        if parsed.scheme == "ssh" and parsed.username not in {None, "git"}:
            return None
        if parsed.scheme not in {"https", "ssh"}:
            return None
    elif f"{host}:{port}" in {value.casefold() for value in trusted_proxy_hosts}:
        if parsed.scheme not in {"http", "https"} or parsed.username:
            return None
    else:
        return None
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path) else None


_GIT_SAFE_SUBCOMMANDS = frozenset(
    {
        "add",
        "branch",
        "checkout",
        "commit",
        "diff",
        "fsck",
        "init",
        "log",
        "merge",
        "rebase",
        "remote",
        "reflog",
        "reset",
        "restore",
        "rev-parse",
        "show",
        "status",
        "switch",
        "tag",
        "worktree",
    }
)
_GIT_NETWORK_SUBCOMMANDS = frozenset({"clone", "fetch", "pull", "push"})


class _AssignmentError(ValueError):
    pass


class _WriteScopeError(ValueError):
    pass


@dataclass
class Decision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed

    @classmethod
    def ok(cls, *reasons: str) -> "Decision":
        return cls(True, list(reasons))

    @classmethod
    def deny(cls, *reasons: str) -> "Decision":
        return cls(False, list(reasons))


class Governance:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.policy: dict[str, Any] = self.config.governance
        self.git: dict[str, Any] = self.policy.get("git", {})
        self.review: dict[str, Any] = self.policy.get("review", {})
        self.autonomy: dict[str, Any] = self.policy.get("autonomy", {})
        self.escalation: dict[str, Any] = self.policy.get("escalation", {})
        self.delegation: dict[str, Any] = self.policy.get("delegation", {})
        self.tracking: dict[str, Any] = self.policy.get("tracking", {})

    # -- branches ------------------------------------------------------
    @property
    def default_branch(self) -> str:
        return self.git.get("default_branch", "main")

    @property
    def protected_branches(self) -> list[str]:
        return list(self.git.get("protected_branches", [self.default_branch]))

    def check_branch(self, branch: str) -> Decision:
        """Rule 1 + 2: never work on the default branch, always use a feature branch."""
        branch = branch.strip()
        if not branch:
            return Decision.deny("branch name is empty")
        if branch in self.protected_branches:
            return Decision.deny(f"'{branch}' is protected; Saturnin never writes to it")
        pattern = self.git.get("branch_name_pattern")
        if pattern and not re.match(pattern, branch):
            prefixes = ", ".join(self.git.get("branch_prefixes", []))
            return Decision.deny(
                f"'{branch}' does not match {pattern} (expected one of: {prefixes})"
            )
        return Decision.ok(f"'{branch}' is an acceptable feature branch")

    # -- reviews -------------------------------------------------------
    def _review_gate(
        self,
        records: Sequence[ReviewRecord],
        author: str,
        settings: dict[str, Any],
        subject: str,
        *,
        kind: str = "",
    ) -> Decision:
        from .review import _allowed_reviewer_roles
        reasons: list[str] = []
        author_lower = author.strip().lower()
        records = [r for r in records if r.author.strip().lower() == author_lower]
        if self.review.get("attestation", {}).get("required", False):
            records = [r for r in records if r.attestation_id and r.attestation_signature]
        allowed = _allowed_reviewer_roles(kind, self.config) if kind else set()
        if kind:
            records = [r for r in records if r.reviewer.strip().lower() in allowed]
        latest_by_reviewer: dict[str, ReviewRecord] = {}
        for record in records:
            latest_by_reviewer[record.reviewer.strip().lower()] = record
        records = list(latest_by_reviewer.values())
        approvals = [r for r in records if r.verdict == "approved"]
        blocking = [
            r for r in records if r.verdict in ("changes_requested", "rejected", "dismissed")
        ]
        if blocking:
            return Decision.deny(
                f"{subject}: {len(blocking)} blocking review(s) outstanding: "
                + ", ".join(f"{r.reviewer}={r.verdict}" for r in blocking)
            )
        if settings.get("independent", True) and not settings.get("author_may_review", False):
            self_reviews = [r for r in approvals if r.reviewer.strip().lower() == author_lower]
            if self_reviews:
                return Decision.deny(f"{subject}: author {author!r} may not review their own work")
        if settings.get("zero_context", False):
            approvals = [r for r in approvals if r.zero_context]
            if not approvals:
                return Decision.deny(f"{subject}: a zero-context reviewer approval is required")
        minimum = int(settings.get("min_approvals", 1))
        if len(approvals) < minimum:
            return Decision.deny(
                f"{subject}: {len(approvals)}/{minimum} independent approval(s)"
            )
        reasons.append(f"{subject}: {len(approvals)} independent approval(s)")
        return Decision(True, reasons)

    def merge_allowed(
        self, *, repo: str, author: str, records: Iterable[ReviewRecord], head_sha: str
    ) -> Decision:
        """Rule 3 + 4: merge only after an independent zero-context review."""
        records = [r for r in records if r.kind == "pr"]
        if not head_sha:
            return Decision.deny(
                "head_sha is required: approvals must be verified against the current commit"
            )
        # Only reviews that match the current head SHA are valid.
        records = [r for r in records if r.head_sha == head_sha]
        if not records:
            return Decision.deny(
                f"no review records match the current head SHA ({head_sha[:12]}); "
                "new commits may have been pushed after the last review"
            )
        settings = self.review.get("pr", {})
        if settings.get("required", True):
            decision = self._review_gate(records, author, settings, "pr review", kind="pr")
            if not decision.allowed:
                return decision
            reasons = list(decision.reasons)
        else:  # pragma: no cover - defensive
            reasons = ["pr review not required by policy"]
        if _repo_slug_key(repo) == _repo_slug_key(self.autonomy.get("self_repo")):
            if not self.autonomy.get("self_repo_autonomous_merge", False):
                return Decision.deny(f"{repo}: autonomous merge disabled by policy")
            reasons.append(f"{repo}: autonomous merge allowed after review")
            return Decision(True, reasons)
        return Decision.deny(
            f"{repo}: Saturnin does not merge in managed repos; open an issue or PR for a human"
        )

    def issue_submission_allowed(
        self,
        *,
        repo: str,
        author: str,
        records: Iterable[ReviewRecord],
        issue_digest: str = "",
    ) -> Decision:
        """Rule 5: issues for managed repos need an independent issue review."""
        records = [r for r in records if r.kind == "issue"]
        managed = {
            _repo_slug_key(repo_entry.get("slug"))
            for repo_entry in self.config.policy("repos").get("repos", {}).values()
            if isinstance(repo_entry, dict) and repo_entry.get("slug")
        }
        managed.add(_repo_slug_key(self.autonomy.get("self_repo")))
        # Discovery sources are also managed project repositories.
        discovery = self.config.policy("repos").get("discovery", {})
        for source in discovery.get("sources", []) or []:
            slug = source.get("slug") if isinstance(source, dict) else source
            if slug:
                managed.add(_repo_slug_key(slug))
        repo_key = _repo_slug_key(repo)
        if repo_key not in managed:
            return Decision.deny(f"{repo}: issue creation is only allowed in managed repositories")
        if repo_key == _repo_slug_key(self.autonomy.get("self_repo")):
            return Decision.ok(f"{repo}: own repository, issue may be filed directly")
        if not self.autonomy.get("external_repos_allow_issue_creation", True):
            return Decision.deny(f"{repo}: issue creation is disabled by policy")
        settings = dict(self.review.get("issue", {}))
        if not settings.get("required_for_external_repos", True):  # pragma: no cover
            return Decision.ok(f"{repo}: issue review not required")
        if not issue_digest.strip():
            return Decision.deny(
                "issue_digest is required: approvals must be verified against the current draft"
            )
        records = [
            r
            for r in records
            if r.issue_digest == issue_digest.strip() and r.destination_repo == repo_key
        ]
        if not records:
            return Decision.deny(
                "no issue review records match the current issue-content digest and "
                f"destination repository ({repo_key}); the draft or destination may "
                "have changed after review"
            )
        settings.setdefault("min_approvals", 1)
        return self._review_gate(records, author, settings, "issue review", kind="issue")

    def push_allowed(self, *, repo: str, branch: str) -> Decision:
        branch_check = self.check_branch(branch)
        if not branch_check.allowed:
            return branch_check
        if _repo_slug_key(repo) != _repo_slug_key(
            self.autonomy.get("self_repo")
        ) and not self.autonomy.get(
            "external_repos_allow_direct_push", False
        ):
            return Decision.deny(f"{repo}: direct pushes to managed repos are not allowed")
        return branch_check

    # -- escalation ----------------------------------------------------
    def check_escalation(self, body: str, *, urgency: str) -> Decision:
        reasons: list[str] = []
        missing = [
            section
            for section in self.escalation.get("required_sections", [])
            if section.replace("_", " ") not in body.lower()
        ]
        if missing:
            return Decision.deny(f"escalation is missing section(s): {', '.join(missing)}")
        levels = self.escalation.get("urgency_levels", [])
        if levels and urgency not in levels:
            return Decision.deny(f"unknown urgency {urgency!r}; expected one of {levels}")
        mention = self.escalation.get("mention")
        if mention and mention.lower() not in body.lower():
            return Decision.deny(f"escalation must mention {mention}")
        reasons.append("escalation is well formed")
        return Decision(True, reasons)

    # -- server scope --------------------------------------------------
    def check_server_command(
        self,
        command: str,
        *,
        dedicated_service: str | None = None,
        cwd: Path | None = None,
    ) -> Decision:
        """Rule 7: non-root only, apt/systemctl only for Saturnin-dedicated services."""
        scope = self.config.server_scope
        unsafe_syntax = _unsafe_shell_syntax(command)
        if unsafe_syntax:
            return Decision.deny(f"dynamic shell syntax is not allowed: {unsafe_syntax}")
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            return Decision.deny(f"unparsable command: {exc}")
        if not parts:
            return Decision.deny("empty command")
        if _ASSIGNMENT.fullmatch(parts[0]):
            return Decision.deny("environment variable assignments are not allowed")
        user = scope.get("user", {})
        if not user.get("allow_root", False) and os.geteuid() == 0:
            return Decision.deny("server commands may not run as root")
        return self._check_scoped_command(
            parts, dedicated_service=dedicated_service, cwd=cwd, depth=0
        )

    def _check_scoped_command(
        self,
        parts: Sequence[str],
        *,
        dedicated_service: str | None,
        cwd: Path | None,
        depth: int,
    ) -> Decision:
        if depth >= _MAX_COMMAND_DEPTH:
            return Decision.deny("command wrappers are nested too deeply")
        parts = list(parts)
        if not parts:
            return Decision.deny("wrapper contains no command")
        if _ASSIGNMENT.fullmatch(parts[0]):
            return Decision.deny("environment variable assignments are not allowed")
        executable = parts[0]
        binary = Path(executable).name
        executable_decision = _check_executable_location(
            executable,
            binary,
            self.config.server_scope,
            runtime_root=self.config.data_root,
            cwd=cwd,
        )
        if not executable_decision.allowed:
            return executable_decision
        if binary in self.config.server_scope.get("user", {}).get(
            "forbidden_prefixes", []
        ):
            return Decision.deny(
                f"privilege escalation via {binary!r} is not allowed"
            )
        if binary in _SHELL_RESERVED or binary in _DYNAMIC_COMMANDS:
            return Decision.deny(f"shell keyword {binary!r} is not allowed")
        if binary in _SHELL_BINARIES:
            return Decision.deny(
                f"{binary} execution is not allowed because shell commands are dynamic"
            )
        if binary in _MULTICALL_BINARIES:
            return Decision.deny(
                f"{binary} execution is not allowed because applet dispatch is dynamic"
            )
        if binary == "xargs":
            return Decision.deny(
                "xargs execution is not allowed because its command is input-dependent"
            )
        if binary in _WRAPPERS:
            try:
                wrapped = _wrapped_command(binary, parts[1:])
            except _AssignmentError as exc:
                return Decision.deny(str(exc))
            except ValueError as exc:
                return Decision.deny(f"malformed {binary} wrapper: {exc}")
            if not wrapped:
                return Decision.deny(f"malformed {binary} wrapper: expected a command")
            return self._check_scoped_command(
                wrapped,
                dedicated_service=dedicated_service,
                cwd=cwd,
                depth=depth + 1,
            )

        scope = self.config.server_scope
        services = scope.get("services", {})
        packages = scope.get("packages", {})
        filesystem_decision = _check_filesystem_scope(
            binary, parts[1:], scope.get("filesystem", {}), cwd=cwd
        )
        if not filesystem_decision.allowed:
            return filesystem_decision
        if binary == "apt" or binary.startswith("apt-"):
            if not packages.get("apt_allowed", False):
                return Decision.deny("apt is not allowed")
            try:
                _check_apt_options(parts[1:])
            except _WriteScopeError as exc:
                return Decision.deny(str(exc))
            sub = parts[1] if len(parts) > 1 else ""
            allowed = packages.get("apt_allowed_subcommands", [])
            if allowed and sub not in allowed:
                return Decision.deny(f"apt {sub!r} is not in the allow list {allowed}")
            if packages.get("apt_requires_dedicated_service", False):
                prefix = services.get("unit_prefix", "saturnin-")
                if not dedicated_service or not dedicated_service.startswith(prefix):
                    return Decision.deny(
                        f"apt requires a dedicated {prefix}* service via --service"
                    )
            return Decision.ok(
                f"apt allowed for dependency of dedicated service {dedicated_service}"
            )
        if binary == "systemctl":
            if not services.get("systemctl_allowed", False):
                return Decision.deny("systemctl is not allowed")
            raw_args = parts[1:]
            flags = [p for p in raw_args if p.startswith("-")]
            allowed_flags = {
                "--user",
                "--now",
                "--all",
                "--failed",
                "--type",
                "--state",
                "--property",
                "--quiet",
                "--plain",
                "--no-legend",
                "--no-pager",
                "--show-types",
            }
            allowed_flag_prefixes = ("--type=", "--state=", "--property=")
            unknown = [
                flag
                for flag in flags
                if flag not in allowed_flags and not any(flag.startswith(prefix) for prefix in allowed_flag_prefixes)
            ]
            if unknown:
                return Decision.deny(
                    f"systemctl option(s) not allowed: {', '.join(unknown)}"
                )
            user_scope = "--user" in flags
            if services.get("scheduling_scope") == "user" and not user_scope:
                return Decision.deny("systemctl must use --user scope")
            args = [p for p in raw_args if not p.startswith("-")]
            sub = args[0] if args else ""
            allowed = services.get("allowed_subcommands", [])
            if allowed and sub not in allowed:
                return Decision.deny(f"systemctl {sub!r} is not in the allow list {allowed}")
            units = args[1:]
            prefix = services.get("unit_prefix", "saturnin-")
            bad = [unit for unit in units if not unit.startswith(prefix)]
            if bad:
                return Decision.deny(
                    f"systemctl may only touch {prefix}* units, got: {', '.join(bad)}"
                )
            if not units and sub not in ("list-timers", "status", "daemon-reload"):
                return Decision.deny("systemctl needs an explicit Saturnin unit name")
            return Decision.ok("systemctl limited to Saturnin-dedicated units")
        if binary == "journalctl":
            if not services.get("journalctl_allowed", False):
                return Decision.deny("journalctl is not allowed")
            args = parts[1:]
            if "--user" not in args:
                return Decision.deny("journalctl must use --user scope")
            units: list[str] = []
            for index, value in enumerate(args):
                if value in ("-u", "--unit") and index + 1 < len(args):
                    units.append(args[index + 1])
                elif value.startswith("--unit="):
                    units.append(value.split("=", 1)[1])
            prefix = services.get("unit_prefix", "saturnin-")
            if not units or any(not unit.startswith(prefix) for unit in units):
                return Decision.deny(f"journalctl requires a {prefix}* unit")
            allowed = {"--user", "-u", "--unit", "-n", "--lines", "--no-pager"}
            for index, value in enumerate(args):
                if value.startswith("-") and value not in allowed and not value.startswith(
                    ("--unit=", "--lines=")
                ):
                    return Decision.deny(f"journalctl option not allowed: {value}")
                if value in ("-n", "--lines") and index + 1 == len(args):
                    return Decision.deny(f"journalctl option {value} requires a value")
            return Decision.ok("journalctl limited to Saturnin user units")
        if binary == "gh":
            try:
                _check_gh_command(parts[1:])
            except _WriteScopeError as exc:
                return Decision.deny(str(exc))
            return Decision.ok("gh limited to Saturnin issue, label and API helpers")
        return Decision.ok(f"{binary}: no elevated capability required")

    # -- delegation ----------------------------------------------------
    @property
    def result_contracts(self) -> list[str]:
        return list(self.delegation.get("result_contracts", []))

    def check_result_contract(self, contract: str | None) -> Decision:
        """Rule 8: a dispatch without an agreed result contract would force the
        CEO to wait for the worker, which is forbidden."""
        if self.delegation.get("ceo_may_wait_for_workers", False):
            return Decision.ok("policy permits waiting (not recommended)")
        allowed = self.result_contracts
        if not contract:
            return Decision.deny(
                "no result contract: the CEO would have to wait for the worker. "
                f"Pick one of: {', '.join(allowed)}"
            )
        if allowed and contract not in allowed:
            return Decision.deny(f"unknown result contract {contract!r}; expected one of {allowed}")
        return Decision.ok(f"results arrive via {contract}; the CEO does not wait")

    def mirror_required(self) -> bool:
        """Whether issue mirroring is mandatory before the topology is accepted."""
        return bool(self.tracking.get("mirror_tasks_as_issues", False))

    # -- self check ----------------------------------------------------
    def audit(self) -> list[str]:
        problems: list[str] = []
        if not self.protected_branches:
            problems.append("no protected branches configured")
        if self.default_branch not in self.protected_branches:
            problems.append("the default branch must be protected")
        if not self.review.get("pr", {}).get("required", False):
            problems.append("PR review is not required")
        if self.review.get("pr", {}).get("author_may_review", False):
            problems.append("PR authors are allowed to review themselves")
        if self.mirror_required() and not bool(
            self.config.policy("repos").get("tracking", {}).get("mirror_tasks_as_issues", False)
        ):
            problems.append(
                "governance requires task mirroring but repos policy disables "
                "tracking.mirror_tasks_as_issues"
            )
        for kind in ("pr", "issue"):
            reviewers = self.review.get(kind, {}).get("allowed_reviewer_roles", [])
            if not isinstance(reviewers, list) or not reviewers or not all(
                isinstance(role, str) and role.strip() for role in reviewers
            ):
                problems.append(
                    f"{kind} review policy requires a non-empty list of reviewer roles"
                )
                continue
            unknown = sorted(
                {role.strip() for role in reviewers}
                - set(self.config.routing.get("roles", {}))
            )
            if unknown:
                problems.append(
                    f"{kind} review policy names unknown reviewer role(s): {', '.join(unknown)}"
                )
        github_reviewers = self.review.get("pr", {}).get("github_reviewer_logins", [])
        if not isinstance(github_reviewers, list) or not github_reviewers or not all(
            isinstance(login, str) and login.strip() for login in github_reviewers
        ):
            problems.append(
                "PR review policy requires a non-empty list of GitHub reviewer logins"
            )
        attestation = self.review.get("attestation", {})
        if not attestation.get("required", False):
            problems.append("review records must require signed attestations")
        key_env = attestation.get("key_env")
        if not isinstance(key_env, str) or not key_env.strip():
            problems.append("review attestation policy requires a key_env")
        previous_key_env = attestation.get("previous_key_env")
        if previous_key_env is not None and (
            not isinstance(previous_key_env, str) or not previous_key_env.strip()
        ):
            problems.append("review attestation previous_key_env must be a non-empty string")
        if (
            isinstance(key_env, str)
            and isinstance(previous_key_env, str)
            and key_env.strip() == previous_key_env.strip()
        ):
            problems.append("review attestation previous_key_env must differ from key_env")
        if not attestation.get("role_scoped", False):
            problems.append("review attestation keys must be role-scoped")
        for name in ("key_scope_env", "role_env"):
            value = attestation.get(name)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"review attestation policy requires {name}")
        if self.policy.get("delegation", {}).get("ceo_may_execute", False):
            problems.append("CEO is allowed to execute work; delegation-first is violated")
        server_scope = self.config.server_scope
        if server_scope.get("user", {}).get("allow_root", False):
            problems.append("server scope allows root")
        try:
            filesystem = server_scope.get("filesystem", {})
            _trusted_executable_roots(filesystem)
            _trusted_runtime_executable(filesystem, self.config.data_root)
        except ValueError as error:
            problems.append(f"{self.config.policies / 'server_scope.yaml'}: {error}")
        if self.delegation.get("ceo_may_wait_for_workers", False):
            problems.append("CEO is allowed to wait for workers; dispatch must be non-blocking")
        if not self.result_contracts:
            problems.append("no result contracts defined; dispatch cannot be non-blocking")
        if self.mirror_required() and not self.config.policy("repos").get("repos", {}).get("board"):
            problems.append("task mirroring is on but policies/repos.yaml names no board repo")
        return problems


def _unsafe_shell_syntax(command: str) -> str | None:
    if "\\\n" in command or "\\\r\n" in command:
        return "backslash-newline continuation"
    quote: str | None = None
    escaped = False
    for character in command:
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if character == "'":
                quote = None
            continue
        if quote == '"':
            if character == '"':
                quote = None
            elif character == "\\":
                escaped = True
            elif character in "$`":
                return "expansion inside double quotes"
            continue
        if character == "\\":
            escaped = True
        elif character in "'\"":
            quote = character
        elif character in "!;&|<>()\r\n":
            return f"shell operator {character!r}"
        elif character in "$`*?[]{}~":
            return f"shell expansion token {character!r}"
    return None


def _check_filesystem_scope(
    binary: str,
    arguments: Sequence[str],
    filesystem: dict[str, Any],
    *,
    cwd: Path | None = None,
) -> Decision:
    forbidden_roots = _policy_roots(filesystem.get("forbidden_roots", []))
    try:
        targets = _writable_targets(binary, arguments)
    except _WriteScopeError as exc:
        return Decision.deny(str(exc))
    if not targets:
        # No explicit write targets detected.  Interpreters and shells can
        # perform arbitrary filesystem writes that argument inspection cannot
        # detect, so they must be denied unless an explicit allowlist permits
        # them.  For non-interpreter binaries the allowlist is also checked.
        allowlist = set(filesystem.get("executable_allowlist", []))
        if binary in {"python", "python3"}:
            allowed_modules = {
                str(module) for module in filesystem.get("python_module_allowlist", [])
            }
            if not (
                len(arguments) >= 2
                and arguments[0] == "-m"
                and arguments[1] in allowed_modules
            ):
                return Decision.deny(
                    f"{binary!r} is only allowed for configured Python module invocations"
                )
            if arguments[1] == "saturnin":
                targets = _saturnin_targets(arguments[2:])
                if targets:
                    return _check_filesystem_targets(targets, filesystem, cwd=cwd)
        elif binary in _SHELL_BINARIES or binary in {"ruby", "perl", "node"}:
            if binary not in allowlist:
                return Decision.deny(
                    f"{binary!r} is an interpreter whose filesystem writes cannot be "
                    "statically determined; add it to executable_allowlist to permit it"
                )
        elif allowlist and binary not in allowlist:
            return Decision.deny(
                f"{binary!r} is not in the executable allowlist; "
                "arbitrary executables cannot be sandboxed by argument inspection alone"
            )
        return Decision.ok("command has no explicit filesystem write target")

    return _check_filesystem_targets(targets, filesystem, cwd=cwd)


def _check_executable_location(
    executable: str,
    binary: str,
    scope: dict[str, Any],
    *,
    runtime_root: Path,
    cwd: Path | None = None,
) -> Decision:
    filesystem = scope.get("filesystem", {})
    classified = (
        binary in _SPECIAL_EXECUTABLES
        or binary in set(filesystem.get("executable_allowlist", []))
        or binary in set(scope.get("user", {}).get("forbidden_prefixes", []))
        or binary == "apt"
        or binary.startswith("apt-")
    )
    if not classified:
        return Decision.ok("executable does not receive basename-specific privileges")

    if "/" in executable:
        candidate = Path(executable).expanduser()
        if not candidate.is_absolute() and cwd is not None:
            candidate = cwd / candidate
    else:
        found = shutil.which(executable)
        if found is None:
            if binary in _SHELL_RESERVED | _DYNAMIC_COMMANDS | {"command", "exec"}:
                return Decision.ok("shell syntax is classified without an executable path")
            return Decision.deny(
                f"classified executable {executable!r} could not be resolved from PATH"
            )
        candidate = Path(found)

    try:
        configured_roots = _trusted_executable_roots(filesystem, resolve=False)
        trusted_roots = _trusted_executable_roots(filesystem)
    except ValueError as error:
        return Decision.deny(f"invalid executable trust policy: {error}")

    try:
        selected = Path(os.path.abspath(candidate))
    except (OSError, RuntimeError, ValueError):
        return Decision.deny(
            f"classified executable {executable!r} does not resolve to an existing file"
        )
    if binary == "saturnin":
        try:
            runtime_executable = _trusted_runtime_executable(filesystem, runtime_root)
        except ValueError as error:
            return Decision.deny(f"invalid trusted runtime executable policy: {error}")
        if selected == runtime_executable:
            try:
                resolved_runtime = selected.resolve(strict=True)
            except (OSError, RuntimeError, ValueError):
                return Decision.deny(
                    f"trusted runtime executable {str(selected)!r} does not exist"
                )
            if resolved_runtime != selected:
                return Decision.deny("trusted runtime executable must not be a symlink")
            if not resolved_runtime.is_file() or not os.access(resolved_runtime, os.X_OK):
                return Decision.deny(
                    f"trusted runtime executable {str(selected)!r} must be an executable file"
                )
            return Decision.ok(f"executable {str(selected)!r} is the trusted Saturnin runtime")
    if _containing_root(selected, configured_roots) is None:
        return Decision.deny(
            f"executable {str(selected)!r} is outside trusted system executable roots"
        )

    try:
        resolved = selected.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return Decision.deny(
            f"classified executable {executable!r} does not resolve to an existing file"
        )
    if not resolved.is_file():
        return Decision.deny(
            f"classified executable {str(resolved)!r} is not a regular file"
        )
    if not os.access(resolved, os.X_OK):
        return Decision.deny(
            f"classified executable {str(resolved)!r} is not executable"
        )

    if _containing_root(resolved, trusted_roots) is None:
        return Decision.deny(
            f"executable {str(resolved)!r} is outside trusted system executable roots"
        )
    return Decision.ok(f"executable {str(resolved)!r} is under a trusted system root")


def _trusted_executable_roots(
    filesystem: dict[str, Any], *, resolve: bool = True
) -> list[Path]:
    values = filesystem.get("trusted_executable_roots")
    if not isinstance(values, list) or not values:
        raise ValueError("filesystem.trusted_executable_roots must be a non-empty list")
    roots: list[Path] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "filesystem.trusted_executable_roots entries must be nonempty strings "
                f"(invalid entry at index {index})"
            )
        path = Path(value)
        if not path.is_absolute():
            raise ValueError(
                "filesystem.trusted_executable_roots entries must be absolute paths "
                f"(invalid entry at index {index}: {value!r})"
            )
        try:
            roots.append(
                path.resolve(strict=False)
                if resolve
                else Path(os.path.abspath(path))
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise ValueError(
                "filesystem.trusted_executable_roots entry cannot be resolved "
                f"(invalid entry at index {index}: {value!r})"
            ) from error
    return roots


def _trusted_runtime_executable(filesystem: dict[str, Any], runtime_root: Path) -> Path:
    value = filesystem.get("trusted_runtime_executable")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("filesystem.trusted_runtime_executable must be a nonempty relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative.name != "saturnin":
        raise ValueError(
            "filesystem.trusted_runtime_executable must be a relative path to a saturnin binary"
        )
    return Path(os.path.abspath(runtime_root / relative))


def _check_filesystem_targets(
    targets: Sequence[str],
    filesystem: dict[str, Any],
    *,
    cwd: Path | None = None,
) -> Decision:
    forbidden_roots = _policy_roots(filesystem.get("forbidden_roots", []))
    writable_roots = _policy_roots(filesystem.get("writable_roots", []))
    for raw_path in targets:
        path = _resolve_command_path(raw_path, cwd=cwd)
        forbidden = _containing_root(path, forbidden_roots)
        if forbidden is not None:
            return Decision.deny(
                f"filesystem write target {str(path)!r} is under forbidden root "
                f"{str(forbidden)!r}"
            )
        if _containing_root(path, writable_roots) is None:
            return Decision.deny(
                f"filesystem write target {str(path)!r} is outside writable roots"
            )
    return Decision.ok("filesystem write targets are within writable roots")


def _policy_roots(values: Iterable[Any]) -> list[Path]:
    return [_resolve_command_path(str(value)) for value in values]


def _resolve_command_path(value: str, *, cwd: Path | None = None) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() and cwd is not None:
        path = cwd / path
    return path.resolve(strict=False)


def _containing_root(path: Path, roots: Sequence[Path]) -> Path | None:
    return next((root for root in roots if path == root or root in path.parents), None)


def _writable_targets(binary: str, arguments: Sequence[str]) -> list[str]:
    positional = _positional_arguments(arguments)
    if binary in _ALL_OPERANDS_WRITABLE:
        return positional
    if binary in _DESTINATION_WRITABLE:
        return _destination_targets(binary, arguments)
    if binary == "curl":
        return _curl_targets(arguments)
    if binary == "dd":
        return [
            argument.split("=", 1)[1]
            for argument in arguments
            if argument.startswith("of=")
        ]
    if binary == "sed" and any(
        argument == "-i" or argument.startswith("--in-place") for argument in arguments
    ):
        return _sed_targets(arguments)
    if binary == "saturnin":
        return _saturnin_targets(arguments)
    if binary == "git":
        return _git_targets(arguments)
    if binary == "find":
        return _find_targets(arguments)
    return []


def _saturnin_targets(arguments: Sequence[str]) -> list[str]:
    targets: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--home":
            if index + 1 < len(arguments):
                targets.append(arguments[index + 1])
            index += 2
            continue
        if argument.startswith("--home="):
            targets.append(argument.split("=", 1)[1])
        index += 1
    return targets


def _git_targets(arguments: Sequence[str]) -> list[str]:
    index = 0
    targets: list[str] = []
    subcommand_index: int | None = None
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-C":
            if index + 1 < len(arguments):
                targets.append(arguments[index + 1])
            index += 2
            continue
        if argument.startswith("-C") and len(argument) > 2:
            targets.append(argument[2:])
            index += 1
            continue
        if argument in {"--git-dir", "--work-tree"}:
            if index + 1 < len(arguments):
                targets.append(arguments[index + 1])
            index += 2
            continue
        if argument.startswith(("--git-dir=", "--work-tree=")):
            targets.append(argument.split("=", 1)[1])
            index += 1
            continue
        if (
            argument == "-c"
            or argument.startswith("-c")
            or argument == "--config-env"
            or argument.startswith("--config-env=")
        ):
            raise _WriteScopeError(
                "git command-line configuration overrides are unsupported; "
                "write scope is unknown"
            )
        if argument == "--exec-path" or argument.startswith("--exec-path="):
            raise _WriteScopeError(
                "git executable dispatch options are unsupported; write scope is unknown"
            )
        if not argument.startswith("-"):
            subcommand_index = index
            break
        index += 1
    targets.append(".")
    if subcommand_index is None:
        return targets
    subcommand = arguments[subcommand_index]
    subcommand_arguments = arguments[subcommand_index + 1 :]
    if subcommand == "config":
        raise _WriteScopeError("git config is unsupported; configuration can define shell aliases")
    if subcommand == "fsck" and subcommand_arguments != ["--unreachable"]:
        raise _WriteScopeError(
            "git fsck is limited to the read-only '--unreachable' recovery scan"
        )
    if subcommand in _GIT_NETWORK_SUBCOMMANDS:
        raise _WriteScopeError(
            f"git {subcommand} is unsupported here; use a dedicated governed wrapper"
        )
    if subcommand not in _GIT_SAFE_SUBCOMMANDS:
        raise _WriteScopeError(
            f"unsupported git subcommand {subcommand!r}; executable dispatch is not allowed"
        )
    if subcommand == "remote":
        _check_git_remote_subcommand(subcommand_arguments)
    worktree_subcommand_index: int | None = None
    if subcommand == "worktree":
        worktree_subcommand_index = _check_git_worktree_subcommand(subcommand_arguments)
    targets.extend(_git_write_option_targets(subcommand, subcommand_arguments))
    operands = _positional_arguments(subcommand_arguments)
    if subcommand == "init" and operands:
        targets.append(operands[-1])
    elif subcommand == "worktree" and worktree_subcommand_index is not None:
        if subcommand_arguments[worktree_subcommand_index] == "add":
            targets.append(
                _git_worktree_add_target(subcommand_arguments[worktree_subcommand_index + 1 :])
            )
    return targets


def _check_git_remote_subcommand(arguments: Sequence[str]) -> None:
    for argument in arguments:
        if argument == "--":
            break
        if argument.startswith("-"):
            continue
        if argument not in {"get-url"}:
            raise _WriteScopeError(
                f"git remote {argument} is unsupported; network/config mutations "
                "require a dedicated governed wrapper"
            )
        return


def _check_git_worktree_subcommand(arguments: Sequence[str]) -> int:
    global_options = {"-v", "--verbose", "--porcelain", "-z"}
    for index, argument in enumerate(arguments):
        if argument == "--":
            break
        if argument.startswith("-"):
            if argument not in global_options:
                raise _WriteScopeError(
                    f"unsupported git worktree option {argument!r}; write scope is unknown"
                )
            continue
        subcommand = argument
        if subcommand in {"add", "list"}:
            return index
        raise _WriteScopeError(
            f"git worktree {subcommand} is unsupported; use saturnin worktree lifecycle commands"
        )
    raise _WriteScopeError("git worktree requires a supported subcommand")


def _check_apt_options(arguments: Sequence[str]) -> None:
    for argument in arguments:
        if argument == "-o" or argument.startswith(("-o=", "-o")):
            raise _WriteScopeError("apt configuration overrides are unsupported")
        if argument.startswith("--option"):
            raise _WriteScopeError("apt configuration overrides are unsupported")
        if argument == "-c" or argument.startswith("-c"):
            raise _WriteScopeError("apt configuration files are unsupported")
        if argument.startswith("--config-file"):
            raise _WriteScopeError("apt configuration files are unsupported")


def _check_gh_command(arguments: Sequence[str]) -> None:
    if not arguments:
        raise _WriteScopeError("gh requires a subcommand")
    allowed = {
        "api": None,
        "issue": {"list", "view"},
        "label": {"list"},
    }
    subcommand = arguments[0]
    if subcommand not in allowed:
        raise _WriteScopeError(f"gh {subcommand} is unsupported by the server gate")
    if subcommand == "api":
        _check_gh_api(arguments[1:])
        return
    allowed_children = allowed[subcommand]
    child = next((arg for arg in arguments[1:] if not arg.startswith("-")), "")
    if child not in allowed_children:
        raise _WriteScopeError(
            f"gh {subcommand} {child or '<missing>'} is unsupported by the server gate"
        )


def _check_gh_api(arguments: Sequence[str]) -> None:
    endpoint = ""
    for argument in arguments:
        if argument.startswith("-"):
            raise _WriteScopeError("gh api options are unsupported")
        if argument == "graphql":
            raise _WriteScopeError("gh api graphql is unsupported by the server gate")
        if not argument.startswith("-") and not endpoint:
            endpoint = argument
    if not re.fullmatch(r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pulls/[0-9]+", endpoint):
        raise _WriteScopeError("gh api endpoint is not in the read-only allowlist")


def _git_write_option_targets(subcommand: str, arguments: Sequence[str]) -> list[str]:
    targets: list[str] = []
    value_options = {"--separate-git-dir"}
    if subcommand == "diff":
        value_options.add("--output")
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        if argument in value_options:
            if index + 1 >= len(arguments):
                raise _WriteScopeError(f"git option {argument} requires a value")
            targets.append(arguments[index + 1])
            index += 2
            continue
        matched = next((option for option in value_options if argument.startswith(f"{option}=")), None)
        if matched:
            targets.append(argument.split("=", 1)[1])
        index += 1
    return targets


def _git_worktree_add_target(arguments: Sequence[str]) -> str:
    flags = {
        "-d",
        "--detach",
        "-f",
        "--force",
        "--checkout",
        "--no-checkout",
        "--guess-remote",
        "--no-guess-remote",
        "--lock",
        "-q",
        "--quiet",
        "--relative-paths",
        "--no-relative-paths",
        "--track",
        "--no-track",
    }
    value_options = {"-b", "-B", "--orphan", "--reason"}
    positionals: list[str] = []
    options = True
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if options and argument == "--":
            options = False
            index += 1
            continue
        if options and argument in flags:
            index += 1
            continue
        if options and argument in value_options:
            if index + 1 >= len(arguments):
                raise _WriteScopeError(
                    f"git worktree add option {argument!r} requires a value"
                )
            index += 2
            continue
        if options and (
            (argument.startswith("-b") and len(argument) > 2)
            or (argument.startswith("-B") and len(argument) > 2)
            or argument.startswith("--orphan=")
            or argument.startswith("--reason=")
        ):
            if argument.endswith("="):
                raise _WriteScopeError(
                    f"git worktree add option {argument.split('=', 1)[0]!r} requires a value"
                )
            index += 1
            continue
        if options and argument.startswith("-"):
            raise _WriteScopeError(
                f"unsupported git worktree add option {argument!r}; write scope is unknown"
            )
        positionals.append(argument)
        index += 1
    if not positionals:
        raise _WriteScopeError("git worktree add requires an explicit destination")
    if len(positionals) > 2:
        raise _WriteScopeError(
            "unsupported git worktree add form; expected destination and optional commit-ish"
        )
    return positionals[0]


def _find_targets(arguments: Sequence[str]) -> list[str]:
    roots: list[str] = []
    targets: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-H", "-L", "-P"} or re.fullmatch(r"-O\d+", argument):
            index += 1
            continue
        if argument == "-D":
            if index + 1 >= len(arguments):
                raise _WriteScopeError("find option '-D' requires a value")
            index += 2
            continue
        if argument.startswith("-D") and len(argument) > 2:
            index += 1
            continue
        if argument == "-files0-from" or argument.startswith("-files0-from="):
            raise _WriteScopeError("unsupported find option '-files0-from'; write scope is unknown")
        if argument in {"!", "(", ")"} or argument.startswith("-"):
            break
        roots.append(argument)
        index += 1
    if not roots:
        roots = ["."]
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-delete":
            targets.extend(roots)
        elif argument in {"-exec", "-execdir", "-ok", "-okdir"}:
            raise _WriteScopeError(
                f"unsupported find action {argument!r}; write scope is unknown"
            )
        elif argument in {"-fprint", "-fprint0", "-fprintf", "-fls"}:
            if index + 1 >= len(arguments):
                raise _WriteScopeError(f"find action {argument!r} requires a value")
            targets.append(arguments[index + 1])
            index += 1
        index += 1
    return targets


def _curl_output_dir(arguments: Sequence[str]) -> str | None:
    output_dir: str | None = None
    for index in range(len(arguments) - 1, -1, -1):
        argument = arguments[index]
        if argument == "--output-dir" and index + 1 < len(arguments):
            candidate = arguments[index + 1]
            if candidate and candidate != "-":
                output_dir = candidate
            break
        if argument.startswith("--output-dir="):
            candidate = argument.split("=", 1)[1]
            if candidate and candidate != "-":
                output_dir = candidate
            break
    return output_dir


_CURL_SHORT_OPTIONS_WITH_VALUES = frozenset(
    "AbcCdeEFDHKmoPQrtTuUwXxyz"
)
_CURL_SHORT_WRITE_ACTIONS = {
    "o": "target",
    "D": "target",
    "c": "target",
    "w": "write-out",
}
_CURL_FILE_OPTIONS = frozenset(
    {
        "-o",
        "--output",
        "-D",
        "--dump-header",
        "-c",
        "--cookie-jar",
        "--trace",
        "--trace-ascii",
        "--stderr",
        "--etag-save",
        "--libcurl",
        "--alt-svc",
        "--hsts",
    }
)
_CURL_WRITE_OUT_OPTIONS = frozenset({"-w", "--write-out"})
_CURL_ALWAYS_LOCAL_READ_OPTIONS = frozenset(
    {
        "-T",
        "--upload-file",
        "--netrc-file",
    }
)
_CURL_AT_LOCAL_READ_OPTIONS = frozenset(
    {
        "-d",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-urlencode",
        "--json",
        "-F",
        "--form",
    }
)
_CURL_URL_OPTIONS = frozenset({"--url"})


def _expand_curl_short_next(arguments: Sequence[str]) -> list[str]:
    expanded: list[str] = []
    for argument in arguments:
        if not argument.startswith("-") or argument.startswith("--") or len(argument) <= 2:
            expanded.append(argument)
            continue
        segment: list[str] = []
        for position, option in enumerate(argument[1:], start=1):
            if option in _CURL_SHORT_OPTIONS_WITH_VALUES:
                segment.append(argument[position:])
                break
            if option == ":":
                if segment:
                    expanded.append("-" + "".join(segment))
                    segment = []
                expanded.append("-:")
                continue
            segment.append(option)
        if segment:
            expanded.append("-" + "".join(segment))
    return expanded


def _curl_operation(arguments: Sequence[str], start: int) -> Sequence[str]:
    end = next(
        (
            index
            for index in range(start, len(arguments))
            if arguments[index] in {"--next", "-:"}
        ),
        len(arguments),
    )
    return arguments[start:end]


def _curl_bundled_write_action(argument: str) -> tuple[bool, str, str]:
    if not argument.startswith("-") or argument.startswith("--") or len(argument) <= 2:
        return False, "", ""
    remote_name = False
    for position, option in enumerate(argument[1:], start=1):
        if option not in _CURL_SHORT_OPTIONS_WITH_VALUES:
            if option == "O":
                remote_name = True
            continue
        if option == "K":
            raise _WriteScopeError(
                "unsupported curl option '--config'; write scope is unknown"
            )
        if option in _CURL_SHORT_WRITE_ACTIONS:
            return remote_name, _CURL_SHORT_WRITE_ACTIONS[option], argument[position + 1 :]
        # The remainder belongs to this value-taking option, not to more flags.
        return remote_name, "", ""
    return remote_name, "", ""


def _curl_bundled_read_action(argument: str) -> tuple[str, str]:
    if not argument.startswith("-") or argument.startswith("--") or len(argument) <= 2:
        return "", ""
    for position, option in enumerate(argument[1:], start=1):
        if option not in _CURL_SHORT_OPTIONS_WITH_VALUES:
            continue
        flag = f"-{option}"
        return flag, argument[position + 1 :]
    return "", ""


def _curl_value_mentions_local_file(option: str, value: str) -> bool:
    if option in _CURL_ALWAYS_LOCAL_READ_OPTIONS:
        return True
    if option in _CURL_AT_LOCAL_READ_OPTIONS:
        return value.startswith("@") or "=@" in value or ";@" in value
    if option in _CURL_URL_OPTIONS:
        return value.lower().startswith("file:")
    return False


def _check_curl_local_read_sources(arguments: Sequence[str]) -> None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"--next", "-:"}:
            index += 1
            continue
        bundled_option, bundled_value = _curl_bundled_read_action(argument)
        if bundled_option:
            if bundled_option in _CURL_ALWAYS_LOCAL_READ_OPTIONS or (
                bundled_value
                and _curl_value_mentions_local_file(bundled_option, bundled_value)
            ):
                raise _WriteScopeError(
                    f"unsupported curl option {bundled_option!r}; local file reads are not allowed"
                )
            index += 1
            continue
        long_option, separator, value = argument.partition("=")
        if argument in (
            _CURL_ALWAYS_LOCAL_READ_OPTIONS | _CURL_AT_LOCAL_READ_OPTIONS | _CURL_URL_OPTIONS
        ):
            index += 1
            if index >= len(arguments):
                raise _WriteScopeError(f"curl option {argument!r} requires a value")
            value = arguments[index]
            if _curl_value_mentions_local_file(argument, value):
                raise _WriteScopeError(
                    f"unsupported curl option {argument!r}; local file reads are not allowed"
                )
            index += 1
            continue
        if separator and long_option in (
            _CURL_ALWAYS_LOCAL_READ_OPTIONS | _CURL_AT_LOCAL_READ_OPTIONS | _CURL_URL_OPTIONS
        ):
            if _curl_value_mentions_local_file(long_option, value):
                raise _WriteScopeError(
                    f"unsupported curl option {long_option!r}; local file reads are not allowed"
                )
            index += 1
            continue
        if not argument.startswith("-") and argument.lower().startswith("file:"):
            raise _WriteScopeError("curl file:// URLs are not allowed")
        index += 1


def _curl_write_out_targets(value: str) -> list[str]:
    if value.startswith("@"):
        raise _WriteScopeError(
            "external curl --write-out formats are unsupported; write scope is unknown"
        )
    targets: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        run_end = index
        while run_end < len(value) and value[run_end] == "%":
            run_end += 1
        if (run_end - index) % 2 == 0:
            index = run_end
            continue
        if not value.startswith("output{", run_end):
            index = run_end
            continue
        target_start = run_end + len("output{")
        target_end = value.find("}", target_start)
        if target_end < 0:
            raise _WriteScopeError("malformed curl --write-out %output directive")
        target = value[target_start:target_end]
        if target.startswith(">>"):
            target = target[2:]
        if not target:
            raise _WriteScopeError("curl --write-out %output requires a destination")
        if target not in {"stdout", "stderr"}:
            targets.append(target)
        index = target_end + 1
    return targets


def _curl_disables_default_config(argument: str) -> bool:
    return argument == "--disable" or (
        argument.startswith("-q") and not argument.startswith("--")
    )


def _curl_targets(arguments: Sequence[str]) -> list[str]:
    if not arguments or not _curl_disables_default_config(arguments[0]):
        raise _WriteScopeError(
            "curl must use '-q' or '--disable' as its first argument to disable implicit .curlrc"
        )
    arguments = _expand_curl_short_next(arguments)
    _check_curl_local_read_sources(arguments)
    targets: list[str] = []
    index = 0
    remote_name_all = False
    remote_name_pending = False
    output_dir = _curl_output_dir(_curl_operation(arguments, 0))
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"--next", "-:"}:
            remote_name_all = False
            remote_name_pending = False
            index += 1
            output_dir = _curl_output_dir(_curl_operation(arguments, index))
            continue
        bundled_remote_name, bundled_action, attached_output = (
            _curl_bundled_write_action(argument)
        )
        if bundled_remote_name:
            remote_name_pending = True
        if bundled_action == "target":
            if not attached_output:
                index += 1
                if index >= len(arguments):
                    raise _WriteScopeError(f"curl option {argument!r} requires a value")
                attached_output = arguments[index]
            if attached_output != "-":
                targets.append(attached_output)
            index += 1
            continue
        if bundled_action == "write-out":
            if not attached_output:
                index += 1
                if index >= len(arguments):
                    raise _WriteScopeError(f"curl option {argument!r} requires a value")
                attached_output = arguments[index]
            targets.extend(_curl_write_out_targets(attached_output))
            index += 1
            continue
        if bundled_remote_name:
            index += 1
            continue
        if argument in _CURL_FILE_OPTIONS:
            index += 1
            if index >= len(arguments):
                raise _WriteScopeError(f"curl option {argument!r} requires a value")
            value = arguments[index]
            if value != "-":
                targets.append(value)
            index += 1
            continue
        if argument in {"--output-dir"}:
            index += 1
            if index < len(arguments):
                value = arguments[index]
                if value != "-":
                    output_dir = value
                    targets.append(value)
                index += 1
            continue
        if argument.startswith("--output-dir="):
            value = argument.split("=", 1)[1]
            if value and value != "-":
                output_dir = value
                targets.append(value)
            index += 1
            continue
        long_option, separator, value = argument.partition("=")
        if separator and long_option in _CURL_FILE_OPTIONS:
            if value and value != "-":
                targets.append(value)
            index += 1
            continue
        if argument in _CURL_WRITE_OUT_OPTIONS:
            index += 1
            if index >= len(arguments):
                raise _WriteScopeError(f"curl option {argument!r} requires a value")
            targets.extend(_curl_write_out_targets(arguments[index]))
            index += 1
            continue
        if separator and long_option == "--write-out":
            targets.extend(_curl_write_out_targets(value))
            index += 1
            continue
        if argument in {"-K", "--config"} or argument.startswith("--config="):
            raise _WriteScopeError(
                "unsupported curl option '--config'; write scope is unknown"
            )
        if argument == "--remote-name-all":
            remote_name_all = True
            index += 1
            continue
        if argument in {"-O", "--remote-name"}:
            remote_name_pending = True
            index += 1
            continue
        if remote_name_pending:
            if argument.startswith("-"):
                index += 1
                continue
            target = _curl_remote_name(argument)
            if target:
                if output_dir:
                    targets.append(str(Path(output_dir) / target))
                else:
                    targets.append(target)
            remote_name_pending = False
            index += 1
            continue
        if remote_name_all and not argument.startswith("-"):
            target = _curl_remote_name(argument)
            if target:
                if output_dir:
                    targets.append(str(Path(output_dir) / target))
                else:
                    targets.append(target)
            index += 1
            continue
        index += 1
    return targets


def _curl_remote_name(url: str) -> str | None:
    if not url or url.startswith("-"):
        return None
    name = urlsplit(url).path.rsplit("/", 1)[-1]
    return name or None


def _positional_arguments(arguments: Sequence[str]) -> list[str]:
    positional: list[str] = []
    after_options = False
    for argument in arguments:
        if argument == "--":
            after_options = True
        elif after_options or not argument.startswith("-"):
            positional.append(argument)
    return positional


def _destination_targets(binary: str, arguments: Sequence[str]) -> list[str]:
    target_directory = _target_directory(arguments)
    if target_directory is not None:
        return [target_directory]
    value_options = {
        "cp": {"-S", "--suffix"},
        "install": {"-g", "--group", "-m", "--mode", "-o", "--owner", "-S", "--suffix"},
        "ln": {"-S", "--suffix"},
        "mv": {"-S", "--suffix"},
        "rsync": {
            "--backup-dir",
            "--compare-dest",
            "--copy-dest",
            "--link-dest",
            "--suffix",
        },
    }.get(binary, set())
    short_value_prefixes = {
        option
        for option in value_options
        if option.startswith("-") and not option.startswith("--")
    }
    positionals: list[str] = []
    after_options = False
    seen_operand = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if after_options:
            positionals.append(argument)
            index += 1
            continue
        if argument == "--":
            after_options = True
            index += 1
            continue
        if argument.startswith("-"):
            if seen_operand:
                raise _WriteScopeError(
                    f"unsupported {binary} option after operands; write target is ambiguous"
                )
            if argument in value_options:
                if index + 1 >= len(arguments):
                    raise _WriteScopeError(f"{binary} option {argument} requires a value")
                index += 2
                continue
            if any(
                argument.startswith(f"{option}=")
                for option in value_options
                if option.startswith("--")
            ):
                index += 1
                continue
            if any(
                argument.startswith(option) and len(argument) > len(option)
                for option in short_value_prefixes
            ):
                index += 1
                continue
            index += 1
            continue
        seen_operand = True
        positionals.append(argument)
        index += 1
    return positionals[-1:]


def _target_directory(arguments: Sequence[str]) -> str | None:
    for index, argument in enumerate(arguments):
        if argument in {"-t", "--target-directory"}:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith("--target-directory="):
            return argument.split("=", 1)[1]
        if argument.startswith("-t") and len(argument) > 2:
            return argument[2:].removeprefix("=")
    return None


def _sed_targets(arguments: Sequence[str]) -> list[str]:
    targets: list[str] = []
    script_supplied = False
    skip_value = False
    for argument in arguments:
        if skip_value:
            skip_value = False
            script_supplied = True
        elif argument in {"-e", "--expression", "-f", "--file"}:
            skip_value = True
        elif argument.startswith(("-e", "--expression=", "-f", "--file=")):
            script_supplied = True
        elif argument.startswith("-"):
            continue
        elif not script_supplied:
            script_supplied = True
        else:
            targets.append(argument)
    return targets


def _wrapped_command(binary: str, args: list[str]) -> list[str]:
    if binary == "exec":
        return _after_options(
            args, value_options={"-a"}, flag_options={"-c", "-l"}
        )
    if binary == "command":
        return _after_options(args, value_options=set(), flag_options={"-p"})
    if binary == "env":
        return _after_options(
            args,
            value_options={"-u", "--unset", "-a", "--argv0"},
            flag_options={"-", "-i", "--ignore-environment", "-0", "--null", "--debug"},
            optional_value_options={
                "--default-signal", "--ignore-signal", "--block-signal"
            },
            forbidden_options={"-S", "--split-string", "-C", "--chdir"},
            assignments=True,
        )
    if binary == "nice":
        return _after_options(
            args, value_options={"-n", "--adjustment"}, flag_options=set()
        )
    if binary == "ionice":
        return _after_options(
            args,
            value_options={
                "-c", "--class", "-n", "--classdata", "-p", "--pid",
                "-P", "--pgid", "-u", "--uid",
            },
            flag_options={"-t", "--ignore"},
        )
    if binary == "stdbuf":
        return _after_options(
            args,
            value_options={"-i", "--input", "-o", "--output", "-e", "--error"},
            flag_options=set(),
        )
    if binary == "timeout":
        remainder = _after_options(
            args,
            value_options={"-k", "--kill-after", "-s", "--signal"},
            flag_options={"--preserve-status", "--foreground", "--verbose"},
        )
        if len(remainder) < 2:
            raise ValueError("expected duration and command")
        return remainder[1:]
    raise ValueError(f"unsupported wrapper {binary}")


def _after_options(
    args: list[str],
    *,
    value_options: set[str],
    flag_options: set[str],
    optional_value_options: set[str] | None = None,
    forbidden_options: set[str] | None = None,
    assignments: bool = False,
) -> list[str]:
    optional_value_options = optional_value_options or set()
    forbidden_options = forbidden_options or set()
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if assignments and _ASSIGNMENT.fullmatch(token):
            raise _AssignmentError("environment variable assignments are not allowed")
        if token == "-" and token in flag_options:
            index += 1
            continue
        if not token.startswith("-") or token == "-":
            break
        option = token.split("=", 1)[0]
        short_option = token[:2]
        short_with_value = len(token) > 2 and short_option in value_options
        if option in forbidden_options or short_option in forbidden_options:
            raise ValueError(f"option {option!r} makes the executable position ambiguous")
        if option in optional_value_options:
            pass
        elif option in value_options or short_with_value:
            if "=" in token and not token.split("=", 1)[1]:
                raise ValueError(f"{option} has an empty value")
            if "=" in token or short_with_value:
                index += 1
                continue
            index += 1
            if index >= len(args):
                raise ValueError(f"{option} needs a value")
        elif token not in flag_options:
            raise ValueError(f"unknown option {token!r}")
        index += 1
    command = args[index:]
    if not command:
        raise ValueError("expected a command")
    return command
