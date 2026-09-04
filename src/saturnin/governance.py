"""Governance gates.

Every irreversible action (push, merge, issue submission, server command) has to
pass through here first. The rules themselves live in
``policies/governance.yaml`` and ``policies/server_scope.yaml``.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

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


class _AssignmentError(ValueError):
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
        # Only count approvals from designated reviewer roles for this kind.
        allowed = _allowed_reviewer_roles(kind, self.config) if kind else set()
        approvals = [r for r in records if r.verdict == "approved"]
        if allowed:
            approvals = [r for r in approvals if r.reviewer.strip().lower() in allowed]
        blocking = [r for r in records if r.verdict in ("changes_requested", "rejected")]
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
        if repo == self.autonomy.get("self_repo"):
            if not self.autonomy.get("self_repo_autonomous_merge", False):
                return Decision.deny(f"{repo}: autonomous merge disabled by policy")
            reasons.append(f"{repo}: autonomous merge allowed after review")
            return Decision(True, reasons)
        return Decision.deny(
            f"{repo}: Saturnin does not merge in managed repos; open an issue or PR for a human"
        )

    def issue_submission_allowed(
        self, *, repo: str, author: str, records: Iterable[ReviewRecord]
    ) -> Decision:
        """Rule 5: issues for managed repos need an independent issue review."""
        records = [r for r in records if r.kind == "issue"]
        managed = {
            repo_entry.get("slug")
            for repo_entry in self.config.policy("repos").get("repos", {}).values()
            if isinstance(repo_entry, dict) and repo_entry.get("slug")
        }
        managed.add(self.autonomy.get("self_repo"))
        # Discovery sources are also managed project repositories.
        discovery = self.config.policy("repos").get("discovery", {})
        for source in discovery.get("sources", []) or []:
            slug = source.get("slug") if isinstance(source, dict) else source
            if slug:
                managed.add(str(slug))
        if repo not in managed:
            return Decision.deny(f"{repo}: issue creation is only allowed in managed repositories")
        if repo == self.autonomy.get("self_repo"):
            return Decision.ok(f"{repo}: own repository, issue may be filed directly")
        if not self.autonomy.get("external_repos_allow_issue_creation", True):
            return Decision.deny(f"{repo}: issue creation is disabled by policy")
        settings = dict(self.review.get("issue", {}))
        if not settings.get("required_for_external_repos", True):  # pragma: no cover
            return Decision.ok(f"{repo}: issue review not required")
        settings.setdefault("min_approvals", 1)
        return self._review_gate(records, author, settings, "issue review", kind="issue")

    def push_allowed(self, *, repo: str, branch: str) -> Decision:
        branch_check = self.check_branch(branch)
        if not branch_check.allowed:
            return branch_check
        if repo != self.autonomy.get("self_repo") and not self.autonomy.get(
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
            return Decision.deny("shell variable assignments are not allowed")
        user = scope.get("user", {})
        if not user.get("allow_root", False) and os.geteuid() == 0:
            return Decision.deny("server commands may not run as root")
        forbidden_binaries = user.get("forbidden_prefixes", [])
        for part in parts:
            try:
                candidates = shlex.split(part)
            except ValueError:
                continue
            for candidate in candidates:
                candidate_binary = candidate.rsplit("/", 1)[-1]
                if candidate_binary in forbidden_binaries:
                    return Decision.deny(
                        f"privilege escalation via {candidate_binary!r} is not allowed"
                    )
        return self._check_scoped_command(
            parts, dedicated_service=dedicated_service, depth=0
        )

    def _check_scoped_command(
        self,
        parts: Sequence[str],
        *,
        dedicated_service: str | None,
        depth: int,
    ) -> Decision:
        if depth >= _MAX_COMMAND_DEPTH:
            return Decision.deny("command wrappers are nested too deeply")
        parts = list(parts)
        if not parts:
            return Decision.deny("wrapper contains no command")
        if _ASSIGNMENT.fullmatch(parts[0]):
            return Decision.deny("shell variable assignments are not allowed")
        binary = parts[0].rsplit("/", 1)[-1]
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
                depth=depth + 1,
            )

        scope = self.config.server_scope
        services = scope.get("services", {})
        packages = scope.get("packages", {})
        filesystem_decision = _check_filesystem_scope(
            binary, parts[1:], scope.get("filesystem", {})
        )
        if not filesystem_decision.allowed:
            return filesystem_decision
        if binary == "apt" or binary.startswith("apt-"):
            if not packages.get("apt_allowed", False):
                return Decision.deny("apt is not allowed")
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
            unknown = [flag for flag in flags if flag != "--user"]
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
            if not units and sub not in ("list-timers", "status"):
                return Decision.deny("systemctl needs an explicit Saturnin unit name")
            return Decision.ok("systemctl limited to Saturnin-dedicated units")
        return Decision.ok(f"{binary}: no elevated capability required")

    # -- delegation ----------------------------------------------------
    @property
    def result_contracts(self) -> list[str]:
        return list(self.delegation.get("result_contracts", []))

    def check_result_contract(self, contract: str | None) -> Decision:
        """Rule 9: a dispatch without an agreed result contract would force the
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
        """Rule 8: tasks are mirrored as issues so local loss is survivable."""
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
        if self.policy.get("delegation", {}).get("ceo_may_execute", False):
            problems.append("CEO is allowed to execute work; delegation-first is violated")
        if self.config.server_scope.get("user", {}).get("allow_root", False):
            problems.append("server scope allows root")
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
    binary: str, arguments: Sequence[str], filesystem: dict[str, Any]
) -> Decision:
    forbidden_roots = _policy_roots(filesystem.get("forbidden_roots", []))
    targets = _writable_targets(binary, arguments)
    if not targets:
        # No explicit write targets detected.  Interpreters and shells can
        # perform arbitrary filesystem writes that argument inspection cannot
        # detect, so they must be denied unless an explicit allowlist permits
        # them.  For non-interpreter binaries the allowlist is also checked.
        allowlist = set(filesystem.get("executable_allowlist", []))
        if binary in _SHELL_BINARIES or binary in {"python", "python3", "ruby", "perl", "node"}:
            if binary not in allowlist:
                return Decision.deny(
                    f"{binary!r} is an interpreter whose filesystem writes cannot be "
                    "statically determined; add it to executable_allowlist to permit it"
                )
            # Even when allow-listed, interpreters are restricted to validated
            # Saturnin module invocations (``python3 -m saturnin ...``).
            if binary in {"python", "python3"}:
                if not (len(arguments) >= 2 and arguments[0] == "-m" and arguments[1] == "saturnin"):
                    return Decision.deny(
                        f"{binary!r} is only allowed for Saturnin module invocations "
                        "(python3 -m saturnin ...)"
                    )
        elif allowlist and binary not in allowlist:
            return Decision.deny(
                f"{binary!r} is not in the executable allowlist; "
                "arbitrary executables cannot be sandboxed by argument inspection alone"
            )
        return Decision.ok("command has no explicit filesystem write target")

    writable_roots = _policy_roots(filesystem.get("writable_roots", []))
    for raw_path in targets:
        path = _resolve_command_path(raw_path)
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


def _resolve_command_path(value: str) -> Path:
    return Path(value).expanduser().resolve(strict=False)


def _containing_root(path: Path, roots: Sequence[Path]) -> Path | None:
    return next((root for root in roots if path == root or root in path.parents), None)


def _writable_targets(binary: str, arguments: Sequence[str]) -> list[str]:
    positional = _positional_arguments(arguments)
    if binary in _ALL_OPERANDS_WRITABLE:
        return positional
    if binary in _DESTINATION_WRITABLE:
        target_directory = _target_directory(arguments)
        if target_directory is not None:
            return [target_directory]
        return positional[-1:]
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
    return []


def _positional_arguments(arguments: Sequence[str]) -> list[str]:
    positional: list[str] = []
    after_options = False
    for argument in arguments:
        if argument == "--":
            after_options = True
        elif after_options or not argument.startswith("-"):
            positional.append(argument)
    return positional


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
            value_options={"-u", "--unset", "-C", "--chdir", "-a", "--argv0"},
            flag_options={"-", "-i", "--ignore-environment", "-0", "--null", "--debug"},
            optional_value_options={
                "--default-signal", "--ignore-signal", "--block-signal"
            },
            forbidden_options={"-S", "--split-string"},
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
