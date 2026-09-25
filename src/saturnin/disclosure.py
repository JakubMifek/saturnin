"""Deterministic repository-specific checks for the public disclosure gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

import yaml

TRUSTED_CUSTOM_RULE_DIGESTS = {
    "saturnin-synthetic-token": (
        "32fd28a36d29b0b679afb141f9fcc05308a9f2964bb08850a5fc49d8062e20c1"
    )
}


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int

    def diagnostic(self) -> str:
        file_id = hashlib.sha256(self.path.encode("utf-8")).hexdigest()[:12]
        return f"disclosure violation: rule={self.rule} file_sha256={file_id} line={self.line}"


def load_policy(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("disclosure policy must be a mapping")
    problems = audit_policy(data)
    if problems:
        raise ValueError("; ".join(problems))
    return data


def audit_policy(policy: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    required_sections = {
        "version",
        "scanner",
        "forbidden_markers",
        "allowlist",
        "scanner_allowlist",
    }
    if set(policy) != required_sections or policy.get("version") != 1:
        problems.append("disclosure policy requires only the version 1 governed sections")
    scanner = policy.get("scanner")
    required_scanner = {
        "name",
        "version",
        "linux_x64_sha256",
        "linux_x64_binary_sha256",
        "config",
    }
    if not isinstance(scanner, dict) or set(scanner) != required_scanner:
        problems.append("scanner pin requires only name, version, archive/binary sha256, and config")
    elif (
        scanner["name"] != "gitleaks"
        or scanner["config"] != "policies/gitleaks.toml"
        or not all(
            len(str(scanner[key])) == 64
            and all(char in "0123456789abcdef" for char in str(scanner[key]))
            for key in ("linux_x64_sha256", "linux_x64_binary_sha256")
        )
    ):
        problems.append("scanner must be gitleaks with the governed config and lowercase sha256 pins")
    markers = policy.get("forbidden_markers", [])
    marker_ids: set[str] = set()
    if not isinstance(markers, list) or not markers:
        problems.append("forbidden_markers must be a non-empty list")
        markers = []
    for marker in markers:
        if not isinstance(marker, dict):
            problems.append("each forbidden marker must be a mapping")
            continue
        rule = marker.get("id")
        literal = marker.get("literal")
        if not isinstance(rule, str) or not rule or rule in marker_ids:
            problems.append("forbidden marker ids must be unique non-empty strings")
        else:
            marker_ids.add(rule)
        if (
            not isinstance(literal, str)
            or len(literal) < 12
            or "\n" in literal
            or "\r" in literal
        ):
            problems.append(f"forbidden marker {rule!r} must have a literal of 12+ characters")

    allowlist = policy.get("allowlist", [])
    if not isinstance(allowlist, list):
        return problems + ["allowlist must be a list"]
    for entry in allowlist:
        if not isinstance(entry, dict):
            problems.append("each allowlist entry must be a mapping")
            continue
        if set(entry) != {"rule", "path", "line_sha256"}:
            problems.append("allowlist entries require only rule, path, and line_sha256")
            continue
        path = str(entry["path"])
        pure = PurePosixPath(path)
        if (
            not path.startswith("tests/fixtures/disclosure/")
            or pure.is_absolute()
            or ".." in pure.parts
            or any(char in path for char in "*?[]")
        ):
            problems.append(f"allowlist path is not a narrow disclosure fixture: {path}")
        if entry["rule"] not in marker_ids:
            problems.append(f"allowlist references unknown rule: {entry['rule']}")
        digest = str(entry["line_sha256"])
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            problems.append(f"allowlist line digest is not lowercase sha256: {path}")
    scanner_allowlist = policy.get("scanner_allowlist", [])
    if not isinstance(scanner_allowlist, list):
        return problems + ["scanner_allowlist must be a list"]
    seen_scanner_rules: set[str] = set()
    for entry in scanner_allowlist:
        if not isinstance(entry, dict):
            problems.append("each scanner allowlist entry must be a mapping")
            continue
        if set(entry) != {"rule", "path", "match_sha256"}:
            problems.append(
                "scanner allowlist entries require only rule, path, and match_sha256"
            )
            continue
        rule = entry["rule"]
        path = entry["path"]
        digest = entry["match_sha256"]
        pure = PurePosixPath(path) if isinstance(path, str) else PurePosixPath("/")
        if not isinstance(rule, str) or not rule or rule in seen_scanner_rules:
            problems.append("scanner allowlist rules must be unique non-empty strings")
        else:
            seen_scanner_rules.add(rule)
        if (
            not isinstance(path, str)
            or not path.startswith("tests/fixtures/disclosure/")
            or pure.is_absolute()
            or ".." in pure.parts
            or any(char in path for char in "*?[]")
        ):
            problems.append("scanner allowlist path is not a narrow disclosure fixture")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            problems.append("scanner allowlist match digest is not lowercase sha256")
    return problems


def _exact_regex_literal(pattern: Any) -> str | None:
    if not isinstance(pattern, str) or len(pattern) < 2:
        return None
    if not pattern.startswith("^") or not pattern.endswith("$"):
        return None
    body = pattern[1:-1]
    literal: list[str] = []
    escaped = False
    metacharacters = frozenset(r"\.^$*+?{}[]()|")
    for char in body:
        if escaped:
            if char not in metacharacters:
                return None
            literal.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in metacharacters:
            return None
        else:
            literal.append(char)
    if escaped:
        return None
    value = "".join(literal)
    return value if pattern == f"^{re.escape(value)}$" else None


def audit(root: Path, policy: dict[str, Any]) -> list[str]:
    problems = audit_policy(policy)
    if problems:
        return problems
    config_path = root / policy["scanner"]["config"]
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"invalid gitleaks config: {error}"]
    if set(config) != {"title", "extend", "rules"}:
        problems.append("gitleaks config permits only title, extend, and rules")
    if config.get("extend") != {"useDefault": True}:
        problems.append("gitleaks config must extend the pinned built-in rules")
    if "allowlist" in config or "allowlists" in config:
        problems.append("global gitleaks allowlists are forbidden")
    governed = {
        entry["rule"]: entry
        for entry in policy.get("scanner_allowlist", [])
        if isinstance(entry, dict) and set(entry) == {"rule", "path", "match_sha256"}
    }
    observed: set[str] = set()
    rules = config.get("rules", [])
    if not isinstance(rules, list):
        return problems + ["gitleaks rules must be a list"]
    custom_rule_ids = [
        rule.get("id") for rule in rules if isinstance(rule, dict)
    ]
    if (
        len(custom_rule_ids) != len(set(custom_rule_ids))
        or set(custom_rule_ids) != set(TRUSTED_CUSTOM_RULE_DIGESTS)
    ):
        problems.append("gitleaks custom rule ids must match the trusted rule set")
    for rule in rules:
        if not isinstance(rule, dict):
            problems.append("each gitleaks rule must be a mapping")
            continue
        rule_id = rule.get("id")
        definition = json.dumps(
            rule, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if (
            not isinstance(rule_id, str)
            or hashlib.sha256(definition).hexdigest()
            != TRUSTED_CUSTOM_RULE_DIGESTS.get(rule_id)
        ):
            problems.append(
                "gitleaks custom rule definition does not match its trusted digest"
            )
        entries = rule.get("allowlists", [])
        if not isinstance(entries, list):
            problems.append("gitleaks rule allowlists must be a list")
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                problems.append(
                    "gitleaks allowlist is not an exact governed fixture exception"
                )
                continue
            specification = governed.get(rule_id)
            paths = entry.get("paths", [])
            regexes = entry.get("regexes", [])
            literal = (
                _exact_regex_literal(regexes[0])
                if isinstance(regexes, list) and len(regexes) == 1
                else None
            )
            if (
                specification is None
                or entry.get("condition") != "AND"
                or entry.get("regexTarget") != "match"
                or paths
                != [rf"(?:^|/){re.escape(specification['path'])}$"]
                or literal is None
                or hashlib.sha256(literal.encode("utf-8")).hexdigest()
                != specification["match_sha256"]
            ):
                problems.append(
                    "gitleaks allowlist is not an exact governed fixture exception"
                )
                continue
            fixture = root / specification["path"]
            try:
                fixture_lines = fixture.read_bytes().splitlines()
            except OSError:
                problems.append("gitleaks allowlist fixture is missing")
                continue
            if literal.encode("utf-8") not in fixture_lines:
                problems.append("gitleaks allowlist literal is absent from its exact fixture")
                continue
            observed.add(rule_id)
    if observed != set(governed):
        problems.append("gitleaks allowlist policy and scanner configuration do not match")
    return problems


def _files(root: Path) -> Iterator[tuple[str, Path]]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        yield path.relative_to(root).as_posix(), path


def _marker_lines(
    path: Path, markers: list[tuple[str, bytes]]
) -> Iterator[tuple[str, int, str]]:
    maximum = max(len(literal) for _, literal in markers)
    overlap = b""
    line_number = 1
    line_digest = hashlib.sha256()
    line_has_content = False
    matched: set[str] = set()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            pieces = chunk.split(b"\n")
            for index, piece in enumerate(pieces):
                complete = index < len(pieces) - 1
                window = overlap + piece
                for rule, literal in markers:
                    if literal in window:
                        matched.add(rule)
                line_digest.update(piece)
                line_has_content = line_has_content or bool(piece)
                overlap = window[-(maximum - 1) :] if maximum > 1 else b""
                if complete:
                    digest = line_digest.hexdigest()
                    for rule in sorted(matched):
                        yield rule, line_number, digest
                    line_number += 1
                    line_digest = hashlib.sha256()
                    line_has_content = False
                    matched = set()
                    overlap = b""
    if line_has_content or matched:
        digest = line_digest.hexdigest()
        for rule in sorted(matched):
            yield rule, line_number, digest


def scan_tree(root: Path, policy: dict[str, Any]) -> list[Finding]:
    allowed = {
        (entry["rule"], entry["path"], entry["line_sha256"])
        for entry in policy.get("allowlist", [])
    }
    markers = [
        (marker["id"], marker["literal"].encode("utf-8"))
        for marker in policy["forbidden_markers"]
    ]
    declarations = {
        (
            marker["id"],
            hashlib.sha256(
                f'    literal: "{marker["literal"]}"'.encode("utf-8")
            ).hexdigest(),
        )
        for marker in policy["forbidden_markers"]
    }
    findings: list[Finding] = []
    for relative, path in _files(root):
        for rule, line_number, digest in _marker_lines(path, markers):
            trusted_declaration = (
                relative == "policies/disclosure.yaml"
                and (rule, digest) in declarations
            )
            if not trusted_declaration and (rule, relative, digest) not in allowed:
                findings.append(Finding(rule, relative, line_number))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"disclosure gate configuration error: {error}")
        return 2
    if args.audit_only:
        problems = audit(args.root, policy)
        for problem in problems:
            print(f"disclosure gate configuration error: {problem}")
        return 2 if problems else 0
    try:
        findings = scan_tree(args.root, policy)
    except OSError:
        print("disclosure gate could not read candidate content")
        return 2
    for finding in findings:
        print(finding.diagnostic())
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
