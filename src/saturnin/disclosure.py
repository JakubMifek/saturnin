"""Deterministic repository-specific checks for the public disclosure gate."""

from __future__ import annotations

import argparse
import hashlib
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import yaml


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
        if not isinstance(literal, str) or len(literal) < 12:
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
    return problems


def audit(root: Path, policy: dict[str, Any]) -> list[str]:
    problems = audit_policy(policy)
    if problems:
        return problems
    config_path = root / policy["scanner"]["config"]
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"invalid gitleaks config: {error}"]
    if config.get("extend") != {"useDefault": True}:
        problems.append("gitleaks config must extend the pinned built-in rules")
    if "allowlist" in config or "allowlists" in config:
        problems.append("global gitleaks allowlists are forbidden")
    for rule in config.get("rules", []):
        for entry in rule.get("allowlists", []):
            paths = entry.get("paths", [])
            regexes = entry.get("regexes", [])
            if (
                entry.get("condition") != "AND"
                or entry.get("regexTarget") != "match"
                or not paths
                or not regexes
                or any(
                    not path.startswith("(?:^|/)tests/fixtures/disclosure/")
                    or not path.endswith("$")
                    or ".*" in path
                    for path in paths
                )
                or any(not regex.startswith("^") or not regex.endswith("$") for regex in regexes)
            ):
                problems.append(
                    f"gitleaks allowlist for {rule.get('id', '<unknown>')} is not an exact fixture exception"
                )
    return problems


def _text_files(root: Path) -> Iterable[tuple[str, list[str]]]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        content = path.read_bytes()
        if b"\0" in content:
            continue
        yield path.relative_to(root).as_posix(), content.decode(
            "utf-8", errors="replace"
        ).splitlines()


def scan_tree(root: Path, policy: dict[str, Any]) -> list[Finding]:
    allowed = {
        (entry["rule"], entry["path"], entry["line_sha256"])
        for entry in policy.get("allowlist", [])
    }
    findings: list[Finding] = []
    for path, lines in _text_files(root):
        for line_number, line in enumerate(lines, 1):
            if path == "policies/disclosure.yaml" and line.lstrip().startswith("literal:"):
                continue
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
            for marker in policy["forbidden_markers"]:
                if marker["literal"] not in line:
                    continue
                if (marker["id"], path, digest) not in allowed:
                    findings.append(Finding(marker["id"], path, line_number))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"disclosure gate configuration error: {error}")
        return 2
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
