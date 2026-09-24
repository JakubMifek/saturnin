from __future__ import annotations

import os
import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from saturnin.disclosure import audit, audit_policy, load_policy, scan_tree

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "policies" / "disclosure.yaml"
GATE = REPO_ROOT / "automation" / "library" / "disclosure_gate.sh"
EXACT_SYNTHETIC_REGEX = (
    r"^SATURNIN_SYNTHETIC_TOKEN_" + "4Q7W9E2R5T8Y1U3I6O0P2A4S$"
)


def test_marker_detection_is_redacted(tmp_path: Path) -> None:
    secret = "customer-record-that-must-never-appear"
    marker = "SATURNIN-DISCLOSURE:" + "PROPRIETARY"
    (tmp_path / "data.txt").write_text(f"{marker} {secret}\n", encoding="utf-8")

    findings = scan_tree(tmp_path, load_policy(POLICY))

    file_id = hashlib.sha256(b"data.txt").hexdigest()[:12]
    assert [item.diagnostic() for item in findings] == [
        f"disclosure violation: rule=proprietary-material file_sha256={file_id} line=1"
    ]
    assert secret not in findings[0].diagnostic()


def test_only_exact_trusted_marker_declarations_are_exempt(tmp_path: Path) -> None:
    policy = load_policy(POLICY)
    target = tmp_path / "policies" / "disclosure.yaml"
    target.parent.mkdir()
    marker = "SATURNIN-DISCLOSURE:" + "PRIVATE"
    target.write_text(
        f'    literal: "{marker}"\n'
        f"literal: {marker} candidate-controlled-private-value\n",
        encoding="utf-8",
    )

    findings = scan_tree(tmp_path, policy)

    assert [(finding.rule, finding.line) for finding in findings] == [
        ("private-material", 2)
    ]
    assert "candidate-controlled-private-value" not in findings[0].diagnostic()


def test_binary_pdf_and_archive_markers_are_redacted(tmp_path: Path) -> None:
    marker = b"SATURNIN-DISCLOSURE:" + b"PROPRIETARY"
    secret = b"private-customer-value"
    (tmp_path / "nul.bin").write_bytes(b"\0prefix-" + marker + b"-" + secret)
    (tmp_path / "document.pdf").write_bytes(
        b"%PDF-1.7\n1 0 obj\n\0" + marker + b" " + secret + b"\n%%EOF"
    )
    with zipfile.ZipFile(tmp_path / "stored.zip", "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", b"\0" + marker + b" " + secret)
    with tarfile.open(tmp_path / "stored.tar", "w") as archive:
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"\0" + marker + b" " + secret)
        archive.add(payload, arcname="payload.bin")
        payload.unlink()

    findings = scan_tree(tmp_path, load_policy(POLICY))
    diagnostics = "\n".join(finding.diagnostic() for finding in findings)

    assert {finding.path for finding in findings} == {
        "document.pdf",
        "nul.bin",
        "stored.tar",
        "stored.zip",
    }
    assert secret.decode() not in diagnostics


def test_marker_detection_overlaps_bounded_chunks(tmp_path: Path) -> None:
    marker = b"SATURNIN-DISCLOSURE:" + b"PRIVATE"
    (tmp_path / "chunked.bin").write_bytes(
        b"\0" + b"x" * (64 * 1024 - 10) + marker + b" undisclosed"
    )

    findings = scan_tree(tmp_path, load_policy(POLICY))

    assert [(finding.rule, finding.path) for finding in findings] == [
        ("private-material", "chunked.bin")
    ]


def test_clean_content_and_exact_synthetic_allowlist(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "fixtures" / "disclosure"
    fixture.mkdir(parents=True)
    shutil.copy(
        REPO_ROOT / "tests" / "fixtures" / "disclosure" / "synthetic-allowed.txt",
        fixture / "synthetic-allowed.txt",
    )
    (tmp_path / "README.md").write_text("public documentation\n", encoding="utf-8")

    assert scan_tree(tmp_path, load_policy(POLICY)) == []

    with (fixture / "synthetic-allowed.txt").open("a", encoding="utf-8") as handle:
        handle.write("SATURNIN-DISCLOSURE:" + "PRIVATE a different line\n")
    assert len(scan_tree(tmp_path, load_policy(POLICY))) == 1


def test_allowlist_is_restricted_to_exact_fixture_lines() -> None:
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    policy["allowlist"][0]["path"] = "src/saturnin/private.py"
    assert any("not a narrow disclosure fixture" in item for item in audit_policy(policy))

    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    policy["allowlist"][0]["extra"] = "broad"
    assert any("require only" in item for item in audit_policy(policy))


def test_gitleaks_allowlist_cannot_be_global_or_broad(tmp_path: Path) -> None:
    shutil.copytree(REPO_ROOT / "policies", tmp_path / "policies")
    config = tmp_path / "policies" / "gitleaks.toml"
    config.write_text(
        config.read_text(encoding="utf-8")
        + '\n[allowlist]\npaths = [".*"]\n',
        encoding="utf-8",
    )

    assert "global gitleaks allowlists are forbidden" in audit(
        tmp_path, yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    )


@pytest.mark.parametrize(
    ("path", "regex"),
    [
        (
            r"(?:^|/)tests/fixtures/disclosure/.+\.txt$",
            EXACT_SYNTHETIC_REGEX,
        ),
        (
            r"(?:^|/)tests/fixtures/disclosure/synthetic\-allowed\.txt$",
            r"^.*$",
        ),
        (
            r"(?:^|/)tests/fixtures/disclosure/synthetic\-allowed\.txt$",
            r"^SATURNIN_SYNTHETIC_TOKEN_[A-Z0-9]{24}$",
        ),
    ],
)
def test_gitleaks_allowlist_rejects_regex_equivalents(
    tmp_path: Path, path: str, regex: str
) -> None:
    shutil.copytree(REPO_ROOT / "policies", tmp_path / "policies")
    shutil.copytree(
        REPO_ROOT / "tests" / "fixtures",
        tmp_path / "tests" / "fixtures",
    )
    config = tmp_path / "policies" / "gitleaks.toml"
    text = config.read_text(encoding="utf-8")
    text = text.replace(
        r"(?:^|/)tests/fixtures/disclosure/synthetic\-allowed\.txt$", path
    ).replace(
        EXACT_SYNTHETIC_REGEX, regex
    )
    config.write_text(text, encoding="utf-8")

    problems = audit(
        tmp_path, yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    )

    assert "gitleaks allowlist is not an exact governed fixture exception" in problems


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _fake_gitleaks(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json, pathlib, sys
root = pathlib.Path(sys.argv[2])
report = pathlib.Path(sys.argv[sys.argv.index("--report-path") + 1])
ignore_annotations = "--ignore-gitleaks-allow" not in sys.argv
ignore_path = pathlib.Path(sys.argv[sys.argv.index("--gitleaks-ignore-path") + 1])
candidate_ignore_active = ignore_path != pathlib.Path("/dev/null") and ignore_path.exists()
leak = next(
    (
        path
        for path in root.rglob("*")
        if path.is_file()
        and b"RAW-SYNTHETIC-SECRET" in path.read_bytes()
        and not (
            ignore_annotations and b"gitleaks:allow" in path.read_bytes()
        )
        and not candidate_ignore_active
    ),
    None,
)
if leak is not None:
    print("RAW-SYNTHETIC-SECRET", file=sys.stderr)
    report.write_text(json.dumps([{"RuleID": "fake-token", "File": str(leak),
                                   "StartLine": 1, "Secret": "RAW-SYNTHETIC-SECRET"}]))
    raise SystemExit(1)
report.write_text("[]")
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _trusted_runtime(tmp_path: Path, fake: Path) -> Path:
    trusted = tmp_path / "trusted"
    if trusted.exists():
        shutil.rmtree(trusted)
    shutil.copytree(REPO_ROOT / "policies", trusted / "policies")
    shutil.copytree(REPO_ROOT / "src", trusted / "src")
    automation = trusted / "automation" / "library"
    automation.mkdir(parents=True)
    shutil.copy(REPO_ROOT / "automation" / "library" / "_common.sh", automation)
    python = trusted / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(
        f"#!/bin/sh\nexec {sys.executable} \"$@\"\n",
        encoding="utf-8",
    )
    python.chmod(0o755)
    policy_path = trusted / "policies" / "disclosure.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["scanner"]["version"] = "test"
    policy["scanner"]["linux_x64_binary_sha256"] = hashlib.sha256(
        fake.read_bytes()
    ).hexdigest()
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    scanner = trusted / "var" / "disclosure-tools" / "gitleaks-test"
    scanner.parent.mkdir(parents=True)
    shutil.copy(fake, scanner)
    return trusted


def _run_gate(
    repo: Path, fake: Path, *, source_ref: str = "index"
) -> subprocess.CompletedProcess[str]:
    trusted = _trusted_runtime(repo.parent, fake)
    env = os.environ.copy()
    env.pop("GITLEAKS_BIN", None)
    env.pop("SATURNIN_HOME", None)
    return subprocess.run(
        [str(GATE), str(repo), str(trusted), source_ref],
        text=True,
        capture_output=True,
        env=env,
    )


def test_gate_scans_tracked_content_and_redacts_scanner_output(tmp_path: Path) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    (repo / "leak.txt").write_text("RAW-SYNTHETIC-SECRET\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "-m", "fixture")
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)

    result = _run_gate(repo, fake)

    assert result.returncode == 1
    file_id = hashlib.sha256(b"leak.txt").hexdigest()[:12]
    assert f"rule=fake-token file_sha256={file_id} line=1" in result.stdout
    assert "RAW-SYNTHETIC-SECRET" not in result.stdout + result.stderr


def test_gate_ignores_untracked_and_ignored_content(tmp_path: Path) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    (repo / ".gitignore").write_text("leak.txt\n", encoding="utf-8")
    (repo / "clean.txt").write_text("clean\n", encoding="utf-8")
    (repo / "leak.txt").write_text("untracked\n", encoding="utf-8")
    _git(repo, "add", ".gitignore", "clean.txt")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "-m", "fixture")
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)

    result = _run_gate(repo, fake)

    assert result.returncode == 0
    assert "Git-tracked content only" in result.stdout


def test_gate_scans_index_bytes_not_worktree_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    target = repo / "leak.txt"
    target.write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "fixture",
    )
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)

    target.write_text("RAW-SYNTHETIC-SECRET\n", encoding="utf-8")
    assert _run_gate(repo, fake).returncode == 0

    _git(repo, "add", "leak.txt")
    target.write_text("clean worktree replacement\n", encoding="utf-8")
    result = _run_gate(repo, fake)

    assert result.returncode == 1
    assert "RAW-SYNTHETIC-SECRET" not in result.stdout + result.stderr


def test_gate_scans_exact_commit_tree_despite_index_changes(tmp_path: Path) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    target = repo / "leak.txt"
    target.write_text("RAW-SYNTHETIC-SECRET\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "fixture",
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    target.write_text("clean staged replacement\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)

    result = _run_gate(repo, fake, source_ref=commit)

    assert result.returncode == 1
    assert "RAW-SYNTHETIC-SECRET" not in result.stdout + result.stderr


@pytest.mark.parametrize("immutable", [False, True], ids=["index", "commit"])
def test_gate_rejects_annotated_credentials_with_redacted_output(
    tmp_path: Path, immutable: bool
) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    secret = "RAW-SYNTHETIC-SECRET"
    (repo / "leak.txt").write_text(
        f"token={secret} # gitleaks:allow\n",
        encoding="utf-8",
    )
    _git(repo, "add", "leak.txt")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "annotated credential",
    )
    source_ref = "index"
    if immutable:
        source_ref = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)

    result = _run_gate(repo, fake, source_ref=source_ref)

    assert result.returncode == 1
    assert "rule=fake-token" in result.stdout
    assert secret not in result.stdout + result.stderr


def test_gate_disables_all_candidate_controlled_gitleaks_ignores() -> None:
    script = GATE.read_text(encoding="utf-8")
    match = re.search(r'"\$gitleaks" dir .*?--report-path', script, re.DOTALL)
    assert match is not None
    invocation = match.group()

    assert "--ignore-gitleaks-allow" in invocation
    assert "--gitleaks-ignore-path /dev/null" in invocation
    assert '--config "$config"' in invocation
    assert "--baseline-path" not in invocation


def test_gate_does_not_descend_into_gitlink_worktrees(tmp_path: Path) -> None:
    child = tmp_path / "child"
    child.mkdir()
    _git(child, "init", "-b", "main")
    (child / "content.txt").write_text("clean\n", encoding="utf-8")
    _git(child, "add", "content.txt")
    _git(
        child,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "fixture",
    )
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    _git(repo, "-c", "protocol.file.allow=always", "submodule", "add", str(child), "vendor")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-am",
        "add gitlink",
    )
    (repo / "vendor" / "content.txt").write_text(
        "RAW-SYNTHETIC-SECRET\n", encoding="utf-8"
    )
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)

    result = _run_gate(repo, fake)

    assert result.returncode == 0


def test_gate_rejects_scanner_override(tmp_path: Path) -> None:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "feature/test")
    (repo / "clean.txt").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "clean.txt")
    fake = tmp_path / "gitleaks"
    _fake_gitleaks(fake)
    trusted = _trusted_runtime(tmp_path, fake)
    env = os.environ.copy()
    env["GITLEAKS_BIN"] = str(fake)
    env.pop("SATURNIN_HOME", None)

    result = subprocess.run(
        [str(GATE), str(repo), str(trusted)],
        text=True,
        capture_output=True,
        env=env,
    )

    assert result.returncode == 2
    assert "rejects scanner overrides" in result.stdout


def test_trusted_validator_rejects_candidate_policy_broadening(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    shutil.copytree(REPO_ROOT / "policies", candidate / "policies")
    shutil.copytree(
        REPO_ROOT / "tests" / "fixtures",
        candidate / "tests" / "fixtures",
    )
    config = candidate / "policies" / "gitleaks.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            EXACT_SYNTHETIC_REGEX,
            r"^.*$",
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "saturnin.disclosure",
            "--audit-only",
            "--root",
            str(candidate),
            "--policy",
            str(candidate / "policies" / "disclosure.yaml"),
        ],
        text=True,
        capture_output=True,
        env=env,
    )

    assert result.returncode == 2
    assert "exact governed fixture exception" in result.stdout
    assert "SATURNIN_SYNTHETIC_TOKEN" not in result.stdout + result.stderr


def test_untrusted_candidate_cannot_replace_base_enforcement() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "governance.yml").read_text(
        encoding="utf-8"
    )
    assert "pull_request_target:" in workflow
    assert "working-directory: trusted" in workflow
    assert "github.event.pull_request.head.repo.full_name" in workflow
    assert "github.event.pull_request.base.repo.full_name" in workflow
    assert "candidate trusted \"$CANDIDATE_SHA\"" in workflow
    assert "--policy candidate/policies/disclosure.yaml" in workflow
    assert "candidate/automation/library/disclosure_gate.sh" not in workflow
