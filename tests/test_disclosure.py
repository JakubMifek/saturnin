from __future__ import annotations

import os
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from saturnin.disclosure import audit, audit_policy, load_policy, scan_tree

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "policies" / "disclosure.yaml"
GATE = REPO_ROOT / "automation" / "library" / "disclosure_gate.sh"


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


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _fake_gitleaks(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json, pathlib, sys
root = pathlib.Path(sys.argv[2])
report = pathlib.Path(sys.argv[sys.argv.index("--report-path") + 1])
leak = root / "leak.txt"
if leak.exists():
    print("RAW-SYNTHETIC-SECRET", file=sys.stderr)
    report.write_text(json.dumps([{"RuleID": "fake-token", "File": str(leak),
                                   "StartLine": 1, "Secret": "RAW-SYNTHETIC-SECRET"}]))
    raise SystemExit(1)
report.write_text("[]")
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_gate(repo: Path, fake: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GITLEAKS_BIN"] = str(fake)
    env["PYTHON_BIN"] = sys.executable
    return subprocess.run(
        [str(GATE), str(repo), str(REPO_ROOT)],
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


def test_untrusted_candidate_cannot_replace_base_enforcement() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "governance.yml").read_text(
        encoding="utf-8"
    )
    assert "pull_request_target:" in workflow
    assert "working-directory: trusted" in workflow
    assert "trusted/automation/library/disclosure_gate.sh candidate trusted" in workflow
    assert "candidate/policies" not in workflow
