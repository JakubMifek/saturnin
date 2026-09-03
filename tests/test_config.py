from __future__ import annotations

import subprocess
from pathlib import Path

from saturnin.config import find_root


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_find_root_keeps_the_worktree_as_the_source_root(
    tmp_path: Path, monkeypatch
) -> None:
    main = tmp_path / "main"
    main.mkdir()
    (main / "policies").mkdir()
    (main / "policies" / "governance.yaml").write_text("{}\n", encoding="utf-8")
    _git(main, "init", "-b", "main")
    _git(main, "config", "user.email", "test@example.com")
    _git(main, "config", "user.name", "Test")
    _git(main, "add", ".")
    _git(main, "commit", "-m", "initial")
    linked = tmp_path / "linked"
    _git(main, "worktree", "add", "-b", "feature/linked", str(linked))
    monkeypatch.delenv("SATURNIN_HOME", raising=False)

    assert find_root(linked) == linked
    assert find_root(linked / "policies") == linked


def test_find_root_preserves_saturnin_home_precedence(
    tmp_path: Path, monkeypatch
) -> None:
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    monkeypatch.setenv("SATURNIN_HOME", str(explicit))

    assert find_root(tmp_path) == explicit
