from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from saturnin import docsync
from saturnin.cli import main
from saturnin.config import Config

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def docs_home(config: Config) -> Config:
    for name in ("docs", ".github"):
        shutil.copytree(REPO_ROOT / name, config.root / name)
    return config


def test_checked_in_docs_match_policy() -> None:
    """The repository itself must never be stale."""
    assert docsync.render(Config.load(REPO_ROOT), write=False) == []


def test_generated_blocks_are_found(docs_home: Config) -> None:
    names = {p.name for p in docsync.documents(docs_home)}
    assert {"operating-model.md", "delegation-policy.md", "copilot-instructions.md"} <= names


def test_policy_change_makes_docs_stale(docs_home: Config) -> None:
    policy = docs_home.root / "policies" / "governance.yaml"
    policy.write_text(
        policy.read_text().replace("Never push to the default branch", "Push wherever you like")
    )
    docs_home._cache.clear()
    stale = docsync.render(docs_home, write=False)
    assert stale
    assert docsync.audit(docs_home)

    assert main(["--home", str(docs_home.root), "docs", "render", "--check"]) == 2
    assert main(["--home", str(docs_home.root), "docs", "render"]) == 0
    assert docsync.render(Config.load(docs_home.root), write=False) == []


def test_unknown_block_is_rejected(docs_home: Config) -> None:
    with pytest.raises(KeyError):
        docsync.render_text(
            "<!-- generated:nonsense -->\n\n<!-- /generated:nonsense -->", docs_home
        )
