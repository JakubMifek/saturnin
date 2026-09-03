"""Configuration and policy loading.

Every component reads its rules from ``policies/*.yaml`` so that policies stay
replaceable without touching code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ENV_ROOT = "SATURNIN_HOME"


def find_root(start: Path | None = None) -> Path:
    """Return the Saturnin home directory.

    ``SATURNIN_HOME`` wins. Otherwise we keep the current source checkout so
    worktree-local policy, agent and documentation changes are validated in place;
    the board itself stays shared via its own data root rather than by redirecting
    every repository read back to the main checkout.
    """
    env = os.environ.get(ENV_ROOT)
    if env:
        return Path(env).expanduser().resolve()
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "policies" / "governance.yaml").is_file():
            return candidate.resolve()
    return current


def _canonical_worktree(candidate: Path) -> Path:
    git_file = candidate / ".git"
    if not git_file.is_file():
        return candidate
    try:
        marker, value = git_file.read_text(encoding="utf-8").strip().split(":", 1)
        if marker.lower() != "gitdir":
            return candidate
        git_dir = Path(value.strip())
        if not git_dir.is_absolute():
            git_dir = candidate / git_dir
        git_dir = git_dir.resolve()
        common_file = git_dir / "commondir"
        if not common_file.is_file():
            return candidate
        common_dir = Path(common_file.read_text(encoding="utf-8").strip())
        if not common_dir.is_absolute():
            common_dir = git_dir / common_dir
        common_dir = common_dir.resolve()
        checkout = common_dir.parent
        if common_dir.name == ".git" and (
            checkout / "policies" / "governance.yaml"
        ).is_file():
            return checkout
    except (OSError, ValueError):
        pass
    return candidate


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"policy file {path} must contain a mapping")
    return data


@dataclass
class Config:
    """Resolved paths and policies for one Saturnin installation."""

    root: Path
    policies: Path = field(init=False)
    board_dir: Path = field(init=False)
    tasks_dir: Path = field(init=False)
    checkpoints_dir: Path = field(init=False)
    automation_dir: Path = field(init=False)
    var_dir: Path = field(init=False)
    _cache: dict[str, dict[str, Any]] = field(init=False, default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()
        self.policies = self.root / "policies"
        # Board, checkpoints and automation stay in the main checkout so that
        # linked worktrees share a single data root (and its locks coordinate).
        data_root = _canonical_worktree(self.root)
        self.board_dir = data_root / "board"
        self.tasks_dir = self.board_dir / "tasks"
        self.checkpoints_dir = self.board_dir / "checkpoints"
        self.automation_dir = self.root / "automation"
        self.var_dir = data_root / "var"

    @classmethod
    def load(cls, root: Path | str | None = None) -> "Config":
        return cls(find_root(Path(root) if root else None))

    def policy(self, name: str) -> dict[str, Any]:
        """Load a policy file once per configuration instance."""
        if name not in self._cache:
            self._cache[name] = load_yaml(self.policies / f"{name}.yaml")
        return self._cache[name]

    @property
    def governance(self) -> dict[str, Any]:
        return self.policy("governance")

    @property
    def routing(self) -> dict[str, Any]:
        return self.policy("routing")

    @property
    def cleanup(self) -> dict[str, Any]:
        return self.policy("cleanup")

    @property
    def server_scope(self) -> dict[str, Any]:
        return self.policy("server_scope")

    @property
    def ceo_role(self) -> str:
        """The configured CEO role name (``delegation.ceo_role``), never a bare literal."""
        return self.governance.get("delegation", {}).get("ceo_role", "ceo")

    def ensure_dirs(self) -> None:
        for path in (
            self.tasks_dir,
            self.checkpoints_dir,
            self.automation_dir / "library",
            self.var_dir / "logs",
            self.var_dir / "worktrees",
        ):
            path.mkdir(parents=True, exist_ok=True)


def default_config() -> Config:
    """Resolve the configuration fresh; ``SATURNIN_HOME`` may change at runtime."""
    return Config.load()
