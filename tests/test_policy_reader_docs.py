from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from saturnin import docsync
from saturnin.config import Config


ROOT = Path(__file__).resolve().parents[1]


def policy_config(tmp_path: Path) -> Config:
    root = tmp_path / "root"
    shutil.copytree(ROOT / "policies", root / "policies")
    shutil.copytree(ROOT / "config", root / "config")
    shutil.copytree(ROOT / "systemd", root / "systemd")
    shutil.copy(ROOT / "pyproject.toml", root / "pyproject.toml")
    return Config.load(root)


def test_policy_reader_provisioning_is_generated_from_structured_policy(
    tmp_path: Path,
) -> None:
    rendered = docsync._policy_reader_provisioning(policy_config(tmp_path))

    assert "resource owner `JakubMifek`" in rendered
    assert "only `JakubMifek/saturnin`" in rendered
    assert "**Administration: Read-only**" in rendered
    assert "--name=github.policy" in rendered


def test_merge_credential_has_no_unused_server_scope_duplicate(
    tmp_path: Path,
) -> None:
    config = policy_config(tmp_path)
    assert "merge_credential" not in config.policy("server_scope")[
        "dedicated_attestation_service"
    ]
    assert config.governance["review"]["attestation"]["protected_merge_credential"]


@pytest.mark.parametrize(
    "field, value",
    [
        ("resource_owner", "other"),
        ("repository_access", "all"),
        ("permissions", {"administration": "write", "metadata": "read"}),
        ("mutation_permissions", ["contents:write"]),
        ("mutation_interface", "present"),
    ],
)
def test_policy_reader_rejects_structured_least_privilege_drift(
    tmp_path: Path, field: str, value,
) -> None:
    config = policy_config(tmp_path)
    config.governance["review"]["attestation"]["policy_reader"][field] = value
    with pytest.raises(docsync.GeneratedBlockError, match="least-privilege"):
        docsync._policy_reader_provisioning(config)


@pytest.mark.parametrize(
    "field, value",
    [
        ("policy_actor_login", "saturnin-merge-bot"),
        ("repositories", ["JakubMifek/other"]),
    ],
)
def test_policy_reader_runtime_drift_fails_docs_and_doctor_contract(
    tmp_path: Path, field: str, value,
) -> None:
    config = policy_config(tmp_path)
    path = config.root / "config" / "attestation.json"
    runtime = json.loads(path.read_text(encoding="utf-8"))
    runtime[field] = value
    path.write_text(json.dumps(runtime), encoding="utf-8")

    with pytest.raises(
        docsync.GeneratedBlockError,
        match="runtime configuration disagrees",
    ):
        docsync._policy_reader_provisioning(config)


def test_policy_reader_credential_path_drift_fails_generation(
    tmp_path: Path,
) -> None:
    config = policy_config(tmp_path)
    config.governance["review"]["attestation"]["policy_reader"]["credential"] = (
        "/etc/saturnin-attestation/swapped.cred"
    )

    with pytest.raises(
        docsync.GeneratedBlockError,
        match="credential paths disagree",
    ):
        docsync._policy_reader_provisioning(config)


def test_matching_policy_path_drift_still_fails_systemd_cross_check(
    tmp_path: Path,
) -> None:
    config = policy_config(tmp_path)
    alternate = "/etc/saturnin-attestation/alternate.cred"
    config.governance["review"]["attestation"]["policy_reader"]["credential"] = (
        alternate
    )
    config.policy("server_scope")["dedicated_attestation_service"][
        "policy_credential"
    ] = alternate

    with pytest.raises(
        docsync.GeneratedBlockError,
        match="systemd credential disagrees",
    ):
        docsync._policy_reader_provisioning(config)


@pytest.mark.parametrize(
    "relative",
    [
        "config/attestation.json",
        "systemd/system/saturnin-attestation.service",
    ],
)
def test_source_home_requires_policy_reader_deployment_sources(
    tmp_path: Path, relative: str,
) -> None:
    config = policy_config(tmp_path)
    (config.root / relative).unlink()

    with pytest.raises(
        docsync.GeneratedBlockError,
        match="deployment sources are missing",
    ):
        docsync._policy_reader_provisioning(config)
