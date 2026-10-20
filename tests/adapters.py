"""Shared helpers for the static adapter tests: file locations, loaders, and the
package version both adapters must pin."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

from fcs_deploy_gate.config import DEFAULT_BLOCKING_THRESHOLD, ordered_severities

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "gate.yml"
ACTION = REPO / ".github" / "actions" / "gate" / "action.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
TEMPLATE = REPO / "gitlab" / "fcs-deploy-gate.gitlab-ci.yml"
README = REPO / "README.md"
OWNER_AND_NAME = "lopmigtech/fcs-deploy-gate"
DEFAULT_THRESHOLD = ",".join(ordered_severities(DEFAULT_BLOCKING_THRESHOLD))
RUN_FLAG = re.compile(r"--[a-z][a-z-]*")


def package_version() -> str:
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    return str(data["project"]["version"])


def load(path: Path) -> dict[Any, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


def step(action: dict[str, Any], step_id: str) -> dict[str, Any]:
    [found] = [s for s in action["runs"]["steps"] if s.get("id") == step_id]
    assert isinstance(found, dict)
    return found


def run_flags(script: str) -> set[str]:
    """The flags of the `fcs-deploy-gate run` command line in a shell script."""
    command = script[script.index("fcs-deploy-gate run") :]
    command = command.split("\n\n")[0]
    return set(RUN_FLAG.findall(command))
