"""The GitHub adapter is validated statically (spec: Testing Decisions): a thin reusable
workflow, a composite action that does the plumbing, every external action pinned to a
commit, and the action reference at the package's own version so a release cannot drift."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "gate.yml"
ACTION = REPO / ".github" / "actions" / "gate" / "action.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
OWNER_AND_NAME = "lopmigtech/fcs-deploy-gate"
PINNED = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>[^@\s]+)@(?P<sha>[0-9a-f]{40})\s+#\s*v\d[\w.-]*\s*$")


def package_version() -> str:
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    return str(data["project"]["version"])


def load(path: Path) -> dict[Any, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


def remote_uses(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text().splitlines()
        if re.match(r"^\s*-?\s*uses:", line) and "./" not in line.split("uses:")[1]
    ]


def test_the_action_reference_carries_the_package_version() -> None:
    workflow = load(WORKFLOW)
    [step] = workflow["jobs"]["gate"]["steps"]

    assert step["uses"] == f"{OWNER_AND_NAME}/.github/actions/gate@v{package_version()}"


def test_the_owner_and_name_appear_exactly_once_across_both_files() -> None:
    mentions = [
        f"{path.name}: {line.strip()}"
        for path in (WORKFLOW, ACTION)
        for line in path.read_text().splitlines()
        if "lopmigtech" in line or "fcs-deploy-gate/" in line
    ]

    assert mentions == [
        f"gate.yml: uses: {OWNER_AND_NAME}/.github/actions/gate@v{package_version()}"
    ]


def test_the_reusable_workflow_is_thin() -> None:
    workflow = load(WORKFLOW)
    call = workflow[True]["workflow_call"]  # YAML parses the `on` key as boolean True
    job = workflow["jobs"]["gate"]

    assert set(call["inputs"]) == {
        "path",
        "scope",
        "baseline-ref",
        "blocking-threshold",
        "mode",
        "region",
        "project-name",
    }
    assert call["inputs"]["path"]["required"] is True
    assert call["inputs"]["region"]["required"] is True
    assert call["inputs"]["scope"]["default"] == "whole-tree"
    assert call["inputs"]["mode"]["default"] == "enforcing"
    assert call["inputs"]["blocking-threshold"]["default"] == "critical,high,medium"
    assert set(call["secrets"]) == {"falcon-client-id", "falcon-client-secret"}
    assert all(secret["required"] is True for secret in call["secrets"].values())
    assert set(call["outputs"]) == {"verdict", "blocking-count"}

    assert list(workflow["jobs"]) == ["gate"]
    assert job["timeout-minutes"] == 15
    assert job["permissions"] == {"contents": "read"}
    assert len(job["steps"]) == 1
    assert set(job["outputs"]) == {"verdict", "blocking-count"}


def test_the_composite_action_does_the_plumbing_in_order() -> None:
    action = load(ACTION)
    steps = action["runs"]["steps"]
    ids = [step.get("id") for step in steps]

    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) >= {
        "path",
        "scope",
        "baseline-ref",
        "blocking-threshold",
        "mode",
        "region",
        "project-name",
        "falcon-client-id",
        "falcon-client-secret",
    }
    assert set(action["outputs"]) == {"verdict", "blocking-count"}
    assert ids == [
        "checkout",
        "python",
        "install",
        "resolve-baseline",
        "checkout-baseline",
        "gate",
        "artifacts",
    ]

    by_id = {step["id"]: step for step in steps}
    assert "actions/checkout@" in by_id["checkout"]["uses"]
    assert "actions/setup-python@" in by_id["python"]["uses"]
    assert "pip install" in by_id["install"]["run"]
    assert "github.action_path" in by_id["install"]["run"]
    assert "change-aware" in by_id["resolve-baseline"]["if"]
    assert "resolve-baseline" in by_id["resolve-baseline"]["run"]
    assert "change-aware" in by_id["checkout-baseline"]["if"]
    assert "outputs.ref" in by_id["checkout-baseline"]["if"]
    assert "RUNNER_TEMP" in by_id["checkout-baseline"]["run"]
    assert "always()" in by_id["artifacts"]["if"]
    assert "actions/upload-artifact@" in by_id["artifacts"]["uses"]

    gate = by_id["gate"]["run"]
    assert "fcs-deploy-gate run" in gate
    assert '--work-dir "$RUNNER_TEMP' in gate
    assert "--baseline-error" in gate and "--baseline-ref" in gate and "--baseline-dir" in gate
    assert "--fcs-binary" not in ACTION.read_text()
    assert by_id["gate"]["env"]["FALCON_CLIENT_ID"] == "${{ inputs.falcon-client-id }}"
    assert by_id["gate"]["env"]["FALCON_CLIENT_SECRET"] == "${{ inputs.falcon-client-secret }}"
    assert "continue-on-error" not in by_id["gate"]  # the core's exit code decides


def test_every_external_action_is_pinned_to_a_commit_with_its_tag() -> None:
    for path in (ACTION, CI):
        for line in remote_uses(path):
            assert PINNED.match(line), f"{path.name}: not pinned to a commit with a tag: {line!r}"


def test_the_project_name_defaults_to_the_repository() -> None:
    action = load(ACTION)
    [gate] = [step for step in action["runs"]["steps"] if step.get("id") == "gate"]

    assert "github.repository" in gate["run"] or "github.repository" in str(gate.get("env"))


def test_ci_runs_actionlint() -> None:
    ci = load(CI)

    assert "actionlint" in ci["jobs"]
    text = CI.read_text()
    assert "actionlint" in text
