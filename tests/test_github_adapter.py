"""The GitHub adapter is validated statically (spec: Testing Decisions): a thin reusable
workflow, a composite action that does the plumbing, every external action pinned to a
commit, and the action reference at the package's own version so a release cannot drift."""

from __future__ import annotations

import re
from pathlib import Path

from tests.adapters import (
    ACTION,
    CI,
    DEFAULT_THRESHOLD,
    OWNER_AND_NAME,
    README,
    WORKFLOW,
    load,
    package_version,
    step,
)

PINNED = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>[^@\s]+)@(?P<sha>[0-9a-f]{40})\s+#\s*v\d[\w.-]*\s*$")


def remote_uses(path: Path) -> list[str]:
    """Every `uses:` of an action outside this repository (its own action is exempt)."""
    return [
        line
        for line in path.read_text().splitlines()
        if re.match(r"^\s*-?\s*uses:", line)
        and "./" not in line.split("uses:")[1]
        and OWNER_AND_NAME not in line
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
        if OWNER_AND_NAME.split("/")[0] in line or "fcs-deploy-gate/" in line
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
    assert call["inputs"]["blocking-threshold"]["default"] == DEFAULT_THRESHOLD
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

    workflow_inputs = set(load(WORKFLOW)[True]["workflow_call"]["inputs"])
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) == workflow_inputs | {"falcon-client-id", "falcon-client-secret"}
    for name in workflow_inputs:
        assert action["inputs"][name].get("default") == (
            load(WORKFLOW)[True]["workflow_call"]["inputs"][name].get("default")
        ), name
    assert set(action["outputs"]) == {"verdict", "blocking-count"}
    assert ids == [
        "event",
        "checkout",
        "python",
        "install",
        "resolve-baseline",
        "checkout-baseline",
        "gate",
        "artifacts",
    ]

    assert "pull_request_target" in step(action, "event")["if"]
    assert "exit 1" in step(action, "event")["run"]
    assert "actions/checkout@" in step(action, "checkout")["uses"]
    assert "actions/setup-python@" in step(action, "python")["uses"]
    assert "pip install" in step(action, "install")["run"]
    assert "github.action_path" in step(action, "install")["run"]
    assert "change-aware" in step(action, "resolve-baseline")["if"]
    assert "resolve-baseline" in step(action, "resolve-baseline")["run"]
    assert "pull_request_target" not in str(step(action, "resolve-baseline")["env"])
    assert step(action, "checkout-baseline")["if"] == "steps.resolve-baseline.outputs.ref != ''"
    assert "RUNNER_TEMP" in step(action, "checkout-baseline")["run"]
    assert "error=" in step(action, "checkout-baseline")["run"]  # a failed fetch is a Verdict
    assert "always()" in step(action, "artifacts")["if"]
    assert "actions/upload-artifact@" in step(action, "artifacts")["uses"]
    assert "artifact_name" in step(action, "artifacts")["with"]["name"]  # one per scanned root

    gate = step(action, "gate")
    assert "fcs-deploy-gate run" in gate["run"]
    assert '--work-dir "$RUNNER_TEMP' in gate["run"]
    assert all(
        flag in gate["run"] for flag in ("--baseline-error", "--baseline-ref", "--baseline-dir")
    )
    assert "--fcs-binary" not in ACTION.read_text()
    assert gate["env"]["FALCON_CLIENT_ID"] == "${{ inputs.falcon-client-id }}"
    assert gate["env"]["FALCON_CLIENT_SECRET"] == "${{ inputs.falcon-client-secret }}"
    assert "checkout-baseline.outputs.error" in gate["env"]["BASELINE_ERROR"]
    assert "continue-on-error" not in gate  # the core's exit code decides


def test_every_external_action_is_pinned_to_a_commit_with_its_tag() -> None:
    workflows = sorted(WORKFLOW.parent.glob("*.yml"))
    assert {WORKFLOW, CI} <= set(workflows)
    for path in (*workflows, ACTION):
        for line in remote_uses(path):
            assert PINNED.match(line), f"{path.name}: not pinned to a commit with a tag: {line!r}"


def test_the_project_name_defaults_to_the_repository() -> None:
    gate = step(load(ACTION), "gate")

    assert gate["env"]["PROJECT_NAME"] == "${{ inputs.project-name || github.repository }}"


def test_the_readme_quick_start_pins_the_package_version() -> None:
    references = re.findall(rf"{OWNER_AND_NAME}/[^@\s]+@v(\S+)", README.read_text())

    assert references, "the README quick start should reference the reusable workflow"
    assert set(references) == {package_version()}


def test_ci_runs_actionlint() -> None:
    assert "actionlint" in load(CI)["jobs"]
