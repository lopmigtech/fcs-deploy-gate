"""The GitLab adapter is validated statically (spec: Testing Decisions): an included CI
template whose job clones the Gate at the package's own version with the job token,
resolves the Baseline through the core, and runs the same command as the GitHub adapter."""

from __future__ import annotations

import re
import subprocess
from typing import Any

from tests.adapters import (
    ACTION,
    DEFAULT_THRESHOLD,
    README,
    REPO,
    TEMPLATE,
    load,
    package_version,
    run_flags,
    step,
)

JOB = "fcs-deploy-gate"


def template() -> dict[str, Any]:
    return load(TEMPLATE)


def script_text(job: dict[str, Any]) -> str:
    lines = [*job.get("before_script", []), *job["script"], *job.get("after_script", [])]
    return "\n".join(str(line) for line in lines)


def test_the_clone_ref_carries_the_package_version() -> None:
    assert template()["variables"]["FCS_GATE_REF"] == f"v{package_version()}"


def test_the_readme_include_snippet_pins_the_package_version() -> None:
    refs = re.findall(r"ref:\s*v(\S+)", README.read_text())

    assert refs, "the README should show the include snippet with a ref"
    assert set(refs) == {package_version()}


def test_the_consumer_variables_match_the_github_adapter_defaults() -> None:
    variables = template()["variables"]
    action_inputs = load(ACTION)["inputs"]

    assert variables["FCS_GATE_SCOPE"] == action_inputs["scope"]["default"] == "whole-tree"
    assert variables["FCS_GATE_MODE"] == action_inputs["mode"]["default"] == "enforcing"
    assert variables["FCS_GATE_BLOCKING_THRESHOLD"] == DEFAULT_THRESHOLD
    assert variables["FCS_GATE_BASELINE_REF"] == ""
    assert variables["FCS_GATE_REGION"] == ""  # required: the Consumer sets it
    assert "CI_PROJECT_PATH" in variables["FCS_GATE_PROJECT_NAME"]


def test_the_instance_variables_name_the_image_the_project_and_a_scratch_outside_the_checkout() -> (
    None
):
    variables = template()["variables"]

    assert "python" in variables["FCS_GATE_IMAGE"]
    # The Gate project's path on the instance: the one GitLab-side reference to this
    # repository, set by the maintainers, never a hardcoded clone URL in the script.
    assert variables["FCS_GATE_PROJECT"]
    assert "CI_PROJECT_DIR" not in variables["FCS_GATE_SCRATCH"]
    assert variables["FCS_GATE_SCRATCH"].startswith("/")


def test_both_adapters_run_the_core_with_the_same_flags() -> None:
    github = run_flags(step(load(ACTION), "gate")["run"])
    gitlab = run_flags(script_text(template()[JOB]))

    assert github == gitlab
    assert "--fcs-binary" not in github


def test_the_job_runs_in_merge_request_and_default_branch_pipelines() -> None:
    job = template()[JOB]
    conditions = [rule["if"] for rule in job["rules"]]

    assert any('$CI_PIPELINE_SOURCE == "merge_request_event"' in c for c in conditions)
    assert any("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH" in c for c in conditions)
    assert job["image"] == "$FCS_GATE_IMAGE"
    assert job["timeout"] == "15m"
    assert job["before_script"] == []  # a Consumer's default before_script must not run here


def test_the_job_clones_the_gate_with_the_job_token_and_runs_the_core() -> None:
    job = template()[JOB]
    text = script_text(job)

    assert "git clone" in text and "$FCS_GATE_REF" in text and "CI_JOB_TOKEN" in text
    assert "$FCS_GATE_PROJECT" in text
    assert "pip install" in text
    assert "fcs-deploy-gate resolve-baseline" in text
    assert "--pipeline" in text
    assert "merge_request_event" in text
    assert "CI_MERGE_REQUEST_DIFF_BASE_SHA" in text
    assert "CI_COMMIT_BEFORE_SHA" in text
    assert "$FCS_GATE_BASELINE_REF" in text
    assert "git worktree prune" in text  # a stale registration survives the runner's build cache
    assert "git worktree add" in text
    assert "fcs-deploy-gate run" in text
    assert '--work-dir "$FCS_GATE_SCRATCH' in text
    assert all(flag in text for flag in ("--baseline-dir", "--baseline-ref", "--baseline-error"))
    assert "--fcs-binary" not in TEMPLATE.read_text()
    assert "FALCON_CLIENT_SECRET" not in text  # read by the core from the environment, never echoed


def test_the_script_is_valid_bash() -> None:
    job = template()[JOB]
    for section in ("before_script", "script", "after_script"):
        if section not in job:
            continue
        source = "\n".join(str(line) for line in job[section])
        completed = subprocess.run(
            ["bash", "-n"], input=source, capture_output=True, text=True, check=False
        )
        assert completed.returncode == 0, f"{section}: {completed.stderr}"


def test_artifacts_are_kept_on_success_and_failure() -> None:
    job = template()[JOB]

    assert job["artifacts"]["when"] == "always"
    assert "fcs-gate/" in job["artifacts"]["paths"]
    assert "expire_in" not in job["artifacts"]  # the instance's retention, as on GitHub
    assert "after_script" in job  # copies the work directory into the checkout for upload
    assert "$FCS_GATE_SCRATCH" in "\n".join(job["after_script"])


def test_ci_lints_yaml() -> None:
    ci = load(REPO / ".github" / "workflows" / "ci.yml")

    assert "yamllint" in ci["jobs"]
