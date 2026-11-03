"""The GitLab adapter is validated statically (spec: Testing Decisions): an included CI
template whose job clones the Gate at the package's own version with the job token,
resolves the Baseline through the core, and runs the same command as the GitHub adapter.
Its Baseline step is also run for real against local repositories, since what it does
depends on how git treats the runner's checkout."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
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
PROJECT_URL = "https://gitlab-ci-token:token@gitlab.example/group/consumer.git"


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
    # A shell executor keeps /tmp between jobs; the clone must find its directory absent.
    assert text.index('rm -rf "$FCS_GATE_SCRATCH"') < text.index("git clone")
    assert "$FCS_GATE_PROJECT" in text
    assert "pip install" in text
    assert "fcs-deploy-gate resolve-baseline" in text
    assert "--pipeline" in text
    assert "merge_request_event" in text
    assert "CI_MERGE_REQUEST_DIFF_BASE_SHA" in text
    assert "CI_COMMIT_BEFORE_SHA" in text
    assert "$FCS_GATE_BASELINE_REF" in text
    # The job holds the Falcon client, so it never runs git in the checkout's .git.
    assert "git worktree" not in text
    assert "safe.directory" not in text
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


def git_env(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }


def git(cwd: Path, home: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=cwd, env=git_env(home), capture_output=True, text=True, check=True
    )
    return completed.stdout.strip()


def a_checkout_with_a_baseline(root: Path, home: Path) -> tuple[Path, str]:
    """A checkout with a remote and two commits; returns it and the first commit, the Baseline."""
    origin = root / "origin.git"
    checkout = root / "checkout"
    origin.mkdir()
    checkout.mkdir()
    git(origin, home, "init", "--quiet", "--bare", "--initial-branch=main")
    git(checkout, home, "init", "--quiet", "--initial-branch=main")
    git(checkout, home, "remote", "add", "origin", origin.as_uri())
    (checkout / "main.tf").write_text("# at the Baseline\n")
    git(checkout, home, "add", "main.tf")
    git(checkout, home, "commit", "--quiet", "-m", "the Baseline")
    baseline = git(checkout, home, "rev-parse", "HEAD")
    (checkout / "main.tf").write_text("# at the change\n")
    git(checkout, home, "commit", "--quiet", "--all", "-m", "the change")
    git(checkout, home, "push", "--quiet", "origin", "main")
    # The job fetches from the URL the template builds; here that URL leads to the local remote.
    git(checkout, home, "config", "--global", f"url.{origin.as_uri()}.insteadOf", PROJECT_URL)
    return checkout, baseline


def run_the_baseline_step(
    cwd: Path, scratch: Path, home: Path, ref: str, extra_env: dict[str, str] | None = None
) -> tuple[subprocess.CompletedProcess[str], str]:
    """The template's Baseline step as a runner runs it: under errexit, from the given
    directory. Returns the shell's result and the Baseline error."""
    [step_source] = [str(line) for line in template()[JOB]["script"] if "FETCH_HEAD" in str(line)]
    source = (
        f'set -e\nBASELINE_ERROR=""\n{step_source}\nprintf "%s" "$BASELINE_ERROR" > "$REPORT"\n'
    )
    report = scratch / "baseline-error"
    env = {
        **git_env(home),
        "CI_SERVER_PROTOCOL": "https",
        "CI_JOB_TOKEN": "token",
        "CI_SERVER_FQDN": "gitlab.example",
        "CI_PROJECT_PATH": "group/consumer",
        "FCS_GATE_SCRATCH": str(scratch),
        "BASELINE_REF": ref,
        "REPORT": str(report),
        **(extra_env or {}),
    }
    completed = subprocess.run(
        ["bash", "-c", source], cwd=cwd, env=env, capture_output=True, text=True, check=False
    )
    return completed, report.read_text() if report.exists() else ""


def test_the_baseline_step_does_not_need_the_checkouts_git_directory(tmp_path: Path) -> None:
    """A checkout git refuses, such as one the Kubernetes executor's helper container left
    owned by another user, cannot stop the step if the step never looks at it."""
    home = tmp_path / "home"
    scratch = tmp_path / "scratch"
    elsewhere = tmp_path / "not-a-repository"
    for directory in (home, scratch, elsewhere):
        directory.mkdir()
    _, baseline = a_checkout_with_a_baseline(tmp_path, home)

    completed, error = run_the_baseline_step(elsewhere, scratch, home, baseline)

    assert completed.returncode == 0, completed.stderr
    assert error == ""
    assert (scratch / "baseline" / "main.tf").read_text() == "# at the Baseline\n"


def test_a_hook_planted_in_the_checkout_never_sees_the_falcon_client(tmp_path: Path) -> None:
    """On a reused build directory an earlier job, even one from an unreviewed branch, can
    leave a hook in .git. The default-branch job holds the protected Falcon client, so
    running git there would hand it over."""
    home = tmp_path / "home"
    scratch = tmp_path / "scratch"
    home.mkdir()
    scratch.mkdir()
    checkout, baseline = a_checkout_with_a_baseline(tmp_path, home)
    marker = tmp_path / "the-hook-saw"
    hook = checkout / ".git" / "hooks" / "post-checkout"
    hook.write_text(f'#!/bin/sh\necho "$FALCON_CLIENT_SECRET" > "{marker}"\n')
    hook.chmod(0o755)

    completed, error = run_the_baseline_step(
        checkout, scratch, home, baseline, {"FALCON_CLIENT_SECRET": "secret"}
    )

    assert completed.returncode == 0, completed.stderr
    assert error == ""
    assert not marker.exists()
    assert (scratch / "baseline" / "main.tf").read_text() == "# at the Baseline\n"


def test_a_git_failure_in_the_baseline_step_is_a_baseline_error_not_a_failed_job(
    tmp_path: Path,
) -> None:
    """ADR 0001: the core turns a Baseline error into a blocked Verdict. A git command that
    ends the job instead leaves no Verdict at all, and in Advisory stops the Deployment."""
    home = tmp_path / "home"
    scratch = tmp_path / "scratch"
    home.mkdir()
    scratch.mkdir()
    checkout, _ = a_checkout_with_a_baseline(tmp_path, home)

    completed, error = run_the_baseline_step(checkout, scratch, home, "deadbeef")

    assert completed.returncode == 0, completed.stderr
    assert "the Baseline ref deadbeef could not be checked out" in error


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
