"""The handoff kit is validated statically, like the adapters (spec: Testing Decisions):
the deliberately insecure Terraform fixture the first live run scans, the wizard that walks
a person through the work-environment steps, the live-check pipelines on both platforms,
and the README's release, migration and clear-Verdict statements."""

from __future__ import annotations

import os
import re
import subprocess

from fcs_deploy_gate.falcon import CLIENT_ID_VAR, CLIENT_SECRET_VAR
from tests.adapters import README, REPO, TEMPLATE, load

FIXTURE = REPO / "tests" / "fixtures" / "terraform" / "insecure-bucket"
FIXTURE_PATH = FIXTURE.relative_to(REPO).as_posix()
LIVE_CHECK_GITHUB = REPO / ".github" / "workflows" / "live-check.yml"
LIVE_CHECK_GITLAB = REPO / ".gitlab-ci.yml"
WIZARD = REPO / "scripts" / "handoff-wizard.sh"
# The steps the ticket lists, in its order; each matches one stage title.
HANDOFF_STEPS = (
    "CI client",
    "mapping client",
    "GitHub organisation secrets",
    "GitLab group variables",
    "access policy",
    "job token permissions",
    "checksum pin",
    "release",
    "Advisory run on GitHub",
    "Advisory run on GitLab",
    "real report",
    "console upload",
)
PUBLIC_HOSTS = {
    "github.com",
    "falcon.crowdstrike.com",
    "falcon.us-2.crowdstrike.com",
    "falcon.eu-1.crowdstrike.com",
    "falcon.laggar.gcw.crowdstrike.com",
    "falcon.us-gov-2.crowdstrike.mil",
}


def fixture_source() -> str:
    return "\n".join(path.read_text() for path in sorted(FIXTURE.glob("*.tf")))


def test_the_live_fixture_is_one_public_unencrypted_unlogged_untagged_bucket() -> None:
    source = fixture_source()

    assert source.count('resource "aws_s3_bucket" ') == 1
    for setting in (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ):
        assert re.search(rf"{setting}\s*=\s*false", source), setting
    assert re.search(r'acl\s*=\s*"public-read"', source)
    assert "tags" not in source
    assert "aws_s3_bucket_server_side_encryption_configuration" not in source
    assert "aws_s3_bucket_logging" not in source


def test_the_live_fixture_holds_no_secrets_and_is_not_gitignored() -> None:
    source = fixture_source()

    assert not re.search(r"AKIA[0-9A-Z]{16}", source)
    assert not re.search(r"(?i)(password|secret|token|api_key|access_key)\s*=", source)
    check = subprocess.run(["git", "check-ignore", "-q", str(FIXTURE / "main.tf")], cwd=REPO)
    assert check.returncode == 1, "the CLI skips gitignored files, so the fixture must not be"


def test_the_github_live_check_runs_the_reusable_workflow_on_the_fixture_by_hand_only() -> None:
    workflow = load(LIVE_CHECK_GITHUB)
    [job] = workflow["jobs"].values()
    dispatch = workflow[True]["workflow_dispatch"]  # YAML parses the `on` key as True

    assert list(workflow[True]) == ["workflow_dispatch"]
    assert dispatch["inputs"]["region"]["required"] is True
    assert dispatch["inputs"]["mode"]["default"] == "advisory"
    assert workflow["permissions"] == {"contents": "read"}
    assert job["uses"] == "./.github/workflows/gate.yml"
    assert job["with"]["path"] == FIXTURE_PATH
    assert job["with"]["mode"] == "${{ inputs.mode }}"
    assert job["secrets"] == {
        "falcon-client-id": f"${{{{ secrets.{CLIENT_ID_VAR} }}}}",
        "falcon-client-secret": f"${{{{ secrets.{CLIENT_SECRET_VAR} }}}}",
    }


def test_the_gitlab_live_check_includes_the_template_on_the_fixture_by_hand_only() -> None:
    pipeline = load(LIVE_CHECK_GITLAB)

    assert pipeline["workflow"]["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "web"'}]
    assert pipeline["include"] == [{"local": "/" + TEMPLATE.relative_to(REPO).as_posix()}]
    assert pipeline["variables"]["FCS_GATE_PROJECT"] == "$CI_PROJECT_PATH"  # clones itself
    assert pipeline["variables"]["FCS_GATE_PATH"] == FIXTURE_PATH
    assert pipeline["variables"]["FCS_GATE_MODE"] == "advisory"
    assert "FCS_GATE_REGION" not in pipeline["variables"]  # set in the run form


def test_the_wizard_parses_and_walks_the_handoff_steps_in_the_ticket_order() -> None:
    subprocess.run(["bash", "-n", str(WIZARD)], check=True)
    assert os.access(WIZARD, os.X_OK)
    text = WIZARD.read_text()
    stages = re.findall(r'^stage "([^"]+)"', text, re.MULTILINE)
    totals = re.findall(r"^TOTAL_STAGES=(\d+)$", text, re.MULTILINE)  # the library's 0, then ours

    assert int(totals[-1]) == len(stages)
    positions = []
    for keyword in HANDOFF_STEPS:
        matching = [i for i, title in enumerate(stages) if keyword.lower() in title.lower()]
        assert matching, f"no stage for {keyword!r} among {stages}"
        positions.append(matching[0])
    assert positions == sorted(positions), stages
    bodies = re.split(r'^stage "', text.split("run_wizard() {", 1)[1], flags=re.MULTILINE)[1:]
    assert all(re.search(r"\b(pause|confirm)\b", body) for body in bodies), "a stage never pauses"


def test_the_wizard_places_the_secrets_the_adapters_read_and_persists_none() -> None:
    text = WIZARD.read_text()

    assert set(re.findall(r"^\s*set_org_secret (\w+)", text, re.MULTILINE)) == {
        CLIENT_ID_VAR,
        CLIENT_SECRET_VAR,
    }
    persisted = set(re.findall(r"^\s*write_env (\w+)", text, re.MULTILINE))
    assert not {key for key in persisted if key.endswith("_SECRET")}, persisted
    assert ".env" in (REPO / ".gitignore").read_text().split()


def test_the_wizard_names_the_exact_scopes_and_no_work_environment_host() -> None:
    text = WIZARD.read_text()

    for scope in (
        "Cloud Security Tools Download",
        "Infrastructure as Code",
        "CSPM registration",
        "Cloud Security Policies",
        "Cloud Security API Detections",
        "Cloud Security API Assets",
    ):
        assert scope in text, scope
    hosts = set(re.findall(r"https?://([^/\s\"']+)", text))
    literal_hosts = {h for h in hosts if not h.startswith("$") and re.search("[a-z]", h)}
    assert literal_hosts <= PUBLIC_HOSTS, literal_hosts


def test_the_readme_documents_release_migration_and_what_only_the_work_environment_proves() -> None:
    readme = README.read_text()
    section = {
        heading: readme.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
        for heading in (
            "What a clear Verdict means",
            "Handoff to the work environment",
            "Release procedure",
            "Migration checklist",
            "Verified only in the work environment",
        )
    }

    verdict = section["What a clear Verdict means"]
    assert "no IaC Findings at or above the Blocking threshold" in verdict
    assert "does not yet mean that no IOM will appear" in verdict
    assert "console exemption" in verdict.lower() and "Exclusion" in verdict  # both channels
    handoff = section["Handoff to the work environment"]
    assert WIZARD.relative_to(REPO).as_posix() in handoff
    assert FIXTURE_PATH in handoff
    release = section["Release procedure"]
    assert "pyproject.toml" in release and "both adapter references" in release
    assert "never moved" in release and "pull mirror" in release
    migration = section["Migration checklist"]
    for item in ("gate.yml", "organisation secrets", "access policy", "job token", "image mirror"):
        assert item in migration.lower(), item
    assert section["Verified only in the work environment"].count("\n- ") >= 5


PILOT = REPO / "examples" / "lambda-retention-pilot"


def test_the_pilot_pipeline_includes_the_template_and_gates_the_apply() -> None:
    pipeline = load(PILOT / ".gitlab-ci.yml")
    [include] = pipeline["include"]
    variables = pipeline["variables"]

    assert include["file"] == "/" + TEMPLATE.relative_to(REPO).as_posix()
    assert variables["FCS_GATE_REF"] == include["ref"]  # the clone and the include agree
    assert variables["FCS_GATE_PROJECT"] == include["project"]
    assert variables["FCS_GATE_PATH"] == "lambda"
    assert variables["FCS_GATE_MODE"] == "advisory"  # the first act
    assert variables["FCS_GATE_BLOCKING_THRESHOLD"] == "critical,high,medium,informational"
    assert "test" in pipeline["stages"]  # the template's job runs in stage test
    assert pipeline["apply"]["stage"] in pipeline["stages"]
    assert set(pipeline["apply"]["needs"]) == {"plan", "fcs-deploy-gate"}
    assert "terraform apply" in "\n".join(pipeline["apply"]["script"])
    assert "CI_JOB_TOKEN" in "\n".join(pipeline[".terraform"]["before_script"])


def test_the_pilot_terraform_has_exactly_the_retention_gap() -> None:
    terraform = (PILOT / "lambda" / "main.tf").read_text()

    assert terraform.count('resource "aws_lambda_function"') == 1
    assert terraform.count('resource "aws_cloudwatch_log_group"') == 1
    assert not re.search(r"^\s*retention_in_days\s*=", terraform, re.MULTILINE)
    assert "aws_partition" in terraform  # GovCloud ARNs are arn:aws-us-gov:
    assert not re.search(r"AKIA[0-9A-Z]{16}|secret_key|password", terraform)
