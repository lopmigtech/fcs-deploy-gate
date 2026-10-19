"""Exclusions: approved, expiring exemptions applied to the Verdict (ticket #3)."""

from __future__ import annotations

from datetime import date

from tests.conftest import GateHarness
from tests.test_whole_tree_verdict import (
    LOGS_BUCKET_WITHOUT_LOGGING,
    UNENCRYPTED_LOGS_BUCKET,
    observed,
)

TODAY = date(2026, 10, 19)


def test_without_an_exclusion_file_nothing_is_excluded(gate: GateHarness) -> None:
    result = gate(today=TODAY)

    assert result.verdict["excluded"] == []
    assert result.verdict["stale_exclusions"] == []
    assert len(result.verdict["blocking_findings"]) == 6


def test_fixture_file_excludes_the_active_entry_and_reports_the_stale_ones(
    gate: GateHarness,
) -> None:
    gate.use_exclusion_fixture()

    result = gate(today=TODAY)

    assert result.exit_code == 1
    blocking = [observed(f) for f in result.verdict["blocking_findings"]]
    assert LOGS_BUCKET_WITHOUT_LOGGING not in blocking
    assert UNENCRYPTED_LOGS_BUCKET in blocking  # its entry expired in January
    assert len(blocking) == 5

    [excluded] = result.verdict["excluded"]
    assert observed(excluded["finding"]) == LOGS_BUCKET_WITHOUT_LOGGING
    assert excluded["exclusion"] == {
        "rule": "iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35",
        "resource": "aws_s3_bucket.logs",
        "file": "logging.tf",
        "reason": "The logs bucket is the access-log target itself; logging it would recurse.",
        "expires": "2027-06-30",
        "approved_by": "security-reviewer@example.gov",
    }

    stale = result.verdict["stale_exclusions"]
    assert [(s["rule"], s["why"]) for s in stale] == [
        ("iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84", "expired"),
        ("iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70", "unmatched"),
    ]
    assert stale[0]["expires"] == "2026-01-15"
    assert stale[0]["resource"] == "aws_s3_bucket.logs"


ACTIVE_ENTRY = """\
exclusions:
  - rule: iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35
    resource: aws_s3_bucket.logs
    reason: Recursive logging target.
    expires: {expires}
    approved_by: security-reviewer@example.gov
"""


def test_an_exclusion_applies_on_its_expiry_date_and_not_the_day_after(
    gate: GateHarness,
) -> None:
    gate.write_exclusions(ACTIVE_ENTRY.format(expires="2026-10-19"))

    on_the_day = gate(today=date(2026, 10, 19))
    day_after = gate(today=date(2026, 10, 20))

    assert len(on_the_day.verdict["excluded"]) == 1
    assert on_the_day.verdict["stale_exclusions"] == []
    assert day_after.verdict["excluded"] == []
    assert [s["why"] for s in day_after.verdict["stale_exclusions"]] == ["expired"]
    assert LOGS_BUCKET_WITHOUT_LOGGING in [
        observed(f) for f in day_after.verdict["blocking_findings"]
    ]


def test_expiry_accepts_a_quoted_iso_string_as_well_as_a_yaml_date(gate: GateHarness) -> None:
    gate.write_exclusions(ACTIVE_ENTRY.format(expires='"2027-06-30"'))

    result = gate(today=TODAY)

    assert len(result.verdict["excluded"]) == 1
    assert result.verdict["excluded"][0]["exclusion"]["expires"] == "2027-06-30"


ENTRY = """\
  - rule: {rule}
{fields}    reason: Accepted for now.
    expires: 2027-06-30
    approved_by: security-reviewer@example.gov
"""


def entry(rule: str, **fields: str) -> str:
    lines = "".join(f"    {key}: {value}\n" for key, value in fields.items())
    return ENTRY.format(rule=rule, fields=lines)


ENCRYPTION_RULE = "iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84"


def test_a_file_only_entry_matches_every_finding_of_that_rule_in_the_file(
    gate: GateHarness,
) -> None:
    gate.write_exclusions("exclusions:\n" + entry(ENCRYPTION_RULE, file="./logging.tf"))

    result = gate(today=TODAY)

    assert [observed(e["finding"]) for e in result.verdict["excluded"]] == [UNENCRYPTED_LOGS_BUCKET]
    assert result.verdict["excluded"][0]["exclusion"]["file"] == "logging.tf"


def test_an_entry_matches_only_when_every_named_field_matches(gate: GateHarness) -> None:
    gate.write_exclusions(
        "exclusions:\n"
        + entry(ENCRYPTION_RULE, resource="aws_s3_bucket.logs", file="main.tf")  # wrong file
        + entry(ENCRYPTION_RULE, resource="aws_s3_bucket.public_assets", file="logging.tf")
        + entry("iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70", resource="aws_s3_bucket.logs")
    )

    result = gate(today=TODAY)

    assert result.verdict["excluded"] == []
    assert [s["why"] for s in result.verdict["stale_exclusions"]] == ["unmatched"] * 3
    assert len(result.verdict["blocking_findings"]) == 6


def test_an_entry_can_name_a_secret_or_policy_finding_by_file_or_rule(gate: GateHarness) -> None:
    gate.write_exclusions(
        "exclusions:\n"
        + entry("secret/AWS Access Key ID", file="variables.tf")
        + entry("policy/pv-s3-public-access-block", file="main.tf")  # policy has no file
    )

    result = gate(today=TODAY)

    assert [e["finding"]["rule_id"] for e in result.verdict["excluded"]] == [
        "secret/AWS Access Key ID"
    ]
    assert [s["rule"] for s in result.verdict["stale_exclusions"]] == [
        "policy/pv-s3-public-access-block"
    ]


def test_clean_report_with_the_fixture_file_is_clear_and_reports_every_entry_stale(
    gate: GateHarness,
) -> None:
    gate.use_exclusion_fixture()

    result = gate(report="clean.json", exit_code=0, today=TODAY)

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "clear"
    assert [s["why"] for s in result.verdict["stale_exclusions"]] == [
        "unmatched",
        "expired",
        "unmatched",
    ]


def test_no_cli_exclusion_or_filter_flag_is_ever_passed(gate: GateHarness) -> None:
    gate.use_exclusion_fixture()

    result = gate(today=TODAY)

    [invocation] = result.invocations
    for argument in invocation["argv"]:
        assert not argument.startswith("--exclude")
        assert argument not in {
            "--policy-rule",
            "--severities",
            "--categories",
            "--disable-secrets-scan",
            "--disable-custom-rules",
        }


def test_summary_has_excluded_and_stale_exclusion_tables(gate: GateHarness) -> None:
    gate.use_exclusion_fixture()

    result = gate(today=TODAY)

    assert "## Excluded (1)" in result.summary
    assert "| Severity | Rule | Location | Resource | Reason | Approved by | Expires |" in (
        result.summary
    )
    assert "Recursive" not in result.summary  # the fixture reason is used verbatim
    assert "logging it would recurse" in result.summary
    assert "security-reviewer@example.gov" in result.summary
    assert "2027-06-30" in result.summary
    assert "## Stale exclusions (2)" in result.summary
    assert "| Rule | Resource or file | Expires | Why |" in result.summary
    assert "| expired |" in result.summary
    assert "| unmatched |" in result.summary
