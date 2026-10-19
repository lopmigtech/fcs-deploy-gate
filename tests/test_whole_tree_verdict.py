"""Whole-tree Scope through the run entry point, with the fake CLI and fixture reports."""

from __future__ import annotations

from tests.conftest import GateHarness


def test_clean_report_is_a_clear_verdict_and_exits_0(gate: GateHarness) -> None:
    result = gate(report="clean.json", exit_code=0)

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "clear"
    assert result.verdict["blocking_findings"] == []


def identity(finding: dict[str, object]) -> tuple[object, ...]:
    return (
        finding["severity"],
        finding["rule_id"],
        finding["file"],
        finding["line"],
        finding["resource_type"],
        finding["resource_name"],
    )


PUBLIC_BUCKET = (
    "critical",
    "iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70",
    "main.tf",
    12,
    "aws_s3_bucket",
    "public_assets",
)
UNENCRYPTED_PUBLIC_BUCKET = (
    "high",
    "iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84",
    "main.tf",
    12,
    "aws_s3_bucket",
    "public_assets",
)
UNENCRYPTED_LOGS_BUCKET = (
    "high",
    "iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84",
    "logging.tf",
    4,
    "aws_s3_bucket",
    "logs",
)
HARDCODED_ACCESS_KEY = ("high", "secret/AWS Access Key ID", "variables.tf", 7, None, None)
PUBLIC_ACCESS_BLOCK_POLICY = ("high", "policy/pv-s3-public-access-block", None, None, None, None)
LOGS_BUCKET_WITHOUT_LOGGING = (
    "medium",
    "iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35",
    "logging.tf",
    4,
    "aws_s3_bucket",
    "logs",
)
UNTAGGED_PUBLIC_BUCKET = (
    "informational",
    "iac/b4d81e6f-2c9a-4f03-8e57-7a1b3c5d9f26",
    "main.tf",
    12,
    "aws_s3_bucket",
    "public_assets",
)


def test_enforcing_whole_tree_blocks_on_five_findings_and_exits_1(gate: GateHarness) -> None:
    result = gate()

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert sorted(map(identity, result.verdict["blocking_findings"]), key=str) == sorted(
        [
            PUBLIC_BUCKET,
            UNENCRYPTED_PUBLIC_BUCKET,
            UNENCRYPTED_LOGS_BUCKET,
            HARDCODED_ACCESS_KEY,
            PUBLIC_ACCESS_BLOCK_POLICY,
            LOGS_BUCKET_WITHOUT_LOGGING,
        ],
        key=str,
    )
    assert [identity(f) for f in result.verdict["below_threshold"]] == [UNTAGGED_PUBLIC_BUCKET]


def test_advisory_mode_reports_the_same_blocked_verdict_but_exits_0(gate: GateHarness) -> None:
    enforcing = gate()
    advisory = gate("--mode", "advisory")

    assert advisory.exit_code == 0
    assert advisory.verdict["mode"] == "advisory"
    assert advisory.verdict["blocking_findings"] == enforcing.verdict["blocking_findings"]
    assert advisory.verdict["below_threshold"] == enforcing.verdict["below_threshold"]
    assert "warning" in advisory.stderr.lower()
    assert "advisory" in advisory.stderr.lower()
    assert "blocked" in advisory.stderr.lower()


def test_adding_informational_to_the_threshold_makes_the_tagging_finding_block(
    gate: GateHarness,
) -> None:
    result = gate("--blocking-threshold", "critical,high,medium,informational")

    assert result.exit_code == 1
    assert UNTAGGED_PUBLIC_BUCKET in [identity(f) for f in result.verdict["blocking_findings"]]
    assert result.verdict["below_threshold"] == []
    assert result.verdict["blocking_threshold"] == ["critical", "high", "medium", "informational"]


def test_default_threshold_is_critical_high_medium(gate: GateHarness) -> None:
    result = gate()

    assert result.verdict["blocking_threshold"] == ["critical", "high", "medium"]
