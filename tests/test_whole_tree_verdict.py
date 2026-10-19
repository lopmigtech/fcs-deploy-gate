"""Whole-tree Scope through the run entry point, with the fake CLI and fixture reports."""

from __future__ import annotations

from tests.conftest import GateHarness
from tests.expected import (
    HARDCODED_ACCESS_KEY,
    LOGS_BUCKET_WITHOUT_LOGGING,
    PUBLIC_ACCESS_BLOCK_POLICY,
    PUBLIC_BUCKET,
    UNENCRYPTED_LOGS_BUCKET,
    UNENCRYPTED_PUBLIC_BUCKET,
    UNTAGGED_PUBLIC_BUCKET,
    observed,
)


def test_clean_report_is_a_clear_verdict_and_exits_0(gate: GateHarness) -> None:
    result = gate(report="clean.json", exit_code=0)

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "clear"
    assert result.verdict["blocking_findings"] == []


def test_enforcing_whole_tree_blocks_on_six_findings_and_exits_1(gate: GateHarness) -> None:
    result = gate()

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert sorted(map(observed, result.verdict["blocking_findings"]), key=str) == sorted(
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
    assert [observed(f) for f in result.verdict["below_threshold"]] == [UNTAGGED_PUBLIC_BUCKET]


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
    assert UNTAGGED_PUBLIC_BUCKET in [observed(f) for f in result.verdict["blocking_findings"]]
    assert result.verdict["below_threshold"] == []
    assert result.verdict["blocking_threshold"] == ["critical", "high", "medium", "informational"]


def test_default_threshold_is_critical_high_medium(gate: GateHarness) -> None:
    result = gate()

    assert result.verdict["blocking_threshold"] == ["critical", "high", "medium"]
