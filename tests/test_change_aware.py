"""Change-aware Scope: only Findings the change introduces count (ADR 0002)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from tests.conftest import FIXTURE_REPORTS, GateHarness
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

TODAY = date(2026, 10, 19)
BASELINE_REF = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"


def test_change_aware_blocks_only_on_the_four_findings_the_change_introduces(
    gate: GateHarness,
) -> None:
    gate.use_exclusion_fixture()

    result = gate(baseline_report="baseline.json", today=TODAY)

    assert result.exit_code == 1
    assert sorted(map(observed, result.verdict["blocking_findings"]), key=str) == sorted(
        [
            PUBLIC_BUCKET,
            UNENCRYPTED_PUBLIC_BUCKET,
            HARDCODED_ACCESS_KEY,
            PUBLIC_ACCESS_BLOCK_POLICY,
        ],
        key=str,
    )
    assert [observed(f) for f in result.verdict["below_threshold"]] == [UNTAGGED_PUBLIC_BUCKET]
    considered = [
        observed(f) for key in ("blocking_findings", "below_threshold") for f in result.verdict[key]
    ] + [observed(e["finding"]) for e in result.verdict["excluded"]]
    assert LOGS_BUCKET_WITHOUT_LOGGING not in considered
    assert UNENCRYPTED_LOGS_BUCKET not in considered
    # The active Exclusion covers a pre-existing Finding: matched, so not stale.
    assert [(s["rule"], s["why"]) for s in result.verdict["stale_exclusions"]] == [
        ("iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84", "expired"),
        ("iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70", "unmatched"),
    ]


def test_change_aware_runs_two_scans_from_their_own_directories(gate: GateHarness) -> None:
    result = gate(baseline_report="baseline.json", today=TODAY)

    baseline, change = result.invocations
    assert baseline["cwd"] == str(gate.baseline_dir)
    assert change["cwd"] == str(gate.scan_root)
    assert "--upload-results" not in baseline["argv"]
    assert "--upload-results" in change["argv"]
    assert change["argv"][change["argv"].index("--project-name") + 1] == gate.tmp_path.name
    assert (
        baseline["argv"][baseline["argv"].index("--output-path") + 1]
        != (change["argv"][change["argv"].index("--output-path") + 1])
    )
    assert (result.work_dir / "fcs-report-baseline.json").is_file()
    assert (result.work_dir / "fcs-report.json").is_file()


def test_verdict_document_and_summary_record_the_baseline(gate: GateHarness) -> None:
    result = gate(baseline_report="baseline.json", today=TODAY)

    assert result.verdict["scope"] == "change-aware"
    assert result.verdict["baseline_ref"] == BASELINE_REF
    assert result.verdict["total_findings"] == 7
    assert result.verdict["new_findings"] == 5
    assert "change-aware" in result.summary
    assert "5 new of 7 total" in result.summary
    assert BASELINE_REF in result.summary


def test_whole_tree_records_no_baseline_and_counts_everything_as_new(gate: GateHarness) -> None:
    result = gate(today=TODAY)

    assert result.verdict["scope"] == "whole-tree"
    assert result.verdict["baseline_ref"] is None
    assert result.verdict["total_findings"] == 7
    assert result.verdict["new_findings"] == 7
    assert "--upload-results" in result.invocations[0]["argv"]


def baseline_variant(tmp_path: Path, name: str, **changes: object) -> Path:
    """The Baseline subset with one detection altered (keys of the first detection of
    the first rule, the high encryption Finding on the logs bucket)."""
    report = json.loads((FIXTURE_REPORTS / "baseline.json").read_text())
    report["rule_detections"][0]["detections"][0].update(changes)
    path = tmp_path / f"baseline-{name}.json"
    path.write_text(json.dumps(report))
    return path


def test_a_finding_that_only_moved_to_another_line_is_not_new(
    gate: GateHarness, tmp_path: Path
) -> None:
    result = gate(baseline_report=baseline_variant(tmp_path, "moved", line=99), today=TODAY)

    considered = [observed(f) for f in result.verdict["blocking_findings"]]
    assert UNENCRYPTED_LOGS_BUCKET not in considered
    assert result.verdict["new_findings"] == 5


def test_a_renamed_resource_is_new(gate: GateHarness, tmp_path: Path) -> None:
    result = gate(
        baseline_report=baseline_variant(tmp_path, "renamed", resource_name="audit_logs"),
        today=TODAY,
    )

    assert UNENCRYPTED_LOGS_BUCKET in [observed(f) for f in result.verdict["blocking_findings"]]
    assert result.verdict["new_findings"] == 6


def test_a_resource_moved_to_another_file_is_new(gate: GateHarness, tmp_path: Path) -> None:
    result = gate(
        baseline_report=baseline_variant(tmp_path, "moved-file", file="buckets.tf"),
        today=TODAY,
    )

    assert UNENCRYPTED_LOGS_BUCKET in [observed(f) for f in result.verdict["blocking_findings"]]


def test_baseline_paths_normalise_against_the_baseline_directory(
    gate: GateHarness, tmp_path: Path
) -> None:
    absolute = str(gate.baseline_dir / "logging.tf")
    gate.baseline_dir.mkdir(exist_ok=True)

    result = gate(baseline_report=baseline_variant(tmp_path, "abs", file=absolute), today=TODAY)

    assert UNENCRYPTED_LOGS_BUCKET not in [observed(f) for f in result.verdict["blocking_findings"]]


# ---- Baseline errors (ADR 0001, ADR 0002) ----


def test_a_baseline_error_from_the_adapter_is_a_blocked_verdict_without_scanning(
    gate: GateHarness,
) -> None:
    result = gate(
        "--scope",
        "change-aware",
        "--baseline-error",
        "no usable Baseline: the previous commit is all zeros; pass an explicit Baseline ref",
        today=TODAY,
    )

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert "explicit Baseline ref" in result.verdict["error"]
    assert result.invocations == []
    assert "explicit Baseline ref" in result.summary


def test_change_aware_without_a_baseline_directory_is_a_blocked_verdict(
    gate: GateHarness,
) -> None:
    result = gate("--scope", "change-aware", today=TODAY)

    assert result.exit_code == 1
    assert "Baseline directory" in result.verdict["error"]
    assert result.invocations == []


def test_a_missing_baseline_directory_is_a_blocked_verdict(gate: GateHarness) -> None:
    result = gate(
        "--scope",
        "change-aware",
        "--baseline-dir",
        str(gate.tmp_path / "nowhere"),
        "--baseline-ref",
        BASELINE_REF,
        today=TODAY,
    )

    assert result.exit_code == 1
    assert "nowhere" in result.verdict["error"]
    assert result.invocations == []


def test_baseline_errors_exit_0_with_a_warning_in_advisory_mode(gate: GateHarness) -> None:
    result = gate("--mode", "advisory", "--scope", "change-aware", today=TODAY)

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "blocked"
    assert "warning" in result.stderr.lower()
    assert "Baseline directory" in result.stderr


def test_whole_tree_ignores_baseline_inputs(gate: GateHarness) -> None:
    result = gate(
        "--baseline-error",
        "no usable Baseline",
        "--baseline-dir",
        str(gate.tmp_path / "nowhere"),
        "--baseline-ref",
        BASELINE_REF,
        today=TODAY,
    )

    assert result.exit_code == 1
    assert result.verdict["error"] is None
    assert result.verdict["baseline_ref"] is None
    assert len(result.verdict["blocking_findings"]) == 6
    assert len(result.invocations) == 1


def test_a_failed_baseline_scan_is_a_scan_error_and_the_change_is_not_scanned(
    gate: GateHarness,
) -> None:
    result = gate(baseline_report="baseline.json", baseline_exit_code=201, today=TODAY)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert "Baseline" in result.verdict["error"]
    assert "201" in result.verdict["error"]
    assert len(result.invocations) == 1


def test_a_failed_change_scan_in_change_aware_scope_is_a_scan_error(gate: GateHarness) -> None:
    result = gate(baseline_report="baseline.json", exit_code=201, today=TODAY)

    assert result.exit_code == 1
    assert "201" in result.verdict["error"]
    assert "Baseline" not in result.verdict["error"]
    assert len(result.invocations) == 2


def test_whole_tree_error_verdicts_do_not_record_a_baseline_ref(gate: GateHarness) -> None:
    result = gate("--baseline-ref", BASELINE_REF, exit_code=201, no_report=True, today=TODAY)

    assert result.verdict["error"] is not None
    assert result.verdict["baseline_ref"] is None


def test_error_summaries_do_not_claim_a_finding_count(gate: GateHarness) -> None:
    result = gate("--scope", "change-aware", "--baseline-error", "no usable Baseline", today=TODAY)

    assert "new of" not in result.summary
    assert "no usable Baseline" in result.summary


def test_a_second_instance_of_a_pre_existing_identity_is_new(
    gate: GateHarness, tmp_path: Path
) -> None:
    change = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    secret = dict(change["secrets_analysis"]["secrets"][0])
    secret["line_number"] = 42
    change["secrets_analysis"]["secrets"].append(secret)  # a second key in the same file
    change_path = tmp_path / "two-secrets.json"
    change_path.write_text(json.dumps(change))
    baseline = json.loads((FIXTURE_REPORTS / "baseline.json").read_text())
    baseline["secrets_analysis"]["secrets"] = [change["secrets_analysis"]["secrets"][0]]
    baseline_path = tmp_path / "baseline-one-secret.json"
    baseline_path.write_text(json.dumps(baseline))

    result = gate(report=change_path, baseline_report=baseline_path, today=TODAY)

    secrets = [f for f in result.verdict["blocking_findings"] if f["rule_id"].startswith("secret/")]
    assert len(secrets) == 1
    assert result.verdict["total_findings"] == 8
    assert result.verdict["new_findings"] == 5


def test_a_baseline_directory_without_a_ref_is_a_configuration_error(gate: GateHarness) -> None:
    result = gate(baseline_report="baseline.json", baseline_ref=None, today=TODAY)

    assert result.exit_code == 2
    assert "--baseline-ref" in result.stderr
    assert result.invocations == []
