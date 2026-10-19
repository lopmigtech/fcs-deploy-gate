"""A scan attempt is a result only when the CLI exits 0 or 40 and the report parses (ADR 0001)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import FIXTURE_REPORTS, GateHarness


def report_with_severity(tmp_path: Path, severity: str) -> Path:
    report = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    report["rule_detections"][0]["severity"] = severity
    path = tmp_path / "odd-severity.json"
    path.write_text(json.dumps(report))
    return path


def test_cli_error_without_a_report_is_a_blocked_verdict_with_an_error(
    gate: GateHarness,
) -> None:
    result = gate(exit_code=201, no_report=True)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert result.verdict["blocking_findings"] == []
    assert "201" in result.verdict["error"]
    assert "report" in result.verdict["error"]


def test_cli_error_in_advisory_mode_exits_0_with_a_warning(gate: GateHarness) -> None:
    result = gate("--mode", "advisory", exit_code=201, no_report=True)

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "blocked"
    assert "201" in result.verdict["error"]
    assert "warning" in result.stderr.lower()
    assert "exited with code 201" in result.stderr  # the outage, not the change, is named
    assert "0 Blocking findings" not in result.stderr


@pytest.mark.parametrize("exit_code", [0, 40])
def test_exit_0_and_40_with_a_report_are_results(gate: GateHarness, exit_code: int) -> None:
    result = gate(exit_code=exit_code)

    assert result.verdict["error"] is None
    assert len(result.verdict["blocking_findings"]) == 6


@pytest.mark.parametrize("exit_code", [1, 2, 10, 50, 201])
def test_any_other_exit_code_is_an_error_even_with_a_report(
    gate: GateHarness, exit_code: int
) -> None:
    result = gate(exit_code=exit_code)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert result.verdict["blocking_findings"] == []
    assert str(exit_code) in result.verdict["error"]


def test_unparseable_report_is_a_blocked_verdict_with_an_error(
    gate: GateHarness, tmp_path: Path
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text('{"rule_detections": [')

    result = gate(report=broken)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert "JSON" in result.verdict["error"]


def test_unknown_severity_in_the_report_is_a_report_error(
    gate: GateHarness, tmp_path: Path
) -> None:
    result = gate(report=report_with_severity(tmp_path, "Severe"))

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert "Severe" in result.verdict["error"]


def test_low_severity_normalises_to_informational(gate: GateHarness, tmp_path: Path) -> None:
    result = gate(report=report_with_severity(tmp_path, "LOW"))

    severities = [f["severity"] for f in result.verdict["below_threshold"]]
    assert severities == ["informational", "informational"]


def test_a_report_left_by_an_earlier_run_is_never_judged_again(gate: GateHarness) -> None:
    first = gate()
    assert first.verdict["error"] is None
    assert len(first.verdict["blocking_findings"]) == 6

    second = gate(exit_code=0, no_report=True)  # same work directory, CLI writes nothing

    assert second.exit_code == 1
    assert second.verdict["blocking_findings"] == []
    assert "wrote no report" in second.verdict["error"]


def test_a_planted_symlink_at_the_report_path_is_removed_not_followed(
    gate: GateHarness, tmp_path: Path
) -> None:
    sentinel = tmp_path / "elsewhere.txt"
    sentinel.write_text("must survive")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    (work_dir / "fcs-report.json").symlink_to(sentinel)

    result = gate()

    assert sentinel.read_text() == "must survive"
    assert not (work_dir / "fcs-report.json").is_symlink()
    assert result.verdict["error"] is None
