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
