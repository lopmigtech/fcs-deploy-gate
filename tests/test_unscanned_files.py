"""Files the CLI reports it failed to scan: blocking by default, a toggle to report only."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import FIXTURE_REPORTS, GateHarness


def report_with_failed_to_scan(tmp_path: Path, base: str, count: int) -> Path:
    report = json.loads((FIXTURE_REPORTS / base).read_text())
    report["stats"]["files_stats"]["failed_to_scan"] = count
    path = tmp_path / f"{base.removesuffix('.json')}-unscanned-{count}.json"
    path.write_text(json.dumps(report))
    return path


def test_unscanned_files_block_a_clean_report_by_default(gate: GateHarness, tmp_path: Path) -> None:
    result = gate(report=report_with_failed_to_scan(tmp_path, "clean.json", 2), exit_code=0)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert result.verdict["unscanned_files"] == 2
    assert result.verdict["block_on_unscanned_files"] is True
    assert result.verdict["blocking_findings"] == []
    assert "2" in result.summary and "could not scan" in result.summary.lower()


def test_toggle_off_reports_unscanned_files_without_blocking(
    gate: GateHarness, tmp_path: Path
) -> None:
    result = gate(
        "--no-block-on-unscanned-files",
        report=report_with_failed_to_scan(tmp_path, "clean.json", 2),
        exit_code=0,
    )

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "clear"
    assert result.verdict["unscanned_files"] == 2
    assert result.verdict["block_on_unscanned_files"] is False
    assert "2" in result.summary and "could not scan" in result.summary.lower()


def test_unscanned_files_and_blocking_findings_are_both_reported(
    gate: GateHarness, tmp_path: Path
) -> None:
    result = gate(report=report_with_failed_to_scan(tmp_path, "findings.json", 1))

    assert result.exit_code == 1
    assert len(result.verdict["blocking_findings"]) == 6
    assert result.verdict["unscanned_files"] == 1
    assert "| Severity | Rule | Location | Resource |" in result.summary
    assert "could not scan" in result.summary.lower()


def test_advisory_mode_warns_about_unscanned_files_and_exits_0(
    gate: GateHarness, tmp_path: Path
) -> None:
    result = gate(
        "--mode",
        "advisory",
        report=report_with_failed_to_scan(tmp_path, "clean.json", 3),
        exit_code=0,
    )

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "blocked"
    assert "warning" in result.stderr.lower()
    assert "3" in result.stderr


def test_a_report_without_file_stats_counts_no_unscanned_files(
    gate: GateHarness, tmp_path: Path
) -> None:
    report = json.loads((FIXTURE_REPORTS / "clean.json").read_text())
    del report["stats"]
    path = tmp_path / "no-stats.json"
    path.write_text(json.dumps(report))

    result = gate(report=path, exit_code=0)

    assert result.exit_code == 0
    assert result.verdict["verdict"] == "clear"
    assert result.verdict["unscanned_files"] == 0
