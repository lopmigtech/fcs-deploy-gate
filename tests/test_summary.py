"""The Markdown summary and the GitHub-style output files (user stories 2, 9, 12, 13)."""

from __future__ import annotations

from tests.conftest import GateHarness


def test_summary_leads_with_verdict_mode_scope_and_path(gate: GateHarness) -> None:
    result = gate()

    first_line = result.summary.splitlines()[0]
    assert "blocked" in first_line.lower()
    assert "enforcing" in result.summary
    assert "whole-tree" in result.summary
    assert str(gate.scan_root) in result.summary


def test_summary_has_a_blocking_findings_table(gate: GateHarness) -> None:
    result = gate()

    assert "| Severity | Rule | Location | Resource |" in result.summary
    assert "`main.tf:12`" in result.summary
    assert "`aws_s3_bucket.public_assets`" in result.summary
    assert "S3 Bucket Publicly Accessible" in result.summary
    assert "secret/AWS Access Key ID" in result.summary
    assert "policy/pv-s3-public-access-block" in result.summary
    assert "Resource Missing Required Tags" in result.summary  # below threshold, still listed


def test_error_verdict_summary_shows_the_message(gate: GateHarness) -> None:
    result = gate(exit_code=201, no_report=True)

    assert "blocked" in result.summary.splitlines()[0].lower()
    assert "exited with code 201" in result.summary


def test_clear_summary_says_so(gate: GateHarness) -> None:
    result = gate(report="clean.json", exit_code=0)

    assert "clear" in result.summary.splitlines()[0].lower()
    assert "No Blocking findings" in result.summary


def test_summary_is_printed_to_stdout(gate: GateHarness) -> None:
    result = gate()

    assert result.summary.strip() in result.stdout


def test_github_output_and_step_summary_are_appended_to(gate: GateHarness) -> None:
    gate.tmp_path.joinpath("github_output").write_text("earlier=kept\n")
    gate.tmp_path.joinpath("github_step_summary").write_text("# Earlier step\n")

    result = gate()

    outputs = result.github_output_file.read_text()
    assert outputs.startswith("earlier=kept\n")
    assert "verdict=blocked\n" in outputs
    assert "blocking_count=6\n" in outputs
    step_summary = result.step_summary_file.read_text()
    assert step_summary.startswith("# Earlier step\n")
    assert result.summary.strip() in step_summary


def test_github_files_are_not_required(gate: GateHarness) -> None:
    result = gate(env={"GITHUB_OUTPUT": "", "GITHUB_STEP_SUMMARY": ""})

    assert result.exit_code == 1
    assert not result.github_output_file.exists()
    assert not result.step_summary_file.exists()
