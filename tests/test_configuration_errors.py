"""Configuration mistakes exit 2 in both modes, before any scan happens (user story 11)."""

from __future__ import annotations

import pytest

from tests.conftest import GateHarness

MODES = ["enforcing", "advisory"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("args", "expected_message"),
    [
        (["--blocking-threshold", "critical,high"], "medium"),
        (["--blocking-threshold", "high,medium"], "critical"),
        (["--blocking-threshold", "critical,medium"], "high"),
        (["--blocking-threshold", "critical,high,medium,severe"], "severe"),
        (["--scope", "changed-files"], "scope"),
        (["--mode", "warn"], "mode"),
        (["--region", "us-3"], "region"),
    ],
    ids=[
        "threshold-missing-medium",
        "threshold-missing-critical",
        "threshold-missing-high",
        "threshold-unknown-severity",
        "invalid-scope",
        "invalid-mode",
        "invalid-region",
    ],
)
def test_configuration_errors_exit_2_with_a_message(
    gate: GateHarness, mode: str, args: list[str], expected_message: str
) -> None:
    result = gate("--mode", mode, *args)

    assert result.exit_code == 2
    assert expected_message in result.stderr
    assert result.invocations == []
    assert not (result.work_dir / "verdict.json").exists()


@pytest.mark.parametrize("mode", MODES)
def test_missing_scan_path_exits_2(gate: GateHarness, mode: str) -> None:
    result = gate("--mode", mode, "--path", str(gate.tmp_path / "does-not-exist"))

    assert result.exit_code == 2
    assert "does-not-exist" in result.stderr
    assert result.invocations == []


def test_valid_regions_are_accepted(gate: GateHarness) -> None:
    for region in ("us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2"):
        assert gate("--region", region, report="clean.json", exit_code=0).exit_code == 0
