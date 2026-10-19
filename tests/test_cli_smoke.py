"""Two subprocess smoke tests for the command-line parser (spec: Testing Decisions)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import FAKE_FCS, FIXTURE_REPORTS


def test_help_exits_0_and_names_the_inputs() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "fcs_deploy_gate", "run", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    for option in (
        "--path",
        "--scope",
        "--mode",
        "--blocking-threshold",
        "--region",
        "--block-on-unscanned-files",
    ):
        assert option in completed.stdout


def test_console_entry_point_runs_the_gate_end_to_end(tmp_path: Path) -> None:
    scan_root = tmp_path / "infra"
    scan_root.mkdir()
    (scan_root / "main.tf").write_text("")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "FAKE_FCS_REPORT": str(FIXTURE_REPORTS / "findings.json"),
    }

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "fcs_deploy_gate",
            "run",
            "--path",
            str(scan_root),
            "--region",
            "us-gov-1",
            "--mode",
            "advisory",
            "--work-dir",
            str(tmp_path / "work"),
            "--fcs-binary",
            str(FAKE_FCS),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Verdict **blocked**" in completed.stdout
    assert "warning" in completed.stderr
    assert (tmp_path / "work" / "verdict.json").is_file()
