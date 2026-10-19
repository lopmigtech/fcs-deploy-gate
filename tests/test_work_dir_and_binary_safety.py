"""The Gate runs inside a checkout it does not trust: the binary it launches and the files it
writes must never be chosen by the scanned tree."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import FAKE_FCS, GateHarness


def test_relative_fcs_binary_resolves_against_the_gate_cwd_not_the_scan_root(
    gate: GateHarness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "fake").symlink_to(FAKE_FCS)
    decoy_dir = gate.scan_root / "bin"
    decoy_dir.mkdir()
    decoy = decoy_dir / "fake"
    decoy.write_text("#!/bin/sh\nexit 0\n")  # a Consumer-planted binary: writes no report
    decoy.chmod(0o755)
    monkeypatch.chdir(tmp_path)

    result = gate("--fcs-binary", os.path.join("bin", "fake"))

    assert len(result.invocations) == 1  # the real fake ran, not the decoy
    assert result.verdict["error"] is None


def test_missing_fcs_binary_is_a_configuration_error(gate: GateHarness, tmp_path: Path) -> None:
    result = gate("--fcs-binary", str(tmp_path / "no-such-fcs"))

    assert result.exit_code == 2
    assert "no-such-fcs" in result.stderr
    assert result.invocations == []


def test_planted_symlinks_at_the_output_files_are_replaced_not_followed(
    gate: GateHarness, tmp_path: Path
) -> None:
    sentinel = tmp_path / "elsewhere.txt"
    sentinel.write_text("must survive")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    for name in ("verdict.json", "summary.md"):
        (work_dir / name).symlink_to(sentinel)

    result = gate()

    assert sentinel.read_text() == "must survive"
    assert not (work_dir / "verdict.json").is_symlink()
    assert not (work_dir / "summary.md").is_symlink()
    assert result.verdict["verdict"] == "blocked"


def test_symlinked_work_dir_is_a_configuration_error(gate: GateHarness, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "work").symlink_to(elsewhere)

    result = gate()

    assert result.exit_code == 2
    assert "symlink" in result.stderr
    assert result.invocations == []
