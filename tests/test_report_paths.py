"""Report file paths are normalised relative to the scanned root (spec: Scanning)."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import FIXTURE_REPORTS, GateHarness


def report_with_rewritten_paths(tmp_path: Path, scan_root: Path) -> Path:
    report = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    rules = report["rule_detections"]
    rules[0]["detections"][0]["file"] = str(scan_root / "main.tf")  # absolute
    rules[1]["detections"][0]["file"] = "./main.tf"  # dot-relative
    rules[1]["detections"][1]["file"] = f"{scan_root}/./logging.tf"  # absolute with a dot
    rules[2]["detections"][0]["file"] = "logging.tf"  # already relative
    rules[3]["detections"][0]["file"] = "./modules/../main.tf"  # relative with parent segment
    report["secrets_analysis"]["secrets"][0]["file_path"] = str(scan_root / "variables.tf")
    path = tmp_path / "rewritten-paths.json"
    path.write_text(json.dumps(report))
    return path


def test_absolute_and_dot_relative_paths_normalise_to_the_scanned_root(
    gate: GateHarness, tmp_path: Path
) -> None:
    result = gate(report=report_with_rewritten_paths(tmp_path, gate.scan_root))

    files = {f["rule_id"]: f["file"] for f in result.verdict["blocking_findings"]}
    files.update({f["rule_id"]: f["file"] for f in result.verdict["below_threshold"]})
    assert files["iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70"] == "main.tf"
    assert files["iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35"] == "logging.tf"
    assert files["iac/b4d81e6f-2c9a-4f03-8e57-7a1b3c5d9f26"] == "main.tf"
    assert files["secret/AWS Access Key ID"] == "variables.tf"
    encryption = [
        f["file"]
        for f in result.verdict["blocking_findings"]
        if f["rule_id"] == "iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84"
    ]
    assert sorted(encryption) == ["logging.tf", "main.tf"]


def test_paths_outside_the_scanned_root_are_left_alone(gate: GateHarness, tmp_path: Path) -> None:
    report = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    report["rule_detections"][0]["detections"][0]["file"] = "/elsewhere/shared/main.tf"
    path = tmp_path / "outside.json"
    path.write_text(json.dumps(report))

    result = gate(report=path)

    files = {f["rule_id"]: f["file"] for f in result.verdict["blocking_findings"]}
    assert files["iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70"] == "/elsewhere/shared/main.tf"
