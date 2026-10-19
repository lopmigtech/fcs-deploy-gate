"""Running ``fcs scan iac`` once and reporting what happened, without judging it."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPORT_FILENAME = "fcs-report.json"
BASELINE_REPORT_FILENAME = "fcs-report-baseline.json"
# The only exit codes every CrowdStrike source agrees mean "scan completed"
# (docs/research/fcs-iac-scan-contract.md, section 2).
RESULT_EXIT_CODES: frozenset[int] = frozenset({0, 40})
SCAN_TIMEOUT_SECONDS = 300
FAIL_ON_EVERYTHING = "critical=1,high=1,medium=1,informational=1"

# Credentials are read by Gate code only; the CLI never sees them in its environment.
CREDENTIAL_ENV_VARS: tuple[str, ...] = (
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "FCS_CLIENT_ID",
    "FCS_CLIENT_SECRET",
)


@dataclass(frozen=True)
class ScanAttempt:
    exit_code: int
    report_path: Path
    stderr: str

    @property
    def completed(self) -> bool:
        return self.exit_code in RESULT_EXIT_CODES

    def failure_message(self) -> str:
        wrote = "wrote no report" if not self.report_path.is_file() else "wrote a report"
        message = (
            f"the fcs CLI exited with code {self.exit_code} and {wrote}; "
            f"only exit codes {' and '.join(map(str, sorted(RESULT_EXIT_CODES)))} "
            "count as a completed scan"
        )
        tail = self.stderr.strip().splitlines()[-3:]
        if tail:
            message += ". CLI stderr: " + " | ".join(line.strip() for line in tail)
        return message


def cli_environment(env: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in env.items() if key not in CREDENTIAL_ENV_VARS}


def scan_iac(
    *,
    fcs_binary: Path,
    scan_path: Path,
    region: str,
    work_dir: Path,
    env: Mapping[str, str],
    upload: bool,
    project_name: str | None = None,
    report_filename: str = REPORT_FILENAME,
    token: str | None = None,
) -> ScanAttempt:
    """One ``fcs scan iac`` of ``scan_path``. Only the scan of the change is uploaded to
    the console; a Baseline scan never is (ADR 0002). The short-lived token, when there
    is one, is a single argument; the client secret never appears anywhere."""
    # A report left by an earlier run in a reused workspace must never be judged as this
    # run's result (ADR 0001): only what this invocation writes counts. The entry is
    # unlinked before the path is resolved, so a planted symlink is removed, never followed.
    report_path = work_dir / report_filename
    report_path.unlink(missing_ok=True)
    report_path = report_path.resolve()
    command = [
        str(fcs_binary),
        "scan",
        "iac",
        "--path",
        ".",
        "--report-formats",
        "json",
        "--output-path",
        str(report_path),
        "--fail-on",
        FAIL_ON_EVERYTHING,
        "--timeout",
        str(SCAN_TIMEOUT_SECONDS),
        "--falcon-region",
        region,
    ]
    if token:
        command += ["--falcon-token", token]
    if upload:
        command += ["--upload-results"]
        if project_name:
            command += ["--project-name", project_name]
    completed = subprocess.run(
        command,
        cwd=scan_path,
        env=cli_environment(env),
        capture_output=True,
        text=True,
        check=False,
    )
    return ScanAttempt(
        exit_code=completed.returncode, report_path=report_path, stderr=completed.stderr
    )
