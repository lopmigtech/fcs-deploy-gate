from __future__ import annotations

import io
import json
import os
import shutil
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from fcs_deploy_gate import run
from fcs_deploy_gate.clock import Clock
from fcs_deploy_gate.download import CliPin
from fcs_deploy_gate.http import Transport

TESTS_DIR = Path(__file__).parent
FIXTURE_REPORTS = TESTS_DIR / "fixtures" / "reports"
FIXTURE_EXCLUSIONS = TESTS_DIR / "fixtures" / "exclusions"
FAKE_FCS = TESTS_DIR / "fake_fcs.py"
EXCLUSION_FILENAME = ".fcs-gate.yml"


@dataclass
class GateRun:
    """Everything the outside world can observe from one call of the Gate, captured when
    the call returns so that a later call sharing the work directory cannot change it."""

    exit_code: int
    stdout: str
    stderr: str
    work_dir: Path
    github_output_file: Path
    step_summary_file: Path
    verdict_document: dict[str, Any] | None
    summary_text: str | None
    invocations: list[dict[str, Any]]

    @property
    def verdict(self) -> dict[str, Any]:
        assert self.verdict_document is not None, "the Gate wrote no verdict.json"
        return self.verdict_document

    @property
    def summary(self) -> str:
        assert self.summary_text is not None, "the Gate wrote no summary.md"
        return self.summary_text


@dataclass
class GateHarness:
    tmp_path: Path
    scan_root: Path
    calls: int = 0

    @property
    def repo_root(self) -> Path:
        """The Consumer repository root: tmp_path, where the scan_root fixture puts .git."""
        return self.tmp_path

    @property
    def baseline_dir(self) -> Path:
        """Where the harness checks out the Baseline, as an adapter would."""
        return self.tmp_path / "baseline"

    def write_exclusions(self, content: str) -> Path:
        path = self.repo_root / EXCLUSION_FILENAME
        path.write_text(content)
        return path

    def use_exclusion_fixture(self, name: str = "active-expired-unmatched.yml") -> Path:
        path = self.repo_root / EXCLUSION_FILENAME
        shutil.copyfile(FIXTURE_EXCLUSIONS / name, path)
        return path

    def __call__(
        self,
        *args: str,
        report: str | Path | None = "findings.json",
        exit_code: int | None = None,
        no_report: bool = False,
        env: dict[str, str] | None = None,
        today: date | None = None,
        baseline_report: str | Path | None = None,
        baseline_ref: str | None = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        baseline_exit_code: int = 40,
        transport: Transport | None = None,
        clock: Clock | None = None,
        pin: CliPin | None = None,
        fake_binary: bool = True,
    ) -> GateRun:
        """Call the Gate. ``baseline_report`` switches the call to Change-aware Scope: a
        Baseline directory is created, the fake CLI returns ``baseline_report`` for the
        first (Baseline) scan and ``report`` for the second (change) scan."""
        self.calls += 1
        work_dir = self.tmp_path / "work"
        fake_record = self.tmp_path / f"fake-fcs-invocations-{self.calls}.jsonl"
        github_output_file = self.tmp_path / "github_output"
        step_summary_file = self.tmp_path / "github_step_summary"
        run_env: dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.tmp_path),
            "FAKE_FCS_RECORD": str(fake_record),
            "GITHUB_OUTPUT": str(github_output_file),
            "GITHUB_STEP_SUMMARY": str(step_summary_file),
        }
        if report is not None:
            run_env["FAKE_FCS_REPORT"] = str(fixture_report(report))
        if exit_code is not None:
            run_env["FAKE_FCS_EXIT_CODE"] = str(exit_code)
        scope_args: list[str] = []
        if baseline_report is not None:
            self.baseline_dir.mkdir(exist_ok=True)
            (self.baseline_dir / "logging.tf").write_text('resource "aws_s3_bucket" "logs" {}\n')
            scope_args = ["--scope", "change-aware", "--baseline-dir", str(self.baseline_dir)]
            if baseline_ref is not None:
                scope_args += ["--baseline-ref", baseline_ref]
            run_env["FAKE_FCS_BASELINE_REPORT"] = str(fixture_report(baseline_report))
            run_env["FAKE_FCS_BASELINE_EXIT_CODE"] = str(baseline_exit_code)
        if no_report:
            run_env["FAKE_FCS_NO_REPORT"] = "1"
        if env:
            run_env.update(env)

        argv = [
            "run",
            "--path",
            str(self.scan_root),
            "--region",
            "us-gov-1",
            "--work-dir",
            str(work_dir),
            *(["--fcs-binary", str(FAKE_FCS)] if fake_binary else []),
            *scope_args,
            *args,
        ]
        stdout, stderr = io.StringIO(), io.StringIO()
        code = run(
            argv,
            env=run_env,
            stdout=stdout,
            stderr=stderr,
            today=today,
            transport=transport,
            clock=clock or FakeClock(),
            pin=pin,
        )
        verdict_file = work_dir / "verdict.json"
        summary_file = work_dir / "summary.md"
        return GateRun(
            exit_code=code,
            stdout=stdout.getvalue(),
            stderr=stderr.getvalue(),
            work_dir=work_dir,
            github_output_file=github_output_file,
            step_summary_file=step_summary_file,
            verdict_document=json.loads(verdict_file.read_text())
            if verdict_file.is_file()
            else None,
            summary_text=summary_file.read_text() if summary_file.is_file() else None,
            invocations=[json.loads(line) for line in fake_record.read_text().splitlines() if line]
            if fake_record.exists()
            else [],
        )


def fixture_report(report: str | Path) -> Path:
    path = Path(report)
    return path if path.is_absolute() else FIXTURE_REPORTS / path


@dataclass
class FakeClock:
    """A clock whose sleeps are recorded instead of waited for; the harness default, so
    the retry waits of ten and thirty seconds never slow the suite down."""

    fixed_today: date = date(2026, 10, 19)
    waits: list[float] = field(default_factory=list)

    def today(self) -> date:
        return self.fixed_today

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The suite must run offline: any attempt to open a socket fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise RuntimeError("tests must not use the network")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    yield


@pytest.fixture
def scan_root(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()  # tmp_path is the Consumer repository root
    root = tmp_path / "infra"
    root.mkdir()
    (root / "main.tf").write_text('resource "aws_s3_bucket" "public_assets" {}\n')
    (root / "logging.tf").write_text('resource "aws_s3_bucket" "logs" {}\n')
    (root / "variables.tf").write_text('variable "region" {}\n')
    return root


@pytest.fixture
def gate(tmp_path: Path, scan_root: Path) -> GateHarness:
    return GateHarness(tmp_path=tmp_path, scan_root=scan_root)
