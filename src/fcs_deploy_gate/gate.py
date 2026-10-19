"""The run entry point: the one seam the Gate exposes to adapters and tests."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from fcs_deploy_gate.config import Config, ConfigurationError, parse_args
from fcs_deploy_gate.report import ReportError, findings_from_report, load_report
from fcs_deploy_gate.scan import ScanAttempt, scan_iac
from fcs_deploy_gate.summary import render_summary
from fcs_deploy_gate.verdict import Verdict, decide, verdict_document

VERDICT_FILENAME = "verdict.json"
SUMMARY_FILENAME = "summary.md"


def run(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    try:
        config = parse_args(argv)
    except ConfigurationError as exc:
        stderr.write(f"fcs-deploy-gate: error: {exc}\n")
        return 2

    config.work_dir.mkdir(parents=True, exist_ok=True)
    attempt = scan_iac(
        fcs_binary=config.fcs_binary,
        scan_path=config.scan_path,
        region=config.region,
        work_dir=config.work_dir,
        env=env,
    )
    verdict = _judge(attempt, config)
    summary = render_summary(verdict, config)

    document = json.dumps(verdict_document(verdict, config), indent=2)
    _write(config.work_dir / VERDICT_FILENAME, document)
    _write(config.work_dir / SUMMARY_FILENAME, summary)
    _append(env.get("GITHUB_STEP_SUMMARY"), summary)
    _append(
        env.get("GITHUB_OUTPUT"),
        f"verdict={verdict.outcome}\nblocking_count={len(verdict.blocking_findings)}",
    )
    stdout.write(summary)

    if verdict.blocked and not config.enforcing:
        stderr.write(
            "fcs-deploy-gate: warning: Advisory mode: the Verdict is blocked "
            f"({len(verdict.blocking_findings)} Blocking findings) but the Deployment proceeds\n"
        )
    return 1 if verdict.blocked and config.enforcing else 0


def _judge(attempt: ScanAttempt, config: Config) -> Verdict:
    """Fail closed: a scan that did not complete, or a report the Gate cannot read, blocks."""
    if not attempt.completed:
        return Verdict(error=attempt.failure_message())
    try:
        findings = findings_from_report(load_report(attempt.report_path), config.scan_path)
    except ReportError as exc:
        return Verdict(error=str(exc))
    return decide(findings, config.blocking_threshold)


def _write(path: Path, content: str) -> None:
    path.write_text(content.rstrip("\n") + "\n", encoding="utf-8")


def _append(path: str | None, content: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(content.rstrip("\n") + "\n")


def main() -> int:
    return run(sys.argv[1:], env=os.environ, stdout=sys.stdout, stderr=sys.stderr)
