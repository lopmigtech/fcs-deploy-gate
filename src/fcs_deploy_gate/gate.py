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
    # GitHub's output and summary files are plain appends the core can do without any
    # platform logic, which keeps the GitHub adapter thin (ADR 0004). GitLab reads the
    # job log and the work directory instead.
    _append(env.get("GITHUB_STEP_SUMMARY"), summary)
    _append(
        env.get("GITHUB_OUTPUT"),
        f"verdict={verdict.outcome}\nblocking_count={len(verdict.blocking_findings)}",
    )
    stdout.write(summary)

    if verdict.blocked and not config.enforcing:
        stderr.write(f"fcs-deploy-gate: warning: {_advisory_warning(verdict)}\n")
    return 1 if verdict.blocked and config.enforcing else 0


def _advisory_warning(verdict: Verdict) -> str:
    if verdict.error is not None:
        return (
            "Advisory mode: the Gate could not scan, so the Verdict is blocked, "
            f"but the Deployment proceeds. {verdict.error}"
        )
    return (
        f"Advisory mode: the Verdict is blocked ({len(verdict.blocking_findings)} "
        "Blocking findings) but the Deployment proceeds"
    )


def _judge(attempt: ScanAttempt, config: Config) -> Verdict:
    """Fail closed: a scan that did not complete, or a report the Gate cannot read, blocks."""
    if not attempt.completed:
        return Verdict(error=attempt.failure_message())
    try:
        findings = findings_from_report(load_report(attempt.report_path), config.scan_path)
    except ReportError as exc:
        return Verdict(error=str(exc))
    return decide(findings, config.blocking_threshold)


def _terminated(content: str) -> str:
    return content.rstrip("\n") + "\n"


def _write(path: Path, content: str) -> None:
    """Replace whatever is at ``path`` with a fresh regular file, never writing through a link
    the scanned checkout might have planted there."""
    path.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o644), "w", encoding="utf-8") as handle:
        handle.write(_terminated(content))


def _append(path: str | None, content: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(_terminated(content))


def main() -> int:
    return run(sys.argv[1:], env=os.environ, stdout=sys.stdout, stderr=sys.stderr)
