"""The run entry point: the one seam the Gate exposes to adapters and tests."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, TextIO

from fcs_deploy_gate.baseline import EXPLICIT_REF_HINT, resolve_baseline_command
from fcs_deploy_gate.config import Config, ConfigurationError, ResolveBaselineCommand, parse_args
from fcs_deploy_gate.exclusions import (
    EXCLUSION_FILENAME,
    Exclusion,
    load_exclusions,
    repository_root,
)
from fcs_deploy_gate.report import (
    Finding,
    ReportError,
    findings_from_report,
    load_report,
    unscanned_file_count,
)
from fcs_deploy_gate.scan import BASELINE_REPORT_FILENAME, REPORT_FILENAME, scan_iac
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
    today: date | None = None,
) -> int:
    """The Gate. ``today`` is the clock seam: the UTC date unless a test overrides it."""
    today = today or datetime.now(UTC).date()
    try:
        command = parse_args(argv)
        if isinstance(command, ResolveBaselineCommand):
            return resolve_baseline_command(command, stdout)
        config = command
        root = repository_root(config.scan_path)
        if not (root / ".git").exists():
            stderr.write(
                f"fcs-deploy-gate: note: no .git found at or above {config.scan_path}; "
                f"reading {EXCLUSION_FILENAME} from the scanned directory\n"
            )
        exclusions = load_exclusions(root / EXCLUSION_FILENAME)
    except ConfigurationError as exc:
        stderr.write(f"fcs-deploy-gate: error: {exc}\n")
        return 2

    config.work_dir.mkdir(parents=True, exist_ok=True)
    project_name = config.project_name or root.resolve().name
    verdict = _scan_and_judge(config, env, exclusions, today, project_name)
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
    reasons = [f"{len(verdict.blocking_findings)} Blocking findings"]
    if verdict.blocked_by_unscanned_files:
        reasons.append(f"{verdict.unscanned_files} files the CLI could not scan")
    return (
        f"Advisory mode: the Verdict is blocked ({', '.join(reasons)}) but the Deployment proceeds"
    )


def _scan_and_judge(
    config: Config,
    env: Mapping[str, str],
    exclusions: list[Exclusion],
    today: date,
    project_name: str,
) -> Verdict:
    """Fail closed (ADR 0001): a Baseline that cannot be used, a scan that did not
    complete, or a report the Gate cannot read, blocks."""
    baseline: list[Finding] | None = None
    if config.change_aware:
        if config.baseline_error:
            return _blocked(config, config.baseline_error)
        if config.baseline_dir is None or not config.baseline_dir.is_dir():
            where = f" ({config.baseline_dir} is not a directory)" if config.baseline_dir else ""
            return _blocked(
                config,
                f"Change-aware Scope needs a Baseline directory{where}; the adapter must check "
                f"the Baseline ref out and pass --baseline-dir, or the Consumer must "
                f"{EXPLICIT_REF_HINT}",
            )
        try:
            report = _scan(config, env, config.baseline_dir, BASELINE_REPORT_FILENAME)
            baseline = findings_from_report(report, config.baseline_dir)
        except ReportError as exc:
            return _blocked(config, f"the Baseline scan did not produce a usable report: {exc}")

    try:
        report = _scan(config, env, config.scan_path, upload_as=project_name)
        findings = findings_from_report(report, config.scan_path)
    except ReportError as exc:
        return _blocked(config, str(exc))
    return decide(
        findings,
        config.blocking_threshold,
        exclusions=exclusions,
        today=today,
        baseline=baseline,
        baseline_ref=_baseline_ref(config),
        unscanned_files=unscanned_file_count(report),
        block_on_unscanned_files=config.block_on_unscanned_files,
    )


def _scan(
    config: Config,
    env: Mapping[str, str],
    directory: Path,
    report_filename: str = REPORT_FILENAME,
    *,
    upload_as: str | None = None,
) -> dict[str, Any]:
    """The report of one completed scan of ``directory``; uploaded to the console under
    ``upload_as`` when given (the change), never otherwise (the Baseline). A scan that did
    not complete is a ReportError."""
    attempt = scan_iac(
        fcs_binary=config.fcs_binary,
        scan_path=directory,
        region=config.region,
        work_dir=config.work_dir,
        env=env,
        upload=upload_as is not None,
        project_name=upload_as,
        report_filename=report_filename,
    )
    if not attempt.completed:
        raise ReportError(attempt.failure_message())
    return load_report(attempt.report_path)


def _blocked(config: Config, message: str) -> Verdict:
    return Verdict(
        error=message,
        baseline_ref=_baseline_ref(config),
        block_on_unscanned_files=config.block_on_unscanned_files,
    )


def _baseline_ref(config: Config) -> str | None:
    """Recorded only in Change-aware Scope; Whole-tree ignores every Baseline input."""
    return config.baseline_ref if config.change_aware else None


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
