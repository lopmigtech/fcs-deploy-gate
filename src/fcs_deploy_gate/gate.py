"""The run entry point: the one seam the Gate exposes to adapters and tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, TextIO

from fcs_deploy_gate.baseline import EXPLICIT_REF_HINT, resolve_baseline_command
from fcs_deploy_gate.clock import Clock, SystemClock
from fcs_deploy_gate.config import (
    Config,
    ConfigurationError,
    PinCommand,
    ResolveBaselineCommand,
    parse_args,
)
from fcs_deploy_gate.download import PIN, CliPin, DownloadError, install_cli, published_build
from fcs_deploy_gate.exclusions import (
    EXCLUSION_FILENAME,
    Exclusion,
    load_exclusions,
    repository_root,
)
from fcs_deploy_gate.falcon import (
    CLIENT_ID_VAR,
    CLIENT_SECRET_VAR,
    Credentials,
    FalconApi,
    FalconError,
)
from fcs_deploy_gate.http import ProxySettings, Transport, UrllibTransport
from fcs_deploy_gate.report import (
    CloudRulesEvidence,
    Finding,
    ReportError,
    findings_from_report,
    load_report,
    unscanned_file_count,
)
from fcs_deploy_gate.retry import RetriesExhausted, with_retries
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
    clock: Clock | None = None,
    transport: Transport | None = None,
    pin: CliPin | None = None,
) -> int:
    """The Gate, behind its three injected boundaries: the HTTP ``transport``, the
    ``clock`` (today's date and the retry waits), and the process runner, which is
    whatever ``--fcs-binary`` or the downloaded CLI is. ``pin`` is a fourth, narrower
    seam: tests pin the archive they serve, while the real pin is a constant in the code."""
    clock = clock or SystemClock()
    today = clock.today()
    transport = transport or UrllibTransport()
    pin = pin or PIN
    try:
        command = parse_args(argv)
        if isinstance(command, ResolveBaselineCommand):
            return resolve_baseline_command(command, stdout)
        if isinstance(command, PinCommand):
            return _pin_command(command, env, transport, pin, stdout, stderr)
        config = command
        credentials = _credentials_for(config, env)
        if config.fcs_binary is None and not pin.filled:
            raise ConfigurationError(
                "the fcs CLI checksum pin is empty; fill it from the work environment with "
                f"`fcs-deploy-gate pin --region {config.region}` and a pull request"
            )
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
    api = FalconApi(transport=transport, region=config.region, proxy=ProxySettings.from_env(env))
    with tempfile.TemporaryDirectory(prefix="fcs-cli-", dir=config.work_dir) as cli_dir:
        tools = _prepare_cli(config, credentials, api, pin, clock, Path(cli_dir))
        if isinstance(tools, Verdict):
            verdict = tools
        else:
            verdict = _scan_and_judge(config, env, exclusions, today, project_name, tools, clock)
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


def _credentials_for(config: Config, env: Mapping[str, str]) -> Credentials | None:
    """The Falcon credentials, required unless a test seam supplies the binary."""
    credentials = Credentials.from_env(env)
    if config.fcs_binary is None and credentials is None:
        raise ConfigurationError(
            f"{CLIENT_ID_VAR} and {CLIENT_SECRET_VAR} must be set in the environment "
            "(the Gate obtains its own short-lived token from them)"
        )
    return credentials


@dataclass(frozen=True)
class _PreparedCli:
    """The binary a scan runs and the token it is handed, if any."""

    binary: Path
    token: str | None


def _prepare_cli(
    config: Config,
    credentials: Credentials | None,
    api: FalconApi,
    pin: CliPin,
    clock: Clock,
    cli_dir: Path,
) -> _PreparedCli | Verdict:
    """The test seam binary as given, or the pinned CLI downloaded and verified with a
    fresh token, retried; exhausting the retries is a blocked Verdict (ADR 0001)."""
    if config.fcs_binary is not None:
        return _PreparedCli(binary=config.fcs_binary, token=None)
    assert credentials is not None and pin.filled  # run() checked both before any work

    def download() -> _PreparedCli:
        token = api.token(credentials)
        return _PreparedCli(binary=install_cli(api, token, pin, cli_dir), token=token)

    try:
        return with_retries("the fcs CLI download", download, clock, (FalconError, DownloadError))
    except RetriesExhausted as exc:
        return _blocked(config, str(exc))


def _pin_command(
    command: PinCommand,
    env: Mapping[str, str],
    transport: Transport,
    pin: CliPin,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    """Print the published version, SHA-256, file name and size, for a maintainer to fill
    the pin by pull request."""
    credentials = Credentials.from_env(env)
    if credentials is None:
        raise ConfigurationError(
            f"{CLIENT_ID_VAR} and {CLIENT_SECRET_VAR} must be set in the environment"
        )
    api = FalconApi(transport=transport, region=command.region, proxy=ProxySettings.from_env(env))
    version = command.version or pin.version
    try:
        build = published_build(api, api.token(credentials), version)
    except (FalconError, DownloadError) as exc:
        stderr.write(f"fcs-deploy-gate: error: {exc}\n")
        return 1
    stdout.write(
        f"version={build.version}\nsha256={build.sha256}\n"
        f"file_name={build.file_name}\nsize={build.size}\n"
    )
    return 0


def _scan_and_judge(
    config: Config,
    env: Mapping[str, str],
    exclusions: list[Exclusion],
    today: date,
    project_name: str,
    tools: _PreparedCli,
    clock: Clock,
) -> Verdict:
    """Fail closed (ADR 0001): a Baseline that cannot be used, a scan that did not
    complete after its retries, or a report the Gate cannot trust, blocks."""
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
        baseline_dir = config.baseline_dir
        try:
            baseline = with_retries(
                "the Baseline scan",
                lambda: _scan(config, env, tools, baseline_dir, BASELINE_REPORT_FILENAME),
                clock,
                (ReportError,),
            ).findings
        except RetriesExhausted as exc:
            return _blocked(config, str(exc))

    try:
        scanned = with_retries(
            "the scan",
            lambda: _scan(config, env, tools, config.scan_path, upload_as=project_name),
            clock,
            (ReportError,),
        )
    except RetriesExhausted as exc:
        return _blocked(config, str(exc))
    return decide(
        scanned.findings,
        config.blocking_threshold,
        exclusions=exclusions,
        today=today,
        baseline=baseline,
        baseline_ref=_baseline_ref(config),
        unscanned_files=unscanned_file_count(scanned.report),
        block_on_unscanned_files=config.block_on_unscanned_files,
        cloud_rules_evidence=scanned.evidence,
    )


@dataclass(frozen=True)
class _Scanned:
    report: dict[str, Any]
    findings: list[Finding]
    evidence: CloudRulesEvidence


def _scan(
    config: Config,
    env: Mapping[str, str],
    tools: _PreparedCli,
    directory: Path,
    report_filename: str = REPORT_FILENAME,
    *,
    upload_as: str | None = None,
) -> _Scanned:
    """One completed, trustworthy scan of ``directory``: its report, Findings and
    cloud-rules evidence; uploaded to the console under ``upload_as`` when given (the
    change), never otherwise (the Baseline). A scan that did not complete, a report without
    cloud-rules evidence, or one the Gate cannot interpret is a ReportError, which the
    caller retries."""
    attempt = scan_iac(
        fcs_binary=tools.binary,
        scan_path=directory,
        region=config.region,
        work_dir=config.work_dir,
        env=env,
        upload=upload_as is not None,
        project_name=upload_as,
        report_filename=report_filename,
        token=tools.token,
    )
    if not attempt.completed:
        raise ReportError(attempt.failure_message())
    report = load_report(attempt.report_path)
    evidence = CloudRulesEvidence.gather(report, attempt.stdout)
    evidence.require()
    return _Scanned(report, findings_from_report(report, directory), evidence)


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
