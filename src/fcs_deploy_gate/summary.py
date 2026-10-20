"""Rendering a Verdict as Markdown for job summaries, job logs and artifacts."""

from __future__ import annotations

from collections.abc import Iterable

from fcs_deploy_gate.config import Config
from fcs_deploy_gate.exclusions import ExcludedFinding, StaleExclusion
from fcs_deploy_gate.report import Finding
from fcs_deploy_gate.verdict import Verdict

FINDINGS_TABLE_HEADER = "| Severity | Rule | Location | Resource |\n|---|---|---|---|"
EXCLUDED_TABLE_HEADER = (
    "| Severity | Rule | Location | Resource | Reason | Approved by | Expires |\n"
    "|---|---|---|---|---|---|---|"
)
STALE_TABLE_HEADER = "| Rule | Resource or file | Expires | Why |\n|---|---|---|---|"


def _location(finding: Finding) -> str:
    if finding.file is None:
        return "—"
    if finding.line is None:
        return f"`{finding.file}`"
    return f"`{finding.file}:{finding.line}`"


def _resource(finding: Finding) -> str:
    address = finding.resource_address or finding.resource_name
    return f"`{address}`" if address else "—"


def _rule(finding: Finding) -> str:
    return f"{finding.rule_name} (`{finding.rule_id}`)"


def _finding_cells(finding: Finding) -> str:
    return f"{finding.severity} | {_rule(finding)} | {_location(finding)} | {_resource(finding)}"


def _findings_table(findings: Iterable[Finding]) -> str:
    rows = [f"| {_finding_cells(f)} |" for f in findings]
    return "\n".join([FINDINGS_TABLE_HEADER, *rows])


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _excluded_table(excluded: Iterable[ExcludedFinding]) -> str:
    rows = [
        f"| {_finding_cells(e.finding)} | {_cell(e.exclusion.reason)} "
        f"| {_cell(e.exclusion.approved_by)} | {e.exclusion.expires.isoformat()} |"
        for e in excluded
    ]
    return "\n".join([EXCLUDED_TABLE_HEADER, *rows])


def _stale_table(stale: Iterable[StaleExclusion]) -> str:
    rows = []
    for s in stale:
        where = " ".join(f"`{part}`" for part in (s.exclusion.resource, s.exclusion.file) if part)
        rows.append(
            f"| `{s.exclusion.rule}` | {where} | {s.exclusion.expires.isoformat()} | {s.why} |"
        )
    return "\n".join([STALE_TABLE_HEADER, *rows])


def render_summary(verdict: Verdict, config: Config) -> str:
    threshold = ", ".join(config.blocking_threshold_ordered)
    parts = [
        f"# fcs-deploy-gate: Verdict **{verdict.outcome}**",
        "",
        "| | |",
        "|---|---|",
        f"| Mode | {config.mode} |",
        f"| Scope | {config.scope} |",
        f"| Path | `{config.scan_path_as_given}` |",
        f"| Blocking threshold | {threshold} |",
    ]
    if config.change_aware:
        baseline = f"`{verdict.baseline_ref or 'unresolved'}`"
        if verdict.baseline_path_present is False:
            baseline += " (the scanned path did not exist at the Baseline; every Finding is new)"
        parts += [f"| Baseline | {baseline} |"]
        if verdict.error is None:
            parts += [
                f"| Findings | {verdict.new_findings} new of {verdict.total_findings} total |"
            ]
    parts += [""]
    if verdict.error is not None:
        parts += ["## The Gate could not scan", "", f"> {verdict.error}", ""]
        parts += [
            "The Verdict is blocked because no trustworthy report exists, not because of "
            "your change (ADR 0001).",
            "",
        ]
    elif verdict.blocking_findings:
        parts += [
            f"## Blocking findings ({len(verdict.blocking_findings)})",
            "",
            _findings_table(verdict.blocking_findings),
            "",
        ]
    else:
        parts += ["No Blocking findings at or above the Blocking threshold.", ""]

    if verdict.excluded:
        parts += [
            f"## Excluded ({len(verdict.excluded)})",
            "",
            _excluded_table(verdict.excluded),
            "",
        ]

    if verdict.below_threshold:
        parts += [
            f"## Below the Blocking threshold ({len(verdict.below_threshold)})",
            "",
            _findings_table(verdict.below_threshold),
            "",
        ]

    if verdict.stale_exclusions:
        parts += [
            f"## Stale exclusions ({len(verdict.stale_exclusions)})",
            "",
            _stale_table(verdict.stale_exclusions),
            "",
            "Stale exclusions are reported, never dropped: remove or renew them in "
            "`.fcs-gate.yml`.",
            "",
        ]

    if verdict.unscanned_files:
        consequence = (
            "This blocks the Verdict (`--block-on-unscanned-files`, the default)."
            if verdict.block_on_unscanned_files
            else "Reported only (`--no-block-on-unscanned-files`)."
        )
        parts += [
            f"## Files the CLI could not scan ({verdict.unscanned_files})",
            "",
            f"The CLI reported {verdict.unscanned_files} file(s) it failed to scan, so any "
            f"Findings in them are unknown. {consequence}",
            "",
        ]

    parts += [
        "_A clear Verdict means no IaC Findings at or above the Blocking threshold; "
        "it does not yet guarantee that no IOM will appear (ADR 0005)._",
        "",
    ]
    return "\n".join(parts)
