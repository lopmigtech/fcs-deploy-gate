"""Rendering a Verdict as Markdown for job summaries, job logs and artifacts."""

from __future__ import annotations

from collections.abc import Iterable

from fcs_deploy_gate.config import Config
from fcs_deploy_gate.report import Finding
from fcs_deploy_gate.verdict import Verdict

FINDINGS_TABLE_HEADER = "| Severity | Rule | Location | Resource |\n|---|---|---|---|"


def _location(finding: Finding) -> str:
    if finding.file is None:
        return "—"
    if finding.line is None:
        return f"`{finding.file}`"
    return f"`{finding.file}:{finding.line}`"


def _resource(finding: Finding) -> str:
    if finding.resource_type and finding.resource_name:
        return f"`{finding.resource_type}.{finding.resource_name}`"
    return f"`{finding.resource_name}`" if finding.resource_name else "—"


def _rule(finding: Finding) -> str:
    return f"{finding.rule_name} (`{finding.rule_id}`)"


def _findings_table(findings: Iterable[Finding]) -> str:
    rows = [f"| {f.severity} | {_rule(f)} | {_location(f)} | {_resource(f)} |" for f in findings]
    return "\n".join([FINDINGS_TABLE_HEADER, *rows])


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
        "",
    ]
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

    if verdict.below_threshold:
        parts += [
            f"## Below the Blocking threshold ({len(verdict.below_threshold)})",
            "",
            _findings_table(verdict.below_threshold),
            "",
        ]

    parts += [
        "_A clear Verdict means no IaC Findings at or above the Blocking threshold; "
        "it does not yet guarantee that no IOM will appear (ADR 0005)._",
        "",
    ]
    return "\n".join(parts)
