"""Turning the fcs JSON report into Findings."""

from __future__ import annotations

import json
import os.path
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fcs_deploy_gate.config import SEVERITIES

# CrowdStrike removed "low" in CLI 1.0.0 but editor plugins and older reports still spell it.
SEVERITY_ALIASES: dict[str, str] = {"low": "informational"}
SECRET_SEVERITY = "high"


class ReportError(Exception):
    """The report is missing, is not JSON, or says something the Gate cannot interpret."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file: str | None
    line: int | None
    resource_type: str | None
    resource_name: str | None
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_report(report_path: Path) -> dict[str, Any]:
    if not report_path.is_file():
        raise ReportError(f"the CLI wrote no report at {report_path}")
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"the report at {report_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportError(f"the report at {report_path} is not a JSON object")
    return data


def normalise_severity(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise ReportError(f"{context}: severity {value!r} is not a string")
    severity = SEVERITY_ALIASES.get(value.lower(), value.lower())
    if severity not in SEVERITIES:
        raise ReportError(
            f"{context}: unknown severity {value!r} (expected one of {', '.join(SEVERITIES)})"
        )
    return severity


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def normalise_path(value: str | None, scan_root: Path) -> str | None:
    """Make a report path relative to the scanned root, whichever form the CLI used.

    The change and the Baseline are checked out into different directories, so only a
    root-relative path lets two scans be compared (ADR 0002).
    """
    if value is None:
        return None
    normalised = os.path.normpath(value)
    if not os.path.isabs(normalised):
        return normalised.replace(os.sep, "/")
    for root in {os.path.normpath(scan_root), os.path.realpath(scan_root)}:
        try:
            return Path(normalised).relative_to(root).as_posix()
        except ValueError:
            continue
    return value


def _nested_list(report: dict[str, Any], *keys: str) -> list[Any]:
    node: Any = report
    for key in keys:
        if not isinstance(node, dict):
            return []
        node = node.get(key)
    return node if isinstance(node, list) else []


def _rule_detection_findings(report: dict[str, Any], scan_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for rule in _nested_list(report, "rule_detections"):
        if not isinstance(rule, dict):
            continue
        rule_uuid = rule.get("rule_uuid")
        rule_name = str(rule.get("rule_name") or rule_uuid or "unnamed rule")
        severity = normalise_severity(rule.get("severity"), f"rule {rule_name!r}")
        for detection in rule.get("detections") or []:
            if not isinstance(detection, dict):
                continue
            findings.append(
                Finding(
                    rule_id=f"iac/{rule_uuid}",
                    rule_name=rule_name,
                    severity=severity,
                    file=normalise_path(_optional_str(detection.get("file")), scan_root),
                    line=_optional_int(detection.get("line")),
                    resource_type=_optional_str(detection.get("resource_type")),
                    resource_name=_optional_str(detection.get("resource_name")),
                    description=str(detection.get("reason") or rule.get("description") or ""),
                )
            )
    return findings


def _secret_findings(report: dict[str, Any], scan_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for secret in _nested_list(report, "secrets_analysis", "secrets"):
        if not isinstance(secret, dict):
            continue
        secret_type = str(secret.get("type") or "unknown")
        findings.append(
            Finding(
                rule_id=f"secret/{secret_type}",
                rule_name=f"Hardcoded secret: {secret_type}",
                severity=SECRET_SEVERITY,
                file=normalise_path(
                    _optional_str(secret.get("file_path") or secret.get("file")), scan_root
                ),
                line=_optional_int(secret.get("line_number", secret.get("line"))),
                resource_type=None,
                resource_name=None,
                description=str(secret.get("remediation") or ""),
            )
        )
    return findings


def _policy_violation_findings(report: dict[str, Any], scan_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for violation in _nested_list(report, "policy_violations"):
        if not isinstance(violation, dict):
            continue
        policy_id = str(violation.get("policy_id") or "unknown")
        policy_name = str(violation.get("policy_name") or policy_id)
        findings.append(
            Finding(
                rule_id=f"policy/{policy_id}",
                rule_name=policy_name,
                severity=normalise_severity(violation.get("severity"), f"policy {policy_name!r}"),
                file=normalise_path(_optional_str(violation.get("file")), scan_root),
                line=_optional_int(violation.get("line")),
                resource_type=_optional_str(violation.get("resource_type")),
                resource_name=_optional_str(violation.get("resource_name")),
                description=str(violation.get("description") or ""),
            )
        )
    return findings


def unscanned_file_count(report: dict[str, Any]) -> int:
    """How many files the CLI says it failed to scan (``stats.files_stats.failed_to_scan``).
    Gitignored files it skips by design are ``skipped``, not counted here. A report without
    the statistic counts as zero."""
    stats = report.get("stats")
    files = stats.get("files_stats") if isinstance(stats, dict) else None
    value = files.get("failed_to_scan") if isinstance(files, dict) else None
    count = _optional_int(value)
    return count if count is not None and count > 0 else 0


def findings_from_report(report: dict[str, Any], scan_root: Path) -> list[Finding]:
    return [
        *_rule_detection_findings(report, scan_root),
        *_secret_findings(report, scan_root),
        *_policy_violation_findings(report, scan_root),
    ]
