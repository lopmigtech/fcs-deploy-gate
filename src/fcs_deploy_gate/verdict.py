"""Deciding, from Findings alone, whether a Deployment may proceed (ADR 0001)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from fcs_deploy_gate.config import SEVERITIES, Config
from fcs_deploy_gate.report import Finding


@dataclass(frozen=True)
class Verdict:
    blocking_findings: list[Finding] = field(default_factory=list)
    below_threshold: list[Finding] = field(default_factory=list)
    error: str | None = None
    unscanned_files: int = 0
    block_on_unscanned_files: bool = True

    @property
    def blocked_by_unscanned_files(self) -> bool:
        return self.block_on_unscanned_files and self.unscanned_files > 0

    @property
    def blocked(self) -> bool:
        return (
            bool(self.blocking_findings)
            or self.error is not None
            or self.blocked_by_unscanned_files
        )

    @property
    def outcome(self) -> str:
        return "blocked" if self.blocked else "clear"


def _ordering(finding: Finding) -> tuple[int, str, int, str, str]:
    return (
        SEVERITIES.index(finding.severity),
        finding.file or "",
        finding.line or 0,
        finding.rule_id,
        finding.resource_name or "",
    )


def decide(
    findings: Iterable[Finding],
    blocking_threshold: frozenset[str],
    *,
    unscanned_files: int = 0,
    block_on_unscanned_files: bool = True,
) -> Verdict:
    ordered = sorted(findings, key=_ordering)
    return Verdict(
        blocking_findings=[f for f in ordered if f.severity in blocking_threshold],
        below_threshold=[f for f in ordered if f.severity not in blocking_threshold],
        unscanned_files=unscanned_files,
        block_on_unscanned_files=block_on_unscanned_files,
    )


def verdict_document(verdict: Verdict, config: Config) -> dict[str, Any]:
    return {
        "verdict": verdict.outcome,
        "mode": config.mode,
        "scope": config.scope,
        "path": config.scan_path_as_given,
        "blocking_threshold": config.blocking_threshold_ordered,
        "blocking_findings": [f.to_dict() for f in verdict.blocking_findings],
        "below_threshold": [f.to_dict() for f in verdict.below_threshold],
        "unscanned_files": verdict.unscanned_files,
        "block_on_unscanned_files": verdict.block_on_unscanned_files,
        "error": verdict.error,
    }
