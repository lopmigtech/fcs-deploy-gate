"""Deciding, from Findings alone, whether a Deployment may proceed (ADR 0001)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from fcs_deploy_gate.config import SEVERITIES, Config
from fcs_deploy_gate.exclusions import (
    ExcludedFinding,
    Exclusion,
    StaleExclusion,
    apply_exclusions,
)
from fcs_deploy_gate.report import Finding


@dataclass(frozen=True)
class Verdict:
    blocking_findings: list[Finding] = field(default_factory=list)
    below_threshold: list[Finding] = field(default_factory=list)
    excluded: list[ExcludedFinding] = field(default_factory=list)
    stale_exclusions: list[StaleExclusion] = field(default_factory=list)
    error: str | None = None
    unscanned_files: int = 0
    block_on_unscanned_files: bool = True
    baseline_ref: str | None = None
    total_findings: int = 0
    new_findings: int = 0

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
    exclusions: list[Exclusion],
    today: date,
    baseline: Iterable[Finding] | None = None,
    baseline_ref: str | None = None,
    unscanned_files: int = 0,
    block_on_unscanned_files: bool = True,
) -> Verdict:
    """Whole-tree when ``baseline`` is None; otherwise Change-aware: only Findings whose
    identity is absent from the Baseline are considered (ADR 0002)."""
    ordered = sorted(findings, key=_ordering)
    if baseline is None:
        considered = ordered
    else:
        known = {finding.identity for finding in baseline}
        considered = [f for f in ordered if f.identity not in known]
    counted, excluded, stale = apply_exclusions(considered, exclusions, today, present=ordered)
    return Verdict(
        blocking_findings=[f for f in counted if f.severity in blocking_threshold],
        below_threshold=[f for f in counted if f.severity not in blocking_threshold],
        excluded=excluded,
        stale_exclusions=stale,
        unscanned_files=unscanned_files,
        block_on_unscanned_files=block_on_unscanned_files,
        baseline_ref=baseline_ref,
        total_findings=len(ordered),
        new_findings=len(considered),
    )


def verdict_document(verdict: Verdict, config: Config) -> dict[str, Any]:
    return {
        "verdict": verdict.outcome,
        "mode": config.mode,
        "scope": config.scope,
        "path": config.scan_path_as_given,
        "baseline_ref": verdict.baseline_ref,
        "total_findings": verdict.total_findings,
        "new_findings": verdict.new_findings,
        "blocking_threshold": config.blocking_threshold_ordered,
        "blocking_findings": [f.to_dict() for f in verdict.blocking_findings],
        "below_threshold": [f.to_dict() for f in verdict.below_threshold],
        "excluded": [
            {"finding": e.finding.to_dict(), "exclusion": e.exclusion.to_dict()}
            for e in verdict.excluded
        ],
        "stale_exclusions": [s.to_dict() for s in verdict.stale_exclusions],
        "unscanned_files": verdict.unscanned_files,
        "block_on_unscanned_files": verdict.block_on_unscanned_files,
        "error": verdict.error,
    }
