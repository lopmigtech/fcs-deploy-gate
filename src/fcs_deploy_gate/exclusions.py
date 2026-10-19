"""Exclusions: version-controlled, approved, expiring exemptions declared by a Consumer.

The file lives at the Consumer repository root as ``.fcs-gate.yml``. It changes the
Verdict only: the scan and what is uploaded to the console are untouched, so the CLI's
own exclusion flags are never used (spec: Exclusions).
"""

from __future__ import annotations

import os.path
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal

import yaml

from fcs_deploy_gate.config import ConfigurationError
from fcs_deploy_gate.report import Finding

EXCLUSION_FILENAME = ".fcs-gate.yml"
REQUIRED_KEYS: frozenset[str] = frozenset({"rule", "reason", "expires", "approved_by"})
OPTIONAL_KEYS: frozenset[str] = frozenset({"resource", "file"})
KNOWN_KEYS: frozenset[str] = REQUIRED_KEYS | OPTIONAL_KEYS
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

StaleReason = Literal["expired", "unmatched"]
Fail = Callable[[str], ConfigurationError]


@dataclass(frozen=True)
class Exclusion:
    rule: str
    resource: str | None
    file: str | None
    reason: str
    expires: date
    approved_by: str

    def matches(self, finding: Finding) -> bool:
        """True only when every field the entry names matches the Finding."""
        if finding.rule_id != self.rule:
            return False
        if self.resource is not None and finding.resource_address != self.resource:
            return False
        if self.file is not None and finding.file != self.file:
            return False
        return True

    def active_on(self, today: date) -> bool:
        return self.expires >= today

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "resource": self.resource,
            "file": self.file,
            "reason": self.reason,
            "expires": self.expires.isoformat(),
            "approved_by": self.approved_by,
        }


@dataclass(frozen=True)
class ExcludedFinding:
    finding: Finding
    exclusion: Exclusion


@dataclass(frozen=True)
class StaleExclusion:
    exclusion: Exclusion
    why: StaleReason

    def to_dict(self) -> dict[str, Any]:
        return {**self.exclusion.to_dict(), "why": self.why}


def repository_root(scan_path: Path) -> Path:
    """The Consumer repository root: the scanned path's nearest ancestor (or itself) that
    holds ``.git``; the scanned path when there is none."""
    for candidate in (scan_path, *scan_path.parents):
        if (candidate / ".git").exists():
            return candidate
    return scan_path


def _entry_error(index: int, entry: object, problem: str) -> ConfigurationError:
    label = f"exclusion {index + 1}"
    if isinstance(entry, dict) and isinstance(entry.get("rule"), str) and entry["rule"]:
        label += f" ({entry['rule']})"
    return ConfigurationError(f"{EXCLUSION_FILENAME}: {label}: {problem}")


def _text(entry: dict[str, Any], key: str, fail: Fail, *, required: bool) -> str | None:
    if key not in entry and not required:
        return None
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        when = "" if required else " when present"
        raise fail(f"{key!r} must be a non-empty string{when}")
    return value.strip()


def _expiry(value: object, fail: Fail) -> date:
    """A YAML date or an ISO ``YYYY-MM-DD`` string, nothing else: a timestamp would be
    truncated to some local day, and that is not what an approver wrote down."""
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str) and ISO_DATE.match(value.strip()):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise fail(f"'expires' must be a date (YYYY-MM-DD), got {value!r}")


def _parse_entry(index: int, entry: object) -> Exclusion:
    def fail(problem: str) -> ConfigurationError:
        return _entry_error(index, entry, problem)

    if not isinstance(entry, dict):
        raise fail("must be a mapping")
    unknown = sorted(str(key) for key in entry if key not in KNOWN_KEYS)
    if unknown:
        raise fail(f"unknown key(s): {', '.join(unknown)}")
    rule = _text(entry, "rule", fail, required=True)
    resource = _text(entry, "resource", fail, required=False)
    file = _text(entry, "file", fail, required=False)
    if resource is None and file is None:
        raise fail("at least one of 'resource' or 'file' is required")
    if resource is not None:
        resource_type, _, resource_name = resource.partition(".")
        if not resource_type or not resource_name:
            raise fail(f"'resource' must be 'type.name', got {resource!r}")
    if file is not None:
        file = os.path.normpath(file).replace(os.sep, "/")
    assert rule is not None
    reason = _text(entry, "reason", fail, required=True)
    approved_by = _text(entry, "approved_by", fail, required=True)
    assert reason is not None and approved_by is not None
    return Exclusion(
        rule=rule,
        resource=resource,
        file=file,
        reason=reason,
        expires=_expiry(entry.get("expires"), fail),
        approved_by=approved_by,
    )


def load_exclusions(path: Path) -> list[Exclusion]:
    """The Exclusions declared in ``path``; none when the file does not exist.
    Any malformation is a ConfigurationError that names the entry."""
    if not path.is_file():
        return []
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"{EXCLUSION_FILENAME}: cannot be read as YAML: {exc}") from exc
    if document is None:
        return []
    if not isinstance(document, dict):
        raise ConfigurationError(f"{EXCLUSION_FILENAME}: the document must be a mapping")
    unknown = sorted(str(key) for key in document if key != "exclusions")
    if unknown:
        raise ConfigurationError(
            f"{EXCLUSION_FILENAME}: unknown top-level key(s): {', '.join(unknown)}"
        )
    entries = document.get("exclusions")
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ConfigurationError(f"{EXCLUSION_FILENAME}: 'exclusions' must be a list")
    return [_parse_entry(index, entry) for index, entry in enumerate(entries)]


def apply_exclusions(
    findings: list[Finding],
    exclusions: list[Exclusion],
    today: date,
    *,
    present: list[Finding],
) -> tuple[list[Finding], list[ExcludedFinding], list[StaleExclusion]]:
    """Split the considered Findings into those that still count and those an active
    Exclusion covers (the first matching entry in file order), and list the Stale
    exclusions: expired ones, and active ones that match no Finding ``present`` in the
    scan at all. ``present`` is every Finding of the change, so in Change-aware Scope an
    entry covering a pre-existing Finding is not reported stale."""
    active = [exclusion for exclusion in exclusions if exclusion.active_on(today)]
    counted: list[Finding] = []
    excluded: list[ExcludedFinding] = []
    for finding in findings:
        covering = next((e for e in active if e.matches(finding)), None)
        if covering is None:
            counted.append(finding)
        else:
            excluded.append(ExcludedFinding(finding=finding, exclusion=covering))
    stale: list[StaleExclusion] = []
    for exclusion in exclusions:
        if not exclusion.active_on(today):
            stale.append(StaleExclusion(exclusion=exclusion, why="expired"))
        elif not any(exclusion.matches(finding) for finding in present):
            stale.append(StaleExclusion(exclusion=exclusion, why="unmatched"))
    return counted, excluded, stale
