"""Exclusions: version-controlled, approved, expiring exemptions declared by a Consumer.

The file lives at the Consumer repository root as ``.fcs-gate.yml``. It changes the
Verdict only: the scan and what is uploaded to the console are untouched, so the CLI's
own exclusion flags are never used (spec: Exclusions).
"""

from __future__ import annotations

import os.path
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from fcs_deploy_gate.config import ConfigurationError
from fcs_deploy_gate.report import Finding

EXCLUSION_FILENAME = ".fcs-gate.yml"
REQUIRED_KEYS: frozenset[str] = frozenset({"rule", "reason", "expires", "approved_by"})
OPTIONAL_KEYS: frozenset[str] = frozenset({"resource", "file"})
KNOWN_KEYS: frozenset[str] = REQUIRED_KEYS | OPTIONAL_KEYS


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
        if self.resource is not None:
            if f"{finding.resource_type}.{finding.resource_name}" != self.resource:
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
    why: str  # "expired" or "unmatched"

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


def _required_text(entry: dict[str, Any], key: str, index: int) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _entry_error(index, entry, f"{key!r} must be a non-empty string")
    return value.strip()


def _optional_text(entry: dict[str, Any], key: str, index: int) -> str | None:
    if key not in entry:
        return None
    value = entry[key]
    if not isinstance(value, str) or not value.strip():
        raise _entry_error(index, entry, f"{key!r} must be a non-empty string when present")
    return value.strip()


def _expiry(entry: dict[str, Any], index: int) -> date:
    value = entry.get("expires")
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise _entry_error(index, entry, f"'expires' must be a date (YYYY-MM-DD), got {value!r}")


def _parse_entry(index: int, entry: object) -> Exclusion:
    if not isinstance(entry, dict):
        raise _entry_error(index, entry, "must be a mapping")
    unknown = sorted(str(key) for key in entry if key not in KNOWN_KEYS)
    if unknown:
        raise _entry_error(index, entry, f"unknown key(s): {', '.join(unknown)}")
    rule = _required_text(entry, "rule", index)
    resource = _optional_text(entry, "resource", index)
    file = _optional_text(entry, "file", index)
    if resource is None and file is None:
        raise _entry_error(index, entry, "at least one of 'resource' or 'file' is required")
    if resource is not None:
        resource_type, _, resource_name = resource.partition(".")
        if not resource_type or not resource_name:
            raise _entry_error(index, entry, f"'resource' must be 'type.name', got {resource!r}")
    if file is not None:
        file = os.path.normpath(file).replace(os.sep, "/")
    return Exclusion(
        rule=rule,
        resource=resource,
        file=file,
        reason=_required_text(entry, "reason", index),
        expires=_expiry(entry, index),
        approved_by=_required_text(entry, "approved_by", index),
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
    findings: list[Finding], exclusions: list[Exclusion], today: date
) -> tuple[list[Finding], list[ExcludedFinding], list[StaleExclusion]]:
    """Split Findings into those that still count and those an active Exclusion covers,
    and list the Exclusions that are stale: expired, or matching nothing in this scan."""
    counted: list[Finding] = []
    excluded: list[ExcludedFinding] = []
    matched: set[int] = set()
    active = [(i, e) for i, e in enumerate(exclusions) if e.active_on(today)]
    for finding in findings:
        cover = next(((i, e) for i, e in active if e.matches(finding)), None)
        if cover is None:
            counted.append(finding)
        else:
            matched.add(cover[0])
            excluded.append(ExcludedFinding(finding=finding, exclusion=cover[1]))
    stale: list[StaleExclusion] = []
    for index, exclusion in enumerate(exclusions):
        if not exclusion.active_on(today):
            stale.append(StaleExclusion(exclusion=exclusion, why="expired"))
        elif index not in matched:
            stale.append(StaleExclusion(exclusion=exclusion, why="unmatched"))
    return counted, excluded, stale
