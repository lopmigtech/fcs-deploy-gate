"""Resolving which commit the Baseline is (ADR 0002): one function the adapters feed
with their platform's variables, so the precedence lives in the core and not in YAML."""

from __future__ import annotations

from typing import TextIO

from fcs_deploy_gate.config import ConfigurationError, ResolveBaselineCommand

ALL_ZEROS = "0" * 40
EXPLICIT_REF_HINT = "pass an explicit Baseline ref to the Gate"


class BaselineError(Exception):
    """No usable Baseline. In Change-aware Scope this is a blocked Verdict, never a clear one."""


def usable(value: str) -> bool:
    value = value.strip()
    return bool(value) and value != ALL_ZEROS


def well_formed(candidates: ResolveBaselineCommand) -> None:
    """A candidate with whitespace or control characters is not a ref git could name, and
    would break the one-line KEY=VALUE output: a configuration error, not a Baseline error."""
    for name, value in (
        ("explicit-ref", candidates.explicit_ref),
        ("merge-base", candidates.merge_base),
        ("previous-commit", candidates.previous_commit),
    ):
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value.strip()):
            raise ConfigurationError(
                f"--{name} contains whitespace or control characters: {value!r}"
            )


def resolve_baseline(candidates: ResolveBaselineCommand) -> str:
    """The Baseline ref: the explicit one when usable; otherwise the merge base in a
    merge-request pipeline or the previous commit in a branch pipeline. Empty and
    all-zeros values (a first push, a missing variable) are unusable."""
    if usable(candidates.explicit_ref):
        return candidates.explicit_ref.strip()
    if candidates.pipeline == "merge-request":
        if usable(candidates.merge_base):
            return candidates.merge_base.strip()
        raise BaselineError(
            "no usable Baseline: the merge base is "
            f"{_describe(candidates.merge_base)} in this merge-request pipeline; "
            f"{EXPLICIT_REF_HINT}"
        )
    if usable(candidates.previous_commit):
        return candidates.previous_commit.strip()
    raise BaselineError(
        "no usable Baseline: the previous commit is "
        f"{_describe(candidates.previous_commit)} in this branch pipeline "
        f"(a first push to a branch has none); {EXPLICIT_REF_HINT}"
    )


def _describe(value: str) -> str:
    return "all zeros" if value.strip() == ALL_ZEROS else "empty"


def resolve_baseline_command(candidates: ResolveBaselineCommand, stdout: TextIO) -> int:
    """One line of KEY=VALUE either way, so an adapter can append it to its outputs file
    and hand the result to ``run`` without any logic of its own (ADR 0004)."""
    well_formed(candidates)
    try:
        stdout.write(f"ref={resolve_baseline(candidates)}\n")
    except BaselineError as exc:
        stdout.write(f"error={exc}\n")
    return 0
