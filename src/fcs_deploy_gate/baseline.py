"""Resolving which commit the Baseline is (ADR 0002): one function the adapters feed
with their platform's variables, so the precedence lives in the core and not in YAML."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PIPELINES: tuple[str, ...] = ("merge-request", "branch")
PipelineType = Literal["merge-request", "branch"]
ALL_ZEROS = "0" * 40
EXPLICIT_REF_HINT = "pass an explicit Baseline ref to the Gate"


class BaselineError(Exception):
    """No usable Baseline. In Change-aware Scope this is a blocked Verdict, never a pass."""


@dataclass(frozen=True)
class BaselineCandidates:
    pipeline: PipelineType
    explicit_ref: str = ""
    merge_base: str = ""
    previous_commit: str = ""


def usable(value: str) -> bool:
    value = value.strip()
    return bool(value) and value != ALL_ZEROS


def resolve_baseline(candidates: BaselineCandidates) -> str:
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
