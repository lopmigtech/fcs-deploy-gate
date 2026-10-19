"""Command-line arguments and their validation. Every mistake here is exit code 2."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from fcs_deploy_gate.baseline import PIPELINES, BaselineCandidates

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "informational")
DEFAULT_BLOCKING_THRESHOLD: frozenset[str] = frozenset({"critical", "high", "medium"})
REGIONS: tuple[str, ...] = ("us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2")
SCOPES: tuple[str, ...] = ("whole-tree", "change-aware")
MODES: tuple[str, ...] = ("enforcing", "advisory")


class ConfigurationError(Exception):
    """A mistake in how the Gate was invoked. Fails loudly in both modes."""


def ordered_severities(severities: Iterable[str]) -> list[str]:
    """Severities from most to least severe, the order every table and message uses."""
    return sorted(severities, key=SEVERITIES.index)


@dataclass(frozen=True)
class Config:
    scan_path: Path
    scan_path_as_given: str
    region: str
    scope: str
    mode: str
    blocking_threshold: frozenset[str]
    work_dir: Path
    fcs_binary: Path
    block_on_unscanned_files: bool
    baseline_dir: Path | None
    baseline_ref: str | None
    baseline_error: str | None
    project_name: str | None

    @property
    def change_aware(self) -> bool:
        return self.scope == "change-aware"

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforcing"

    @property
    def blocking_threshold_ordered(self) -> list[str]:
        return ordered_severities(self.blocking_threshold)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise ConfigurationError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="fcs-deploy-gate",
        description="A pre-apply Gate that stops Terraform Deployments which would create IOMs.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    _add_run_command(commands)
    _add_resolve_baseline_command(commands)
    return parser


def _add_resolve_baseline_command(commands: argparse._SubParsersAction[_Parser]) -> None:
    parser = commands.add_parser(
        "resolve-baseline",
        help="Turn a pipeline's variables into the Baseline ref, or an error line.",
        description=(
            "Prints 'ref=<ref>' or 'error=<message>' on one line and exits 0 either way; "
            "the adapter passes the result to 'run' (--baseline-ref or --baseline-error)."
        ),
    )
    parser.add_argument("--pipeline", required=True, choices=PIPELINES)
    parser.add_argument("--explicit-ref", default="", help="Ref the Consumer named, if any.")
    parser.add_argument("--merge-base", default="", help="Merge base with the target branch.")
    parser.add_argument("--previous-commit", default="", help="Commit before the push.")


def _add_run_command(commands: argparse._SubParsersAction[_Parser]) -> None:
    parser = commands.add_parser(
        "run",
        help="Scan a Terraform directory and decide whether the Deployment may proceed.",
        description=(
            "Scan a Terraform directory with the CrowdStrike fcs CLI and decide whether "
            "the Deployment may proceed."
        ),
    )
    parser.add_argument("--path", required=True, help="Terraform directory to scan.")
    parser.add_argument("--region", required=True, choices=REGIONS, help="Falcon region.")
    parser.add_argument(
        "--scope",
        default="whole-tree",
        choices=SCOPES,
        help=(
            "whole-tree considers every Finding; change-aware only those absent from the Baseline."
        ),
    )
    parser.add_argument(
        "--baseline-dir",
        default=None,
        help="Change-aware only: directory holding the Consumer's source at the Baseline ref.",
    )
    parser.add_argument(
        "--baseline-ref",
        default=None,
        help="Change-aware only: the Baseline ref, recorded in the Verdict (see resolve-baseline).",
    )
    parser.add_argument(
        "--baseline-error",
        default=None,
        help="Change-aware only: the error line resolve-baseline printed; makes a blocked Verdict.",
    )
    parser.add_argument(
        "--project-name",
        default=None,
        help="Project name for the console upload; defaults to the repository directory name.",
    )
    parser.add_argument("--mode", default="enforcing", choices=MODES, help="Gate mode.")
    parser.add_argument(
        "--blocking-threshold",
        default=",".join(ordered_severities(DEFAULT_BLOCKING_THRESHOLD)),
        help=(
            "Comma-separated severities that block. Must include critical, high and medium; "
            "informational may be added."
        ),
    )
    parser.add_argument(
        "--block-on-unscanned-files",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Block when the report says the CLI failed to scan one or more files (default). "
            "--no-block-on-unscanned-files reports the count without blocking. Files the CLI "
            "skips by design, such as gitignored ones, are not counted."
        ),
    )
    parser.add_argument(
        "--work-dir",
        default="fcs-gate",
        help="Directory for the verdict document, summary and raw report.",
    )
    parser.add_argument(
        "--fcs-binary",
        default=None,
        help="Path to an fcs binary to use instead of downloading the pinned release.",
    )


def parse_blocking_threshold(value: str) -> frozenset[str]:
    severities = {part.strip().lower() for part in value.split(",") if part.strip()}
    unknown = sorted(severities - set(SEVERITIES))
    if unknown:
        raise ConfigurationError(
            f"unknown severity in --blocking-threshold: {', '.join(unknown)} "
            f"(allowed: {', '.join(SEVERITIES)})"
        )
    missing = ordered_severities(DEFAULT_BLOCKING_THRESHOLD - severities)
    if missing:
        raise ConfigurationError(
            f"--blocking-threshold may be tightened but not loosened; missing: {', '.join(missing)}"
        )
    return frozenset(severities)


def _symlink_within(work_dir: Path) -> bool:
    """True when the work directory, or any component of it below the current directory,
    is a symlink. Inside a checkout the current directory is where a Consumer could plant
    one, so every component from there down is checked, whether the path was given as
    relative or absolute. Components above the current directory are the host's own
    (``/tmp`` is a link on some systems), so only the final component is checked there.
    The literal path is walked, never a resolved one, which would hide the links sought.
    """
    if work_dir.is_absolute():
        base = Path.cwd()
        try:
            below = work_dir.relative_to(base)
        except ValueError:
            return work_dir.is_symlink()
    else:
        base, below = Path(), work_dir
    seen = base
    for part in below.parts:
        seen = seen / part
        if seen.is_symlink():
            return True
    return False


def parse_args(argv: Sequence[str]) -> Config | BaselineCandidates:
    namespace = build_parser().parse_args(list(argv))
    if namespace.command == "resolve-baseline":
        return BaselineCandidates(
            pipeline=namespace.pipeline,
            explicit_ref=namespace.explicit_ref,
            merge_base=namespace.merge_base,
            previous_commit=namespace.previous_commit,
        )
    return _run_config(namespace)


def _run_config(namespace: argparse.Namespace) -> Config:
    scan_path = Path(namespace.path)
    if not scan_path.is_dir():
        raise ConfigurationError(f"--path {namespace.path!r} is not a directory")

    if namespace.fcs_binary is None:
        raise ConfigurationError(
            "downloading the pinned fcs CLI is not available yet; pass --fcs-binary"
        )
    # Resolved against the Gate's own working directory before the CLI is launched from the
    # scanned directory, so a relative path can never pick up a binary planted in the checkout.
    fcs_binary = Path(namespace.fcs_binary).resolve()
    if not fcs_binary.is_file():
        raise ConfigurationError(f"--fcs-binary {namespace.fcs_binary!r} is not a file")

    work_dir = Path(namespace.work_dir)
    if _symlink_within(work_dir):
        raise ConfigurationError(
            f"--work-dir {namespace.work_dir!r} is or lies under a symlink; "
            "the Gate will not write through it"
        )

    return Config(
        scan_path=scan_path.resolve(),
        scan_path_as_given=namespace.path,
        region=namespace.region,
        scope=namespace.scope,
        mode=namespace.mode,
        blocking_threshold=parse_blocking_threshold(namespace.blocking_threshold),
        work_dir=work_dir,
        fcs_binary=fcs_binary,
        block_on_unscanned_files=namespace.block_on_unscanned_files,
        baseline_dir=Path(namespace.baseline_dir) if namespace.baseline_dir else None,
        baseline_ref=namespace.baseline_ref or None,
        baseline_error=namespace.baseline_error or None,
        project_name=namespace.project_name or None,
    )
