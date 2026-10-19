#!/usr/bin/env python3
"""A stand-in for the CrowdStrike ``fcs`` CLI, driven entirely by environment variables.

It imitates ``fcs scan iac``: it copies the report named by ``FAKE_FCS_REPORT`` to the
path given after ``--output-path``, appends a JSON line describing the invocation
(arguments, environment, working directory) to ``FAKE_FCS_RECORD``, and exits with
``FAKE_FCS_EXIT_CODE`` (default 40, the CLI's "completed with findings" code).
Set ``FAKE_FCS_NO_REPORT=1`` to write nothing, which together with an exit code such
as 201 imitates a CLI failure.

When the Gate scans more than once per run (a Baseline and the change), ``FAKE_FCS_REPORTS``
and ``FAKE_FCS_EXIT_CODES`` give one value per invocation, ``os.pathsep``- and
comma-separated respectively, consumed in order; the invocation index is the number of
lines already in ``FAKE_FCS_RECORD``. The last value repeats when the list runs out.
"""

import json
import os
import shutil
import sys
from pathlib import Path


def output_path(argv: list[str]) -> Path | None:
    for index, argument in enumerate(argv):
        if argument == "--output-path" and index + 1 < len(argv):
            return Path(argv[index + 1])
        if argument.startswith("--output-path="):
            return Path(argument.split("=", 1)[1])
    return None


def nth(values: str, separator: str, index: int) -> str:
    parts = values.split(separator)
    return parts[min(index, len(parts) - 1)]


def main() -> int:
    argv = sys.argv[1:]
    record = os.environ.get("FAKE_FCS_RECORD")
    index = 0
    if record:
        if os.path.exists(record):
            with open(record, encoding="utf-8") as handle:
                index = sum(1 for line in handle if line.strip())
        with open(record, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps({"argv": argv, "env": dict(os.environ), "cwd": os.getcwd()}) + "\n"
            )

    exit_codes = os.environ.get("FAKE_FCS_EXIT_CODES")
    if exit_codes:
        exit_code = int(nth(exit_codes, ",", index))
    else:
        exit_code = int(os.environ.get("FAKE_FCS_EXIT_CODE", "40"))
    if os.environ.get("FAKE_FCS_NO_REPORT") == "1":
        return exit_code

    reports = os.environ.get("FAKE_FCS_REPORTS")
    source = nth(reports, os.pathsep, index) if reports else os.environ.get("FAKE_FCS_REPORT")
    target = output_path(argv)
    if source and target is not None:
        if target.is_dir():
            target = target / "fcs-report.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        print(f"Results saved to file: {target}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
