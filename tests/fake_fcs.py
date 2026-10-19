#!/usr/bin/env python3
"""A stand-in for the CrowdStrike ``fcs`` CLI, driven entirely by environment variables.

It imitates ``fcs scan iac``: it copies a report to the path given after ``--output-path``,
appends a JSON line describing the invocation (arguments, environment, working directory)
to ``FAKE_FCS_RECORD``, and exits with a configurable code (default 40, the CLI's
"completed with findings" code). ``FAKE_FCS_NO_REPORT=1`` makes it write nothing, which
with an exit code such as 201 imitates a CLI failure.

The Gate scans the change with ``--upload-results`` and a Baseline without it, so the fake
tells the two apart by that flag. Change scans use ``FAKE_FCS_REPORT`` and
``FAKE_FCS_EXIT_CODE``; Baseline scans use ``FAKE_FCS_BASELINE_REPORT`` and
``FAKE_FCS_BASELINE_EXIT_CODE``. For retries, ``FAKE_FCS_EXIT_CODES`` and
``FAKE_FCS_BASELINE_EXIT_CODES`` give one comma-separated code per attempt of that kind,
the last repeating; the attempt index is the number of earlier invocations of the same
kind in ``FAKE_FCS_RECORD``.
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


def earlier_invocations_of_kind(record: str, upload: bool) -> int:
    if not os.path.exists(record):
        return 0
    count = 0
    with open(record, encoding="utf-8") as handle:
        for line in handle:
            if line.strip() and (("--upload-results" in json.loads(line)["argv"]) == upload):
                count += 1
    return count


def main() -> int:
    argv = sys.argv[1:]
    upload = "--upload-results" in argv
    prefix = "FAKE_FCS_" if upload else "FAKE_FCS_BASELINE_"
    record = os.environ.get("FAKE_FCS_RECORD")
    index = 0
    if record:
        index = earlier_invocations_of_kind(record, upload)
        with open(record, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps({"argv": argv, "env": dict(os.environ), "cwd": os.getcwd()}) + "\n"
            )

    exit_codes = os.environ.get(prefix + "EXIT_CODES")
    if exit_codes:
        exit_code = int(nth(exit_codes, ",", index))
    else:
        exit_code = int(os.environ.get(prefix + "EXIT_CODE", "40"))
    if os.environ.get("FAKE_FCS_NO_REPORT") == "1":
        return exit_code

    source = os.environ.get(prefix + "REPORT")
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
