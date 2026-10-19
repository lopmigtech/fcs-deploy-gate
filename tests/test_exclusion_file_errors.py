"""A malformed Exclusion file is a configuration error in both modes (user story 11)."""

from __future__ import annotations

import pytest

from tests.conftest import GateHarness

GOOD = """\
exclusions:
  - rule: iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35
    resource: aws_s3_bucket.logs
    reason: Recursive logging target.
    expires: 2027-06-30
    approved_by: security-reviewer@example.gov
"""


def without(line_fragment: str) -> str:
    return "".join(line for line in GOOD.splitlines(True) if line_fragment not in line)


CASES = {
    "unknown-key": (GOOD + "    ticket: SEC-123\n", "ticket"),
    "missing-reason": (without("reason:"), "reason"),
    "empty-approved-by": (GOOD.replace("security-reviewer@example.gov", '""'), "approved_by"),
    "missing-expires": (without("expires:"), "expires"),
    "unparseable-date": (GOOD.replace("2027-06-30", "next June"), "expires"),
    "neither-resource-nor-file": (without("resource:"), "resource"),
    "resource-not-type-dot-name": (GOOD.replace("aws_s3_bucket.logs", "logs"), "type.name"),
    "exclusions-not-a-list": ("exclusions: yes\n", "list"),
    "document-not-a-mapping": ("- just\n- a list\n", "mapping"),
    "entry-not-a-mapping": ("exclusions:\n  - just a string\n", "mapping"),
    "unknown-top-level-key": (GOOD + "approvals: []\n", "approvals"),
    "not-yaml": ("exclusions: [\n", "YAML"),
}


@pytest.mark.parametrize("mode", ["enforcing", "advisory"])
@pytest.mark.parametrize(("content", "expected"), CASES.values(), ids=CASES.keys())
def test_malformed_exclusion_file_exits_2_and_names_the_problem(
    gate: GateHarness, mode: str, content: str, expected: str
) -> None:
    gate.write_exclusions(content)

    result = gate("--mode", mode)

    assert result.exit_code == 2
    assert ".fcs-gate.yml" in result.stderr
    assert expected in result.stderr
    assert result.invocations == []


def test_error_message_names_the_entry_by_position_and_rule(gate: GateHarness) -> None:
    gate.write_exclusions(GOOD + GOOD.replace("exclusions:\n", "").replace("reason:", "why:"))

    result = gate()

    assert result.exit_code == 2
    assert "exclusion 2 (iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35)" in result.stderr


def test_empty_file_means_no_exclusions(gate: GateHarness) -> None:
    gate.write_exclusions("# nothing yet\n")

    result = gate()

    assert result.exit_code == 1
    assert result.verdict["excluded"] == []
