"""What the fcs CLI receives from the Gate, proven by the fake's recorded invocation."""

from __future__ import annotations

from tests.conftest import GateHarness

CREDENTIALS = {
    "FALCON_CLIENT_ID": "client-id-from-ci",
    "FALCON_CLIENT_SECRET": "s3cret-from-ci",
    "FCS_CLIENT_ID": "fcs-client-id",
    "FCS_CLIENT_SECRET": "fcs-s3cret",
}


def test_cli_is_launched_once_from_the_scanned_directory(gate: GateHarness) -> None:
    result = gate()

    assert len(result.invocations) == 1
    assert result.invocations[0]["cwd"] == str(gate.scan_root)


def test_cli_never_receives_falcon_credentials(gate: GateHarness) -> None:
    result = gate(env=CREDENTIALS)

    [invocation] = result.invocations
    for name in CREDENTIALS:
        assert name not in invocation["env"]
    for value in CREDENTIALS.values():
        assert value not in invocation["argv"]
        assert value not in invocation["env"].values()


def test_cli_arguments_pin_fail_on_region_and_json_report(gate: GateHarness) -> None:
    result = gate()

    [invocation] = result.invocations
    argv = invocation["argv"]
    assert argv[:2] == ["scan", "iac"]
    assert argv[argv.index("--falcon-region") + 1] == "us-gov-1"
    assert argv[argv.index("--fail-on") + 1] == "critical=1,high=1,medium=1,informational=1"
    assert argv[argv.index("--report-formats") + 1] == "json"
    assert argv[argv.index("--output-path") + 1] == str(result.work_dir / "fcs-report.json")
    assert (result.work_dir / "fcs-report.json").is_file()
