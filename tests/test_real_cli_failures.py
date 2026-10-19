"""Everything the real path refuses to trust, and how it retries (ticket #5, ADR 0001)."""

from __future__ import annotations

import io
from pathlib import Path

from fcs_deploy_gate import run
from tests.conftest import FakeClock, GateHarness, GateRun
from tests.fake_falcon import (
    CREDENTIALS,
    FakeFalcon,
    connection_refused,
    http_error,
    pin_for,
    sha256,
    tar_gz_archive,
    zip_archive,
)


def real(
    gate: GateHarness,
    falcon: FakeFalcon,
    clock: FakeClock | None = None,
    env: dict[str, str] | None = None,
) -> GateRun:
    return gate.real(falcon, pin=pin_for(falcon), clock=clock, env=env)


# ---- token ----


def test_token_failure_blocks_with_status_and_api_text_but_never_the_secret(
    gate: GateHarness,
) -> None:
    falcon = FakeFalcon(token_failures=[http_error(403, "access denied, scope missing")] * 3)
    clock = FakeClock()

    result = real(gate, falcon, clock)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert "HTTP 403" in result.verdict["error"]
    assert "scope missing" in result.verdict["error"]
    assert "api.laggar.gcw.crowdstrike.com" in result.verdict["error"]
    for text in (result.verdict["error"], result.summary, result.stderr, result.stdout):
        assert "s3cret-from-ci" not in text
    assert clock.waits == [10.0, 30.0]
    assert result.invocations == []


def test_a_transient_token_outage_is_retried_then_succeeds(gate: GateHarness) -> None:
    falcon = FakeFalcon(token_failures=[http_error(503, "try later"), connection_refused()])
    clock = FakeClock()

    result = real(gate, falcon, clock)

    assert result.verdict["error"] is None
    assert clock.waits == [10.0, 30.0]
    assert len(result.invocations) == 1


# ---- download info ----


def test_no_resource_for_the_pinned_version_is_an_error(gate: GateHarness) -> None:
    falcon = FakeFalcon(resources=[])

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "4.2.3" in result.verdict["error"]
    assert not any("amazonaws" in r.url for r in falcon.requests)


def test_a_different_version_than_the_pin_is_an_error(gate: GateHarness) -> None:
    falcon = FakeFalcon()
    other = falcon.resource()
    other["file_version"] = "4.3.0"
    falcon.resources = [other]

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "4.2.3" in result.verdict["error"] and "4.3.0" in result.verdict["error"]
    assert not any("amazonaws" in r.url for r in falcon.requests)


def test_a_reported_hash_that_differs_from_the_pin_stops_before_downloading(
    gate: GateHarness,
) -> None:
    falcon = FakeFalcon(reported_hash="f" * 64)

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "refusing to download" in result.verdict["error"]
    assert not any("amazonaws" in r.url for r in falcon.requests)
    assert not list(result.work_dir.rglob("fcs"))


def test_downloaded_bytes_whose_hash_differs_from_the_pin_are_rejected(
    gate: GateHarness,
) -> None:
    falcon = FakeFalcon()
    pin = pin_for(falcon)
    falcon.archive = tar_gz_archive(content=b"#!/bin/sh\nexit 0\n")  # swapped after the pin

    result = gate.real(falcon, pin=pin)

    assert result.exit_code == 1
    assert "SHA-256" in result.verdict["error"]
    assert result.invocations == []
    assert not list(result.work_dir.rglob("fcs"))


def test_a_zip_archive_is_handled(gate: GateHarness) -> None:
    falcon = FakeFalcon(archive=zip_archive(), file_name="fcs_4.2.3_linux_amd64.zip")

    result = real(gate, falcon)

    assert result.verdict["error"] is None
    assert len(result.invocations) == 1


def test_an_archive_without_an_fcs_member_is_an_error_and_leaves_nothing_behind(
    gate: GateHarness,
) -> None:
    falcon = FakeFalcon(archive=tar_gz_archive(member="README.md", content=b"hello"))

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "no member named fcs" in result.verdict["error"]
    assert not list(result.work_dir.rglob("fcs"))
    assert result.invocations == []


def test_a_corrupt_archive_is_an_error_and_leaves_nothing_behind(gate: GateHarness) -> None:
    falcon = FakeFalcon(archive=b"\x1f\x8b\x08\x00garbage-not-a-tar")

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "cannot be read" in result.verdict["error"]
    assert not list(result.work_dir.rglob("fcs"))


def test_only_the_fcs_member_is_extracted(gate: GateHarness, tmp_path: Path) -> None:
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in (
            ("LICENSE", b"text"),
            ("fcs", Path("tests/fake_fcs.py").read_bytes()),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    falcon = FakeFalcon(archive=buffer.getvalue())

    result = real(gate, falcon)

    assert result.verdict["error"] is None
    assert not list(result.work_dir.rglob("LICENSE"))


def test_download_is_retried_three_times_with_waits_of_ten_and_thirty_seconds(
    gate: GateHarness,
) -> None:
    falcon = FakeFalcon(info_failures=[http_error(502, "bad gateway"), connection_refused()])
    clock = FakeClock()

    result = real(gate, falcon, clock)

    assert result.verdict["error"] is None
    assert clock.waits == [10.0, 30.0]


def test_exhausting_download_attempts_blocks_with_the_last_error(gate: GateHarness) -> None:
    falcon = FakeFalcon(
        archive_failures=[http_error(500, "one"), http_error(500, "two"), http_error(500, "three")]
    )
    clock = FakeClock()

    result = real(gate, falcon, clock)

    assert result.exit_code == 1
    assert "3 attempts" in result.verdict["error"]
    assert "HTTP 500" in result.verdict["error"]
    assert clock.waits == [10.0, 30.0]


# ---- scans ----


def test_a_failing_scan_is_retried_and_a_later_success_counts(gate: GateHarness) -> None:
    falcon = FakeFalcon()
    clock = FakeClock()

    result = real(gate, falcon, clock, env={"FAKE_FCS_EXIT_CODES": "201,201,40"})

    assert result.exit_code == 1
    assert result.verdict["error"] is None
    assert len(result.verdict["blocking_findings"]) == 6
    assert len(result.invocations) == 3
    assert clock.waits == [10.0, 30.0]


def test_a_scan_that_keeps_failing_blocks_with_the_last_error(gate: GateHarness) -> None:
    clock = FakeClock()

    result = gate(exit_code=201, no_report=True, clock=clock)

    assert result.exit_code == 1
    assert "3 attempts" in result.verdict["error"]
    assert "201" in result.verdict["error"]
    assert len(result.invocations) == 3
    assert clock.waits == [10.0, 30.0]


def test_both_scans_are_retried_in_change_aware_scope(gate: GateHarness) -> None:
    clock = FakeClock()

    result = gate(
        baseline_report="baseline.json",
        clock=clock,
        env={"FAKE_FCS_BASELINE_EXIT_CODES": "201,40", "FAKE_FCS_EXIT_CODES": "201,40"},
    )

    assert result.verdict["error"] is None
    assert len(result.invocations) == 4
    assert clock.waits == [10.0, 10.0]


def test_a_report_without_cloud_rules_evidence_is_a_scan_error(
    gate: GateHarness, tmp_path: Path
) -> None:
    import json

    from tests.conftest import FIXTURE_REPORTS

    report = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    report["stats"]["rule_stats"] = {"total_rules": 0, "rules_enabled": 0}
    path = tmp_path / "local-rules.json"
    path.write_text(json.dumps(report))
    clock = FakeClock()

    result = gate(report=path, clock=clock)

    assert result.exit_code == 1
    assert "cloud rules" in result.verdict["error"]
    assert result.verdict["blocking_findings"] == []
    assert len(result.invocations) == 3


# ---- pin ----


def pin_command(
    falcon: FakeFalcon, *args: str, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["pin", "--region", "us-gov-1", *args],
        env=CREDENTIALS if env is None else env,
        stdout=stdout,
        stderr=stderr,
        transport=falcon,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_pin_prints_the_published_version_and_hash(gate: GateHarness) -> None:
    falcon = FakeFalcon()

    code, out, _ = pin_command(falcon)

    assert code == 0
    assert "version=4.2.3\n" in out
    assert f"sha256={sha256(falcon.archive)}\n" in out
    assert "file_name=fcs_4.2.3_linux_amd64.tar.gz\n" in out
    assert not any("amazonaws" in r.url for r in falcon.requests)  # info only, no download


def test_pin_accepts_a_version_override(gate: GateHarness) -> None:
    falcon = FakeFalcon(version="4.3.0")

    code, out, _ = pin_command(falcon, "--version", "4.3.0")

    assert code == 0
    assert "version=4.3.0\n" in out


def test_pin_without_credentials_exits_2(gate: GateHarness) -> None:
    falcon = FakeFalcon()

    code, out, err = pin_command(falcon, env={})

    assert code == 2
    assert "FALCON_CLIENT_ID" in err
    assert falcon.requests == []


def test_pin_reports_api_errors(gate: GateHarness) -> None:
    falcon = FakeFalcon(token_failures=[http_error(401, "invalid client")])

    code, out, err = pin_command(falcon)

    assert code == 1
    assert "HTTP 401" in err and "invalid client" in err


# ---- review findings ----


def test_a_non_object_json_body_is_an_error_not_a_crash(gate: GateHarness) -> None:
    from fcs_deploy_gate.http import HttpResponse

    array_body = HttpResponse(status=200, headers={}, body=b"[]")
    falcon = FakeFalcon(token_failures=[array_body] * 3)

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert result.verdict["verdict"] == "blocked"
    assert "token" in result.verdict["error"].lower()
    assert result.summary_text is not None


def test_a_zip_archive_is_recognised_without_its_suffix(gate: GateHarness) -> None:
    falcon = FakeFalcon(archive=zip_archive(), file_name="fcs-linux-amd64")

    result = real(gate, falcon)

    assert result.verdict["error"] is None
    assert len(result.invocations) == 1


def test_a_nested_member_is_not_the_fcs_binary(gate: GateHarness) -> None:
    falcon = FakeFalcon(archive=tar_gz_archive(member="bin/fcs"))

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "no member named fcs" in result.verdict["error"]


def test_zero_enabled_rules_is_not_evidence_even_with_a_total(
    gate: GateHarness, tmp_path: Path
) -> None:
    import json

    from tests.conftest import FIXTURE_REPORTS

    report = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    report["stats"]["rule_stats"] = {"total_rules": 1850, "rules_enabled": 0}
    path = tmp_path / "zero-enabled.json"
    path.write_text(json.dumps(report))

    result = gate(report=path)

    assert result.exit_code == 1
    assert "cloud rules" in result.verdict["error"]


def test_the_fetching_custom_rules_line_is_recorded_but_never_sufficient_alone(
    gate: GateHarness, tmp_path: Path
) -> None:
    import json

    from tests.conftest import FIXTURE_REPORTS

    report = json.loads((FIXTURE_REPORTS / "findings.json").read_text())
    del report["stats"]["rule_stats"]
    path = tmp_path / "no-rule-stats.json"
    path.write_text(json.dumps(report))

    stats_missing = gate(report=path, env={"FAKE_FCS_SAY_FETCHING_RULES": "1"})
    stats_present = gate(env={"FAKE_FCS_SAY_FETCHING_RULES": "1"})

    assert "cloud rules" in stats_missing.verdict["error"]  # CLI output can echo scanned text
    assert stats_present.verdict["cloud_rules_evidence"] == {
        "rules_enabled": 1850,
        "total_rules": 1850,
        "custom_rules_fetched": True,
    }


def test_the_verdict_records_the_rule_statistics_seen(gate: GateHarness) -> None:
    result = gate()

    assert result.verdict["cloud_rules_evidence"] == {
        "rules_enabled": 1850,
        "total_rules": 1850,
        "custom_rules_fetched": False,
    }


def test_a_transport_failure_never_leaks_the_signed_url(gate: GateHarness) -> None:
    falcon = FakeFalcon(archive_failures=[connection_refused()] * 3)

    result = real(gate, falcon)

    assert result.exit_code == 1
    assert "X-Amz-Signature" not in result.verdict["error"]
    assert "X-Amz-Signature" not in result.summary
    assert "fcs-downloads.s3.amazonaws.com" in result.verdict["error"]


def test_the_token_is_redacted_from_cli_output_in_messages(gate: GateHarness) -> None:
    from tests.fake_falcon import TOKEN

    falcon = FakeFalcon()

    result = real(gate, falcon, env={"FAKE_FCS_EXIT_CODES": "201", "FAKE_FCS_ECHO_ARGV": "1"})

    assert result.exit_code == 1
    assert "CLI stderr" in result.verdict["error"]
    assert TOKEN not in result.verdict["error"]
    assert TOKEN not in result.summary
    assert "<redacted>" in result.verdict["error"]


def test_the_baseline_scan_also_receives_the_token_and_no_upload(gate: GateHarness) -> None:
    from tests.fake_falcon import TOKEN

    falcon = FakeFalcon()

    result = gate.real(falcon, pin=pin_for(falcon), baseline_report="baseline.json")

    baseline, change = result.invocations
    assert baseline["argv"][baseline["argv"].index("--falcon-token") + 1] == TOKEN
    assert "--upload-results" not in baseline["argv"]
    assert change["argv"][change["argv"].index("--falcon-token") + 1] == TOKEN
