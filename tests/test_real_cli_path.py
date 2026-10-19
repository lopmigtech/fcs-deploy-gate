"""The real path: token, pinned download, verify, extract, scan (ticket #5), proven through
the run entry point with a fake Falcon API and the fake CLI served as the archive member."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from tests.conftest import FakeClock, GateHarness
from tests.fake_falcon import TOKEN, FakeFalcon, pin_for


def test_missing_credentials_exit_2_before_any_network_call(gate: GateHarness) -> None:
    falcon = FakeFalcon()

    result = gate(fake_binary=False, transport=falcon, pin=pin_for(falcon))

    assert result.exit_code == 2
    assert "FALCON_CLIENT_ID" in result.stderr
    assert falcon.requests == []
    assert result.invocations == []


def test_an_empty_checksum_pin_refuses_to_run_before_any_network_call(gate: GateHarness) -> None:
    falcon = FakeFalcon()

    result = gate.real(falcon, pin=None)  # the code's own pin, which is empty

    assert result.exit_code == 2
    assert "pin" in result.stderr.lower()
    assert falcon.requests == []


def test_the_real_path_downloads_verifies_extracts_and_scans(gate: GateHarness) -> None:
    falcon = FakeFalcon()
    clock = FakeClock()

    result = gate.real(falcon, pin=pin_for(falcon), clock=clock)

    assert result.exit_code == 1, result.stderr
    assert len(result.verdict["blocking_findings"]) == 6
    assert clock.waits == []

    token, info, archive = falcon.requests
    assert token.method == "POST"
    assert token.url == "https://api.laggar.gcw.crowdstrike.com/oauth2/token"
    assert token.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert token.body is not None
    assert parse_qs(token.body.decode()) == {
        "client_id": ["client-id-from-ci"],
        "client_secret": ["s3cret-from-ci"],
    }

    assert info.method == "GET"
    assert urlsplit(info.url).path == "/csdownloads/combined/files-download/v2"
    assert info.headers["Authorization"] == f"Bearer {TOKEN}"
    params = parse_qs(urlsplit(info.url).query)
    assert params["filter"] == ["category:'fcs'+os:'linux'+arch:'amd64'+file_version:'4.2.3'"]
    assert params["sort"] == ["file_version|desc"]

    assert archive.method == "GET"
    assert "amazonaws.com" in archive.url
    assert "Authorization" not in archive.headers  # a pre-signed URL never gets the token

    [invocation] = result.invocations
    argv = invocation["argv"]
    assert argv[:2] == ["scan", "iac"]
    assert argv[argv.index("--falcon-token") + 1] == TOKEN
    assert argv[argv.index("--falcon-region") + 1] == "us-gov-1"
    assert argv[argv.index("--timeout") + 1] == "300"
    assert "--upload-results" in argv
    assert "s3cret-from-ci" not in argv
    assert "client-id-from-ci" not in argv
    assert "FALCON_CLIENT_SECRET" not in invocation["env"]
    assert "FALCON_CLIENT_ID" not in invocation["env"]
    assert not list(result.work_dir.rglob("fcs"))  # no binary is left behind


def test_proxy_variables_reach_the_transport(gate: GateHarness) -> None:
    falcon = FakeFalcon()

    gate.real(
        falcon,
        pin=pin_for(falcon),
        env={"HTTPS_PROXY": "http://proxy.example.gov:3128", "NO_PROXY": "localhost"},
    )

    assert falcon.requests[0].proxy.proxies == {"https": "http://proxy.example.gov:3128"}
    assert falcon.requests[0].proxy.no_proxy == "localhost"
