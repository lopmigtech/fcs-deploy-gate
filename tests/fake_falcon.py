"""A fake Falcon API behind the Gate's HTTP transport seam: OAuth2 token, download info
and the pre-signed archive download, with every request recorded.

The archive it serves contains the fake CLI script as its ``fcs`` member, so the Gate's
real path (token, pinned download, verify, extract, scan) runs end to end offline.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fcs_deploy_gate.http import HttpRequest, HttpResponse, TransportError
from tests.conftest import FAKE_FCS

VERSION = "4.2.3"
TOKEN = "tok-0123456789abcdef"
DOWNLOAD_URL = (
    "https://fcs-downloads.s3.amazonaws.com/fcs_4.2.3_linux_amd64.tar.gz?X-Amz-Signature=abc"
)


def tar_gz_archive(member: str = "fcs", content: bytes | None = None) -> bytes:
    content = FAKE_FCS.read_bytes() if content is None else content
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name=member)
        info.size = len(content)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def zip_archive(member: str = "fcs", content: bytes | None = None) -> bytes:
    content = FAKE_FCS.read_bytes() if content is None else content
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        archive.writestr(member, content)
    return buffer.getvalue()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(status: int, payload: Any) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers={"Content-Type": "application/json"},
        body=json.dumps(payload).encode(),
    )


@dataclass
class FakeFalcon:
    archive: bytes = field(default_factory=tar_gz_archive)
    file_name: str = "fcs_4.2.3_linux_amd64.tar.gz"
    version: str = VERSION
    token: str = TOKEN
    reported_hash: str | None = None  # defaults to the archive's real SHA-256
    resources: list[dict[str, Any]] | None = None  # overrides the download-info resources
    token_failures: list[HttpResponse | Exception] = field(default_factory=list)
    info_failures: list[HttpResponse | Exception] = field(default_factory=list)
    archive_failures: list[HttpResponse | Exception] = field(default_factory=list)
    requests: list[HttpRequest] = field(default_factory=list)

    @property
    def archive_hash(self) -> str:
        return self.reported_hash or sha256(self.archive)

    def resource(self) -> dict[str, Any]:
        return {
            "arch": "amd64",
            "category": "fcs",
            "download_info": {
                "download_url": DOWNLOAD_URL,
                "expires_at": "2026-10-19T23:59:59Z",
                "file_hash": self.archive_hash,
            },
            "file_hash": self.archive_hash,
            "file_name": self.file_name,
            "file_type": "archive",
            "file_version": self.version,
            "os": "linux",
            "size": len(self.archive),
        }

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        parts = urlsplit(request.url)
        if parts.path == "/oauth2/token":
            return self._fail_or(self.token_failures, self._token_response(request))
        if parts.path == "/csdownloads/combined/files-download/v2":
            return self._fail_or(self.info_failures, self._info_response(request, parts.query))
        if request.url == DOWNLOAD_URL:
            return self._fail_or(
                self.archive_failures,
                HttpResponse(
                    status=200, headers={"Content-Type": "binary/octet-stream"}, body=self.archive
                ),
            )
        return _json(404, {"errors": [{"code": 404, "message": f"no route for {request.url}"}]})

    @staticmethod
    def _fail_or(failures: list[HttpResponse | Exception], success: HttpResponse) -> HttpResponse:
        if failures:
            failure = failures.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return failure
        return success

    def _token_response(self, request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return _json(405, {"errors": [{"code": 405, "message": "method not allowed"}]})
        form = parse_qs((request.body or b"").decode())
        if form.get("client_id") != ["client-id-from-ci"] or form.get("client_secret") != [
            "s3cret-from-ci"
        ]:
            return _json(
                401, {"errors": [{"code": 401, "message": "access denied, invalid client"}]}
            )
        return _json(201, {"access_token": self.token, "expires_in": 1799, "token_type": "bearer"})

    def _info_response(self, request: HttpRequest, query: str) -> HttpResponse:
        if request.headers.get("Authorization") != f"Bearer {self.token}":
            return _json(
                401, {"errors": [{"code": 401, "message": "access denied, invalid bearer token"}]}
            )
        params = parse_qs(query)
        if self.resources is not None:
            resources = self.resources
        else:
            wanted = f"file_version:'{self.version}'"
            resources = [self.resource()] if wanted in params.get("filter", [""])[0] else []
        return _json(200, {"meta": {"query_time": 0.01}, "resources": resources, "errors": []})


def http_error(status: int, message: str) -> HttpResponse:
    return _json(status, {"errors": [{"code": status, "message": message}]})


def connection_refused() -> TransportError:
    return TransportError("connection refused")


def pin_for(falcon: FakeFalcon) -> Any:
    from fcs_deploy_gate.download import CliPin

    return CliPin(version=falcon.version, sha256=sha256(falcon.archive))


CREDENTIALS = {"FALCON_CLIENT_ID": "client-id-from-ci", "FALCON_CLIENT_SECRET": "s3cret-from-ci"}
