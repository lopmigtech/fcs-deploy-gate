"""The two Falcon API calls the Gate makes itself: an OAuth2 token and the download info
for the pinned CLI (docs/research/fcs-cli.md sections 8 and 9). The client secret is
read by Gate code only and appears in no message, argument or environment."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from fcs_deploy_gate.http import (
    HttpRequest,
    HttpResponse,
    ProxySettings,
    Transport,
    TransportError,
    safe_url,
)

API_HOSTS: dict[str, str] = {
    "us-1": "api.crowdstrike.com",
    "us-2": "api.us-2.crowdstrike.com",
    "eu-1": "api.eu-1.crowdstrike.com",
    "us-gov-1": "api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "api.us-gov-2.crowdstrike.mil",
}
CLIENT_ID_VAR = "FALCON_CLIENT_ID"
CLIENT_SECRET_VAR = "FALCON_CLIENT_SECRET"
DOWNLOAD_INFO_PATH = "/csdownloads/combined/files-download/v2"


class FalconError(Exception):
    """A Falcon API call failed. The message carries the status and the API's error text."""


@dataclass(frozen=True)
class Credentials:
    client_id: str
    client_secret: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Credentials | None:
        client_id = env.get(CLIENT_ID_VAR, "").strip()
        client_secret = env.get(CLIENT_SECRET_VAR, "").strip()
        if client_id and client_secret:
            return cls(client_id=client_id, client_secret=client_secret)
        return None


@dataclass(frozen=True)
class DownloadResource:
    """One published build of the CLI, as the download API describes it."""

    version: str
    sha256: str
    download_url: str
    file_name: str
    size: int | None

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> DownloadResource:
        info = raw.get("download_info")
        info = info if isinstance(info, dict) else {}
        digest = info.get("file_hash") or raw.get("file_hash")
        size = raw.get("size")
        return cls(
            version=str(raw.get("file_version") or ""),
            sha256=str(digest).lower() if isinstance(digest, str) else "",
            download_url=str(info.get("download_url") or ""),
            file_name=str(raw.get("file_name") or ""),
            size=size if isinstance(size, int) and not isinstance(size, bool) else None,
        )


def api_error_text(response: HttpResponse) -> str:
    payload = _json_payload(response)
    if isinstance(payload, dict):
        messages = [
            str(error.get("message"))
            for error in payload.get("errors", [])
            if isinstance(error, dict) and error.get("message")
        ]
        if messages:
            return "; ".join(messages)
    return response.text()


def _json_payload(response: HttpResponse) -> Any:
    try:
        return json.loads(response.body.decode("utf-8"))
    except ValueError:
        return None


@dataclass(frozen=True)
class FalconApi:
    transport: Transport
    region: str
    proxy: ProxySettings

    @property
    def host(self) -> str:
        return API_HOSTS[self.region]

    def _send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None = None
    ) -> HttpResponse:
        request = HttpRequest(method=method, url=url, headers=headers, body=body, proxy=self.proxy)
        try:
            return self.transport(request)
        except TransportError as exc:
            raise FalconError(f"{method} {safe_url(url)} failed: {exc}") from exc

    def _json_object(
        self, response: HttpResponse, what: str, expected: tuple[int, ...]
    ) -> dict[str, Any]:
        """The JSON object a successful call returns; anything else is a FalconError that
        names the call, the status and the API's error text."""
        if response.status not in expected:
            raise FalconError(
                f"{what} to {self.host} failed with HTTP {response.status}: "
                f"{api_error_text(response)}"
            )
        payload = _json_payload(response)
        if not isinstance(payload, dict):
            raise FalconError(f"{what} to {self.host} returned no JSON object")
        return payload

    def token(self, credentials: Credentials) -> str:
        """A short-lived bearer token (client-credentials grant, 30-minute lifetime)."""
        response = self._send(
            "POST",
            f"https://{self.host}/oauth2/token",
            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            urlencode(
                {"client_id": credentials.client_id, "client_secret": credentials.client_secret}
            ).encode(),
        )
        token = self._json_object(response, "token request", (200, 201)).get("access_token")
        if not isinstance(token, str) or not token:
            raise FalconError(f"token request to {self.host} returned no access_token")
        return token

    def download_info(self, token: str, version: str | None) -> list[DownloadResource]:
        """The published CLI builds for linux/amd64, newest version first, narrowed to
        ``version`` when given."""
        filter_ = "category:'fcs'+os:'linux'+arch:'amd64'"
        if version:
            filter_ += f"+file_version:'{version}'"
        query = urlencode({"filter": filter_, "sort": "file_version|desc", "limit": 100})
        response = self._send(
            "GET",
            f"https://{self.host}{DOWNLOAD_INFO_PATH}?{query}",
            {"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        resources = self._json_object(response, "download-info query", (200,)).get("resources")
        if not isinstance(resources, list):
            raise FalconError(f"download-info query to {self.host} returned no resources list")
        return [DownloadResource.parse(r) for r in resources if isinstance(r, dict)]

    def fetch(self, url: str) -> bytes:
        """The bytes behind a pre-signed download URL. No bearer token: the URL carries its
        own authorisation and the token must not reach a third-party host."""
        response = self._send("GET", url, {})
        if response.status != 200:
            raise FalconError(
                f"archive download from {safe_url(url)} failed with HTTP {response.status}"
            )
        return response.body
