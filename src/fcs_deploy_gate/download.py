"""The pinned CLI: resolve the pinned version through the download API, verify the archive
against the pin and the hash the API reports, and extract the one binary (ADR 0003)."""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fcs_deploy_gate.falcon import FalconApi

BINARY_NAME = "fcs"


@dataclass(frozen=True)
class CliPin:
    """The fcs CLI version the Gate runs and the SHA-256 of its linux/amd64 archive.
    Bumped by pull request, with a note on rule and severity changes (ADR 0003)."""

    version: str
    sha256: str

    @property
    def filled(self) -> bool:
        return bool(self.sha256.strip())


# The SHA-256 is filled from the work environment with `fcs-deploy-gate pin`; the Gate
# refuses to download while it is empty.
PIN = CliPin(version="4.2.3", sha256="")


class DownloadError(Exception):
    """The pinned CLI could not be obtained and verified."""


def select_resource(resources: list[dict[str, Any]], version: str) -> dict[str, Any]:
    for resource in resources:
        if resource.get("file_version") == version:
            return resource
    listed = ", ".join(sorted({str(r.get("file_version")) for r in resources})) or "nothing"
    raise DownloadError(
        f"the download API lists no fcs {version} for linux/amd64 (it lists: {listed})"
    )


def reported_hash(resource: dict[str, Any]) -> str:
    info = resource.get("download_info")
    value = (info.get("file_hash") if isinstance(info, dict) else None) or resource.get("file_hash")
    if not isinstance(value, str) or not value:
        raise DownloadError("the download API reported no file hash for the pinned fcs")
    return value.lower()


def install_cli(api: FalconApi, token: str, pin: CliPin, into: Path) -> Path:
    """Download, verify and extract the pinned CLI into ``into``; the path of the binary."""
    resource = select_resource(api.download_info(token, pin.version), pin.version)
    reported = reported_hash(resource)
    if reported != pin.sha256.lower():
        raise DownloadError(
            f"the download API reports SHA-256 {reported} for fcs {pin.version} but the pin "
            f"is {pin.sha256.lower()}; refusing to download"
        )
    info = resource.get("download_info")
    url = info.get("download_url") if isinstance(info, dict) else None
    if not isinstance(url, str) or not url:
        raise DownloadError("the download API reported no download URL for the pinned fcs")
    data = api.fetch(url)
    actual = hashlib.sha256(data).hexdigest()
    if actual != pin.sha256.lower():
        raise DownloadError(
            f"the downloaded archive has SHA-256 {actual}, not the pinned {pin.sha256.lower()}"
        )
    return extract_binary(data, str(resource.get("file_name") or ""), into)


def _member_from_tar(data: bytes) -> bytes | None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            if member.isfile() and os.path.basename(member.name) == BINARY_NAME:
                extracted = archive.extractfile(member)
                return extracted.read() if extracted is not None else None
    return None


def _member_from_zip(data: bytes) -> bytes | None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            if not member.is_dir() and os.path.basename(member.filename) == BINARY_NAME:
                return archive.read(member)
    return None


def extract_binary(data: bytes, file_name: str, into: Path) -> Path:
    """Write only the archive member named ``fcs`` to ``into``, executable. A corrupt
    archive or one without that member is an error, and nothing is written."""
    is_zip = file_name.endswith(".zip") or data[:4] == b"PK\\x03\\x04"
    try:
        content = _member_from_zip(data) if is_zip else _member_from_tar(data)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as exc:
        raise DownloadError(f"the downloaded archive {file_name!r} cannot be read: {exc}") from exc
    if content is None:
        raise DownloadError(f"the downloaded archive {file_name!r} has no member named fcs")
    into.mkdir(parents=True, exist_ok=True)
    target = into / BINARY_NAME
    partial = into / f".{BINARY_NAME}.partial"
    try:
        with open(partial, "wb") as handle:
            handle.write(content)
        os.chmod(partial, 0o755)
        os.replace(partial, target)
    except OSError:
        partial.unlink(missing_ok=True)
        raise
    return target
