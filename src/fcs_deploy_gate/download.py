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

from fcs_deploy_gate.falcon import DownloadResource, FalconApi

BINARY_NAME = "fcs"
ZIP_MAGIC = b"PK\x03\x04"


@dataclass(frozen=True)
class CliPin:
    """The fcs CLI version the Gate runs and the SHA-256 of its linux/amd64 archive.
    Bumped by pull request, with a note on rule and severity changes (ADR 0003)."""

    version: str
    sha256: str

    @property
    def filled(self) -> bool:
        return bool(self.sha256.strip())


# Filled from the work environment with `fcs-deploy-gate pin` (README, "API clients, the
# pin and the bounds"); the Gate refuses to download while the SHA-256 is empty.
PIN = CliPin(
    version="4.2.3", sha256="69e2144db0e881e0101df363e0b2ab8416a8a5d5c6eb6db1304559690772dc8f"
)


class DownloadError(Exception):
    """The pinned CLI could not be obtained and verified."""


def published_build(api: FalconApi, token: str, version: str) -> DownloadResource:
    """The download API's description of exactly ``version``; anything else is an error."""
    resources = api.download_info(token, version)
    for resource in resources:
        if resource.version == version:
            if not resource.sha256:
                raise DownloadError(f"the download API reported no file hash for fcs {version}")
            return resource
    listed = ", ".join(sorted({r.version for r in resources})) or "nothing"
    raise DownloadError(
        f"the download API lists no fcs {version} for linux/amd64 (it lists: {listed})"
    )


def install_cli(api: FalconApi, token: str, pin: CliPin, into: Path) -> Path:
    """Download, verify and extract the pinned CLI into ``into``; the path of the binary."""
    build = published_build(api, token, pin.version)
    pinned = pin.sha256.lower()
    if build.sha256 != pinned:
        raise DownloadError(
            f"the download API reports SHA-256 {build.sha256} for fcs {pin.version} but the "
            f"pin is {pinned}; refusing to download"
        )
    if not build.download_url:
        raise DownloadError(f"the download API reported no download URL for fcs {pin.version}")
    data = api.fetch(build.download_url)
    actual = hashlib.sha256(data).hexdigest()
    if actual != pinned:
        raise DownloadError(f"the downloaded archive has SHA-256 {actual}, not the pinned {pinned}")
    return extract_binary(data, build.file_name, into)


def _is_the_binary(name: str) -> bool:
    return name in (BINARY_NAME, f"./{BINARY_NAME}")


def _member_from_tar(data: bytes) -> bytes | None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            if member.isfile() and _is_the_binary(member.name):
                extracted = archive.extractfile(member)
                return extracted.read() if extracted is not None else None
    return None


def _member_from_zip(data: bytes) -> bytes | None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            if not member.is_dir() and _is_the_binary(member.filename):
                return archive.read(member)
    return None


def extract_binary(data: bytes, file_name: str, into: Path) -> Path:
    """Write only the archive member named ``fcs`` to ``into``, executable. A corrupt
    archive or one without that member is an error, and nothing is written."""
    is_zip = file_name.endswith(".zip") or data[: len(ZIP_MAGIC)] == ZIP_MAGIC
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
