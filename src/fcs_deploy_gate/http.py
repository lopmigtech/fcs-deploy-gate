"""The HTTP transport: an injected boundary. The Gate decides what to send and which
proxy applies; the transport only moves bytes."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

REQUEST_TIMEOUT_SECONDS = 60


class TransportError(Exception):
    """The request could not be completed at all (DNS, connection, TLS, timeout)."""


@dataclass(frozen=True)
class ProxySettings:
    """Which proxy applies, read from the environment the Gate was given (so a CI job's
    HTTPS_PROXY reaches the transport even though the transport never reads os.environ)."""

    proxies: dict[str, str] = field(default_factory=dict)
    no_proxy: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> ProxySettings:
        proxies: dict[str, str] = {}
        for scheme in ("https", "http"):
            value = env.get(f"{scheme.upper()}_PROXY") or env.get(f"{scheme}_proxy")
            if value:
                proxies[scheme] = value
        return cls(proxies=proxies, no_proxy=env.get("NO_PROXY") or env.get("no_proxy") or None)

    def bypasses(self, host: str) -> bool:
        """Whether ``host`` is listed in NO_PROXY: ``*``, an exact host, or a domain suffix,
        each optionally with a port."""
        if not self.no_proxy:
            return False
        host = host.lower()
        for entry in self.no_proxy.split(","):
            entry = entry.strip().lower().lstrip(".").split(":")[0]
            if entry == "*" or (entry and (host == entry or host.endswith("." + entry))):
                return True
        return False


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    proxy: ProxySettings = field(default_factory=ProxySettings)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def text(self, limit: int = 300) -> str:
        return self.body[:limit].decode("utf-8", errors="replace")


Transport = Callable[[HttpRequest], HttpResponse]


def safe_url(url: str) -> str:
    """The URL without its query or fragment, fit for a message: a pre-signed download URL
    carries its authorisation in the query string."""
    return urlsplit(url)._replace(query="", fragment="").geturl()


class UrllibTransport:
    """The default transport, on the standard library."""

    def __call__(self, request: HttpRequest) -> HttpResponse:
        host = urlsplit(request.url).hostname or ""
        proxies = {} if request.proxy.bypasses(host) else request.proxy.proxies
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        prepared = urllib.request.Request(
            request.url, data=request.body, headers=request.headers, method=request.method
        )
        try:
            with opener.open(prepared, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return HttpResponse(
                    status=response.status, headers=dict(response.headers), body=response.read()
                )
        except urllib.error.HTTPError as error:
            return HttpResponse(status=error.code, headers=dict(error.headers), body=error.read())
        except urllib.error.URLError as error:
            raise TransportError(
                f"{request.method} {safe_url(request.url)}: {error.reason}"
            ) from error
        except OSError as error:
            raise TransportError(f"{request.method} {safe_url(request.url)}: {error}") from error
