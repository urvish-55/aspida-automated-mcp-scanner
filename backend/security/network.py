"""SSRF defenses for outbound scanner connections.

The scanner only talks to explicitly authorized MCP server URLs. This module
enforces that a URL cannot trick the scanner into contacting internal
infrastructure:

- scheme allowlist (http/https only)
- hostname resolution with validation of EVERY resolved address
- rejection of loopback, private, link-local (incl. cloud metadata), reserved
  and unspecified addresses unless local targets are explicitly allowed
- redirect handling is manual: each hop is re-validated (follow_redirects=False)
- DNS pinning: the addresses validated for a hostname are the ONLY addresses the
  connection may use (see PinnedTransport). The hostname is never resolved a second
  time at connect time, which closes the DNS-rebinding window. TLS still verifies the
  certificate against the original hostname (only the TCP destination is pinned).
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass

import httpcore
import httpx

from backend.core.config import get_settings

MAX_REDIRECTS = 3
RESOLVE_TIMEOUT = 5.0

# Cloud metadata endpoints are NEVER legitimate MCP scan targets. They are
# blocked unconditionally — even when ALLOW_LOCAL_TARGETS=true — because a lab
# switch for localhost fixtures must not open the door to metadata SSRF.
ALWAYS_BLOCKED_IPS = (
    ipaddress.ip_address("169.254.169.254"),  # AWS/EC2 metadata
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 metadata
)


class SSRFBlockedError(Exception):
    """Raised when a target URL fails SSRF validation."""


@dataclass
class UrlValidation:
    url: str
    host: str
    port: int
    scheme: str
    resolved_ips: list[str]


def _is_always_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """IPs that are never scannable, regardless of any operator switch."""
    return ip in ALWAYS_BLOCKED_IPS


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or getattr(ip, "is_global", True) is False
    )


def validate_target_url(url: str, *, allow_local: bool | None = None) -> UrlValidation:
    """Validate a URL for dynamic scanning. Raises SSRFBlockedError."""
    settings = get_settings()
    if allow_local is None:
        allow_local = settings.allow_local_targets

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"scheme '{parsed.scheme}' not allowed (use http/https)")
    if not parsed.hostname:
        raise SSRFBlockedError("URL has no hostname")
    if parsed.username or parsed.password:
        raise SSRFBlockedError("credentials in URL are not allowed")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Literal IPs are checked directly; hostnames are resolved and every
    # resolved address is checked (defeats DNS-based SSRF to private space).
    try:
        addr = ipaddress.ip_address(parsed.hostname)
        literal = True
    except ValueError:
        addr = None
        literal = False

    resolved: list[str] = []
    if literal and addr is not None:
        if _is_always_blocked(addr):
            raise SSRFBlockedError(
                f"target {parsed.hostname} is a cloud-metadata/reserved endpoint and is never scannable"
            )
        if _is_disallowed_ip(addr) and not allow_local:
            raise SSRFBlockedError(
                f"target {parsed.hostname} resolves to a non-public address and local targets are disabled"
            )
        resolved.append(str(addr))
    elif not literal:
        try:
            infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise SSRFBlockedError(f"cannot resolve host '{parsed.hostname}': {exc}") from exc
        for info in infos[:8]:
            ip_str = info[4][0]
            ip = ipaddress.ip_address(ip_str)
            if _is_always_blocked(ip):
                raise SSRFBlockedError(
                    f"host '{parsed.hostname}' resolves to {ip_str}, a cloud-metadata/reserved "
                    f"endpoint that is never scannable"
                )
            if _is_disallowed_ip(ip) and not allow_local:
                raise SSRFBlockedError(
                    f"host '{parsed.hostname}' resolves to non-public address {ip_str} "
                    f"and local targets are disabled"
                )
            if ip_str not in resolved:
                resolved.append(str(ip_str))
        if not resolved:
            raise SSRFBlockedError(f"host '{parsed.hostname}' resolved to no usable addresses")

    # Operator allowlist of extra CIDRs (lab subnets) still applies beyond the
    # public/private split above.
    if settings.allowed_target_cidrs:
        allowed = any(
            any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False) for ip in resolved)
            for cidr in settings.allowed_target_cidrs
        )
        if not allowed and not allow_local:
            raise SSRFBlockedError("target not in ALLOWED_TARGET_CIDRS and local targets disabled")

    return UrlValidation(
        url=url, host=parsed.hostname, port=port, scheme=parsed.scheme, resolved_ips=resolved
    )


def validate_redirect(base: UrlValidation, location: str) -> UrlValidation:
    """Validate a redirect target against the same policy."""
    next_url = urllib.parse.urljoin(base.url, location)
    return validate_target_url(next_url)


def register_pins(pins: dict[str, list[str]], validation: UrlValidation) -> None:
    """Record the validated addresses for a hostname; only these may be connected to."""
    pins[validation.host.lower()] = list(validation.resolved_ips)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connects only to pre-validated addresses; never performs its own DNS lookup.

    Fails closed: a host without pins (e.g. a redirect that was not validated), unix sockets,
    and any pinned address that violates the policy are refused.
    """

    def __init__(self, inner: httpcore.AsyncNetworkBackend, pins: dict[str, list[str]], allow_local: bool) -> None:
        self._inner = inner
        self._pins = pins
        self._allow_local = allow_local

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # type: ignore[no-untyped-def]
        ips = self._pins.get(host.lower())
        if not ips:
            raise httpcore.ConnectError(f"refusing to connect to unvalidated host {host!r}")
        last: Exception | None = None
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if _is_always_blocked(addr) or (_is_disallowed_ip(addr) and not self._allow_local):
                continue  # re-checked at connect time (defense in depth)
            try:
                return await self._inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except httpcore.ConnectError as exc:
                last = exc
        raise last or httpcore.ConnectError(f"no permitted pinned address for {host!r}")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # type: ignore[no-untyped-def]
        raise httpcore.ConnectError("unix sockets are not permitted")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose TCP connections are restricted to validated, pinned addresses."""

    def __init__(self, pins: dict[str, list[str]], *, allow_local: bool, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(**kwargs)
        pool = getattr(self, "_pool", None)
        if pool is None or not hasattr(pool, "_network_backend"):
            # Unknown httpx/httpcore internals: refuse to run unpinned rather than silently weaken the guarantee.
            raise RuntimeError("DNS pinning unsupported with this httpx/httpcore version")
        pool._network_backend = PinnedNetworkBackend(pool._network_backend, pins, allow_local)


def safe_client(
    *, timeout: float, pins: dict[str, list[str]] | None = None, allow_local: bool = False
) -> httpx.AsyncClient:
    """An httpx client that never follows redirects automatically.

    With ``pins`` the client uses DNS pinning. Environment proxies are intentionally ignored in
    that mode: a proxy would resolve the hostname itself and bypass the pin.
    """
    kwargs: dict = {
        "timeout": timeout,
        "follow_redirects": False,
        "headers": {"User-Agent": "mcp-pentester/0.1.0 (authorized security scan)"},
    }
    if pins is not None:
        kwargs["transport"] = PinnedTransport(pins, allow_local=allow_local)
    return httpx.AsyncClient(**kwargs)
