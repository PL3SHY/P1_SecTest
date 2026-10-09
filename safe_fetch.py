"""Fetch a URL's response headers without being tricked into reaching internal addresses.

A tool that visits whatever address a stranger types is a classic server-side request forgery
(SSRF) risk. Defences, in order:
  1. only http/https, no credentials in the URL, only the default ports
  2. the host name is resolved here, and every address it resolves to must be a public one
  3. the connection is then made to that exact validated IP (the original host name is kept
     for the Host header and TLS), so DNS cannot swap in a private address afterwards
  4. redirects are followed by hand, and every hop goes through steps 1-3
  5. hard limits on hops and time, and the response body is never downloaded
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx


class BlockedAddressError(Exception):
    """The address is not allowed (private, local, odd port, bad scheme...)."""


class FetchFailedError(Exception):
    """The site could not be reached (offline, too slow, TLS problem...)."""


# Ranges Python's own checks do not already flag as non-public.
_EXTRA_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "64:ff9b::/96",  # NAT64
        "100::/64",  # discard-only
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4 (embeds an IPv4 address)
    )
]

MAX_REDIRECTS = 4
REQUEST_TIMEOUT = 6.0
TOTAL_TIMEOUT = 12.0
USER_AGENT = "HeaderAuditor/1.0 (portfolio demo)"


def is_blocked_ip(address: str) -> bool:
    """True if the address is not a normal public internet address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # not an IP: treat as unsafe
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is really 127.0.0.1
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    return any(ip.version == net.version and ip in net for net in _EXTRA_BLOCKED)


def validate_url(url: str):
    """Reject anything that is not a plain public http(s) address. Returns the parsed URL."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedAddressError("only http and https are allowed")
    if parts.username or parts.password:
        raise BlockedAddressError("credentials in URLs are not allowed")
    try:
        port = parts.port
    except ValueError:
        raise BlockedAddressError("invalid port") from None
    if port not in (None, 80, 443):
        raise BlockedAddressError("only the default web ports are allowed")
    if not parts.hostname:
        raise BlockedAddressError("missing host")
    return parts


async def resolve_public_addresses(host: str, port: int) -> list[str]:
    """Resolve a host name and make sure EVERY address it points to is public."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise FetchFailedError("could not resolve the host") from None
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses or any(is_blocked_ip(a) for a in addresses):
        raise BlockedAddressError("blocked address")
    return addresses[:4]


@dataclass
class FetchResult:
    final_url: str
    status: int
    headers: dict
    redirects: list = field(default_factory=list)


def _headers_to_dict(headers: httpx.Headers) -> dict:
    out: dict = {}
    for key in headers.keys():
        values = headers.get_list(key)
        out[key.lower()] = values[0] if len(values) == 1 else values
    return out


async def _request_once(parts, addresses: list[str]):
    """GET the page from one of the validated IPs; keep only the status and headers."""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    last_error: Exception | None = None
    for ip in addresses:
        ip_host = f"[{ip}]" if ":" in ip else ip
        netloc = ip_host if parts.port is None else f"{ip_host}:{parts.port}"
        target = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
        host_header = parts.hostname if parts.port is None else f"{parts.hostname}:{parts.port}"
        try:
            # trust_env=False: ignore proxy environment variables, which would bypass the IP pinning
            async with httpx.AsyncClient(
                follow_redirects=False, timeout=REQUEST_TIMEOUT, trust_env=False
            ) as client:
                async with client.stream(
                    "GET",
                    target,
                    headers={"Host": host_header, "User-Agent": USER_AGENT, "Accept": "*/*"},
                    # sni_hostname makes TLS use (and verify the certificate for) the real host name
                    extensions={"sni_hostname": parts.hostname},
                ) as response:
                    return response.status_code, _headers_to_dict(response.headers)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_error = exc  # try the next address
    raise FetchFailedError("could not connect") from last_error


async def fetch_headers(start_url: str) -> FetchResult:
    redirects: list[dict] = []
    current = start_url
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            for _ in range(MAX_REDIRECTS + 1):
                parts = validate_url(current)
                port = parts.port or (443 if parts.scheme == "https" else 80)
                addresses = await resolve_public_addresses(parts.hostname, port)
                try:
                    status, headers = await _request_once(parts, addresses)
                except (httpx.HTTPError, OSError):
                    raise FetchFailedError("request failed") from None
                location = headers.get("location")
                if 300 <= status < 400 and isinstance(location, str):
                    nxt = urljoin(current, location)
                    redirects.append({"from": current, "status": status, "to": nxt})
                    current = nxt
                    continue
                return FetchResult(current, status, headers, redirects)
    except TimeoutError:
        raise FetchFailedError("timed out") from None
    raise FetchFailedError("too many redirects")
