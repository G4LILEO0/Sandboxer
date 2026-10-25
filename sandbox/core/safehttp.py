"""Outbound HTTP that cannot be steered at internal addresses (SUB-4, CAP-9).

Checking a host name with ``NetGuard`` and then letting the HTTP client resolve it again
leaves a gap: a name with a short TTL can answer the check with a public address and
the connection with an internal one (DNS rebinding). ``guarded_send`` closes it by
resolving once, checking every address, and connecting to the checked address while
keeping the original name in the ``Host`` header and in TLS (SNI and certificate
verification). Redirects are followed one hop at a time, each hop checked the same way.

Used by the API's redirect walk and by the worker's feed downloads and webhooks. The
session runner has its own per-request check inside the browser.
"""

import ipaddress

import httpx

from sandbox.core.netguard import BlockedDestination, NetGuard, Resolver

_REDIRECT_CODES = {301, 302, 303, 307, 308}


class UnresolvedHost(httpx.ConnectError):
    """The host did not resolve, so there is no checked address to connect to."""


async def checked_address(host: str, guard: NetGuard, resolver: Resolver) -> str:
    """The address to connect to for ``host``; raises if any of its addresses is refused."""
    addresses = await guard.check_host(host, resolver)
    if not addresses:
        raise UnresolvedHost(f"{host} did not resolve")
    return addresses[0]


def pinned_request(
    http: httpx.AsyncClient, method: str, url: str | httpx.URL, address: str, **kwargs
) -> httpx.Request:
    """A request for ``url`` that connects to ``address`` but still presents the URL's
    host name to the server (``Host``) and to TLS (SNI, certificate check)."""
    original = httpx.URL(url)
    host = original.host
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if is_literal:
        return http.build_request(method, original, **kwargs)
    headers = httpx.Headers(kwargs.pop("headers", None))
    default_port = {"http": 80, "https": 443}.get(original.scheme)
    port = original.port
    headers["Host"] = host if port in (None, default_port) else f"{host}:{port}"
    extensions = dict(kwargs.pop("extensions", None) or {})
    if original.scheme == "https":
        extensions["sni_hostname"] = host
    return http.build_request(
        method,
        original.copy_with(host=address),
        headers=headers,
        extensions=extensions,
        **kwargs,
    )


async def guarded_send(
    http: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    guard: NetGuard,
    resolver: Resolver,
    max_redirects: int = 5,
    **kwargs,
) -> httpx.Response:
    """Send a request (streamed: the caller reads and closes the response) to a checked,
    pinned address, following up to ``max_redirects`` redirects with the same checks.
    With ``max_redirects=0`` a redirect response is returned as is.

    Raises ``BlockedDestination`` for a refused address, ``UnresolvedHost`` when a name
    does not resolve, and ``httpx.HTTPError`` for transport errors.
    """
    current = httpx.URL(url)
    for _ in range(max_redirects + 1):
        if current.scheme not in ("http", "https") or not current.host:
            raise BlockedDestination(str(current), "-", "not an http(s) URL")
        address = await checked_address(current.host, guard, resolver)
        request = pinned_request(http, method, current, address, **kwargs)
        response = await http.send(request, follow_redirects=False, stream=True)
        location = response.headers.get("location")
        if response.status_code not in _REDIRECT_CODES or not location or not max_redirects:
            return response
        await response.aclose()
        current = current.join(location)
        if response.status_code == 303 or (
            response.status_code in (301, 302) and method.upper() == "POST"
        ):
            method = "GET"
            kwargs.pop("content", None)
            kwargs.pop("data", None)
            kwargs.pop("json", None)
    raise httpx.TooManyRedirects(f"More than {max_redirects} redirects", request=request)
