"""Refuse destinations in internal address ranges (SUB-4, CAP-9).

The API calls this at submission time; the runner calls it again after DNS resolution
and on every redirect, because a public name can resolve to, or redirect to, an
internal address.
"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Awaitable[list[str]]]

_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
# Ranges Python's ipaddress still calls global, but the egress guard drops
# (docker/egress-guard.sh): deprecated site-local IPv6 and the 6to4 relay anycast.
_ALSO_RESERVED = (
    ipaddress.IPv6Network("fec0::/10"),
    ipaddress.IPv4Network("192.88.99.0/24"),
)
# The only IPv6 space with public unicast addresses; the guard drops everything else.
_GLOBAL_UNICAST6 = ipaddress.IPv6Network("2000::/3")


class BlockedDestination(Exception):
    def __init__(self, host: str, address: str, reason: str):
        super().__init__(f"{host} resolves to {address}, which is {reason}")
        self.host = host
        self.address = address
        self.reason = reason


@dataclass(frozen=True)
class NetGuard:
    extra_blocked: tuple[Network, ...] = ()
    allowed: tuple[Network, ...] = ()

    @classmethod
    def from_cidrs(cls, blocked: Iterable[str] = (), allowed: Iterable[str] = ()) -> "NetGuard":
        return cls(
            extra_blocked=tuple(ipaddress.ip_network(c, strict=False) for c in blocked),
            allowed=tuple(ipaddress.ip_network(c, strict=False) for c in allowed),
        )

    def blocked_reason(self, address: str | IPAddress) -> str | None:
        """Return why ``address`` is refused, or None if it may be contacted."""
        ip = ipaddress.ip_address(address)
        if any(ip in net for net in self.allowed):
            return None
        # An IPv4-mapped address (::ffff:a.b.c.d) goes out as plain IPv4, so it is judged
        # as that IPv4 address alone; some resolvers return public IPv4 hosts this way.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
            if any(ip in net for net in self.allowed):
                return None
        for candidate in _embedded_addresses(ip):
            if reason := self._reason(candidate):
                return reason
        return None

    def _reason(self, ip: IPAddress) -> str | None:
        if ip.is_loopback:
            return "a loopback address"
        if ip.is_link_local:
            return "a link-local address (includes cloud metadata)"
        if ip.is_private:
            return "a private address"
        if ip.is_multicast:
            return "a multicast address"
        if ip.is_unspecified or ip.is_reserved or any(ip in net for net in _ALSO_RESERVED):
            return "a reserved address"
        if isinstance(ip, ipaddress.IPv6Address) and ip not in _GLOBAL_UNICAST6:
            return "outside IPv6 global unicast (2000::/3)"
        if any(ip in net for net in self.extra_blocked):
            return "in a blocked range"
        if not ip.is_global:
            return "not a public address"
        return None

    async def check_host(self, host: str, resolver: Resolver) -> list[str]:
        """Raise BlockedDestination if ``host`` is or resolves to a refused address.

        Returns the resolved addresses; an empty list means the name did not resolve.
        """
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            addresses = await resolver(host)
        for address in addresses:
            if reason := self.blocked_reason(address):
                raise BlockedDestination(host, address, reason)
        return addresses


def _embedded_addresses(ip: IPAddress) -> list[IPAddress]:
    """The address itself plus any IPv4 address tunnelled inside an IPv6 one."""
    found: list[IPAddress] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            found.append(ip.ipv4_mapped)
        if ip.sixtofour:
            found.append(ip.sixtofour)
        if ip.teredo:
            found.extend(ip.teredo)
        if ip in _NAT64:
            found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


async def system_resolver(host: str) -> list[str]:
    """Resolve A and AAAA records with the OS resolver; [] if the name does not resolve."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})
