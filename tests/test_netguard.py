import pytest

from sandbox.core.netguard import BlockedDestination, NetGuard

guard = NetGuard()


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # AWS, GCP and Azure metadata
        "100.100.100.200",  # Alibaba metadata (carrier-grade NAT range)
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",  # AWS IPv6 metadata
        "::ffff:127.0.0.1",  # IPv4-mapped
        "::ffff:169.254.169.254",
        "2002:7f00:1::",  # 6to4 wrapping 127.0.0.1
        "64:ff9b::a00:1",  # NAT64 wrapping 10.0.0.1
    ],
)
def test_blocks_internal(address):
    assert guard.blocked_reason(address) is not None


@pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_allows_public(address):
    assert guard.blocked_reason(address) is None


def test_extra_blocked_and_allowed_ranges():
    custom = NetGuard.from_cidrs(blocked=["1.1.1.0/24"], allowed=["10.99.0.0/16"])
    assert custom.blocked_reason("1.1.1.1") is not None
    assert custom.blocked_reason("10.99.1.1") is None
    assert custom.blocked_reason("10.98.1.1") is not None


async def test_check_host_uses_resolver():
    async def resolver(host):
        return {"good.example": ["93.184.216.34"], "rebind.example": ["93.184.216.34", "10.0.0.5"]}[
            host
        ]

    assert await guard.check_host("good.example", resolver) == ["93.184.216.34"]
    with pytest.raises(BlockedDestination) as exc:
        await guard.check_host("rebind.example", resolver)
    assert exc.value.address == "10.0.0.5"


async def test_check_host_ip_literal_skips_resolver():
    async def resolver(host):
        raise AssertionError("should not resolve an IP literal")

    with pytest.raises(BlockedDestination):
        await guard.check_host("127.0.0.1", resolver)


async def test_unresolvable_host_returns_empty():
    async def resolver(host):
        return []

    assert await guard.check_host("nxdomain.example", resolver) == []
