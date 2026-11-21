"""Public IPv6 for sessions (NFR-3): the egress guard's IPv6 blocks, the worker's
per-session IPv6 switch and the probe's IPv6 targets."""

import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sandbox.analysis.suricata import HOME_NET
from sandbox.config import Settings
from sandbox.core.netguard import NetGuard
from sandbox.orchestrator.backend import SessionSpec
from sandbox.orchestrator.docker_backend import _PROBE_SCRIPT, DockerBackend

ROOT = Path(__file__).resolve().parents[1]


def _read(*parts: str) -> str:
    path = ROOT.joinpath(*parts)
    if not path.exists():  # the API image ships tests/ but not docker/ or compose.yaml
        pytest.skip(f"{path} not in this checkout")
    return path.read_text()


def _guard() -> str:
    return _read("docker", "egress-guard.sh")


def _guard_list(name: str) -> list[str]:
    match = re.search(rf'^{name}="([^"]*)"', _guard(), re.M)
    assert match, name
    return match.group(1).split()


# --- egress-guard.sh -------------------------------------------------------------------


def test_guard_no_longer_drops_all_ipv6():
    GUARD = _guard()
    assert not re.search(r'-I DOCKER-USER 1 -i "\$BRIDGE" -j DROP', GUARD)
    assert "build_v6" in GUARD
    assert '! -d "$GLOBAL6" -j DROP' in GUARD


@pytest.mark.parametrize(
    "cidr",
    [
        "fc00::/7",
        "fe80::/10",
        "::1",
        "::ffff:0:0/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "ff00::/8",
        "2001:db8::/32",
        "3fff::/20",
        "2002::/16",
        "2001::/32",
        "fd00:ec2::254",
        "fec0::/10",
        "100::/64",
    ],
)
def test_guard_blocks_the_ipv6_equivalents(cidr):
    assert cidr in _guard_list("BLOCKED6")


def test_every_guard_range_is_valid_and_refused_by_netguard():
    """The firewall and the runner's own check agree on what is internal."""
    guard = NetGuard()
    for cidr in _guard_list("BLOCKED") + _guard_list("BLOCKED6"):
        net = ipaddress.ip_network(cidr, strict=True)
        for address in (net.network_address, net[-1]):
            assert guard.blocked_reason(address), f"{address} ({cidr}) passes netguard"


def test_public_ipv6_is_outside_every_guard_range():
    blocked = [ipaddress.ip_network(c) for c in _guard_list("BLOCKED6")]
    global6 = ipaddress.ip_network(_guard_list("GLOBAL6")[0])
    for address in ("2606:4700:4700::1111", "2a00:1450:4001:82a::200e", "2620:fe::fe"):
        ip = ipaddress.ip_address(address)
        assert ip in global6
        assert not any(ip in net for net in blocked), address
        assert NetGuard().blocked_reason(ip) is None


def test_guard_keeps_neighbour_discovery_and_the_api_exception():
    GUARD = _guard()
    assert "neighbour-solicitation" in GUARD and "neighbour-advertisement" in GUARD
    assert '-o "$BRIDGE" -p ipv6-icmp' in GUARD
    assert '-s "$API_IP6" -p tcp --dport "$STREAM_PORT" -j RETURN' in GUARD
    assert "host_v6" in GUARD and "SANDBOX_EGRESS_BLOCKED6" in GUARD


def test_guard_script_parses():
    _guard()
    sh = "sh"
    try:
        subprocess.run([sh, "-n", str(ROOT / "docker" / "egress-guard.sh")], check=True)  # noqa: S603
    except FileNotFoundError:
        pytest.skip("no POSIX sh")


# --- settings, compose and Suricata ----------------------------------------------------


def test_defaults_are_a_ula_subnet_inside_suricata_home_net():
    s = Settings(_env_file=None)
    subnet = ipaddress.ip_network(s.session_subnet_v6)
    assert subnet.subnet_of(ipaddress.ip_network("fc00::/7"))
    assert ipaddress.ip_address(s.session_api_ip6) in subnet
    assert "fc00::/7" in HOME_NET
    assert s.session_ipv6 == "auto"


def test_compose_matches_the_settings():
    compose = _read("compose.yaml")
    s = Settings(_env_file=None)
    assert "enable_ipv6: true" in compose
    assert f"subnet: {s.session_subnet_v6}" in compose
    assert f"ipv6_address: {s.session_api_ip6}" in compose
    assert f"SANDBOX_SESSION_API_IP6: {s.session_api_ip6}" in compose


def test_probe_targets_cover_ipv6_api_and_metadata():
    targets = Settings(_env_file=None).egress_probe_targets()
    assert "[fd5b:d213:5e55::2]:8000" in targets
    assert "[fd00:ec2::254]:80" in targets


# --- probe script ----------------------------------------------------------------------


def _listener(family, host):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen()
    threading.Thread(target=lambda: sock.accept(), daemon=True).start()
    return sock


def test_probe_script_handles_bracketed_ipv6_targets():
    if not socket.has_ipv6:
        pytest.skip("no IPv6 loopback")
    try:
        v6 = _listener(socket.AF_INET6, "::1")
    except OSError:
        pytest.skip("no IPv6 loopback")
    v4 = _listener(socket.AF_INET, "127.0.0.1")
    with v6, v4:
        p6, p4 = v6.getsockname()[1], v4.getsockname()[1]
        out = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-c",
                _PROBE_SCRIPT,
                f"127.0.0.1:{p4}",
                f"[::1]:{p6}",
                f"[::1]:{p6}",
                "[::1]:1",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout
    result = json.loads(out.strip().splitlines()[-1])
    assert result == {"public": True, "public6": True, "leaks": [f"[::1]:{p6}"]}


# --- per-session IPv6 ------------------------------------------------------------------


class _Fake:
    def __init__(self, ipv6_network: bool):
        self.runs = []
        outer = self

        class Images:
            def get(self, name):
                return name

        class Network:
            attrs = {"EnableIPv6": ipv6_network}

        class Networks:
            def get(self, name):
                return Network()

        class Container:
            id = "c1"

        class Containers:
            def run(self, **kwargs):
                outer.runs.append(kwargs)
                return Container()

        self.images, self.networks, self.containers = Images(), Networks(), Containers()


def _start(mode: str, public6: bool, ipv6_network: bool = True) -> dict:
    client = _Fake(ipv6_network)
    settings = Settings(
        _env_file=None, env="test", session_ipv6=mode, capture_pcap=False, egress_guard="enforce"
    )
    backend = DockerBackend(settings, client=client)
    backend._probe_egress = lambda: ([], True, public6)
    spec = SessionSpec(
        session_id="s1",
        analysis_id="a1",
        url="https://example.com/",
        interactive=False,
        time_limit_s=60,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    backend._start(spec)
    return client.runs[-1]


def test_auto_gives_ipv6_when_the_probe_reaches_public_ipv6():
    run = _start("auto", public6=True)
    assert "sysctls" not in run
    assert run["labels"]["sandbox.ipv6"] == "1"


def test_auto_disables_ipv6_when_the_host_has_no_ipv6_route():
    run = _start("auto", public6=False)
    assert run["sysctls"]["net.ipv6.conf.all.disable_ipv6"] == "1"
    assert run["labels"]["sandbox.ipv6"] == "0"


def test_on_forces_ipv6_and_off_disables_it():
    assert "sysctls" not in _start("on", public6=False)
    assert _start("off", public6=True)["sysctls"]["net.ipv6.conf.all.disable_ipv6"] == "1"


def test_network_without_ipv6_runs_sessions_ipv4_only():
    run = _start("on", public6=True, ipv6_network=False)
    assert run["labels"]["sandbox.ipv6"] == "0"
