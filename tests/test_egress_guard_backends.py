"""The egress guard finds Docker's DOCKER-USER chain on either iptables backend.

Hosts such as openSUSE keep iptables on the legacy (x_tables) backend, while the
guard's Alpine image defaults to nf_tables. The guard must install its rules where
Docker's chain is, and say clearly when it cannot. These tests run the real script
against stub iptables binaries that record each call."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "docker" / "egress-guard.sh"

# A tiny iptables: chains and rules live in files under $STUB_STATE/<binary>/.
# $STUB_DOCKER lists the binaries where Docker created DOCKER-USER.
STUB = r"""#!/bin/sh
me="$(basename "$0")"
dir="$STUB_STATE/$me"
mkdir -p "$dir"
echo "$me $*" >> "$STUB_STATE/calls"
while [ "$1" = "-w" ] || [ "$1" = "-n" ]; do shift; done
cmd="$1"; shift
chain="$1"; shift
has_docker() { case " $STUB_DOCKER " in *" $me "*) return 0;; esac; return 1; }
exists() {
    case "$chain" in
        INPUT|FORWARD) return 0;;
        DOCKER-USER) has_docker; return $?;;
    esac
    [ -e "$dir/$chain" ]
}
case "$cmd" in
    -L) exists || { echo "iptables: No chain/target/match by that name." >&2; exit 1; } ;;
    -N) [ -e "$dir/$chain" ] && exit 1; : > "$dir/$chain" ;;
    -F) : > "$dir/$chain" ;;
    -A) exists || exit 1; echo "-A $chain $*" >> "$dir/$chain" ;;
    -I) exists || exit 1; shift; echo "-A $chain $*" >> "$dir/$chain" ;;
    -C) grep -qxF -- "-A $chain $*" "$dir/$chain" 2>/dev/null ;;
    -D) exit 1 ;;
    -S) cat "$dir/$chain" 2>/dev/null ;;
esac
"""

BINARIES = ("iptables-nft", "iptables-legacy", "ip6tables-nft", "ip6tables-legacy")


def _sh() -> str:
    sh = shutil.which("sh")
    if not sh or os.name == "nt":
        pytest.skip("needs a POSIX sh on Linux")
    return sh


def _run(tmp_path: Path, docker: str, installed=BINARIES, backend: str | None = None):
    sh = _sh()
    bin_dir = tmp_path / "bin"
    state = tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    for name in installed:
        stub = bin_dir / name
        stub.write_text(STUB)
        stub.chmod(0o755)
    # Only the stubs and the basic tools the script uses: no real iptables or ip.
    tools = bin_dir / "tools"
    tools.mkdir()
    for tool in ("cat", "grep", "head", "wc", "sort", "tr", "sleep", "basename", "mkdir"):
        path = shutil.which(tool)
        if path:
            (tools / tool).symlink_to(path)
    env = {
        "PATH": f"{bin_dir}:{tools}",
        "STUB_STATE": str(state),
        "STUB_DOCKER": docker,
        "SANDBOX_SESSION_API_IP": "172.31.213.2",
        "SANDBOX_SESSION_API_IP6": "fd5b:d213:5e55::2",
        "EGRESS_GUARD_ONCE": "1",
    }
    if backend:
        env["SANDBOX_EGRESS_IPTABLES"] = backend
    result = subprocess.run(  # noqa: S603
        [sh, str(GUARD)], env=env, capture_output=True, text=True, timeout=60
    )
    calls = (state / "calls").read_text() if (state / "calls").exists() else ""

    def hooked(binary: str, chain: str) -> bool:
        rules = state / binary / chain
        return rules.exists() and "-j SBX-EGRESS" in rules.read_text()

    return result, calls, hooked


def test_legacy_host_gets_rules_on_the_legacy_backend(tmp_path):
    """openSUSE: the host's iptables is legacy, DOCKER-USER exists only there."""
    result, calls, hooked = _run(tmp_path, docker="iptables-legacy ip6tables-legacy")
    assert result.returncode == 0, result.stdout + result.stderr
    assert hooked("iptables-legacy", "DOCKER-USER")
    assert hooked("ip6tables-legacy", "DOCKER-USER")
    assert "iptables-nft -w -N" not in calls
    assert "ip6tables-nft -w -N" not in calls
    assert "rules installed with iptables-legacy" in result.stdout


def test_nft_host_gets_rules_on_the_nft_backend(tmp_path):
    result, calls, hooked = _run(tmp_path, docker="iptables-nft ip6tables-nft")
    assert result.returncode == 0, result.stdout + result.stderr
    assert hooked("iptables-nft", "DOCKER-USER")
    assert hooked("ip6tables-nft", "DOCKER-USER")
    assert "iptables-legacy -w -N" not in calls


def test_ipv6_without_docker_user_hooks_forward_on_the_ipv4_backend(tmp_path):
    result, calls, hooked = _run(tmp_path, docker="iptables-legacy")
    assert result.returncode == 0, result.stdout + result.stderr
    assert hooked("ip6tables-legacy", "FORWARD")
    assert not hooked("ip6tables-nft", "FORWARD")


def test_chain_in_both_backends_gets_rules_in_both(tmp_path):
    result, _, hooked = _run(tmp_path, docker=" ".join(BINARIES))
    assert result.returncode == 0
    assert hooked("iptables-nft", "DOCKER-USER") and hooked("iptables-legacy", "DOCKER-USER")
    assert "more than one backend" in result.stdout


def test_forced_backend_uses_only_that_backend(tmp_path):
    result, calls, hooked = _run(tmp_path, docker=" ".join(BINARIES), backend="legacy")
    assert result.returncode == 0
    assert hooked("iptables-legacy", "DOCKER-USER")
    assert "iptables-nft" not in calls


def test_no_docker_user_fails_with_a_clear_message(tmp_path):
    """The old image had no legacy binaries and retried silently forever."""
    result, _, _ = _run(
        tmp_path,
        docker="iptables-legacy",
        installed=("iptables-nft", "ip6tables-nft"),
    )
    assert result.returncode == 1
    assert "NOT isolated" in result.stdout
    assert "iptables-legacy: not installed in this image" in result.stdout
    assert "iptables-nft: iptables: No chain/target/match by that name." in result.stdout


def test_bad_backend_setting_is_refused(tmp_path):
    result, _, _ = _run(tmp_path, docker="iptables-nft", backend="nftables")
    assert result.returncode == 2
    assert "must be auto, nft or legacy" in result.stdout


def test_image_ships_both_backends():
    dockerfile = (ROOT / "docker" / "egress.Dockerfile").read_text()
    assert "iptables-legacy" in dockerfile
