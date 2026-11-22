#!/bin/sh
# Checks a Linux Docker host before (and after) `docker compose up`, and with --fix
# makes the host changes the sandbox needs. See docs/operations.md, "Linux hosts".
#
#   scripts/host-setup.sh           # check only, changes nothing
#   sudo scripts/host-setup.sh --fix
#
# --fix only does this: loads br_netfilter, sets net.bridge.bridge-nf-call-iptables and
# -ip6tables to 1, and writes /etc/modules-load.d/sandbox-br_netfilter.conf and
# /etc/sysctl.d/90-sandbox-bridge.conf so both survive a reboot. Everything else is
# reported with the command to run. Exit status: 0 when nothing failed, 1 otherwise.
set -u

FIX=0
for arg in "$@"; do
    case "$arg" in
        --fix) FIX=1 ;;
        -h | --help)
            sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg (use --fix or --help)" >&2
            exit 2
            ;;
    esac
done

cd "$(dirname "$0")/.." || exit 2

FAILS=0
WARNS=0
ok() { echo "  ok    $*"; }
info() { echo "  info  $*"; }
warn() { echo "  WARN  $*"; WARNS=$((WARNS + 1)); }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }
fixed() { echo "  fixed $*"; }
section() { echo; echo "$*"; }
is_root() { [ "$(id -u)" = "0" ]; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(uname -s)" != "Linux" ]; then
    echo "This script checks Linux Docker hosts. On Docker Desktop the Linux VM is set up already."
    exit 0
fi

# --- Docker -----------------------------------------------------------------------------
section "Docker"
if ! have docker; then
    fail "docker is not installed"
elif ! docker info >/dev/null 2>&1; then
    fail "cannot reach the Docker daemon as $(id -un) (run with sudo, or add yourself to the docker group)"
else
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
    if docker compose version >/dev/null 2>&1; then
        ok "$(docker compose version 2>/dev/null | head -n 1)"
    else
        fail "the docker compose plugin (v2) is missing"
    fi
    firewall="$(docker info 2>/dev/null | sed -n 's/^ *Firewall Backend: *//p' | head -n 1)"
    case "$firewall" in
        "") info "Docker does not report a firewall backend (older Docker): assuming iptables" ;;
        nftables*)
            fail "Docker's firewall backend is $firewall. It has no DOCKER-USER chain, so the egress guard cannot work. Set \"firewall-backend\": \"iptables\" in /etc/docker/daemon.json and restart Docker, or firewall the session bridge in the host firewall (docs/operations.md)"
            ;;
        *) ok "Docker firewall backend: $firewall" ;;
    esac
    if docker info 2>/dev/null | grep -qi 'rootless'; then
        warn "rootless Docker: the egress guard cannot program the host firewall. Apply the rules in the host firewall instead (docs/operations.md, Before production)"
    fi
fi

# --- br_netfilter -----------------------------------------------------------------------
section "Bridge filtering (br_netfilter)"
bridge_ok() {
    [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" = "1" ] \
        && [ "$(cat /proc/sys/net/bridge/bridge-nf-call-ip6tables 2>/dev/null)" = "1" ]
}
persisted() {
    grep -qs '^br_netfilter' /etc/modules-load.d/*.conf \
        && grep -qsE '^net\.bridge\.bridge-nf-call-iptables *= *1' /etc/sysctl.d/*.conf /etc/sysctl.conf \
        && grep -qsE '^net\.bridge\.bridge-nf-call-ip6tables *= *1' /etc/sysctl.d/*.conf /etc/sysctl.conf
}
if [ "$FIX" = "1" ]; then
    if ! is_root; then
        fail "--fix needs root: sudo $0 --fix"
    else
        if [ ! -d /sys/module/br_netfilter ]; then
            if modprobe br_netfilter; then fixed "loaded br_netfilter"; else fail "modprobe br_netfilter failed"; fi
        fi
        if ! bridge_ok && [ -d /proc/sys/net/bridge ]; then
            sysctl -q -w net.bridge.bridge-nf-call-iptables=1 net.bridge.bridge-nf-call-ip6tables=1 \
                && fixed "set net.bridge.bridge-nf-call-iptables=1 and -ip6tables=1"
        fi
        if ! persisted; then
            mkdir -p /etc/modules-load.d /etc/sysctl.d
            echo br_netfilter > /etc/modules-load.d/sandbox-br_netfilter.conf
            printf '%s\n' \
                '# URL sandbox: bridged container traffic must pass iptables (egress guard).' \
                'net.bridge.bridge-nf-call-iptables = 1' \
                'net.bridge.bridge-nf-call-ip6tables = 1' > /etc/sysctl.d/90-sandbox-bridge.conf
            fixed "wrote /etc/modules-load.d/sandbox-br_netfilter.conf and /etc/sysctl.d/90-sandbox-bridge.conf"
        fi
    fi
fi
if bridge_ok; then
    ok "br_netfilter is on (bridge-nf-call-iptables and -ip6tables are 1)"
else
    fail "br_netfilter is off: sessions could reach the API and each other, and the worker will refuse sessions. Fix: sudo $0 --fix"
fi
if persisted; then
    ok "br_netfilter and the sysctls are set to survive a reboot"
elif bridge_ok; then
    warn "br_netfilter is on now but not persisted; it is lost on reboot. Fix: sudo $0 --fix"
fi

# --- iptables ---------------------------------------------------------------------------
section "iptables"
if ! is_root; then
    info "run as root to see the host's iptables backend and the egress guard's rules"
elif ! have iptables; then
    warn "no iptables binary on the host (Docker needs it for its iptables firewall)"
else
    version="$(iptables --version 2>/dev/null)"
    case "$version" in
        *legacy*) ok "$version: the egress guard finds DOCKER-USER on the legacy backend by itself (SANDBOX_EGRESS_IPTABLES=auto)" ;;
        *nf_tables*) ok "$version" ;;
        *) info "${version:-iptables --version printed nothing}" ;;
    esac
    if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        ok "DOCKER-USER chain exists"
        if iptables -S DOCKER-USER 2>/dev/null | grep -q 'SBX-EGRESS'; then
            ok "egress guard rules are hooked into DOCKER-USER"
        else
            info "egress guard rules are not in DOCKER-USER yet (normal before docker compose up)"
        fi
    else
        info "no DOCKER-USER chain yet (Docker creates it when it starts its first network)"
    fi
fi
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    info "firewalld is running: a firewall-cmd --reload can remove the guard's rules, which it restores within 10 s"
fi

# --- SELinux ----------------------------------------------------------------------------
section "SELinux"
if have getenforce; then
    mode="$(getenforce 2>/dev/null)"
    if [ "$mode" = "Enforcing" ]; then
        if grep -q 'label=disable' compose.yaml 2>/dev/null; then
            ok "SELinux is enforcing; compose.yaml runs the worker with label=disable so it can use the Docker socket"
        else
            fail "SELinux is enforcing but compose.yaml has no label=disable for the worker: update compose.yaml"
        fi
    else
        ok "SELinux is ${mode:-not reported}"
        [ "$mode" = "Permissive" ] && info "the sandbox does not need SELinux off; you can turn it back on with: sudo setenforce 1"
    fi
else
    ok "SELinux tools not installed (SELinux probably off)"
fi

# --- Configuration ----------------------------------------------------------------------
section "Configuration (.env)"
if [ ! -f .env ]; then
    warn "no .env: copy .env.example to .env and edit it"
else
    bad="$(grep -nvE '^[[:space:]]*(#.*)?$|^[A-Za-z_][A-Za-z0-9_]*=' .env | head -n 3)"
    if [ -n "$bad" ]; then
        fail "lines in .env that are neither comments nor KEY=value (docker compose refuses the file): $(echo "$bad" | tr '\n' ' ')- put # in front of them"
    else
        ok ".env parses"
    fi
    if grep -qs "$(printf '\r')" .env; then
        warn ".env has Windows line endings; values may carry a stray \\r. Fix: sed -i 's/\\r\$//' .env"
    fi
    key="$(sed -n 's/^SANDBOX_SECRET_KEY=//p' .env | tail -n 1)"
    if [ -z "$key" ] || [ "${#key}" -lt 32 ]; then
        warn "SANDBOX_SECRET_KEY is unset or shorter than 32 characters (required in production). Generate one: openssl rand -hex 32"
    else
        ok "SANDBOX_SECRET_KEY is set"
    fi
fi

# --- Images -----------------------------------------------------------------------------
section "Images"
if have docker && docker info >/dev/null 2>&1; then
    for image in sandbox-session:latest sandbox-pcap:latest; do
        if docker image inspect "$image" >/dev/null 2>&1; then
            ok "$image is built"
        else
            fail "$image is not built (sessions fail without it): docker compose --profile build build"
        fi
    done
    # After `up`: is the guard running and did it install IPv4 rules?
    guard="$(docker compose ps -q egress-guard 2>/dev/null)"
    if [ -n "$guard" ]; then
        logs="$(docker logs "$guard" 2>&1)"
        if echo "$logs" | grep -q 'IPv4 rules \(installed\|already in place\)'; then
            ok "egress guard: $(echo "$logs" | grep 'IPv4 rules' | tail -n 1 | sed 's/^egress-guard: //' | cut -c1-90)"
        elif echo "$logs" | grep -q 'NOT isolated'; then
            fail "egress guard could not install its rules; see: docker compose logs egress-guard"
        else
            info "egress guard is running; no IPv4 status line yet (older image? docker compose up -d --build egress-guard)"
        fi
    else
        info "the stack is not running yet; run this again after docker compose up -d"
    fi
fi

echo
if [ "$FAILS" -gt 0 ]; then
    echo "$FAILS failed, $WARNS warnings."
    exit 1
fi
echo "No failures ($WARNS warnings)."
exit 0
