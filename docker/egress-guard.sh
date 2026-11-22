#!/bin/sh
# Egress firewall for the session network (NFR-3, docs/operations.md).
#
# Runs on the Docker host's network namespace with NET_ADMIN and installs rules on the
# session bridge so session containers reach the public internet only, over IPv4 and
# IPv6:
#
#   - replies to connections the API opened (the live view) are allowed;
#   - the API may open connections to sessions on the live-view port, nothing else may;
#   - new connections from sessions to private, loopback, link-local (cloud metadata),
#     CGNAT, multicast and reserved ranges are dropped: that covers the host, the API,
#     Postgres, other sessions and the office network;
#   - IPv6 gets the same blocks: ULA (fc00::/7, includes fd00:ec2::254 metadata),
#     link-local, loopback, IPv4-mapped/compatible/translated, NAT64, 6to4, Teredo,
#     multicast, documentation and reserved ranges, then everything outside global
#     unicast (2000::/3). The host's own global IPv6 addresses and their on-link
#     prefixes are dropped too, and so is SANDBOX_EGRESS_BLOCKED6 (extra CIDRs, for
#     example the office's public IPv6 prefix on Docker Desktop, where this namespace
#     cannot see the Windows host's addresses);
#   - anything addressed to the host itself from the bridge is dropped (INPUT), except
#     the IPv6 neighbour discovery that sessions need to find their gateway.
#
# Rules live in their own chains (SBX-EGRESS, SBX-INPUT in iptables and ip6tables, on
# the nf_tables or legacy backend, whichever holds Docker's DOCKER-USER chain),
# hooked from DOCKER-USER and INPUT. The script re-checks every few seconds and restores
# them if Docker or anyone else removed them, or if the host's IPv6 addresses changed.
# The worker independently probes the result before every batch of sessions and refuses
# to start sessions if internal targets answer.
set -eu

BRIDGE="${SANDBOX_SESSION_BRIDGE:-sbx-sessions}"
API_IP="${SANDBOX_SESSION_API_IP:?set SANDBOX_SESSION_API_IP}"
API_IP6="${SANDBOX_SESSION_API_IP6:-}"
STREAM_PORT="${SANDBOX_STREAM_PORT:-6080}"
INTERVAL="${EGRESS_GUARD_INTERVAL_S:-10}"
EXTRA6="${SANDBOX_EGRESS_BLOCKED6:-}"
BLOCKED="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"
# IPv6 equivalents. ::/8 covers ::/128, ::1/128, IPv4-compatible ::/96, IPv4-mapped
# ::ffff:0:0/96, IPv4-translated ::ffff:0:0:0/96 and NAT64 64:ff9b::/96; they are listed
# one by one as well so the rule set reads like the IPv4 one.
BLOCKED6=":: ::1 ::/96 ::ffff:0:0/96 ::ffff:0:0:0/96 64:ff9b::/96 64:ff9b:1::/48 ::/8
100::/64 2001::/23 2001::/32 2001:db8::/32 2002::/16 3fff::/20 5f00::/16 fc00::/7
fd00:ec2::254 fe80::/10 fec0::/10 ff00::/8"
GLOBAL6="2000::/3"

log() { echo "egress-guard: $*"; }

# iptables backend: auto | nft | legacy. Docker programs its chains with the host's
# iptables, which is either the nf_tables or the legacy (x_tables) backend. Rules added
# with the other backend never see DOCKER-USER, so auto looks for DOCKER-USER in both
# and installs into every backend that has it (a DROP in either one drops the packet).
BACKEND="${SANDBOX_EGRESS_IPTABLES:-auto}"
case "$BACKEND" in
    auto | nft | legacy) ;;
    *)
        log "error: SANDBOX_EGRESS_IPTABLES must be auto, nft or legacy (got '$BACKEND')"
        exit 2
        ;;
esac

# The binaries to try for one family (iptables or ip6tables).
candidates() {
    case "$BACKEND" in
        nft) echo "$1-nft" ;;
        legacy) echo "$1-legacy" ;;
        *) echo "$1-nft $1-legacy" ;;
    esac
}

# Every candidate that has Docker's DOCKER-USER chain, space-separated.
pick() {
    found=""
    for candidate in $(candidates "$1"); do
        if "$candidate" -w -n -L DOCKER-USER >/dev/null 2>&1; then
            found="$found $candidate"
        fi
    done
    echo $found
}

# Why no candidate has DOCKER-USER, one "binary: reason" per candidate.
why_not() {
    out=""
    for candidate in $(candidates "$1"); do
        if ! command -v "$candidate" >/dev/null 2>&1; then
            reason="not installed in this image"
        else
            reason="$("$candidate" -w -n -L DOCKER-USER 2>&1 | grep -v '^#' | head -n 1)"
            reason="${reason:-no DOCKER-USER chain}"
        fi
        out="$out${out:+; }$candidate: $reason"
    done
    echo "$out"
}

# The IPv6 binary on the same backend as an IPv4 one (iptables-legacy -> ip6tables-legacy).
v6_of() {
    echo "ip6tables${1#iptables}"
}

# Bridged traffic between containers only meets iptables with br_netfilter on (Docker
# turns it on itself; the worker's probe catches the case where it is off).
for family in iptables ip6tables; do
    if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-$family 2>/dev/null)" != "1" ]; then
        log "warning: net.bridge.bridge-nf-call-$family is not 1; session-to-API traffic on the bridge may bypass these rules"
    fi
done

# The host's global IPv6 addresses and the on-link prefixes they sit in (the office
# LAN), excluding the session bridge's own prefix (already inside fc00::/7 or the
# configured subnet). Prints one CIDR per line, sorted, so a change is easy to spot.
host_v6() {
    ip -6 -o addr show scope global 2>/dev/null | while read -r _ dev _ cidr _; do
        [ "$dev" = "$BRIDGE" ] && continue
        echo "${cidr%/*}"
        echo "$cidr"
    done | sort -u
}

build_v4() {
    ipt="$1"
    "$ipt" -w -N SBX-EGRESS 2>/dev/null || "$ipt" -w -F SBX-EGRESS
    "$ipt" -w -A SBX-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    "$ipt" -w -A SBX-EGRESS -s "$API_IP" -p tcp --dport "$STREAM_PORT" -j RETURN
    for net in $BLOCKED; do
        "$ipt" -w -A SBX-EGRESS -d "$net" -j DROP
    done
    "$ipt" -w -A SBX-EGRESS -j RETURN

    "$ipt" -w -N SBX-INPUT 2>/dev/null || "$ipt" -w -F SBX-INPUT
    "$ipt" -w -A SBX-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    "$ipt" -w -A SBX-INPUT -j DROP
}

build_v6() {
    ipt="$1" hostnets="$2"
    "$ipt" -w -N SBX-EGRESS 2>/dev/null || "$ipt" -w -F SBX-EGRESS
    "$ipt" -w -A SBX-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    if [ -n "$API_IP6" ]; then
        "$ipt" -w -A SBX-EGRESS -s "$API_IP6" -p tcp --dport "$STREAM_PORT" -j RETURN
    fi
    # Neighbour discovery between containers on the bridge (bridged frames meet these
    # rules through br_netfilter). Without it the API cannot find a session's IPv6
    # neighbour entry and the live view over IPv6 hangs. It never leaves the bridge.
    for type in neighbour-solicitation neighbour-advertisement; do
        "$ipt" -w -A SBX-EGRESS -o "$BRIDGE" -p ipv6-icmp --icmpv6-type "$type" -j RETURN
    done
    for net in $BLOCKED6 $hostnets $EXTRA6; do
        "$ipt" -w -A SBX-EGRESS -d "$net" -j DROP
    done
    "$ipt" -w -A SBX-EGRESS ! -d "$GLOBAL6" -j DROP
    "$ipt" -w -A SBX-EGRESS -j RETURN

    "$ipt" -w -N SBX-INPUT 2>/dev/null || "$ipt" -w -F SBX-INPUT
    "$ipt" -w -A SBX-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    # Neighbour discovery: without it a session cannot reach its IPv6 gateway at all.
    for type in router-solicitation neighbour-solicitation neighbour-advertisement; do
        "$ipt" -w -A SBX-INPUT -p ipv6-icmp --icmpv6-type "$type" -j RETURN
    done
    "$ipt" -w -A SBX-INPUT -j DROP
}

hook() {
    ipt="$1" chain="$2" target="$3"
    if ! "$ipt" -w -C "$chain" -i "$BRIDGE" -j "$target" 2>/dev/null; then
        "$ipt" -w -I "$chain" 1 -i "$BRIDGE" -j "$target"
        log "hooked $target into $chain ($ipt)"
    fi
}

V6_SIGNATURE=""
V6_MIN_DROPS="$(echo $BLOCKED6 | wc -w)"
LAST_ERROR=""
BOTH_WARNED=""

# Log a problem once, not on every re-check, until it changes.
problem() {
    if [ "$*" != "$LAST_ERROR" ]; then
        log "$*"
        LAST_ERROR="$*"
    fi
}

ensure_v6() {
    v4_backends="$1"
    IP6S="$(pick ip6tables)"
    forward_chain=DOCKER-USER
    if [ -z "$IP6S" ]; then
        # Docker's ip6tables support is off: hook FORWARD on the backend Docker uses
        # for IPv4.
        forward_chain=FORWARD
        for ipt in $v4_backends; do
            candidate="$(v6_of "$ipt")"
            if "$candidate" -w -n -L FORWARD >/dev/null 2>&1; then
                IP6S="$IP6S $candidate"
            fi
        done
        IP6S="$(echo $IP6S)"
    fi
    if [ -z "$IP6S" ]; then
        problem "no usable ip6tables ($(why_not ip6tables)); IPv6 on $BRIDGE is not filtered (the worker probe still checks it)"
        return 0
    fi
    hostnets="$(host_v6 | tr '\n' ' ')"
    signature="$IP6S $hostnets $EXTRA6"
    for IP6 in $IP6S; do
        # Remove the blanket IPv6 drop that earlier versions of this script installed.
        while "$IP6" -w -D "$forward_chain" -i "$BRIDGE" -j DROP 2>/dev/null; do
            log "removed the old blanket IPv6 drop from $forward_chain ($IP6)"
        done
        if [ "$signature" != "$V6_SIGNATURE" ] \
            || ! "$IP6" -w -n -L SBX-EGRESS >/dev/null 2>&1 \
            || [ "$("$IP6" -w -S SBX-EGRESS | grep -c DROP)" -lt "$V6_MIN_DROPS" ] \
            || ! "$IP6" -w -n -L SBX-INPUT >/dev/null 2>&1; then
            build_v6 "$IP6" "$hostnets"
            log "IPv6 rules installed with $IP6 into $forward_chain (api ${API_IP6:-none}, host prefixes: ${hostnets:-none}, extra: ${EXTRA6:-none})"
        fi
        hook "$IP6" "$forward_chain" SBX-EGRESS
        hook "$IP6" INPUT SBX-INPUT
    done
    V6_SIGNATURE="$signature"
}

ensure() {
    IPTS="$(pick iptables)"
    if [ -z "$IPTS" ]; then
        problem "error: no iptables backend has Docker's DOCKER-USER chain, so sessions are NOT isolated ($(why_not iptables)). Check that Docker's firewall is on and uses iptables: 'docker info | grep -i firewall' should show 'iptables' (Docker's nftables backend has no DOCKER-USER chain; firewall the session bridge on the host instead). Compare 'sudo iptables --version' on the host with SANDBOX_EGRESS_IPTABLES ($BACKEND). Retrying every ${INTERVAL}s"
        return 1
    fi
    case "$IPTS" in
        *" "*)
            if [ -z "$BOTH_WARNED" ]; then
                log "DOCKER-USER exists in more than one backend ($IPTS); installing rules in each. Set SANDBOX_EGRESS_IPTABLES to the host's backend to use only one"
                BOTH_WARNED=1
            fi
            ;;
    esac
    for IPT in $IPTS; do
        # Rebuild when a chain is missing or was emptied.
        if ! "$IPT" -w -n -L SBX-EGRESS >/dev/null 2>&1 \
            || [ "$("$IPT" -w -S SBX-EGRESS | grep -c DROP)" -lt 15 ] \
            || ! "$IPT" -w -n -L SBX-INPUT >/dev/null 2>&1; then
            build_v4 "$IPT"
            log "rules installed with $IPT (bridge $BRIDGE, api $API_IP)"
        fi
        hook "$IPT" DOCKER-USER SBX-EGRESS
        hook "$IPT" INPUT SBX-INPUT
    done
    ensure_v6 "$IPTS"
    LAST_ERROR=""
    return 0
}

log "starting (bridge $BRIDGE, api $API_IP ${API_IP6}, iptables backend $BACKEND, re-check every ${INTERVAL}s)"
# EGRESS_GUARD_ONCE=1: one pass, exit 0 when the IPv4 rules are in place (tests, checks).
if [ "${EGRESS_GUARD_ONCE:-0}" = "1" ]; then
    if ensure; then exit 0; else exit 1; fi
fi
while true; do
    ensure || true
    sleep "$INTERVAL"
done
