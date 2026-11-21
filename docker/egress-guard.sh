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
# Rules live in their own chains (SBX-EGRESS, SBX-INPUT in iptables and ip6tables),
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

# Use the iptables flavour Docker itself uses: the one where DOCKER-USER exists.
pick() {
    for candidate in "$@"; do
        if "$candidate" -w -n -L DOCKER-USER >/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
}

# ip6tables without DOCKER-USER (Docker's ip6tables support off): hook FORWARD instead.
pick_any() {
    for candidate in "$@"; do
        if "$candidate" -w -n -L FORWARD >/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
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

ensure_v6() {
    IP6="$(pick ip6tables ip6tables-nft ip6tables-legacy)"
    forward_chain=DOCKER-USER
    if [ -z "$IP6" ]; then
        IP6="$(pick_any ip6tables ip6tables-nft ip6tables-legacy)"
        forward_chain=FORWARD
    fi
    if [ -z "$IP6" ]; then
        log "no ip6tables available; IPv6 on $BRIDGE is not filtered (the worker probe still checks it)"
        return 0
    fi
    # Remove the blanket IPv6 drop that earlier versions of this script installed.
    while "$IP6" -w -D "$forward_chain" -i "$BRIDGE" -j DROP 2>/dev/null; do
        log "removed the old blanket IPv6 drop from $forward_chain"
    done
    hostnets="$(host_v6 | tr '\n' ' ')"
    signature="$IP6 $hostnets $EXTRA6"
    if [ "$signature" != "$V6_SIGNATURE" ] \
        || ! "$IP6" -w -n -L SBX-EGRESS >/dev/null 2>&1 \
        || [ "$("$IP6" -w -S SBX-EGRESS | grep -c DROP)" -lt "$V6_MIN_DROPS" ] \
        || ! "$IP6" -w -n -L SBX-INPUT >/dev/null 2>&1; then
        build_v6 "$IP6" "$hostnets"
        V6_SIGNATURE="$signature"
        log "IPv6 rules installed with $IP6 (api ${API_IP6:-none}, host prefixes: ${hostnets:-none}, extra: ${EXTRA6:-none})"
    fi
    hook "$IP6" "$forward_chain" SBX-EGRESS
    hook "$IP6" INPUT SBX-INPUT
}

ensure() {
    IPT="$(pick iptables iptables-nft iptables-legacy)"
    if [ -z "$IPT" ]; then
        log "no DOCKER-USER chain yet (is Docker's firewall enabled?); retrying"
        return 1
    fi
    # Rebuild when a chain is missing or was emptied.
    if ! "$IPT" -w -n -L SBX-EGRESS >/dev/null 2>&1 \
        || [ "$("$IPT" -w -S SBX-EGRESS | grep -c DROP)" -lt 15 ] \
        || ! "$IPT" -w -n -L SBX-INPUT >/dev/null 2>&1; then
        build_v4 "$IPT"
        log "rules installed with $IPT (bridge $BRIDGE, api $API_IP)"
    fi
    hook "$IPT" DOCKER-USER SBX-EGRESS
    hook "$IPT" INPUT SBX-INPUT
    ensure_v6
    return 0
}

log "starting (bridge $BRIDGE, api $API_IP ${API_IP6}, re-check every ${INTERVAL}s)"
while true; do
    ensure || true
    sleep "$INTERVAL"
done
