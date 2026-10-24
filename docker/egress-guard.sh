#!/bin/sh
# Egress firewall for the session network (NFR-3, docs/operations.md).
#
# Runs on the Docker host's network namespace with NET_ADMIN and installs rules on the
# session bridge so session containers reach the public internet only:
#
#   - replies to connections the API opened (the live view) are allowed;
#   - the API may open connections to sessions on the live-view port, nothing else may;
#   - new connections from sessions to private, loopback, link-local (cloud metadata),
#     CGNAT, multicast and reserved ranges are dropped: that covers the host, the API,
#     Postgres, other sessions and the office network;
#   - anything addressed to the host itself from the bridge is dropped (INPUT);
#   - all IPv6 forwarding from the bridge is dropped.
#
# Rules live in their own chains (SBX-EGRESS, SBX-INPUT), hooked from DOCKER-USER and
# INPUT. The script re-checks every few seconds and restores them if Docker or anyone
# else removed them. The worker independently probes the result before every batch of
# sessions and refuses to start sessions if internal targets answer.
set -eu

BRIDGE="${SANDBOX_SESSION_BRIDGE:-sbx-sessions}"
API_IP="${SANDBOX_SESSION_API_IP:?set SANDBOX_SESSION_API_IP}"
STREAM_PORT="${SANDBOX_STREAM_PORT:-6080}"
INTERVAL="${EGRESS_GUARD_INTERVAL_S:-10}"
BLOCKED="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"

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

# Bridged traffic between containers only meets iptables with br_netfilter on (Docker
# turns it on itself; the worker's probe catches the case where it is off).
if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" != "1" ]; then
    log "warning: net.bridge.bridge-nf-call-iptables is not 1; session-to-API traffic on the bridge may bypass these rules"
fi

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

hook() {
    ipt="$1" chain="$2" target="$3"
    if ! "$ipt" -w -C "$chain" -i "$BRIDGE" -j "$target" 2>/dev/null; then
        "$ipt" -w -I "$chain" 1 -i "$BRIDGE" -j "$target"
        log "hooked $target into $chain ($ipt)"
    fi
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

    IP6="$(pick ip6tables ip6tables-nft ip6tables-legacy)"
    if [ -n "$IP6" ] && ! "$IP6" -w -C DOCKER-USER -i "$BRIDGE" -j DROP 2>/dev/null; then
        "$IP6" -w -I DOCKER-USER 1 -i "$BRIDGE" -j DROP && log "IPv6 forwarding from $BRIDGE dropped"
    fi
    return 0
}

log "starting (bridge $BRIDGE, api $API_IP, re-check every ${INTERVAL}s)"
while true; do
    ensure || true
    sleep "$INTERVAL"
done
