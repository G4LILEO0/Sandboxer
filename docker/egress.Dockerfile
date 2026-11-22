# Egress firewall for the session network (NFR-3). Runs with the host's network
# namespace and NET_ADMIN only; see docker/egress-guard.sh.
FROM alpine:3.20
# iptables-legacy too: hosts whose iptables is the legacy (x_tables) backend keep
# Docker's DOCKER-USER chain there, where the nf_tables binaries cannot see it.
RUN apk add --no-cache iptables ip6tables iptables-legacy tini
COPY docker/egress-guard.sh /usr/local/bin/egress-guard
RUN sed -i 's/\r$//' /usr/local/bin/egress-guard && chmod 755 /usr/local/bin/egress-guard
ENTRYPOINT ["tini", "--", "egress-guard"]
