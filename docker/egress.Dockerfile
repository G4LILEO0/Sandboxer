# Egress firewall for the session network (NFR-3). Runs with the host's network
# namespace and NET_ADMIN only; see docker/egress-guard.sh.
FROM alpine:3.20
RUN apk add --no-cache iptables ip6tables tini
COPY docker/egress-guard.sh /usr/local/bin/egress-guard
RUN sed -i 's/\r$//' /usr/local/bin/egress-guard && chmod 755 /usr/local/bin/egress-guard
ENTRYPOINT ["tini", "--", "egress-guard"]
