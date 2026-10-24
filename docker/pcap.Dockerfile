# Packet-capture sidecar (CAP-3). Shares the session container's network namespace and
# holds the only extra capability (NET_RAW), so the browser container needs none.
FROM alpine:3.20
RUN apk add --no-cache tcpdump tini && mkdir /out
VOLUME /out
# The live-view port is excluded: it carries the analyst's screen, not the page's traffic.
# No -Z: with every capability but NET_RAW dropped, tcpdump cannot (and need not) setuid.
ENTRYPOINT ["tini", "--", "tcpdump", "-i", "eth0", "-U", "-s", "0", "-w", "/out/capture.pcap", "not", "port", "6080"]
