# Disposable browser session (ORC-1). Runs as non-root with a read-only root filesystem;
# the orchestrator adds tmpfs mounts, drops all capabilities and sets no-new-privileges.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Live view stack for interactive sessions (INT-1): virtual display, VNC server, noVNC.
# xclip carries explicit analyst clipboard copies in and out (INT-7); VNC clipboard
# sync stays off (x11vnc -nosel).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tini xvfb x11vnc novnc websockify xclip fonts-liberation fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "playwright==1.49.1" "idna>=3.7" \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* /root/.cache

WORKDIR /app
# Only the runner and the shared URL/SSRF code; no API, database or analysis code.
COPY sandbox/__init__.py sandbox/__init__.py
COPY sandbox/core sandbox/core
COPY sandbox/runner sandbox/runner
COPY docker/session-entrypoint.sh /usr/local/bin/session-entrypoint

RUN useradd --uid 10002 --create-home --shell /usr/sbin/nologin runner \
    && chmod 755 /usr/local/bin/session-entrypoint \
    && mkdir /out && chown runner:runner /out

USER runner
ENV PYTHONPATH=/app HOME=/home/runner SANDBOX_OUT=/out
# Captures survive the container stopping so the orchestrator can copy them out; the
# volume is removed together with the container.
VOLUME /out
ENTRYPOINT ["tini", "--", "session-entrypoint"]
