#!/bin/sh
# Starts the live-view stack for interactive sessions, then hands over to the runner.
set -eu

if [ "${SANDBOX_INTERACTIVE:-0}" = "1" ]; then
    export DISPLAY=:99
    Xvfb :99 -screen 0 "${SANDBOX_SCREEN:-1366x888x24}" -nolisten tcp >/tmp/xvfb.log 2>&1 &
    i=0
    while [ ! -e /tmp/.X11-unix/X99 ] && [ "$i" -lt 50 ]; do
        sleep 0.1; i=$((i + 1))
    done
    # VNC is reachable only from the session network, through the API's token-checked
    # proxy, and also needs this per-session password. -nosel turns off clipboard
    # exchange in both directions (INT-4).
    x11vnc -storepasswd "${SANDBOX_VNC_PASSWORD:?}" /tmp/vncpass >/dev/null 2>&1
    x11vnc -display :99 -forever -shared -rfbauth /tmp/vncpass -localhost -rfbport 5900 \
        -nosel -noxdamage -quiet >/tmp/x11vnc.log 2>&1 &
    websockify --web /usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &
    unset SANDBOX_VNC_PASSWORD
fi

exec python -m sandbox.runner
