"""Docker API filter that stands between the worker and the Docker socket (SR-19).

The worker used to mount ``/var/run/docker.sock`` as root, which is root on the host:
any bug in the code that parses hostile captures and feeds gave the host away. Now only
this small process holds the socket. The worker talks to it over TCP on a network that
nothing else joins, and it forwards a request only when it is one the worker's Docker
backend (``sandbox/orchestrator/docker_backend.py``) and Suricata runner
(``sandbox/analysis/suricata.py``) make:

* containers: list, create, inspect, start, stop, kill, wait, logs, archive copy in and
  out, exec, remove;
* the session network: inspect and create;
* images: inspect (never pull or build);
* ``/_ping`` and ``/version``.

An endpoint list alone is not enough, because ``POST /containers/create`` with a bind
mount of ``/`` or ``Privileged`` is host root as well. So the proxy also reads every
create body and allows only what the backend sends: an allowlisted image, a
``sandbox.role`` label, the session network (or none, or the network of a session
container for the pcap sidecar), no host mounts, devices, ports or host namespaces, no
capability but ``NET_RAW``, ``no-new-privileges`` as the only security option, IPv6
sysctls only, and an allowlisted runtime. Every request on an existing container or exec
must name a container that carries the ``sandbox.role`` label, so the worker cannot
reach the API, Postgres or the proxy itself. The path is rewritten to the full container
id the check resolved.

One request per client connection: the proxy forwards it with ``Connection: close`` and
then only relays the reply. The exec start call keeps its ``Upgrade`` header and is
relayed both ways, since Docker hijacks that connection for the exec's output.

Run: ``python -m sandbox.dockerproxy`` (as a user that can open the socket). Settings
come from the environment, see ``ProxyConfig.from_env``.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import logging
import os
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

log = logging.getLogger("sandbox.dockerproxy")

ROLE_LABEL = "sandbox.role"
ROLES = frozenset({"browser", "pcap", "egress-probe", "suricata"})
MAX_HEAD = 64 * 1024
MAX_JSON_BODY = 1024 * 1024
MAX_CHUNKED_BODY = 256 * 1024 * 1024


class Denied(Exception):
    """The request is not one the worker needs. The message goes back to the worker."""

    def __init__(self, reason: str, status: int = 403):
        super().__init__(reason)
        self.status = status


@dataclass(frozen=True)
class ProxyConfig:
    socket_path: str = "/var/run/docker.sock"
    listen_host: str = "0.0.0.0"  # noqa: S104 - an internal compose network only
    listen_port: int = 2375
    session_network: str = "sandbox_sessions"
    session_bridge: str = "sbx-sessions"
    images: frozenset[str] = field(default_factory=frozenset)
    runtimes: frozenset[str] = frozenset({"runc", "runsc"})

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ProxyConfig:
        env = dict(os.environ if env is None else env)
        images = env.get(
            "SANDBOX_PROXY_IMAGES", "sandbox-session:latest sandbox-pcap:latest"
        ).split()
        runtimes = env.get("SANDBOX_PROXY_RUNTIMES", "runc runsc").split()
        return cls(
            socket_path=env.get("SANDBOX_PROXY_SOCKET", cls.socket_path),
            listen_host=env.get("SANDBOX_PROXY_LISTEN", cls.listen_host),
            listen_port=int(env.get("SANDBOX_PROXY_PORT", cls.listen_port)),
            session_network=env.get("SANDBOX_SESSION_NETWORK", cls.session_network),
            session_bridge=env.get("SANDBOX_SESSION_BRIDGE", cls.session_bridge),
            images=frozenset(images),
            runtimes=frozenset(runtimes),
        )


# --- request rules -----------------------------------------------------------------

_ID = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_VERSION = re.compile(r"^/v\d+\.\d+(?=/)")

# (method, path pattern, kind). kind says which check runs before the request goes on.
ROUTES: list[tuple[frozenset[str], re.Pattern[str], str]] = [
    (frozenset({"GET", "HEAD"}), re.compile(r"/_ping"), "open"),
    (frozenset({"GET"}), re.compile(r"/version"), "open"),
    (frozenset({"GET"}), re.compile(r"/containers/json"), "open"),
    (frozenset({"POST"}), re.compile(r"/containers/create"), "create"),
    (frozenset({"GET"}), re.compile(rf"/containers/(?P<id>{_ID})/(json|logs)"), "container"),
    (
        frozenset({"POST"}),
        re.compile(rf"/containers/(?P<id>{_ID})/(start|stop|kill|wait)"),
        "container",
    ),
    (
        frozenset({"GET", "HEAD", "PUT"}),
        re.compile(rf"/containers/(?P<id>{_ID})/archive"),
        "container",
    ),
    (frozenset({"POST"}), re.compile(rf"/containers/(?P<id>{_ID})/exec"), "exec-create"),
    (frozenset({"DELETE"}), re.compile(rf"/containers/(?P<id>{_ID})"), "container"),
    (frozenset({"POST"}), re.compile(rf"/exec/(?P<id>{_ID})/start"), "exec"),
    (frozenset({"GET"}), re.compile(rf"/exec/(?P<id>{_ID})/json"), "exec"),
    (frozenset({"GET"}), re.compile(rf"/networks/(?P<id>{_ID})"), "open"),
    (frozenset({"POST"}), re.compile(r"/networks/create"), "network-create"),
    # Image names keep their "/" and ":" in docker-py's URLs.
    (frozenset({"GET"}), re.compile(r"/images/(?P<id>[A-Za-z0-9][A-Za-z0-9_./:@-]*)/json"), "open"),
]


def match_route(method: str, path: str) -> tuple[str, str | None, str]:
    """``(kind, id, path without the API version)`` for an allowed request, else Denied."""
    if "%" in path or ".." in path or "//" in path or "\\" in path:
        raise Denied(f"path not allowed: {path}")
    bare = _VERSION.sub("", path, count=1)
    for methods, pattern, kind in ROUTES:
        m = pattern.fullmatch(bare)
        if m:
            if method not in methods:
                break
            return kind, m.groupdict().get("id"), bare
    raise Denied(f"{method} {bare} is not an API call the worker uses")


def _empty(value: object) -> bool:
    return value in (None, False, 0, "", [], {})


# HostConfig fields the backend sets, and what each may hold. Any other field must be
# absent or empty, so a field Docker adds later is refused until it is reviewed here.
_FREE_HOST_FIELDS = frozenset(
    {
        "CapDrop",
        "Memory",
        "MemorySwap",
        "NanoCpus",
        "PidsLimit",
        "ShmSize",
        "ReadonlyRootfs",
        "Tmpfs",
        "ExtraHosts",
        "LogConfig",
        "RestartPolicy",
        "AutoRemove",
        "Init",
    }
)
_SECURITY_OPTS = frozenset(
    {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
)
_CAPS = frozenset({"NET_RAW", "CAP_NET_RAW"})


def check_create(body: dict, cfg: ProxyConfig, network_owner_role: str | None) -> None:
    """Refuse a container that could reach the host. ``network_owner_role`` is the role
    label of the container named by a ``container:<id>`` network mode (None if absent)."""
    if not isinstance(body, dict):
        raise Denied("create body is not a JSON object", 400)
    image = body.get("Image")
    if image not in cfg.images:
        raise Denied(f"image {image!r} is not one the sandbox runs")
    role = (body.get("Labels") or {}).get(ROLE_LABEL)
    if role not in ROLES:
        raise Denied(f"container has no {ROLE_LABEL} label of a known role")
    host = body.get("HostConfig") or {}
    if not isinstance(host, dict):
        raise Denied("HostConfig is not an object", 400)
    for key, value in host.items():
        if key in _FREE_HOST_FIELDS or _empty(value):
            continue
        if key == "NetworkMode":
            continue  # below
        if key == "CapAdd":
            extra = set(value) - _CAPS
            if extra:
                raise Denied(f"capabilities not allowed: {sorted(extra)}")
            continue
        if key == "SecurityOpt":
            extra = set(value) - _SECURITY_OPTS
            if extra:
                raise Denied(f"security options not allowed: {sorted(extra)}")
            continue
        if key == "Sysctls":
            bad = [k for k in value if not k.startswith("net.ipv6.conf.")]
            if bad:
                raise Denied(f"sysctls not allowed: {bad}")
            continue
        if key == "Runtime":
            if value not in cfg.runtimes:
                raise Denied(f"runtime {value!r} not allowed")
            continue
        raise Denied(f"HostConfig.{key} is not allowed")

    mode = host.get("NetworkMode") or "default"
    if mode == cfg.session_network or mode == "none":
        pass
    elif mode in ("default", "bridge"):
        if not body.get("NetworkDisabled"):
            raise Denied("containers must join the session network or have no network")
    elif mode.startswith("container:"):
        if network_owner_role != "browser":
            raise Denied("only a session container's network may be shared")
    else:
        raise Denied(f"network mode {mode!r} not allowed")

    endpoints = (body.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}
    for name, endpoint in endpoints.items():
        if name not in (cfg.session_network, mode):
            raise Denied(f"network {name!r} not allowed")
        for key, value in (endpoint or {}).items():
            if key not in ("Aliases", "NetworkID") and not _empty(value):
                raise Denied(f"endpoint setting {key} not allowed (fixed addresses are)")


def check_exec_create(body: dict) -> None:
    if not isinstance(body, dict):
        raise Denied("exec body is not a JSON object", 400)
    if body.get("Privileged"):
        raise Denied("privileged exec is not allowed")


def check_network_create(body: dict, cfg: ProxyConfig) -> None:
    if not isinstance(body, dict):
        raise Denied("network body is not a JSON object", 400)
    if body.get("Name") != cfg.session_network:
        raise Denied("only the session network may be created")
    if body.get("Driver") not in (None, "bridge"):
        raise Denied("the session network is a bridge")
    options = body.get("Options") or {}
    if options and options != {"com.docker.network.bridge.name": cfg.session_bridge}:
        raise Denied("network options not allowed")
    if body.get("ConfigFrom") or body.get("ConfigOnly") or body.get("Ingress"):
        raise Denied("network settings not allowed")


# --- upstream -------------------------------------------------------------------------


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("docker", timeout=30)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _inspect(cfg: ProxyConfig, path: str) -> dict | None:
    conn = _UnixHTTPConnection(cfg.socket_path)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        data = res.read()
        if res.status == 404:
            return None
        if res.status != 200:
            raise Denied(f"upstream inspect failed ({res.status})", 502)
        return json.loads(data)
    finally:
        conn.close()


async def managed_container(cfg: ProxyConfig, ref: str) -> tuple[str, str]:
    """``(full id, role)`` of a sandbox container, else Denied (404 when it is gone)."""
    info = await asyncio.to_thread(_inspect, cfg, f"/containers/{quote(ref, safe='')}/json")
    if info is None:
        raise Denied(f"No such container: {ref}", 404)
    role = ((info.get("Config") or {}).get("Labels") or {}).get(ROLE_LABEL)
    if role not in ROLES:
        raise Denied(f"container {ref} is not a sandbox container")
    return info["Id"], role


async def managed_exec(cfg: ProxyConfig, exec_id: str) -> None:
    info = await asyncio.to_thread(_inspect, cfg, f"/exec/{quote(exec_id, safe='')}/json")
    if info is None:
        raise Denied(f"No such exec instance: {exec_id}", 404)
    await managed_container(cfg, info.get("ContainerID", ""))


# --- HTTP plumbing -------------------------------------------------------------------


async def _read_head(reader: asyncio.StreamReader) -> tuple[str, str, str, list[tuple[str, str]]]:
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError:
        raise Denied("request head too large", 431) from None
    lines = raw[:-4].decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise Denied("bad request line", 400)
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise Denied("bad header", 400)
        headers.append((name, value.strip()))
    return parts[0], parts[1], parts[2], headers


async def _read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    body = bytearray()
    while True:
        size_line = await reader.readuntil(b"\r\n")
        size = int(size_line.split(b";")[0].strip(), 16)
        if size == 0:
            while await reader.readuntil(b"\r\n") != b"\r\n":
                pass  # trailers
            return bytes(body)
        if len(body) + size > limit:
            raise Denied("request body too large", 413)
        body += await reader.readexactly(size)
        await reader.readexactly(2)


def _reply(status: int, message: str) -> bytes:
    body = json.dumps({"message": message}).encode()
    reason = http.client.responses.get(status, "Error")
    return (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if writer.can_write_eof():
                writer.write_eof()


_HOP = frozenset({"connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"})


class DockerProxy:
    def __init__(self, cfg: ProxyConfig):
        self.cfg = cfg

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            await self._handle(reader, writer)
        except Denied as exc:
            # A 404 is a container that is already gone, which the backend expects.
            log.log(
                logging.INFO if exc.status == 404 else logging.WARNING, "denied %s: %s", peer, exc
            )
            with contextlib.suppress(Exception):
                writer.write(_reply(exc.status, str(exc)))
                await writer.drain()
        except (PermissionError, FileNotFoundError) as exc:
            # The worker turns this into its operator message (explain_docker_error).
            message = f"docker-proxy cannot open the Docker socket {self.cfg.socket_path}: {exc!r}"
            log.error("%s", message)
            with contextlib.suppress(Exception):
                writer.write(_reply(502, message))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception:
            log.exception("proxy error")
            with contextlib.suppress(Exception):
                writer.write(_reply(502, "docker proxy error"))
                await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        method, target, version, headers = await _read_head(reader)
        url = urlsplit(target)
        if url.scheme or url.netloc or url.fragment:
            raise Denied("absolute URLs are not allowed", 400)
        kind, ref, bare = match_route(method, url.path)

        lower = {}
        for name, value in headers:
            lower.setdefault(name.lower(), []).append(value)
        lengths = lower.get("content-length", [])
        chunked = any("chunked" in v.lower() for v in lower.get("transfer-encoding", []))
        if len(lengths) > 1 or (lengths and chunked):
            raise Denied("ambiguous request length", 400)
        if lower.get("transfer-encoding") and not chunked:
            raise Denied("unsupported transfer encoding", 400)
        length = int(lengths[0]) if lengths else 0
        if length < 0:
            raise Denied("bad Content-Length", 400)

        needs_body = kind in ("create", "exec-create", "network-create")
        body: bytes | None = None
        if needs_body or chunked:
            limit = MAX_JSON_BODY if needs_body else MAX_CHUNKED_BODY
            if chunked:
                body = await _read_chunked(reader, limit)
            elif length > limit:
                raise Denied("request body too large", 413)
            else:
                body = await reader.readexactly(length)

        path = bare
        upgrade = False
        if kind == "create":
            data = _json(body)
            mode = (
                ((data.get("HostConfig") or {}).get("NetworkMode") or "")
                if isinstance(data, dict)
                else ""
            )
            owner_role = None
            if mode.startswith("container:"):
                with contextlib.suppress(Denied):
                    full, owner_role = await managed_container(self.cfg, mode.split(":", 1)[1])
                    data["HostConfig"]["NetworkMode"] = f"container:{full}"
                    body = json.dumps(data).encode()
            check_create(data, self.cfg, owner_role)
        elif kind == "network-create":
            check_network_create(_json(body), self.cfg)
        elif kind in ("container", "exec-create"):
            full, _ = await managed_container(self.cfg, ref or "")
            path = bare.replace(f"/containers/{ref}", f"/containers/{full}", 1)
            if kind == "exec-create":
                check_exec_create(_json(body))
        elif kind == "exec":
            await managed_exec(self.cfg, ref or "")
            upgrade = bare.endswith("/start")

        up_reader, up_writer = await asyncio.open_unix_connection(self.cfg.socket_path)
        try:
            out = [f"{method} {path}{'?' + url.query if url.query else ''} {version}"]
            for name, value in headers:
                n = name.lower()
                if n in _HOP or n in ("content-length", "transfer-encoding"):
                    if upgrade and n in ("connection", "upgrade"):
                        out.append(f"{name}: {value}")
                    continue
                out.append(f"{name}: {value}")
            if not upgrade:
                out.append("Connection: close")
            if body is not None:
                out.append(f"Content-Length: {len(body)}")
            elif length:
                out.append(f"Content-Length: {length}")
            up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
            if body is not None:
                up_writer.write(body)
            await up_writer.drain()
            log.log(logging.DEBUG if bare == "/_ping" else logging.INFO, "%s %s", method, bare)

            to_client = asyncio.create_task(_pipe(up_reader, writer))
            if body is None and length:
                await _copy_exact(reader, up_writer, length)
            if upgrade:
                to_upstream = asyncio.create_task(_pipe(reader, up_writer))
                await to_client
                to_upstream.cancel()
            else:
                await to_client
        finally:
            with contextlib.suppress(Exception):
                up_writer.close()


async def _copy_exact(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, n: int) -> None:
    while n > 0:
        data = await reader.read(min(n, 65536))
        if not data:
            raise asyncio.IncompleteReadError(b"", n)
        writer.write(data)
        await writer.drain()
        n -= len(data)


def _json(body: bytes | None) -> dict:
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        raise Denied("body is not JSON", 400) from None
    if not isinstance(data, dict):
        raise Denied("body is not a JSON object", 400)
    return data


async def serve(cfg: ProxyConfig) -> None:
    proxy = DockerProxy(cfg)
    server = await asyncio.start_server(
        proxy.handle, cfg.listen_host, cfg.listen_port, limit=MAX_HEAD
    )
    log.info(
        "docker proxy on %s:%s for %s; images: %s",
        cfg.listen_host,
        cfg.listen_port,
        cfg.socket_path,
        " ".join(sorted(cfg.images)),
    )
    async with server:
        await server.serve_forever()


def check(cfg: ProxyConfig) -> int:
    """Health check: the proxy answers and Docker behind it answers ``/_ping``."""
    conn = http.client.HTTPConnection("127.0.0.1", cfg.listen_port, timeout=5)
    try:
        conn.request("GET", "/_ping")
        return 0 if conn.getresponse().status == 200 else 1
    except OSError:
        return 1
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> None:
    import sys

    argv = sys.argv[1:] if argv is None else argv
    cfg = ProxyConfig.from_env()
    if argv == ["--check"]:
        raise SystemExit(check(cfg))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(serve(cfg))


if __name__ == "__main__":
    main()
