"""Docker API filter in front of the socket (SR-19, sandbox/dockerproxy.py).

The create bodies here come from docker-py itself, driven by the real session backend
and Suricata runner, so a change in what they send shows up as a refused call."""

from datetime import UTC, datetime, timedelta

import pytest

import docker
from sandbox.config import Settings
from sandbox.dockerproxy import (
    Denied,
    ProxyConfig,
    check_create,
    check_exec_create,
    check_network_create,
    match_route,
)
from sandbox.orchestrator.backend import SessionSpec
from sandbox.orchestrator.docker_backend import DockerBackend

CFG = ProxyConfig(
    images=frozenset({"sandbox-session:latest", "sandbox-pcap:latest", "jasonish/suricata:7.0"})
)


class _Capture:
    """A docker-py client whose API layer records bodies instead of calling Docker."""

    def __init__(self):
        self.client = docker.DockerClient(base_url="tcp://127.0.0.1:9", version="1.44")
        self.creates: list[dict] = []
        self.networks: list[dict] = []
        api = self.client.api

        def create_from_config(config, name=None, platform=None):
            self.creates.append(config)
            return {"Id": f"c{len(self.creates)}"}

        def create_network(name, **kwargs):
            # Build the body the way docker-py does, then record it.
            body = {"Name": name, "Driver": kwargs.get("driver"), "Options": kwargs.get("options")}
            self.networks.append(body)
            return {"Id": "n1"}

        api.create_container_from_config = create_from_config
        api.start = lambda *a, **k: None
        api.inspect_container = lambda cid: {"Id": cid, "Name": "/x", "Config": {"Labels": {}}}
        api.inspect_image = lambda name: {"Id": "sha256:1"}
        api.inspect_network = lambda *a, **k: {"Id": "n1", "EnableIPv6": False}


def _session_bodies(**settings) -> list[dict]:
    cap = _Capture()
    backend = DockerBackend(
        Settings(_env_file=None, env="test", egress_guard="off", **settings), client=cap.client
    )
    spec = SessionSpec(
        session_id="se_1",
        analysis_id="an_1",
        url="https://example.com/",
        interactive=True,
        time_limit_s=60,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    backend._start(spec)
    return cap.creates


def test_session_and_pcap_containers_pass():
    browser, pcap = _session_bodies()
    check_create(browser, CFG, None)
    # The sidecar shares the browser container's network namespace.
    assert pcap["HostConfig"]["NetworkMode"].startswith("container:")
    check_create(pcap, CFG, "browser")


def test_gvisor_session_passes():
    (browser, _pcap) = _session_bodies(session_runtime="runsc")
    assert browser["HostConfig"]["Runtime"] == "runsc"
    check_create(browser, CFG, None)


def test_egress_probe_passes():
    cap = _Capture()
    backend = DockerBackend(Settings(_env_file=None, env="test"), client=cap.client)
    api = cap.client.api
    api.wait = lambda *a, **k: {"StatusCode": 0}
    api.logs = lambda *a, **k: b'{"leaks": [], "public": true}\n'
    api.remove_container = lambda *a, **k: None
    backend._probe_egress()
    check_create(cap.creates[0], CFG, None)


def test_suricata_container_passes(tmp_path):
    import unittest.mock as mock

    from sandbox.analysis import suricata

    cap = _Capture()
    api = cap.client.api
    api.put_archive = mock.Mock(side_effect=RuntimeError("stop here"))
    api.remove_container = lambda *a, **k: None
    rules = tmp_path / "r.rules"
    rules.write_text("")

    class S:
        docker_url = "tcp://127.0.0.1:9"

    with (
        mock.patch.object(docker, "DockerClient", return_value=cap.client),
        pytest.raises(RuntimeError, match="stop here"),
    ):
        suricata._run(S(), "jasonish/suricata:7.0", rules, [])
    check_create(cap.creates[0], CFG, None)


def _browser() -> dict:
    return _session_bodies()[0]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Privileged", True),
        ("Binds", ["/:/host"]),
        ("Mounts", [{"Type": "bind", "Source": "/", "Target": "/host"}]),
        ("Devices", [{"PathOnHost": "/dev/sda"}]),
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("UsernsMode", "host"),
        ("CgroupnsMode", "host"),
        ("PortBindings", {"8000/tcp": [{"HostPort": "8000"}]}),
        ("VolumesFrom", ["sandbox-api-1"]),
        ("CapAdd", ["SYS_ADMIN"]),
        ("SecurityOpt", ["seccomp=unconfined"]),
        ("SecurityOpt", ["label=disable"]),
        ("Sysctls", {"kernel.core_pattern": "|/bin/sh"}),
        ("Runtime", "kata"),
        ("NetworkMode", "host"),
        ("NetworkMode", "sandbox_default"),
        ("CgroupParent", "/"),
    ],
)
def test_host_escapes_are_refused(field, value):
    body = _browser()
    body["HostConfig"][field] = value
    with pytest.raises(Denied):
        check_create(body, CFG, None)


def test_unknown_image_and_missing_label_are_refused():
    body = _browser()
    body["Image"] = "alpine:latest"
    with pytest.raises(Denied, match="image"):
        check_create(body, CFG, None)
    body = _browser()
    del body["Labels"]["sandbox.role"]
    with pytest.raises(Denied, match="label"):
        check_create(body, CFG, None)


def test_sharing_a_non_session_network_namespace_is_refused():
    _browser_body, pcap = _session_bodies()
    with pytest.raises(Denied):
        check_create(pcap, CFG, None)  # the target is not a sandbox container
    with pytest.raises(Denied):
        check_create(pcap, CFG, "pcap")


def test_fixed_session_address_is_refused():
    body = _browser()
    body["NetworkingConfig"] = {
        "EndpointsConfig": {"sandbox_sessions": {"IPAMConfig": {"IPv4Address": "172.31.213.2"}}}
    }
    with pytest.raises(Denied, match="fixed"):
        check_create(body, CFG, None)


def test_routes():
    assert match_route("GET", "/v1.44/_ping")[0] == "open"
    assert match_route("POST", "/v1.44/containers/create")[0] == "create"
    assert match_route("DELETE", "/v1.44/containers/abc")[:2] == ("container", "abc")
    assert match_route("PUT", "/v1.44/containers/abc/archive")[0] == "container"
    assert match_route("POST", "/v1.44/exec/e1/start")[:2] == ("exec", "e1")
    assert match_route("GET", "/v1.44/images/jasonish/suricata:7.0/json")[0] == "open"
    for method, path in [
        ("POST", "/v1.44/images/create"),  # pull
        ("POST", "/v1.44/build"),
        ("POST", "/v1.44/containers/abc/update"),
        ("POST", "/v1.44/containers/abc/attach"),
        ("GET", "/v1.44/info"),
        ("POST", "/v1.44/volumes/create"),
        ("GET", "/v1.44/containers/abc/../../info"),
        ("GET", "/v1.44/containers/abc%2f..%2f/json"),
        ("POST", "/v1.44/swarm/init"),
        ("POST", "/v1.44/plugins/pull"),
        ("DELETE", "/v1.44/networks/sandbox_sessions"),
    ]:
        with pytest.raises(Denied):
            match_route(method, path)


def test_exec_and_network_bodies():
    check_exec_create({"Cmd": ["xclip", "-o"], "User": "runner", "Privileged": False})
    with pytest.raises(Denied):
        check_exec_create({"Cmd": ["sh"], "Privileged": True})
    check_network_create(
        {
            "Name": "sandbox_sessions",
            "Driver": "bridge",
            "Options": {"com.docker.network.bridge.name": "sbx-sessions"},
        },
        CFG,
    )
    with pytest.raises(Denied):
        check_network_create({"Name": "other", "Driver": "bridge"}, CFG)
    with pytest.raises(Denied):
        check_network_create(
            {"Name": "sandbox_sessions", "Driver": "macvlan", "Options": {"parent": "eth0"}}, CFG
        )
