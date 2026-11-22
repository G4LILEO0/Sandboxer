"""Egress isolation gate (NFR-3): the worker refuses to start sessions unless a probe from
the session network shows internal targets are unreachable."""

import pytest

import docker
from sandbox.config import Settings
from sandbox.orchestrator.docker_backend import (
    DockerBackend,
    EgressNotIsolated,
    SessionImageMissing,
)


def _backend(mode: str, probe) -> DockerBackend:
    backend = DockerBackend(Settings(_env_file=None, env="test", egress_guard=mode))
    calls = []

    def fake_probe():
        calls.append(1)
        return probe()

    backend._probe_egress = fake_probe
    backend.calls = calls
    return backend


def test_enforce_refuses_when_internal_targets_answer():
    backend = _backend("enforce", lambda: (["172.31.213.2:8000"], True, False))
    with pytest.raises(EgressNotIsolated, match="172.31.213.2:8000"):
        backend._check_egress()


def test_enforce_refuses_when_the_probe_itself_fails():
    def broken():
        raise RuntimeError("image missing")

    with pytest.raises(EgressNotIsolated, match="probe failed"):
        _backend("enforce", broken)._check_egress()


def test_passing_probe_is_cached():
    backend = _backend("enforce", lambda: ([], True, False))
    backend._check_egress()
    backend._check_egress()
    assert len(backend.calls) == 1


def test_failing_probe_is_not_cached():
    backend = _backend("warn", lambda: (["169.254.169.254:80"], True, False))
    backend._check_egress()  # warn mode logs and continues
    backend._check_egress()
    assert len(backend.calls) == 2


def test_off_skips_the_probe():
    backend = _backend("off", lambda: (["x:1"], False, False))
    backend._check_egress()
    assert backend.calls == []


def test_probe_targets_always_cover_api_and_host():
    targets = Settings(
        _env_file=None, egress_probe_extra_targets=["10.0.0.5:22"]
    ).egress_probe_targets()
    assert "172.31.213.2:8000" in targets
    assert "host.docker.internal:5432" in targets
    assert "169.254.169.254:80" in targets
    assert "10.0.0.5:22" in targets


def test_missing_session_image_is_reported_not_pulled():
    class Images:
        def get(self, name):
            raise docker.errors.ImageNotFound(name)

    class Client:
        images = Images()

    backend = DockerBackend(Settings(_env_file=None, env="test"), client=Client())
    with pytest.raises(SessionImageMissing, match="docker compose --profile build build"):
        backend._require_image("sandbox-session:latest")


# --- Docker socket access at worker start ----------------------------------------------


def _docker_error(cause: BaseException) -> docker.errors.DockerException:
    try:
        try:
            raise cause
        except OSError as exc:
            raise docker.errors.DockerException(
                f"Error while fetching server API version: ('Connection aborted.', {exc!r})"
            ) from exc
    except docker.errors.DockerException as wrapped:
        return wrapped


def test_socket_permission_error_points_at_selinux():
    from sandbox.orchestrator.docker_backend import explain_docker_error

    message = explain_docker_error(_docker_error(PermissionError(13, "Permission denied")))
    assert "/var/run/docker.sock" in message
    assert "SELinux" in message and "label=disable" in message
    assert "group_add" in message


def test_permission_error_seen_only_in_the_text_is_still_explained():
    from sandbox.orchestrator.docker_backend import explain_docker_error

    exc = docker.errors.DockerException(
        "Error while fetching server API version: ('Connection aborted.', "
        "PermissionError(13, 'Permission denied'))"
    )
    assert "SELinux" in explain_docker_error(exc, "unix:///run/docker.sock")
    assert "/run/docker.sock" in explain_docker_error(exc, "unix:///run/docker.sock")


def test_missing_socket_is_explained():
    from sandbox.orchestrator.docker_backend import explain_docker_error

    message = explain_docker_error(_docker_error(FileNotFoundError(2, "No such file or directory")))
    assert "No Docker socket" in message


def test_check_access_raises_a_clear_error():
    from sandbox.orchestrator.docker_backend import DockerUnavailable

    class Client:
        def ping(self):
            raise _docker_error(PermissionError(13, "Permission denied"))

    backend = DockerBackend(Settings(_env_file=None, env="test"), client=Client())
    with pytest.raises(DockerUnavailable, match="SELinux"):
        backend.check_access()


def test_compose_lets_the_worker_use_the_socket_under_selinux():
    from pathlib import Path

    compose = Path(__file__).resolve().parents[1] / "compose.yaml"
    if not compose.exists():
        pytest.skip("compose.yaml not in this checkout")
    import yaml

    services = yaml.safe_load(compose.read_text())["services"]
    assert "label=disable" in services["worker"]["security_opt"]
    assert not any(":z" in v or ":Z" in v for v in services["worker"]["volumes"])
    assert "SANDBOX_EGRESS_IPTABLES" in services["egress-guard"]["environment"]
