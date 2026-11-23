"""Process configuration (NFR-9).

Static settings come from environment variables prefixed ``SANDBOX_``. Values that
analysts or admins change at runtime (weights, quotas, feed settings) belong in
Postgres, not here.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sandbox.core.urls import MAX_URL_LENGTH


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SANDBOX_", env_file=".env", extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: str = "postgresql+asyncpg://sandbox:sandbox@localhost:5432/sandbox"
    log_level: str = "INFO"

    # "dev" trusts X-Dev-User / X-Dev-Roles headers; "oidc" validates SSO tokens and
    # sessions against the configured issuer. Service tokens work in both modes.
    auth_mode: Literal["dev", "oidc"] = "dev"
    # Signs stream, embed, download and login-session tokens. Must be set in prod and be
    # the same on every API instance.
    secret_key: SecretStr = SecretStr("dev-insecure-secret-change-me")

    # OIDC single sign-on (ADM-1). Roles come from the ``oidc_roles_claim`` claim, mapped
    # through ``oidc_role_map`` (IdP group -> sandbox role) when given.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_url: str | None = None
    oidc_scopes: str = "openid email profile"
    oidc_roles_claim: str = "roles"
    oidc_role_map: dict[str, str] = Field(default_factory=dict)
    oidc_audience: str | None = None
    session_cookie_name: str = "sandbox_session"
    session_ttl_s: int = 8 * 3600

    max_url_length: int = MAX_URL_LENGTH
    # CIDRs that are refused in addition to every non-global address.
    ssrf_extra_blocked_cidrs: list[str] = Field(default_factory=list)
    # CIDRs exempted from the block, e.g. the local test server in integration tests.
    # Never set in production.
    ssrf_allowed_cidrs: list[str] = Field(default_factory=list)

    # External enrichment for the IoC lookup page (ANA-10). Unset keys disable that vendor.
    vt_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    # One abuse.ch Auth-Key (auth.abuse.ch) serves URLhaus, ThreatFox and MalwareBazaar.
    # A key set on a feed in Admin -> Feeds takes precedence.
    abusech_auth_key: SecretStr | None = None
    intel_timeout_s: float = 15.0
    # VirusTotal URL scans: how long to wait for a fresh submission to finish.
    vt_url_poll_attempts: int = 10
    vt_url_poll_interval_s: float = 2.0
    redirect_max_hops: int = 15

    # Artifact storage (local filesystem; the store interface allows S3 later). The
    # quarantine root holds downloaded files and is kept separate (NFR-5).
    artifact_root: str = "./var/artifacts"
    quarantine_root: str = "./var/quarantine"

    # Session containers (ORC-1, NFR-3).
    docker_url: str | None = None  # None: DOCKER_HOST or the local socket
    session_image: str = "sandbox-session:latest"
    pcap_image: str = "sandbox-pcap:latest"
    # Docker network the session containers join; the API must be on it for the live view.
    session_network: str = "sandbox_sessions"
    # Egress isolation (NFR-3). The session network is a bridge with a fixed interface
    # name and subnet so the egress-guard service (docker/egress-guard.sh) can firewall
    # it: sessions reach the public internet only. The API's fixed address on it is the
    # one host allowed to open connections to sessions (the live view).
    session_bridge: str = "sbx-sessions"
    session_subnet: str = "172.31.213.0/24"
    session_api_ip: str = "172.31.213.2"
    # IPv6 on the session network (a ULA subnet, NAT66 to the host's public IPv6). The
    # egress guard applies the IPv6 equivalents of the IPv4 blocks. "auto" gives a
    # session IPv6 only when the egress probe reached a public IPv6 address; on a host
    # without IPv6 routing, sessions run IPv4-only so nothing waits on a dead IPv6 path.
    # "on" always gives sessions IPv6; "off" never does.
    session_ipv6: Literal["auto", "on", "off"] = "auto"
    session_subnet_v6: str = "fd5b:d213:5e55::/64"
    session_api_ip6: str = "fd5b:d213:5e55::2"
    # Before starting sessions the worker runs a probe container on the session network
    # that tries to reach internal targets. "enforce" refuses to start sessions if any
    # answers, "warn" logs and continues, "off" skips the probe (tests only).
    egress_guard: Literal["enforce", "warn", "off"] = "enforce"
    # Extra host:port targets that must be unreachable; the API and the Docker host are
    # always probed.
    egress_probe_extra_targets: list[str] = Field(default_factory=list)
    # A public host:port that should be reachable; only reported, never enforced.
    egress_probe_public: str = "1.1.1.1:443"
    # The same over IPv6; with session_ipv6="auto" it decides whether sessions get IPv6.
    egress_probe_public6: str = "[2606:4700:4700::1111]:443"
    egress_probe_ttl_s: int = 300
    # "runsc" for gVisor where installed; None uses Docker's default runtime.
    session_runtime: str | None = None
    session_memory: str = "2g"
    session_cpus: float = 2.0
    session_pids_limit: int = 512
    capture_pcap: bool = True
    # Seconds an automated run watches the page after it loads.
    automated_observe_s: int = 20
    # Run automated sessions in a headed Chromium on a virtual display (Xvfb in the
    # session image) rather than headless. Bot checks (Cloudflare managed challenges,
    # Turnstile) block headless browsers much more often. False runs new headless mode.
    automated_headed: bool = True
    # Seconds an automated run waits for a Cloudflare-style bot check to clear (it ticks
    # the Turnstile box if it has to) before the run is recorded as blocked by it.
    antibot_wait_s: int = 45

    # --- Active-probe capture profiles (NFR-10 legal sign-off) --------------------------
    # These make the session *do* something a victim would, so they are OFF by default and
    # must be enabled deliberately after legal review. Each is recorded with the capture so
    # re-analysis stays reproducible, and none change page behaviour beyond observing it.
    #
    # Fill synthetic canary credentials into forms and submit, to trace where they go
    # (DE-PHI-003/004, DE-SKM-001). Submitting data to an attacker needs sign-off; the
    # canary mailbox must be one the MSOC controls. "off" | "automated" | "always".
    canary_fill: Literal["off", "automated", "always"] = "off"
    # Send a synthetic DevTools/context-menu key probe to see what the page blocks
    # (DE-EVA-001). Dispatches untrusted key events only; may trigger redirects.
    key_probe: bool = False
    # Expose a fake, keyless EIP-1193 wallet (window.ethereum) that logs and rejects every
    # signing/sending request, to observe drainer flows (DE-W3B-005/006). Touches no network
    # and holds no keys, but announcing a wallet is an interaction, so it is off by default.
    fake_wallet: bool = False
    # Register service workers and record their script URLs / push endpoints (DE-SCM-003).
    # Default off: service workers stay blocked (safer); turn on to observe push-abuse flows.
    allow_service_workers: bool = False
    # Directory with the noVNC client (e.g. /usr/share/novnc from the Debian "novnc"
    # package). When set, the API serves the live-view page from here and proxies only
    # the websocket, so no file from a session container is served on the API origin.
    # Unset: noVNC's files are proxied from the session container (type-checked).
    novnc_dir: str | None = None
    # Grace after the time limit before the reaper force-removes a container (ORC-5).
    reaper_grace_s: int = 60
    worker_id: str | None = None
    worker_poll_s: float = 2.0

    # Suricata over session pcaps (ANA-2). Empty disables it.
    suricata_image: str | None = None
    # Also run Suricata over the HTTPS requests in the HAR, rebuilt as plaintext HTTP
    # (sandbox/analysis/har_pcap.py), so HTTP rules match HTTPS traffic.
    suricata_decrypted_https: bool = True

    # RDAP lookups for domain registration age (CAP-8); empty disables.
    rdap_base_url: str | None = "https://rdap.org"

    # Bearer token required by /metrics when set (ADM-5).
    metrics_token: SecretStr | None = None
    # Extra origins allowed to frame the UI besides the embed page (normally none).
    ui_frame_ancestors: str = "'self'"

    def egress_probe_targets(self) -> list[str]:
        return [
            f"{self.session_api_ip}:8000",  # the API on the session network
            "host.docker.internal:8000",  # the Docker host (Docker Desktop), API port
            "host.docker.internal:5432",  # ...and Postgres
            "169.254.169.254:80",  # cloud metadata
            f"[{self.session_api_ip6}]:8000",  # the API over IPv6
            "[fd00:ec2::254]:80",  # cloud metadata over IPv6 (AWS)
            *self.egress_probe_extra_targets,
        ]

    @field_validator(
        "vt_api_key",
        "abuseipdb_api_key",
        "abusech_auth_key",
        "suricata_image",
        "novnc_dir",
        "metrics_token",
        "oidc_client_secret",
        mode="before",
    )
    @classmethod
    def _blank_key_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value


@lru_cache
def get_settings() -> Settings:
    return Settings()
