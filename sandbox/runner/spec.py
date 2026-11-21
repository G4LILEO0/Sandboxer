"""What the orchestrator tells a runner to do. Passed as JSON in ``SANDBOX_RUN_SPEC``."""

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RunSpec:
    analysis_id: str
    url: str
    interactive: bool = False
    # Automated runs: a headed browser on the session's virtual display (Xvfb) instead of
    # headless, which bot checks such as Cloudflare's are far more likely to let through.
    headed: bool = False
    # Seconds an automated run waits for a bot-check page (Cloudflare "Just a moment...")
    # to clear before it gives up and records the run as blocked.
    antibot_wait_s: int = 45
    # Hard cap for the runner itself; the orchestrator normally stops it first.
    time_limit_s: int = 600
    observe_s: int = 20
    locale: str = "en-US"
    timezone: str = "UTC"
    viewport_width: int = 1366
    viewport_height: int = 768
    user_agent_profile: str = "chrome-windows"
    max_body_bytes: int = 2 * 1024 * 1024
    max_screenshots: int = 60
    screenshot_interval_s: int = 5
    ssrf_extra_blocked_cidrs: list[str] = field(default_factory=list)
    ssrf_allowed_cidrs: list[str] = field(default_factory=list)
    # Active-probe capture (off by default; need legal sign-off, see config.py).
    canary_fill: str = "off"  # off | automated | always
    key_probe: bool = False
    fake_wallet: bool = False
    allow_service_workers: bool = False

    @classmethod
    def from_json(cls, raw: str) -> "RunSpec":
        data: dict[str, Any] = json.loads(raw)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_json(self) -> str:
        return json.dumps(asdict(self))
