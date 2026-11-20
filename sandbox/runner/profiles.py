"""Browser profiles (CAP-10). The engine is always Chromium; the profile sets what the
page sees: user agent, platform hints and whether it looks like a phone.

Bot checks (Cloudflare and others) compare the user agent with the client hints the
browser sends (Sec-CH-UA*, navigator.userAgentData). Chromium derives the hints'
platform from the user agent but takes the version from itself, so the runner puts the
version of the Chromium it actually launched into the user agent (``user_agent_for``).
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BrowserProfile:
    name: str
    user_agent: str
    is_mobile: bool = False
    has_touch: bool = False
    device_scale_factor: float = 1.0
    # navigator.platform override, so platform-gated kits (macOS ClickFix) show real content.
    platform: str = ""
    description: str = ""

    def user_agent_for(self, browser_version: str | None) -> str:
        """The profile's user agent with the Chrome (and Edge) major version of the
        browser that is really running, in Chrome's reduced form (NNN.0.0.0)."""
        major = _major(browser_version)
        if not major or "Chrome/" not in self.user_agent:
            return self.user_agent
        ua = re.sub(r"Chrome/[\d.]+", f"Chrome/{major}.0.0.0", self.user_agent)
        return re.sub(r"Edg/[\d.]+", f"Edg/{major}.0.0.0", ua)


def _major(version: str | None) -> str | None:
    m = re.match(r"\s*(\d+)\.", version or "")
    return m.group(1) if m else None


_CHROME = "131.0.0.0"

PROFILES: dict[str, BrowserProfile] = {
    p.name: p
    for p in [
        BrowserProfile(
            "chrome-windows",
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Safari/537.36",
            platform="Win32",
            description="Chrome on Windows 10/11 desktop",
        ),
        BrowserProfile(
            "edge-windows",
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Safari/537.36 Edg/131.0.0.0",
            platform="Win32",
            description="Edge on Windows desktop",
        ),
        BrowserProfile(
            "chrome-mac",
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like "
            f"Gecko) Chrome/{_CHROME} Safari/537.36",
            platform="MacIntel",
            description="Chrome on macOS (opt-in macOS detonation profile, A16)",
        ),
        BrowserProfile(
            "chrome-linux",
            f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Safari/537.36",
            platform="Linux x86_64",
            description="Chrome on Linux desktop",
        ),
        BrowserProfile(
            "chrome-android",
            f"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Mobile Safari/537.36",
            is_mobile=True,
            has_touch=True,
            device_scale_factor=2.625,
            platform="Linux armv8l",
            description="Chrome on an Android phone (mobile viewport, touch)",
        ),
        BrowserProfile(
            "safari-iphone",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
            is_mobile=True,
            has_touch=True,
            device_scale_factor=3,
            platform="iPhone",
            description="iPhone user agent (rendered by Chromium)",
        ),
    ]
}


def get_profile(name: str) -> BrowserProfile:
    return PROFILES.get(name, PROFILES["chrome-windows"])
