"""Browser profiles (CAP-10). The engine is always Chromium; the profile sets what the
page sees: user agent, platform hints and whether it looks like a phone."""

from dataclasses import dataclass


@dataclass(frozen=True)
class BrowserProfile:
    name: str
    user_agent: str
    is_mobile: bool = False
    has_touch: bool = False
    device_scale_factor: float = 1.0
    description: str = ""


_CHROME = "131.0.0.0"

PROFILES: dict[str, BrowserProfile] = {
    p.name: p
    for p in [
        BrowserProfile(
            "chrome-windows",
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Safari/537.36",
            description="Chrome on Windows 10/11 desktop",
        ),
        BrowserProfile(
            "edge-windows",
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Safari/537.36 Edg/131.0.0.0",
            description="Edge on Windows desktop",
        ),
        BrowserProfile(
            "chrome-mac",
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like "
            f"Gecko) Chrome/{_CHROME} Safari/537.36",
            description="Chrome on macOS",
        ),
        BrowserProfile(
            "chrome-linux",
            f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Safari/537.36",
            description="Chrome on Linux desktop",
        ),
        BrowserProfile(
            "chrome-android",
            f"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_CHROME} Mobile Safari/537.36",
            is_mobile=True,
            has_touch=True,
            device_scale_factor=2.625,
            description="Chrome on an Android phone (mobile viewport, touch)",
        ),
        BrowserProfile(
            "safari-iphone",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
            is_mobile=True,
            has_touch=True,
            device_scale_factor=3,
            description="iPhone user agent (rendered by Chromium)",
        ),
    ]
}


def get_profile(name: str) -> BrowserProfile:
    return PROFILES.get(name, PROFILES["chrome-windows"])
