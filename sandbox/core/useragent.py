"""The user agent every outbound HTTP request presents.

Phishing kits and cloakers serve a decoy (or nothing) to clients that do not look like
a browser, so the redirect walk, feed downloads, webhooks and vendor lookups all send
the same desktop Chrome user agent as the default detonation profile
(``sandbox.runner.profiles``, "chrome-windows"); a test keeps the two in step.
"""

CHROME_VERSION = "131.0.0.0"

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_VERSION} Safari/537.36"
)

# What Chrome sends for a top-level page load, so a header check does not give the
# walker away either.
BROWSER_PAGE_HEADERS = {
    "User-Agent": BROWSER_USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}
