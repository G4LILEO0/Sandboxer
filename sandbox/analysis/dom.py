"""Extract forms, title, text, iframes and links from stored DOM snapshots.

The runner collects live page data only at the end of a session; pages visited earlier
in a redirect chain survive as DOM snapshots, and this gives them the same shape so
facts cover every page the session saw.
"""

from html.parser import HTMLParser
from urllib.parse import urljoin

_HIDDEN_STYLE = (
    "display:none",
    "visibility:hidden",
    "width:0",
    "height:0",
    "width:1px",
    "height:1px",
)


class _Extractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.title = ""
        self.text: list[str] = []
        self.forms: list[dict] = []
        self.loose_password_fields = 0
        self.iframes: list[dict] = []
        self.links: list[str] = []
        self._in_title = False
        self._skip = 0
        self._form: dict | None = None

    def _abs(self, url: str | None) -> str:
        try:
            return urljoin(self.base, url or "")
        except ValueError:
            return url or ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style", "noscript", "template"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "base" and a.get("href"):
            self.base = self._abs(a["href"])
        elif tag == "form":
            self._form = {
                "action": self._abs(a.get("action") or self.base),
                "method": (a.get("method") or "get").lower(),
                "id": a.get("id") or None,
                "fields": [],
            }
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button"):
            field = {
                "tag": tag,
                "type": (a.get("type") or ("text" if tag == "input" else "")).lower(),
                "name": a.get("name") or None,
                "autocomplete": a.get("autocomplete") or None,
            }
            if self._form is not None and len(self._form["fields"]) < 60:
                self._form["fields"].append(field)
            elif field["type"] == "password":
                self.loose_password_fields += 1
        elif tag in ("iframe", "frame"):
            style = a.get("style", "").replace(" ", "").lower()
            hidden = (
                any(s in style for s in _HIDDEN_STYLE)
                or a.get("width") in ("0", "1")
                or a.get("height") in ("0", "1")
                or "hidden" in a
            )
            self.iframes.append(
                {"src": self._abs(a.get("src")) if a.get("src") else None, "hidden": hidden}
            )
        elif tag == "a" and a.get("href") and len(self.links) < 500:
            self.links.append(self._abs(a["href"]))

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "template"):
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip and data.strip():
            self.text.append(data.strip())


def parse_dom(html: str, url: str) -> dict:
    parser = _Extractor(url)
    try:
        parser.feed(html[:5_000_000])
        parser.close()
    except Exception:  # noqa: BLE001, S110 - malformed pages still yield what was parsed
        pass
    return {
        "url": url,
        "title": parser.title.strip()[:500],
        "text": " ".join(" ".join(parser.text).split())[:8000],
        "forms": parser.forms[:50],
        "loose_password_fields": parser.loose_password_fields,
        "iframes": parser.iframes[:50],
        "links": parser.links,
        "source": "dom_snapshot",
    }
