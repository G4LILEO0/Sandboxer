"""Lure wording: the text a page shows to talk the visitor into a step (paste into Run,
press Allow, call a number, open the download). The wording itself is matched in the
rules (rules/lures/) with detection strings; this module gives them the text."""

from sandbox.detections.base import Capture, _all_frames, _lure_frames
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import memo, table

# --- tables -------------------------------------------------------------------------------


@table(
    "lure_texts",
    "The text of every frame (as in frames), plus the whole text of each raw page "
    "snapshot with hidden elements, cut into overlapping 4,000-character windows. "
    "Fake-verification kits reveal their Win+R steps only after a click, so the visible "
    "text alone never shows them; the windows keep wording that must sit together on "
    "one overlay together.",
    {
        "url": "The frame or page URL",
        "title": "The frame title (empty for a snapshot window)",
        "text": "The text",
        "content": "The title and the text, joined by a space",
        "snapshot": "True for a raw snapshot window",
    },
)
def _lure_texts(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        frames = _all_frames(cap.data)
        return [
            {
                "url": f.get("url", ""),
                "title": f.get("title", ""),
                "text": f.get("text", ""),
                "content": f"{f.get('title', '')} {f.get('text', '')}",
                "snapshot": n >= len(frames),
            }
            for n, f in enumerate(_lure_frames(cap.data))
        ]

    return memo(cap, "lure_texts", build)
