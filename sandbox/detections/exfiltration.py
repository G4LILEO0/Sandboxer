"""exfiltration"""

from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import CaptureData

_TELEGRAM_BOT = S.bind(globals(), "_TELEGRAM_BOT", "exfiltration.telegram_bot")

_DISCORD_WEBHOOK = S.bind(globals(), "_DISCORD_WEBHOOK", "exfiltration.discord_webhook")

_DISCORD_HOSTS = S.bind(globals(), "_DISCORD_HOSTS", "exfiltration.discord_hosts", S.as_set)

FORM_COLLECTORS = S.bind(globals(), "FORM_COLLECTORS", "exfiltration.form_collectors", S.as_set)


def _exfil(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    telegram, discord, collectors = [], [], []
    for r in reqs:
        if r["host"] == "api.telegram.org" and (m := _TELEGRAM_BOT.match(r["path"])):
            telegram.append(
                {"method": m.group(2), "bot_id": m.group(1), "has_post": bool(r["post"])}
            )
        elif r["host"] in _DISCORD_HOSTS and _DISCORD_WEBHOOK.match(r["path"]):
            discord.append({"host": r["host"], "has_post": bool(r["post"])})
        elif r["host"] in FORM_COLLECTORS and r["method"] in ("POST", "PUT"):
            collectors.append(r["host"])
    return {
        "telegram": telegram[:20],
        "telegram_count": len(telegram),
        "discord": discord[:20],
        "discord_count": len(discord),
        "form_collectors": sorted(set(collectors))[:20],
        "form_collector_count": len(set(collectors)),
    }
