"""exfiltration"""

from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData
from sandbox.detections.model import all_of, any_of, detection, sig, signal

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


# --- observed values ---------------------------------------------------------------------


def exfil_section(cap: Capture) -> dict[str, Any]:
    """Posts to known data drops (Telegram bots, Discord webhooks, form collectors)."""
    return _exfil(cap.data, cap.reqs)


# --- signals: the values this area observes --------------------------------------------

signal(
    "exfil.telegram_count",
    "Telegram bot API calls",
    (
        "Requests to api.telegram.org that match the bot API shape (string "
        "exfiltration.telegram_bot): a phishing kit sending loot to a Telegram chat."
    ),
)

signal(
    "exfil.telegram",
    "Telegram bot calls",
    ("Bot id, method and whether a body was sent, for each Telegram bot API call (first 20)."),
)

signal(
    "exfil.discord_count",
    "Discord webhook calls",
    (
        "Requests to a Discord host (string exfiltration.discord_hosts) on a webhook path "
        "(string exfiltration.discord_webhook)."
    ),
)

signal(
    "exfil.discord",
    "Discord webhook calls (details)",
    "Host and whether a body was sent, for each Discord webhook call (first 20).",
)

signal(
    "exfil.form_collector_count",
    "Posts to form-collector services",
    (
        "Distinct form-collector services (string exfiltration.form_collectors) that received "
        "a POST or PUT."
    ),
)

signal(
    "exfil.form_collectors",
    "Form-collector services",
    "The form-collector hosts that received a POST or PUT (first 20).",
)


# --- detections ------------------------------------------------------------------------

detection(
    "telegram_bot_exfil",
    title="Data sent to a Telegram bot",
    severity="critical",
    score=80,
    tags=["phishing", "exfil-telegram"],
    attack=["T1567", "T1102.002", "T1056.003"],
    description=(
        "The page called the Telegram Bot API from the browser "
        "(api.telegram.org/bot<token>/sendMessage or similar). Phishing kits use a Telegram "
        "bot as their drop."
    ),
    when=sig("exfil.telegram_count") > 0,
    evidence=[
        "exfil.telegram",
        "forms.password_forms",
        "final.url",
    ],
)

detection(
    "discord_webhook_exfil",
    title="Data sent to a Discord webhook",
    severity="high",
    score=65,
    tags=["phishing", "exfil"],
    attack=["T1567", "T1102.002"],
    description=(
        "The page posted to a Discord webhook (discord.com/api/webhooks/...) from the "
        "browser: webhooks are a server-side drop, not something a normal web page uses."
    ),
    when=sig("exfil.discord_count") > 0,
    evidence=[
        "exfil.discord",
        "forms.password_forms",
        "final.url",
    ],
)

detection(
    "credential_post_to_form_collector",
    title="Credentials posted to a form-collector service",
    severity="high",
    score=45,
    tags=["phishing", "exfil", "credential-harvest"],
    attack=["T1567", "T1056.003"],
    description=(
        "A page that asks for a password, card, one-time code or recovery phrase POSTs to a "
        "form-backend or webhook service (Formspree, EmailJS, webhook.site...). This is a kit "
        "with no backend of its own. Contact forms on these services ask for none of these."
    ),
    when=all_of(
        sig("exfil.form_collector_count") > 0,
        any_of(
            sig("forms.password_forms") > 0,
            sig("forms.payment_card_forms") > 0,
            sig("forms.otp_forms") > 0,
            sig("forms.seed_phrase_forms") > 0,
        ),
    ),
    evidence=[
        "exfil.form_collectors",
        "forms.sensitive_prompt_pages",
        "final.url",
    ],
)
