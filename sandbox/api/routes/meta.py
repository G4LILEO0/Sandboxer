"""Static facts the UI needs: browser profiles, scopes, and descriptions for tag and rule
badges so every badge can explain itself on hover (REP-9)."""

from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from sandbox.api.auth import SCOPES, CurrentPrincipal
from sandbox.api.deps import AppSettings, Db
from sandbox.db.models import Rule
from sandbox.runner.profiles import PROFILES

router = APIRouter(prefix="/v1", tags=["meta"])

TAG_DESCRIPTIONS = {
    "phishing": "The page collects credentials or imitates a login.",
    "credential-harvest": "A password form submits to a different site.",
    "brand-impersonation": "The page presents a known brand but is not on its domains.",
    "clickfix": "The page wrote a shell command to the clipboard (fake CAPTCHA, paste-and-run).",
    "malware-download": "The page delivered a file, possibly without a click.",
    "obfuscation": "Scripts hide their code (eval of decoded strings, packers, encoded blobs).",
    "newly-registered": "A contacted domain is less than 30 days old.",
    "punycode": "An internationalised (punycode) domain was used.",
    "lookalike": "A domain imitates a brand's domain (typo, homoglyph or brand name inside).",
    "suspicious-redirect": "Long, cross-site or downgrading redirect chain.",
    "cloaking": "The site may show different content to different visitors.",
    "internal-probe": "The page tried to reach internal or cloud-metadata addresses (blocked).",
    "hidden-iframe": "The page embeds an invisible frame.",
    "insecure-form": "A password form uses plain http.",
    "known-bad": "A URL, domain, IP or hash matched a threat-intel feed.",
    "ids-alert": "Suricata raised an alert on the session's traffic.",
    "executable": "A downloaded file is an executable.",
}


@router.get("/meta")
async def meta(principal: CurrentPrincipal, settings: AppSettings, db: Db) -> dict[str, Any]:
    rules = await db.execute(select(Rule.name, Rule.description, Rule.severity, Rule.engine))
    return {
        "auth_mode": settings.auth_mode,
        "env": settings.env,
        "profiles": [{"name": p.name, "description": p.description} for p in PROFILES.values()],
        "scopes": list(SCOPES),
        "tag_descriptions": TAG_DESCRIPTIONS,
        "rule_descriptions": {
            name: {"description": desc, "severity": sev, "engine": engine}
            for name, desc, sev, engine in rules
            if engine != "suricata"
        },
        "vendors": {
            "virustotal": settings.vt_api_key is not None,
            "abuseipdb": settings.abuseipdb_api_key is not None,
        },
    }
