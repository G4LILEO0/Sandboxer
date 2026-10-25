"""Import rule sets into Postgres (FED-7, FED-8).

Each rule keeps its source, version, licence and content hash. Rules are validated as
they arrive: one that does not compile is stored with its error and never enters a
bundle. Re-importing updates changed bodies but never flips ``enabled`` back on, so a
local disable survives upstream updates (FED-10).
"""

import hashlib
import re
from typing import Any

from sqlalchemy import select

from sandbox.db.models import Rule
from sandbox.feeds.parsers import RuleFile
from sandbox.ids import new_id

# External variables common community YARA sets reference; defined empty so they compile.
YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
# Every compile of rule text passes this: an ``include "/path"`` directive would make the
# compiler open files on the API or worker host (file probing, /dev/zero hangs).
YARA_COMPILE_OPTIONS = {"externals": YARA_EXTERNALS, "includes": False}

_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
_MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')
_PRIORITY = re.compile(r"\bpriority\s*:\s*(\d)\s*;")
_YARA_META = re.compile(
    r'\b(description|severity|score|mitre_att(?:ack)?)\s*=\s*(?:"([^"\n]*)"|([\w.]+))'
)
_YARA_TAGS = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+\w+\s*:\s*([\w \t]+?)\s*\{", re.M)
_SEVERITY_BY_PRIORITY = {"1": "high", "2": "medium", "3": "low", "4": "info"}
# ET rules carry "metadata: ... signature_severity Major" and a classtype, not priority.
_SIG_SEVERITY = re.compile(r"\bsignature_severity\s+(\w+)", re.I)
_CLASSTYPE = re.compile(r"\bclasstype\s*:\s*([\w-]+)\s*;")
_SEVERITY_BY_ET = {"critical": "critical", "major": "high", "minor": "low", "informational": "info"}
_SEVERITY_BY_CLASSTYPE = {
    "trojan-activity": "high",
    "command-and-control": "high",
    "exploit-kit": "high",
    "domain-c2": "high",
    "credential-theft": "high",
    "social-engineering": "medium",
    "web-application-attack": "medium",
    "attempted-admin": "medium",
    "attempted-user": "medium",
    "bad-unknown": "medium",
    "policy-violation": "info",
    "misc-activity": "info",
    "not-suspicious": "info",
    "protocol-command-decode": "info",
    "unknown": "low",
}


def content_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def validate_yara(body: str) -> str | None:
    try:
        import yara
    except ImportError:  # pragma: no cover - yara-python is a declared dependency
        return "yara-python is not installed"
    try:
        yara.compile(source=body, **YARA_COMPILE_OPTIONS)
    except yara.SyntaxError as exc:
        return str(exc)[:1000]
    except yara.Error as exc:
        return str(exc)[:1000]
    return None


def yara_metadata(body: str) -> dict[str, Any]:
    meta: dict[str, str] = {}
    for key, quoted, bare in _YARA_META.findall(body):
        meta.setdefault(key.lower(), (quoted or bare).strip())
    tags = sorted({t.lower() for group in _YARA_TAGS.findall(body) for t in group.split()})
    severity = meta.get("severity", "").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        score = meta.get("score", "")
        severity = (
            "high"
            if score.isdigit() and int(score) >= 75
            else "medium"
            if score.isdigit() and int(score) >= 50
            else "low"
            if score.isdigit()
            else "medium"
        )
    attack = re.findall(r"T\d{4}(?:\.\d{3})?", meta.get("mitre_attack", meta.get("mitre_att", "")))
    return {
        "description": meta.get("description", "")[:500],
        "severity": severity,
        "tags": tags[:10],
        "attack_ids": attack,
    }


async def _existing(db, engine: str, source: str) -> dict[str, Rule]:
    rows = await db.scalars(select(Rule).where(Rule.engine == engine, Rule.source == source))
    return {r.name: r for r in rows}


def _upsert(
    db,
    existing: dict[str, Rule],
    engine: str,
    source: str,
    name: str,
    body: str,
    values: dict[str, Any],
) -> str:
    """Return 'added', 'updated' or 'same'."""
    digest = content_hash(body)
    rule = existing.get(name)
    if rule is None:
        rule = Rule(
            id=new_id("ru"),
            engine=engine,
            source=source,
            name=name,
            body=body,
            content_hash=digest,
            **values,
        )
        db.add(rule)
        existing[name] = rule
        return "added"
    if rule.content_hash == digest and rule.error == values.get("error"):
        return "same"
    rule.body, rule.content_hash = body, digest
    for key, value in values.items():
        if key != "enabled":  # never re-enable what an admin or upstream turned off
            setattr(rule, key, value)
    return "updated"


async def import_yara_files(
    db, *, source: str, files: list[RuleFile], licence: str, version: str
) -> dict[str, int]:
    stats = {"total": 0, "added": 0, "updated": 0, "invalid": 0}
    existing = await _existing(db, "yara", source)
    for f in files:
        error = validate_yara(f.text)
        meta = yara_metadata(f.text)
        outcome = _upsert(
            db,
            existing,
            "yara",
            source,
            f.path,
            f.text,
            {"version": version, "licence": licence, "error": error, **meta},
        )
        stats["total"] += 1
        stats["invalid"] += error is not None
        if outcome != "same":
            stats[outcome] += 1
    return stats


def parse_suricata_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    enabled = True
    if stripped.startswith("#"):
        stripped = stripped.lstrip("#").strip()
        enabled = False
    if not re.match(r"^(alert|drop|reject|pass)\s", stripped):
        return None
    sid = _SID.search(stripped)
    if not sid:
        return None
    msg = _MSG.search(stripped)
    return {
        "name": f"sid:{sid.group(1)}",
        "body": stripped,
        "enabled": enabled,
        "description": (msg.group(1) if msg else "")[:500],
        "severity": suricata_severity(stripped, msg.group(1) if msg else ""),
    }


def suricata_severity(body: str, msg: str = "") -> str:
    """Explicit priority, then ET's signature_severity, then the classtype."""
    priority = _PRIORITY.search(body)
    if priority and priority.group(1) in _SEVERITY_BY_PRIORITY:
        return _SEVERITY_BY_PRIORITY[priority.group(1)]
    if msg.upper().startswith(("ET INFO", "ET POLICY", "ET HUNTING", "GPL INFO")):
        return "info"
    sig = _SIG_SEVERITY.search(body)
    if sig and sig.group(1).lower() in _SEVERITY_BY_ET:
        return _SEVERITY_BY_ET[sig.group(1).lower()]
    classtype = _CLASSTYPE.search(body)
    return _SEVERITY_BY_CLASSTYPE.get(classtype.group(1) if classtype else "", "medium")


async def import_suricata_files(
    db, *, source: str, files: list[RuleFile], licence: str, version: str
) -> dict[str, int]:
    stats = {"total": 0, "added": 0, "updated": 0, "invalid": 0}
    seen: set[str] = set()
    existing = await _existing(db, "suricata", source)
    for f in files:
        for line in f.text.splitlines():
            parsed = parse_suricata_line(line)
            if parsed is None or parsed["name"] in seen:
                continue
            seen.add(parsed["name"])
            name, body = parsed.pop("name"), parsed.pop("body")
            attack = sorted(set(re.findall(r"mitre_technique_id\s+(T\d{4}(?:\.\d{3})?)", body)))
            outcome = _upsert(
                db,
                existing,
                "suricata",
                source,
                name,
                body,
                {
                    "version": version,
                    "licence": licence,
                    "error": None,
                    "attack_ids": attack,
                    **parsed,
                },
            )
            stats["total"] += 1
            if outcome != "same":
                stats[outcome] += 1
    return stats
