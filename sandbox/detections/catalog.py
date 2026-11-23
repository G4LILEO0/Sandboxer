"""Every detection, loaded and checked, and the one function that runs them.

Detections are being moved to query rules (``sandbox/detections/rules/<area>/*.kql``,
see sandbox.detections.kql); the areas not moved yet still declare theirs in Python.
Both kinds load here into one catalog and run through ``run``. The load fails at once if
a rule does not parse, names something unknown, or a Python detection reads a signal
nobody declared, so a typo can never ship as a rule that silently never fires.
"""

from __future__ import annotations

from typing import Any

from sandbox.detections import observe  # noqa: F401  (imports every area module)
from sandbox.detections.kql import rules as query_rules
from sandbox.detections.kql.rules import RuleDetection
from sandbox.detections.model import DETECTIONS, SIGNALS, Detection

# Weights that are not a detection's own score: the severity fall-backs (YARA and feed
# rules), the indicator base weight and the per-alert Suricata weight (ANA-7).
BASE_WEIGHTS: dict[str, int] = {
    "severity:info": 0,
    "severity:low": 10,
    "severity:medium": 25,
    "severity:high": 45,
    "severity:critical": 75,
    "indicator": 60,
    "suricata:alert": 20,
}


def _check() -> None:
    problems = []
    for d in DETECTIONS.values():
        if isinstance(d, RuleDetection):
            continue  # checked when parsed
        for t in d.when.tests():
            if t.path not in SIGNALS:
                problems.append(f"{d.name} reads undeclared signal {t.path}")
        for path in d.evidence:
            if path not in SIGNALS:
                problems.append(f"{d.name} names undeclared evidence {path}")
    if problems:
        raise RuntimeError("Detection catalog is broken: " + "; ".join(problems))


_check()

for _rule in query_rules.load():
    if _rule.name in DETECTIONS:
        raise RuntimeError(f"Detection {_rule.name} is declared in Python and in {_rule.source}")
    DETECTIONS[_rule.name] = _rule


def detections() -> list[Detection | RuleDetection]:
    return list(DETECTIONS.values())


def get(name: str) -> Detection | RuleDetection | None:
    return DETECTIONS.get(name)


def default_weights() -> dict[str, int]:
    """Every weight Sandboxer ships: the base weights plus each detection's score."""
    return {**BASE_WEIGHTS, **{d.name: d.score for d in DETECTIONS.values()}}


def definitions() -> list[dict[str, Any]]:
    """Every detection as a rule definition (what a bundle stores and the engine runs)."""
    return [definition(d) for d in DETECTIONS.values()]


def definition(d: Detection | RuleDetection, rule_id: str | None = None) -> dict[str, Any]:
    return {
        "id": rule_id or d.name,
        "name": d.name,
        "severity": d.severity,
        "tags": list(d.tags),
        "attack_ids": list(d.attack),
        "description": d.description,
    }


def run(definitions: list[dict[str, Any]], facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate the enabled detections (``definitions``, one per enabled rule row) over one
    capture's observed values. Returns one hit per detection that fired, carrying every
    check it made, so the report can say exactly why."""
    from sandbox.ids import new_id

    hits = []
    for spec in definitions:
        # In-process callers (tests, local runs) may hand over the Detection itself.
        d = spec.get("detection") or DETECTIONS.get(spec["name"])
        if d is None:
            continue  # a rule row whose detection was removed from the code
        outcome = d.evaluate(facts)
        if not outcome.matched:
            continue
        hits.append(
            {
                "id": new_id("rh"),
                "rule_id": spec.get("id"),
                "rule_name": d.name,
                "engine": "behaviour",
                "severity": spec.get("severity") or d.severity,
                "tags": list(spec.get("tags") or d.tags),
                "attack_ids": list(spec.get("attack_ids") or d.attack),
                "artifact_id": None,
                "detail": {
                    **({"kind": "query"} if isinstance(d, RuleDetection) else {}),
                    "title": d.title,
                    "description": spec.get("description") or d.description,
                    "facts": outcome.facts,
                    "checks": outcome.checks,
                },
            }
        )
    return hits


def describe(d: Detection | RuleDetection) -> dict[str, Any]:
    """A detection as Admin shows it."""
    if isinstance(d, RuleDetection):
        return describe_rule(d)
    return _describe_python(d)


def describe_rule(d: RuleDetection) -> dict[str, Any]:
    """A query rule: its metadata, its query, the shared named queries it uses, and the
    description of every table, function and detection string it names."""
    import re

    from sandbox.detections import strings
    from sandbox.detections.kql.tables import FUNCTIONS, TABLE_FUNCTIONS, TABLES

    text = d.rule_text()
    shared = {}
    for name, q in d.env.shared.items():
        if re.search(rf"\b{re.escape(name)}\b", text):
            shared[name] = q
    # The text a reader has to follow: the rule plus the shared queries it uses (and any
    # shared queries those use).
    sources = {name: _shared_text(d, name) for name in shared}
    changed = True
    while changed:
        changed = False
        for name in d.env.shared:
            if name not in sources and any(
                re.search(rf"\b{re.escape(name)}\b", t) for t in sources.values()
            ):
                sources[name] = _shared_text(d, name)
                changed = True
    everything = re.sub(r"//[^\n]*", "", text + "\n" + "\n".join(sources.values()))
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", everything))
    keys = sorted(set(re.findall(r'list\("([^"]+)"\)', everything)))
    entries = strings.entries()
    return {
        "kind": "query",
        "name": d.name,
        "title": d.title,
        "severity": d.severity,
        "score": d.score,
        "tags": list(d.tags),
        "attack_ids": list(d.attack),
        "description": d.description,
        "area": d.area,
        "source": d.source,
        "rule": text,
        "shared": [{"name": n, "query": t} for n, t in sources.items()],
        "tables": [
            {"name": n, "description": t["description"], "columns": t["columns"]}
            for n, t in TABLES.items()
            if n in words
        ]
        + [
            {
                "name": n,
                "signature": t["signature"],
                "description": t["description"],
                "columns": t["columns"],
            }
            for n, t in TABLE_FUNCTIONS.items()
            if n in words
        ],
        "functions": [
            {"name": n, "signature": f["signature"], "description": f["description"]}
            for n, f in FUNCTIONS.items()
            if n in words
        ],
        "strings": [
            {"key": k, "title": entries[k].title, "description": entries[k].description}
            for k in keys
            if k in entries
        ],
        "signals": [],
    }


def _shared_text(d: RuleDetection, name: str) -> str:
    from sandbox.detections.kql.rules import shared_source

    return shared_source(d.env, name)


def _describe_python(d: Detection) -> dict[str, Any]:
    """A detection as Admin shows it: metadata, the rule as sentences, and each signal it
    reads with its description and where it is computed."""
    from sandbox.detections import strings

    used_strings = sorted(
        {
            b.key
            for b in strings._state.bindings
            if b.namespace.get("__name__", "").rsplit(".", 1)[-1] in {s.area for s in d.signals()}
        }
    )
    return {
        "name": d.name,
        "title": d.title,
        "severity": d.severity,
        "score": d.score,
        "tags": list(d.tags),
        "attack_ids": list(d.attack),
        "description": d.description,
        "area": d.area,
        "source": f"sandbox/detections/{d.area}.py",
        "rule": d.rule_text(),
        "signals": [
            {
                "path": s.path,
                "title": s.title,
                "description": s.description,
                "area": s.area,
                "source": f"sandbox/detections/{s.area}.py",
                "evidence_only": s.path in d.evidence
                and s.path not in {t.path for t in d.when.tests()},
            }
            for s in d.signals()
        ],
        "strings": used_strings,
    }
