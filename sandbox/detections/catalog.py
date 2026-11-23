"""Every detection and signal, loaded and checked, and the one function that runs them.

Importing this module imports every area module, so ``DETECTIONS`` and ``SIGNALS`` are
complete. The load fails at once if a detection reads a signal nobody declared, so a
typo can never ship as a rule that silently never fires.
"""

from __future__ import annotations

from typing import Any

from sandbox.detections import observe  # noqa: F401  (imports every area module)
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
        for t in d.when.tests():
            if t.path not in SIGNALS:
                problems.append(f"{d.name} reads undeclared signal {t.path}")
        for path in d.evidence:
            if path not in SIGNALS:
                problems.append(f"{d.name} names undeclared evidence {path}")
    if problems:
        raise RuntimeError("Detection catalog is broken: " + "; ".join(problems))


_check()


def detections() -> list[Detection]:
    return list(DETECTIONS.values())


def get(name: str) -> Detection | None:
    return DETECTIONS.get(name)


def default_weights() -> dict[str, int]:
    """Every weight Sandboxer ships: the base weights plus each detection's score."""
    return {**BASE_WEIGHTS, **{d.name: d.score for d in DETECTIONS.values()}}


def definitions() -> list[dict[str, Any]]:
    """Every detection as a rule definition (what a bundle stores and the engine runs)."""
    return [definition(d) for d in DETECTIONS.values()]


def definition(d: Detection, rule_id: str | None = None) -> dict[str, Any]:
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
                    "title": d.title,
                    "description": spec.get("description") or d.description,
                    "facts": outcome.facts,
                    "checks": outcome.checks,
                },
            }
        )
    return hits


def describe(d: Detection) -> dict[str, Any]:
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
