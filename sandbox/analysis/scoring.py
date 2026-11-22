"""Score and verdict from weighted hits (ANA-7, ANA-11, FED-11).

Weights come from ``scoring_config`` (latest row per key wins), so they change without a
deploy. Every contribution is listed, so a stored verdict can be explained and
reproduced from the stored hits, weights and thresholds.
"""

from dataclasses import dataclass, field
from typing import Any

SEVERITY_FALLBACK = {"info": 0, "low": 10, "medium": 25, "high": 45, "critical": 75}
ALLOWLIST_FACTOR = 0.25
SURICATA_DEFAULT_CAP = 45
# Suricata alert severity (the classtype priority: 1 is most severe) -> share of the
# per-alert weight. ET INFO / POLICY / HUNTING rules describe traffic rather than
# malice and fire on ordinary browsing, so they are shown but never scored.
_SURICATA_SEVERITY_FACTOR = {1: 1.0, 2: 0.5, 3: 0.15}
_SURICATA_INFORMATIONAL = ("ET INFO", "ET POLICY", "ET HUNTING", "GPL INFO", "SURICATA ")


def suricata_factor(alert: dict[str, Any]) -> float:
    if alert.get("not_applicable"):
        return 0.0
    signature = str(alert.get("signature") or "")
    if signature.upper().startswith(_SURICATA_INFORMATIONAL):
        return 0.0
    severity = alert.get("severity")
    return _SURICATA_SEVERITY_FACTOR.get(severity, 0.0) if isinstance(severity, int) else 0.5


@dataclass
class Contribution:
    source: str  # rule, indicator, suricata
    name: str
    weight: float
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreResult:
    score: int
    verdict: str
    contributions: list[Contribution]
    weights_used: dict[str, float]


def _weight(
    weights: dict[str, tuple[int, int | None]], key: str, fallback: float
) -> tuple[float, int | None]:
    if key in weights:
        weight, cap = weights[key]
        return float(weight), cap
    return fallback, None


def score(
    *,
    rule_hits: list[dict[str, Any]],
    indicator_hits: list[dict[str, Any]],
    suricata_alerts: list[dict[str, Any]],
    weights: dict[str, tuple[int, int | None]],
    thresholds: dict[str, int],
    allowlisted: set[str],
    capture_ok: bool,
) -> ScoreResult:
    contributions: list[Contribution] = []
    used: dict[str, float] = {}

    seen_rules: set[str] = set()
    for hit in rule_hits:
        if hit["rule_name"] in seen_rules:
            continue  # a rule counts once however many artifacts it matched
        seen_rules.add(hit["rule_name"])
        severity = hit.get("severity", "medium")
        fallback, _ = _weight(weights, f"severity:{severity}", SEVERITY_FALLBACK.get(severity, 25))
        w, cap = _weight(weights, hit["rule_name"], fallback)
        if cap is not None:
            w = min(w, cap)
        used[hit["rule_name"]] = w
        contributions.append(
            Contribution(
                "rule", hit["rule_name"], w, {"engine": hit["engine"], "severity": severity}
            )
        )

    base, cap = _weight(weights, "indicator", 60)
    indicator_total = 0.0
    for hit in indicator_hits:
        confidence = (
            max((s.get("confidence") or 0) for s in hit["sources"]) if hit["sources"] else 0
        )
        w = base * confidence / 100
        note = {}
        if hit["matched_value"] in allowlisted or hit.get("registrable") in allowlisted:
            w *= ALLOWLIST_FACTOR  # FED-11: allowlisted stays visible but weighs less
            note["allowlisted"] = True
        indicator_total += w
        contributions.append(
            Contribution(
                "indicator",
                f"{hit['type']}:{hit['matched_value']}",
                round(w, 1),
                {
                    "feeds": [s.get("feed") for s in hit["sources"]],
                    "confidence": confidence,
                    **note,
                },
            )
        )
    if cap is not None and indicator_total > cap:
        contributions.append(Contribution("cap", "indicator", cap - indicator_total))
    used["indicator"] = base

    per_alert, sur_cap = _weight(weights, "suricata:alert", 20)
    if "suricata:alert" not in weights:
        sur_cap = SURICATA_DEFAULT_CAP
    sur_total = 0.0
    for alert in suricata_alerts:
        factor = suricata_factor(alert)
        w = round(per_alert * factor, 1)
        sur_total += w
        contributions.append(
            Contribution(
                "suricata",
                f"sid:{alert['sid']}",
                w,
                {
                    "signature": alert.get("signature"),
                    "severity": alert.get("severity"),
                    **(
                        {"not_applicable": alert["not_applicable"]}
                        if alert.get("not_applicable")
                        else {}
                    ),
                },
            )
        )
    if sur_cap is not None and sur_total > sur_cap:
        contributions.append(Contribution("cap", "suricata:alert", sur_cap - sur_total))
    used["suricata:alert"] = per_alert

    total = max(0, min(100, round(sum(c.weight for c in contributions))))
    if total >= thresholds.get("malicious", 70):
        verdict = "malicious"
    elif total >= thresholds.get("suspicious", 30):
        verdict = "suspicious"
    elif not capture_ok:
        verdict = "unknown"
    else:
        verdict = "benign"
    return ScoreResult(total, verdict, contributions, used)
