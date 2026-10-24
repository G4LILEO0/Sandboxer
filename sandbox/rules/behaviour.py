"""Declarative behaviour rules (ANA-4, section 9: "Behaviour rules hold a declarative JSON
condition").

A rule body is JSON::

    {"condition": {"any": [
        {"fact": "forms.cross_domain_credential", "op": "gt", "value": 0},
        {"all": [{"fact": "redirects.count", "op": "gte", "value": 4},
                 {"not": {"fact": "final.allowlisted", "op": "eq", "value": true}}]}
     ]},
     "evidence": ["forms.cross_domain_credential_forms"]}

Facts are a nested dict computed by ``sandbox.analysis.facts``; ``fact`` is a dotted path.
A hit records every fact the condition read plus the ``evidence`` paths, so each verdict
shows exactly why it fired (ANA-11).
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any

OPS = ("eq", "ne", "gt", "gte", "lt", "lte", "in", "contains", "exists", "matches", "any_matches")
_MISSING = object()


class RuleSyntaxError(ValueError):
    pass


@dataclass
class Evaluation:
    matched: bool
    facts: dict[str, Any] = field(default_factory=dict)


def get_fact(facts: dict[str, Any], path: str) -> Any:
    node: Any = facts
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


def parse_rule(body: str | dict[str, Any]) -> dict[str, Any]:
    rule = json.loads(body) if isinstance(body, str) else body
    if not isinstance(rule, dict) or "condition" not in rule:
        raise RuleSyntaxError("A behaviour rule needs a 'condition'")
    _check(rule["condition"])
    evidence = rule.get("evidence", [])
    if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
        raise RuleSyntaxError("'evidence' must be a list of fact paths")
    return rule


def _check(cond: Any) -> None:
    if not isinstance(cond, dict) or not cond:
        raise RuleSyntaxError(f"Condition must be a non-empty object: {cond!r}")
    if "all" in cond or "any" in cond:
        key = "all" if "all" in cond else "any"
        if not isinstance(cond[key], list) or not cond[key]:
            raise RuleSyntaxError(f"'{key}' needs a non-empty list")
        for sub in cond[key]:
            _check(sub)
        return
    if "not" in cond:
        _check(cond["not"])
        return
    if "fact" not in cond or "op" not in cond:
        raise RuleSyntaxError(f"Leaf condition needs 'fact' and 'op': {cond!r}")
    if cond["op"] not in OPS:
        raise RuleSyntaxError(f"Unknown op '{cond['op']}'")
    if cond["op"] in ("matches", "any_matches"):
        try:
            re.compile(cond.get("value", ""))
        except re.error as exc:
            raise RuleSyntaxError(f"Bad regex: {exc}") from exc


def evaluate(rule: dict[str, Any], facts: dict[str, Any]) -> Evaluation:
    seen: dict[str, Any] = {}
    matched = _eval(rule["condition"], facts, seen)
    if matched:
        for path in rule.get("evidence", []):
            value = get_fact(facts, path)
            if value is not _MISSING:
                seen[path] = value
    return Evaluation(matched, seen)


def _eval(cond: dict[str, Any], facts: dict[str, Any], seen: dict[str, Any]) -> bool:
    if "all" in cond:
        return all(_eval(c, facts, seen) for c in cond["all"])
    if "any" in cond:
        return any([_eval(c, facts, seen) for c in cond["any"]])  # read every branch's facts
    if "not" in cond:
        return not _eval(cond["not"], facts, seen)
    value = get_fact(facts, cond["fact"])
    if value is not _MISSING:
        seen[cond["fact"]] = value
    op, target = cond["op"], cond.get("value")
    if op == "exists":
        return (value is not _MISSING and value not in (None, [], {}, "")) == (target is not False)
    if value is _MISSING:
        return False
    try:
        if op == "eq":
            return value == target
        if op == "ne":
            return value != target
        if op == "gt":
            return value > target
        if op == "gte":
            return value >= target
        if op == "lt":
            return value < target
        if op == "lte":
            return value <= target
        if op == "in":
            return value in target
        if op == "contains":
            return target in value
        if op == "matches":
            return re.search(target, str(value), re.I) is not None
        if op == "any_matches":
            return any(re.search(target, str(v), re.I) for v in (value or []))
    except TypeError:
        return False
    return False
