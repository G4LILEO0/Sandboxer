"""Rule-hit evidence resolution (REP-4): from recorded facts to the content behind them."""

import hashlib

from sandbox.analysis.engine import behaviour_hits
from sandbox.api.evidence import SAMPLE_CAP, entropy, resolve
from sandbox.rules.behaviour import parse_rule

PACKED = "".join(chr(33 + (i * 7919) % 90) for i in range(3000))
SHORT_EVAL = "var x = atob('aGVsbG8='); " * 20
DYN_SHA = hashlib.sha256(PACKED.encode()).hexdigest()

RUNTIME_RULE = {
    "id": "r1",
    "name": "runtime_dynamic_execution",
    "description": "Packed code run through eval.",
    **parse_rule(
        {
            "condition": {
                "all": [
                    {"fact": "js.code_exec_count", "op": "gte", "value": 2},
                    {"fact": "js.code_exec_max_len", "op": "gt", "value": 1024},
                    {"fact": "js.code_exec_max_entropy", "op": "gt", "value": 4.5},
                    {"not": {"fact": "final.allowlisted", "op": "eq", "value": True}},
                ]
            },
            "evidence": ["js.dynamic_exec_count"],
        }
    ),
}


def _artifact(id_, kind, name, sha256="0" * 64, quarantined=False):
    return {
        "id": id_,
        "kind": kind,
        "name": name,
        "size": 10,
        "sha256": sha256,
        "quarantined": quarantined,
        "deleted": False,
    }


def _facts():
    return {
        "js": {
            "code_exec_count": 3,
            "code_exec_max_len": len(PACKED),
            "code_exec_max_entropy": 6.1,
            "dynamic_exec_count": 5,
        },
        "final": {"allowlisted": False},
    }


ARTIFACTS = [
    _artifact("ar_dyn", "script", f"dynamic-{DYN_SHA}.js", DYN_SHA),
    _artifact("ar_lib", "script", "abc.js", "a" * 64),
    _artifact("ar_dom", "dom", "000.html"),
    _artifact("ar_dl", "download", "invoice.exe", "d" * 64, quarantined=True),
]
CONTENT = {"ar_dyn": PACKED.encode(), "ar_dom": b"<form></form>"}


def _read(artifact):
    assert not artifact["quarantined"], "quarantined files are never read"
    return CONTENT.get(artifact["id"])


def test_runtime_dynamic_execution_returns_the_evald_code():
    facts = _facts()
    [hit] = behaviour_hits([RUNTIME_RULE], facts)
    capture = {"jsapi": {"exec": {"code_samples": [PACKED[:4096], SHORT_EVAL]}}}
    ev = resolve(
        {**hit, "id": hit["id"]},
        RUNTIME_RULE,
        all_facts=facts,
        artifacts=ARTIFACTS,
        capture=capture,
        read=_read,
    )
    assert ev["rule"] == "runtime_dynamic_execution"
    leaves = {c["fact"]: c for c in ev["condition"]}
    assert leaves["js.code_exec_count"] == {
        "fact": "js.code_exec_count",
        "op": "gte",
        "threshold": 2,
        "actual": 3,
        "missing": False,
        "negated": False,
        "group": "all",
        "passed": True,
    }
    assert leaves["final.allowlisted"]["negated"] and leaves["final.allowlisted"]["passed"]
    assert all(c["passed"] for c in ev["condition"])
    # The full decoded script, plus the short eval'd string; the 4 KB prefix of the
    # script is not repeated.
    contents = [s["content"] for s in ev["samples"]]
    assert contents == [PACKED, SHORT_EVAL]
    assert ev["samples"][0]["entropy"] == entropy(PACKED) > 4.5
    assert [f["id"] for f in ev["files"]] == ["ar_dyn"]
    assert ev["facts"]["js.dynamic_exec_count"] == 5


def test_long_samples_are_capped():
    huge = "A" * (SAMPLE_CAP + 10)
    facts = _facts()
    [hit] = behaviour_hits([RUNTIME_RULE], facts)
    ev = resolve(
        hit,
        RUNTIME_RULE,
        all_facts=facts,
        artifacts=[],
        capture={"jsapi": {"exec": {"code_samples": [huge]}}},
        read=_read,
    )
    [sample] = ev["samples"]
    assert sample["truncated"] and len(sample["content"]) == SAMPLE_CAP
    assert sample["length"] == SAMPLE_CAP + 10


def test_failed_leaf_under_any_is_marked():
    rule = {
        "name": "r",
        **parse_rule(
            {
                "condition": {
                    "any": [
                        {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                        {"fact": "clipboard.writes", "op": "gt", "value": 5},
                    ]
                }
            }
        ),
    }
    facts = {"clipboard": {"command_like": 1, "writes": 1}}
    [hit] = behaviour_hits([rule], facts)
    ev = resolve(
        hit,
        rule,
        all_facts=facts,
        artifacts=[],
        capture={"clipboard": [{"api": "writeText", "text": "powershell -c iex"}]},
        read=_read,
    )
    assert [c["passed"] for c in ev["condition"]] == [True, False]
    assert ev["samples"][0]["content"] == "powershell -c iex"


def test_yara_hit_links_the_file_and_match_strings():
    hit = {
        "id": "rh_y",
        "rule_name": "js_packer",
        "engine": "yara",
        "artifact_id": "ar_lib",
        "detail": {
            "artifact": "abc.js",
            "kind": "script",
            "matches": [{"string": "$a", "offset": 12, "data": "eval(function(p,a,c,k"}],
        },
    }
    rule = {"description": "Dean Edwards packer", "source_text": "rule js_packer { ... }"}
    ev = resolve(hit, rule, all_facts={}, artifacts=ARTIFACTS, capture={}, read=_read)
    assert [f["id"] for f in ev["files"]] == ["ar_lib"]
    assert ev["samples"][0]["content"] == "eval(function(p,a,c,k"
    assert ev["samples"][0]["label"] == "$a at offset 12"
    assert ev["rule_source"].startswith("rule js_packer")
    assert ev["condition"] == []


def test_fallback_links_artifacts_named_in_facts():
    rule = {
        "name": "risky",
        **parse_rule(
            {
                "condition": {"fact": "network.weird", "op": "gt", "value": 0},
                "evidence": ["network.details"],
            }
        ),
    }
    facts = {"network": {"weird": 1, "details": [{"sha256": "d" * 64}, {"file": "abc.js"}]}}
    [hit] = behaviour_hits([rule], facts)
    ev = resolve(hit, rule, all_facts=facts, artifacts=ARTIFACTS, capture={}, read=_read)
    linked = {f["id"]: f for f in ev["files"]}
    assert set(linked) == {"ar_dl", "ar_lib"}
    assert linked["ar_dl"]["quarantined"]  # linked, never read
    assert ev["samples"] == []


def test_missing_rule_falls_back_to_recorded_facts():
    facts = _facts()
    [hit] = behaviour_hits([RUNTIME_RULE], facts)
    ev = resolve(hit, None, all_facts=facts, artifacts=ARTIFACTS, capture={}, read=_read)
    assert not ev["rule_found"] and ev["condition"] == []
    assert ev["facts"]["js.code_exec_count"] == 3
    assert ev["description"] == "Packed code run through eval."
    assert [f["id"] for f in ev["files"]] == ["ar_dyn"]  # resolved from the fact paths
