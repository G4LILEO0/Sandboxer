"""Rule-hit evidence resolution (REP-4): from a hit to the content behind it."""

import hashlib

from sandbox.analysis.engine import behaviour_hits
from sandbox.api.evidence import SAMPLE_CAP, entropy, resolve
from sandbox.detections import catalog
from sandbox.detections.base import Capture, CaptureData

PACKED = "".join(chr(33 + (i * 7919) % 90) for i in range(3000))
SHORT_EVAL = "var x = atob('aGVsbG8='); " * 20
DYN_SHA = hashlib.sha256(PACKED.encode()).hexdigest()


def _rule(name):
    """A catalog rule as the engine and the resolver take it."""
    d = catalog.get(name)
    return {"id": name, "name": name, "description": d.description, "detection": d}


RUNTIME_RULE = _rule("runtime_dynamic_execution")


def _capture(samples):
    jsapi = {
        "exec": {
            "code_count": 3,
            "code_max_len": len(PACKED),
            "code_max_entropy": 6.1,
            "code_samples": samples,
        }
    }
    result = {"url": "https://kit.example/", "final_url": "https://kit.example/", "jsapi": jsapi}
    return result, Capture(CaptureData(result=result))


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
    result, cap = _capture([PACKED[:4096], SHORT_EVAL])
    [hit] = behaviour_hits([RUNTIME_RULE], cap)
    ev = resolve(hit, RUNTIME_RULE, all_facts={}, artifacts=ARTIFACTS, capture=result, read=_read)
    assert ev["rule"] == "runtime_dynamic_execution"
    assert ev["kind"] == "query"
    assert ev["rows"] == [{"runs": 3, "max_len": len(PACKED), "max_entropy": 6.1}]
    assert [s["rows"] for s in ev["steps"]][-1] == 1
    assert "code_exec" in ev["rule_text"]
    # The full decoded script, plus the short eval'd string; the 4 KB prefix of the
    # script is not repeated.
    contents = [s["content"] for s in ev["samples"]]
    assert contents == [PACKED, SHORT_EVAL]
    assert ev["samples"][0]["entropy"] == entropy(PACKED) > 4.5
    assert [f["id"] for f in ev["files"]] == ["ar_dyn"]


def test_long_samples_are_capped():
    huge = "A" * (SAMPLE_CAP + 10)
    result, cap = _capture([huge])
    [hit] = behaviour_hits([RUNTIME_RULE], cap)
    ev = resolve(hit, RUNTIME_RULE, all_facts={}, artifacts=[], capture=result, read=_read)
    [sample] = ev["samples"]
    assert sample["truncated"] and len(sample["content"]) == SAMPLE_CAP
    assert sample["length"] == SAMPLE_CAP + 10


def test_clipboard_rule_shows_the_clipboard_text():
    rule = _rule("clipboard_command_write")
    clip = [{"api": "writeText", "text": "powershell Get-ChildItem"}]
    result = {
        "url": "https://docs.example/",
        "final_url": "https://docs.example/",
        "clipboard": clip,
    }
    [hit] = behaviour_hits([rule], Capture(CaptureData(result=result)))
    ev = resolve(hit, rule, all_facts={}, artifacts=[], capture=result, read=_read)
    assert ev["rows"][0]["command"] == "powershell Get-ChildItem"
    assert ev["samples"][0]["content"] == clip[0]["text"]


def _old_hit(name, facts, description=""):
    """A hit recorded before rules were queries: the values it read, by dotted name."""
    return {
        "id": "rh_old",
        "rule_name": name,
        "engine": "behaviour",
        "artifact_id": None,
        "detail": {"title": name, "description": description, "facts": facts, "checks": []},
    }


def test_old_hit_resolves_its_recorded_values():
    hit = _old_hit("clipboard_command_write", {"clipboard.commands": [{"text": "iex"}]})
    ev = resolve(
        hit,
        _rule("clipboard_command_write"),
        all_facts={},
        artifacts=[],
        capture={"clipboard": [{"api": "writeText", "text": "powershell -c iex"}]},
        read=_read,
    )
    assert ev["kind"] == "conditions"
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
    assert ev["kind"] == "conditions"


def test_fallback_links_artifacts_named_in_facts():
    hit = _old_hit("risky", {"network.details": [{"sha256": "d" * 64}, {"file": "abc.js"}]})
    ev = resolve(hit, None, all_facts={}, artifacts=ARTIFACTS, capture={}, read=_read)
    linked = {f["id"]: f for f in ev["files"]}
    assert set(linked) == {"ar_dl", "ar_lib"}
    assert linked["ar_dl"]["quarantined"]  # linked, never read
    assert ev["samples"] == []


def test_missing_rule_falls_back_to_recorded_facts():
    hit = _old_hit(
        "gone_rule",
        {"js.code_exec_count": 3, "js.code_exec_max_len": len(PACKED)},
        description="Packed code run through eval.",
    )
    ev = resolve(hit, None, all_facts={}, artifacts=ARTIFACTS, capture={}, read=_read)
    assert not ev["rule_found"]
    assert ev["facts"]["js.code_exec_count"] == 3
    assert ev["description"] == "Packed code run through eval."
    assert [f["id"] for f in ev["files"]] == ["ar_dyn"]  # resolved from the value names
