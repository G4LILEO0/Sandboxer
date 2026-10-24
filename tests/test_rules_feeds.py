import io
import json
import zipfile

import pytest

from sandbox.feeds import parsers
from sandbox.rules import defaults
from sandbox.rules.behaviour import RuleSyntaxError, evaluate, parse_rule
from sandbox.rules.importer import parse_suricata_line, validate_yara, yara_metadata
from sandbox.runner.events import STDOUT_PREFIX, parse_stdout_line
from sandbox.storage import LocalStore

FACTS = {"forms": {"cross": 2, "list": ["a"]}, "final": {"host": "x.example", "ok": True}}


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ({"fact": "forms.cross", "op": "gt", "value": 1}, True),
        ({"fact": "forms.cross", "op": "lt", "value": 1}, False),
        ({"fact": "missing.path", "op": "gt", "value": 0}, False),
        ({"fact": "missing.path", "op": "exists", "value": False}, True),
        ({"fact": "final.host", "op": "matches", "value": r"\.example$"}, True),
        ({"fact": "forms.list", "op": "any_matches", "value": "^a$"}, True),
        (
            {
                "all": [
                    {"fact": "final.ok", "op": "eq", "value": True},
                    {"not": {"fact": "forms.cross", "op": "eq", "value": 0}},
                ]
            },
            True,
        ),
        (
            {
                "any": [
                    {"fact": "forms.cross", "op": "eq", "value": 0},
                    {"fact": "final.ok", "op": "eq", "value": False},
                ]
            },
            False,
        ),
        ({"fact": "final.host", "op": "gt", "value": 3}, False),  # type mismatch is a miss
    ],
)
def test_behaviour_conditions(condition, expected):
    assert evaluate(parse_rule({"condition": condition}), FACTS).matched is expected


def test_behaviour_records_facts_and_evidence():
    rule = parse_rule(
        {"condition": {"fact": "forms.cross", "op": "gt", "value": 0}, "evidence": ["final.host"]}
    )
    outcome = evaluate(rule, FACTS)
    assert outcome.facts == {"forms.cross": 2, "final.host": "x.example"}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"condition": {}},
        {"condition": {"fact": "a"}},
        {"condition": {"fact": "a", "op": "nope"}},
        {"condition": {"all": []}},
        {"condition": {"fact": "a", "op": "matches", "value": "("}},
        {"condition": {"fact": "a", "op": "eq"}, "evidence": "x"},
    ],
)
def test_behaviour_syntax_errors(body):
    with pytest.raises(RuleSyntaxError):
        parse_rule(body)


def test_builtin_rules_are_valid():
    for spec in defaults.BEHAVIOUR_RULES:
        parse_rule(spec["body"])
    for name, body in defaults.BUILTIN_YARA.items():
        assert validate_yara(body) is None, name


def test_yara_validation_and_metadata():
    assert validate_yara("rule broken { condition: nope }") is not None
    meta = yara_metadata(
        'rule r : web phish { meta: score = 80 mitre_attack = "T1566" condition: true }'
    )
    assert meta["severity"] == "high"
    assert meta["tags"] == ["phish", "web"]
    assert meta["attack_ids"] == ["T1566"]


def test_suricata_line_parsing():
    line = (
        'alert http any any -> any any (msg:"ET PHISHING Test"; priority:1; '
        "metadata: mitre_technique_id T1566; sid:2000001; rev:1;)"
    )
    parsed = parse_suricata_line(line)
    assert parsed["name"] == "sid:2000001"
    assert parsed["severity"] == "high"
    assert parsed["enabled"] is True
    assert parse_suricata_line("# " + line)["enabled"] is False
    assert parse_suricata_line("# just a comment") is None


def test_urlhaus_parser():
    data = (
        b'# comment\n"1","2026-10-10","hxxp://bad[.]example/x","online","","malware_download",'
        b'"exe,elf","https://urlhaus.abuse.ch/url/1/","r"\n'
    )
    [rec] = list(parsers.urlhaus_csv(data))
    assert rec.type == "url"
    assert rec.value == "http://bad.example/x"
    assert set(rec.tags) == {"malware_download", "exe", "elf"}


def test_urlhaus_parser_rejects_malformed():
    with pytest.raises(parsers.FeedError):
        list(parsers.urlhaus_csv(b"just,two\n"))


def test_threatfox_parser():
    payload = {
        "1": [
            {
                "ioc_value": "1.2.3.4:443",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware_printable": "X",
                "confidence_level": 90,
                "tags": ["a"],
            }
        ],
        "2": [{"ioc_value": "EVIL.example", "ioc_type": "domain"}],
    }
    recs = list(parsers.threatfox_json(json.dumps(payload).encode()))
    assert {(r.type, r.value) for r in recs} == {("ip", "1.2.3.4"), ("domain", "evil.example")}
    assert next(r for r in recs if r.type == "ip").confidence == 90


def test_plain_lists_and_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top.csv", "1,google.com\n2,Example.ORG.\n")
    assert parsers.tranco_csv(buf.getvalue()) == [(1, "google.com"), (2, "example.org")]
    assert [r.value for r in parsers.plain_domains(b"# x\nbad.example\nnot a domain!\n")] == [
        "bad.example"
    ]
    assert [r.value for r in parsers.plain_urls(b"https://a.example/p\n")] == [
        "https://a.example/p"
    ]


def test_attack_parser():
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Phishing",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1566",
                        "url": "https://attack.mitre.org/techniques/T1566",
                    }
                ],
                "kill_chain_phases": [{"phase_name": "initial-access"}],
            },
            {
                "type": "attack-pattern",
                "name": "Old",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0000"}],
            },
        ]
    }
    [tech] = parsers.attack_stix(json.dumps(bundle).encode())
    assert (tech.id, tech.name, tech.tactics) == ("T1566", "Phishing", ["initial-access"])


@pytest.mark.parametrize(
    ("ioc_type", "raw", "expected"),
    [
        ("domain", "*.Bad.Example.", "bad.example"),
        ("ip", "2001:DB8::1", "2001:db8::1"),
        ("hash", "ABCDEF" * 10 + "ABCD", ("abcdef" * 10 + "abcd")),
        ("hash", "xyz", None),
        ("url", "javascript:alert(1)", None),
    ],
)
def test_normalise_value(ioc_type, raw, expected):
    assert parsers.normalise_value(ioc_type, raw) == expected


def test_store_rejects_traversal_and_separates_quarantine(tmp_path):
    store = LocalStore(tmp_path / "a", tmp_path / "q")
    obj = store.put_bytes("an_1/x.txt", b"hi")
    assert obj.size == 2 and store.read_bytes("an_1/x.txt") == b"hi"
    store.put_bytes("quarantine/an_1/abc", b"MZ")
    assert (tmp_path / "q" / "an_1" / "abc").exists()
    for bad in ("../x", "/etc/passwd", "a/../../x", ""):
        with pytest.raises(ValueError):
            store.put_bytes(bad, b"x")
    store.delete("quarantine/an_1/abc")
    assert not store.exists("quarantine/an_1/abc")


def test_runner_stdout_protocol():
    line = STDOUT_PREFIX + json.dumps(
        {"ts": "2026-10-10T00:00:00+00:00", "kind": "x", "payload": {}}
    )
    assert parse_stdout_line(line)["kind"] == "x"
    assert parse_stdout_line("INFO something") is None
    assert parse_stdout_line(STDOUT_PREFIX + "{broken") is None
