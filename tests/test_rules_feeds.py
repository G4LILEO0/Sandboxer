import io
import json
import zipfile

import pytest

from sandbox.detections import catalog
from sandbox.detections.model import SEVERITIES, all_of, any_of, detection, not_, sig
from sandbox.feeds import parsers
from sandbox.rules import defaults
from sandbox.rules.importer import parse_suricata_line, validate_yara, yara_metadata
from sandbox.runner.events import STDOUT_PREFIX, parse_stdout_line
from sandbox.storage import LocalStore

FACTS = {"forms": {"cross": 2, "list": ["a"]}, "final": {"host": "x.example", "ok": True}}
CROSS, OK, HOST, GONE = sig("forms.cross"), sig("final.ok"), sig("final.host"), sig("missing.path")


def _detection(when, evidence=()):
    return detection(
        "t",
        title="t",
        severity="high",
        score=10,
        tags=[],
        attack=[],
        description="",
        when=when,
        evidence=evidence,
        register=False,
    )


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (CROSS > 1, True),
        (CROSS < 1, False),
        (GONE > 0, False),
        (not_(GONE.present()), True),
        (HOST.one_of(["x.example", "y.example"]), True),
        (all_of(OK.is_true(), not_(CROSS.equals(0))), True),
        (any_of(CROSS.equals(0), OK.equals(False)), False),
        (HOST > 3, False),  # type mismatch is a miss
        (OK.is_true() & ~(CROSS.equals(0)), True),
        (CROSS.equals(0) | OK.is_true(), True),
    ],
)
def test_detection_conditions(condition, expected):
    assert _detection(condition).evaluate(FACTS).matched is expected


def test_detection_records_values_checks_and_evidence():
    outcome = _detection(all_of(CROSS > 0, OK.is_true()), evidence=["final.host"]).evaluate(FACTS)
    assert outcome.facts == {"forms.cross": 2, "final.ok": True, "final.host": "x.example"}
    assert [c["passed"] for c in outcome.checks] == [True, True]
    assert outcome.checks[0]["value"] == 2


def test_any_of_checks_every_branch():
    """The report shows every value a rule looked at, so ``any`` never short-circuits."""
    outcome = _detection(any_of(CROSS > 0, OK.is_true())).evaluate(FACTS)
    assert len(outcome.checks) == 2


@pytest.mark.parametrize(
    "kwargs",
    [{"severity": "nope"}, {"score": 101}, {"score": -1}],
)
def test_detection_declaration_errors(kwargs):
    base = dict(
        title="t",
        severity="high",
        score=10,
        tags=[],
        attack=[],
        description="",
        when=CROSS > 0,
        register=False,
    )
    with pytest.raises(ValueError):
        detection("t", **{**base, **kwargs})


def test_builtin_detections_load_and_are_documented():
    assert len(catalog.detections()) >= 85
    for d in catalog.detections():
        assert d.title and d.description and d.severity in SEVERITIES, d.name
        for s in d.signals():  # the catalog refuses to load an undeclared signal
            assert s.title and s.description, (d.name, s.path)
        assert d.rule_text().startswith("Fires when")
    for name, body in defaults.BUILTIN_YARA.items():
        assert validate_yara(body) is None, name


def test_every_signal_is_read_by_a_detection_and_exists_in_the_observed_values():
    from sandbox.detections.base import CaptureData
    from sandbox.detections.model import _MISSING, SIGNALS, get_value
    from sandbox.detections.observe import build_facts

    used = {s.path for d in catalog.detections() for s in d.signals()}
    assert used == set(SIGNALS)
    facts = build_facts(CaptureData(result={"url": "https://a.example/", "pages": []}))
    # Fake-wallet values only exist when the wallet profile ran.
    optional = {"web3.wallet_requests", "web3.wallet_drainer"}
    missing = [p for p in SIGNALS if p not in optional and get_value(facts, p) is _MISSING]
    assert missing == []


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


def test_detection_reference_doc_is_current():
    """docs/detections.md is generated from the catalog: python -m sandbox.detections.docs."""
    from sandbox.detections import docs

    assert docs.OUT.read_text(encoding="utf-8") == docs.render()
