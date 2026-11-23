import io
import json
import re
import zipfile

import pytest

from sandbox.detections import catalog
from sandbox.detections.base import Capture, CaptureData
from sandbox.detections.kql.language import QueryError, parse
from sandbox.detections.kql.rules import RULES_DIR, SEVERITIES, load
from sandbox.detections.kql.tables import FUNCTIONS, TABLE_FUNCTIONS, TABLES, environment
from sandbox.feeds import parsers
from sandbox.rules import defaults
from sandbox.rules.importer import parse_suricata_line, validate_yara, yara_metadata
from sandbox.runner.events import STDOUT_PREFIX, parse_stdout_line
from sandbox.storage import LocalStore

CAP = Capture(
    CaptureData(
        result={
            "url": "https://x.example/",
            "final_url": "https://x.example/login",
            "clipboard": [{"api": "writeText", "text": "hello"}],
        }
    )
)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ('capture | where final_host == "x.example"', True),
        ('capture | where final_host != "x.example"', False),
        ("capture | where missing_column > 0", False),  # a missing value is a miss
        ("capture | where not(isnotempty(missing_column))", True),
        ('capture | where final_host in ("x.example", "y.example")', True),
        ('capture | where final_host =~ "X.EXAMPLE" and final_url endswith "/login"', True),
        ("capture | where final_host > 3", False),  # a type mismatch is a miss
        ("clipboard | where page_write and strlen(text) == 5", True),
        ("capture | where toscalar(clipboard | count) == 1", True),
        ("capture | where exists(clipboard) and not(exists(downloads))", True),
        ("capture | where toscalar(downloads | summarize max(size)) > 0", False),
    ],
)
def test_query_semantics(query, expected):
    rows, _ = parse(query, environment()).run(CAP, environment())
    assert bool(rows) is expected


def test_query_records_each_step():
    q = parse('clipboard | where page_write | where text == "nope"', environment())
    rows, run = q.run(CAP, environment())
    assert rows == []
    assert [s["rows"] for s in run.steps] == [1, 1, 0]


@pytest.mark.parametrize(
    "query",
    [
        "nosuchtable | where x",
        "capture | where nosuchfunction(final_host)",
        'capture | where final_host matches list("no.such_string")',
        "capture | where exists(nosuchquery)",
        "capture | where (final_host",
    ],
)
def test_broken_queries_stop_the_load(query):
    with pytest.raises(QueryError):
        parse(query, environment())


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ("severity: nope\nscore: 10", "unknown severity"),
        ("severity: high\nscore: 101", "0 to 100"),
        ("severity: high\nscore: -1", "0 to 100"),
        ("severity: high", "missing score"),
    ],
)
def test_rule_header_errors(tmp_path, header, message):
    area = tmp_path / "pkg" / "detections" / "rules" / "test"
    area.mkdir(parents=True)
    (area / "t.kql").write_text(
        f"title: t\n{header}\ndescription: d\n---\ncapture\n", encoding="utf-8"
    )
    with pytest.raises(QueryError, match=message):
        load(area.parent)


def test_builtin_detections_load_and_are_documented():
    assert len(catalog.detections()) >= 85
    for d in catalog.detections():
        assert d.title and d.description and d.severity in SEVERITIES, d.name
        assert d.rule_text(), d.name  # parsed when the catalog loaded
    for name, body in defaults.BUILTIN_YARA.items():
        assert validate_yara(body) is None, name


def test_every_table_and_function_is_documented():
    for name, t in {**TABLES, **TABLE_FUNCTIONS}.items():
        assert t["description"] and t["columns"], name
        assert all(c and m for c, m in t["columns"].items()), name
    for name, f in FUNCTIONS.items():
        assert f["signature"].startswith(name) and f["description"], name


def test_every_shared_query_is_used():
    texts = [p.read_text(encoding="utf-8") for p in RULES_DIR.glob("*/*.kql")]
    env = catalog.detections()[0].env
    for name in env.shared:
        uses = sum(len(re.findall(rf"\b{name}\b", t)) for t in texts)
        assert uses > 1, f"shared query {name} is never used"


def test_tables_give_the_columns_they_document():
    data = CaptureData(result={"url": "https://a.example/", "final_url": "https://a.example/"})
    cap = Capture(data)
    for name, t in TABLES.items():
        for row in t["build"](cap):
            assert set(row) <= set(t["columns"]), name


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
