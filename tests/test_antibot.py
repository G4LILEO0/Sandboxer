"""Bot-check pages (Cloudflare challenge / block): recognising them, keeping the verdict
off "benign" when the run never got past one, and the browser fingerprint fixes that
keep Cloudflare from challenging the sandbox in the first place."""

import json

from sandbox.analysis.engine import evaluate
from sandbox.analysis.facts import CaptureData, build_facts
from sandbox.core import antibot
from sandbox.orchestrator.docker_backend import DockerBackend
from sandbox.runner.page_scripts import INIT_SCRIPT, init_script
from sandbox.runner.profiles import PROFILES, get_profile
from sandbox.runner.spec import RunSpec

URL = "https://shop.example/login"
CHALLENGE_TEXT = (
    "shop.example\nVerifying you are human. This may take a few seconds.\n"
    "shop.example needs to review the security of your connection before proceeding.\n"
    "Ray ID: 8e1f2a3b4c5d6e7f\nPerformance & security by Cloudflare"
)
BLOCK_TEXT = (
    "Sorry, you have been blocked\nYou are unable to access shop.example\n"
    "Cloudflare Ray ID: 8e1f2a3b4c5d6e80"
)


# --- classify ---------------------------------------------------------------------------


def test_managed_challenge_from_response_header():
    found = antibot.classify(
        "Just a moment...", "", [], {"cf-mitigated": "challenge", "cf-ray": "8e1f2a3b4c5d6e7f-FRA"}
    )
    assert found == {"provider": "cloudflare", "kind": "challenge", "ray_id": "8e1f2a3b4c5d6e7f"}


def test_challenge_from_page_markers_and_ray_id_in_text():
    found = antibot.classify("Just a moment...", CHALLENGE_TEXT, ["challenge_platform"])
    assert found["kind"] == "challenge"
    assert found["ray_id"] == "8e1f2a3b4c5d6e7f"
    assert antibot.classify("Un instant…", "", ["cf_chl_opt"])["kind"] == "challenge"


def test_block_page():
    found = antibot.classify(
        "Attention Required! | Cloudflare", BLOCK_TEXT, ["cf_error_details", "cf_wrapper"]
    )
    assert found["kind"] == "blocked"
    headers = {"server": "cloudflare", "cf-ray": "8e1f2a3b4c5d6e80-AMS"}
    assert antibot.classify("Access denied | shop.example", BLOCK_TEXT, [], headers, 403)


def test_words_alone_are_not_a_challenge():
    # An article about Cloudflare challenges, and an ordinary page on a Cloudflare site
    # (which loads the challenge platform's bot-detection script on every page).
    article = "Just a moment... how Cloudflare challenges work"
    assert antibot.classify(article, CHALLENGE_TEXT) is None
    assert antibot.classify("Sign in", "Welcome back", ["challenge_platform"]) is None
    assert antibot.classify("Sorry, you have been blocked: a story", BLOCK_TEXT) is None
    headers = {"server": "cloudflare", "cf-ray": "8e1f2a3b4c5d6e7f-FRA"}
    assert antibot.classify("Sign in", "Welcome back", [], headers, 200) is None


def test_describe():
    note = antibot.describe({"provider": "cloudflare", "kind": "challenge", "waited_ms": 30100})
    assert "Cloudflare's bot check" in note and "30 s" in note and "interactively" in note
    note = antibot.describe({"provider": "cloudflare", "kind": "blocked", "ray_id": "8e1f"})
    assert "blocked the sandbox browser" in note and "Ray ID 8e1f" in note


# --- analysis ---------------------------------------------------------------------------


def _data(title, text, *, antibot_result=None, forms=(), har=()) -> CaptureData:
    result = {
        "url": URL,
        "final_url": URL,
        "title": title,
        "pages": [{"frames": [{"url": URL, "title": title, "text": text, "forms": list(forms)}]}],
        "redirects": [],
        "navigations": [{"url": URL}],
        "hosts": {},
    }
    if antibot_result is not None:
        result["antibot"] = antibot_result
    data = CaptureData(result=result)
    data.har_entries = list(har)
    return data


def _evaluate(data: CaptureData):
    return evaluate(
        data,
        behaviour=[],
        yara_hits=[],
        indicator_hits=[],
        suricata_alerts=[],
        weights={},
        thresholds={"malicious": 70, "suspicious": 30},
    )


def test_runner_recorded_unpassed_challenge_makes_verdict_unknown():
    encounter = {
        "provider": "cloudflare",
        "kind": "challenge",
        "url": URL,
        "ray_id": "8e1f2a3b4c5d6e7f",
        "waited_ms": 30000,
        "clicks": 2,
        "cleared": False,
    }
    data = _data(
        "Just a moment...",
        CHALLENGE_TEXT,
        antibot_result={"encounters": [encounter], "blocked": True},
    )
    ev = _evaluate(data)
    assert ev.facts["capture"]["antibot"]["kind"] == "challenge"
    assert ev.facts["capture"]["antibot"]["clicks"] == 2
    assert ev.result.verdict == "unknown"


def test_passed_challenge_does_not_flag_the_run():
    encounter = {"provider": "cloudflare", "kind": "challenge", "url": URL, "cleared": True}
    data = _data("Sign in", "Welcome", antibot_result={"encounters": [encounter], "blocked": False})
    ev = _evaluate(data)
    assert ev.facts["capture"]["antibot"] is None
    assert ev.result.verdict == "benign"


def test_older_capture_challenge_read_from_page_and_har():
    har = [
        {
            "request": {"url": URL, "method": "GET", "headers": []},
            "response": {
                "status": 403,
                "headers": [
                    {"name": "Server", "value": "cloudflare"},
                    {"name": "cf-mitigated", "value": "challenge"},
                    {"name": "CF-RAY", "value": "8e1f2a3b4c5d6e7f-FRA"},
                ],
            },
        }
    ]
    facts = build_facts(_data("Just a moment...", CHALLENGE_TEXT, har=har))
    assert facts["capture"]["antibot"] == {
        "provider": "cloudflare",
        "kind": "challenge",
        "ray_id": "8e1f2a3b4c5d6e7f",
        "url": URL,
    }
    # The same page with a 200 and no challenge header or markers is just text.
    har[0]["response"] = {"status": 200, "headers": [{"name": "Server", "value": "cloudflare"}]}
    assert build_facts(_data("Sign in", CHALLENGE_TEXT, har=har))["capture"]["antibot"] is None


def test_older_capture_block_page_from_har_status():
    har = [
        {
            "request": {"url": URL, "method": "GET", "headers": []},
            "response": {"status": 403, "headers": [{"name": "server", "value": "cloudflare"}]},
        }
    ]
    data = _data("Attention Required! | Cloudflare", BLOCK_TEXT, har=har)
    assert build_facts(data)["capture"]["antibot"]["kind"] == "blocked"
    assert _evaluate(data).result.verdict == "unknown"


# --- browser fingerprint ----------------------------------------------------------------


def test_user_agent_follows_the_running_browser_version():
    windows = get_profile("chrome-windows")
    assert windows.user_agent_for("131.0.6778.33") == windows.user_agent
    assert "Chrome/140.0.0.0 Safari" in windows.user_agent_for("140.0.7339.16")
    edge = PROFILES["edge-windows"].user_agent_for("140.0.7339.16")
    assert "Chrome/140.0.0.0" in edge and edge.endswith("Edg/140.0.0.0")
    # Safari's user agent has no Chrome version to follow; unknown versions change nothing.
    iphone = PROFILES["safari-iphone"]
    assert iphone.user_agent_for("140.0.7339.16") == iphone.user_agent
    assert windows.user_agent_for(None) == windows.user_agent


def test_init_script_platform_and_native_looking_hooks():
    script = init_script("Win32")
    assert 'const platform = "Win32";' in script
    assert 'const platform = "";' in init_script("")
    assert init_script("") != INIT_SCRIPT  # the placeholder is always filled
    # Wrappers report native source through one patched Function.prototype.toString, not
    # an own toString property (Object.hasOwn(fn, 'toString') gave the old hooks away).
    assert "Function.prototype, 'toString'" in script
    assert "Object.defineProperty(wrapper, 'toString'" not in script
    # navigator.platform is a prototype getter, not an own property of navigator.
    assert "Navigator.prototype, 'platform'" in script


def test_run_spec_carries_headed_and_wait():
    spec = RunSpec.from_json(json.dumps({"analysis_id": "a", "url": URL, "headed": True}))
    assert spec.headed is True and spec.antibot_wait_s == 30


class _Containers:
    def __init__(self):
        self.kwargs = None

    def run(self, **kwargs):
        self.kwargs = kwargs
        raise RuntimeError("stop here")


def test_headed_automated_session_gets_a_display_but_no_vnc(monkeypatch):
    from datetime import UTC, datetime

    from sandbox.config import Settings
    from sandbox.orchestrator.backend import SessionSpec

    containers = _Containers()
    backend = DockerBackend(Settings(), client=type("C", (), {"containers": containers})())
    monkeypatch.setattr(backend, "_ensure_network", lambda: None)
    monkeypatch.setattr(backend, "_check_egress", lambda: None)
    spec = SessionSpec(
        session_id="se_1",
        analysis_id="an_1",
        url=URL,
        interactive=False,
        time_limit_s=60,
        expires_at=datetime.now(UTC),
        runner={"headed": True, "viewport_width": 1366, "viewport_height": 768},
    )
    try:
        backend._start(spec)
    except RuntimeError:
        pass
    env = containers.kwargs["environment"]
    assert env["SANDBOX_HEADED"] == "1"
    assert env["SANDBOX_SCREEN"] == "1366x888x24"
    assert "SANDBOX_INTERACTIVE" not in env and "SANDBOX_VNC_PASSWORD" not in env


def test_playwright_binding_reply_is_harness_code():
    from sandbox.runner.page_scripts import is_harness_code

    reply = (
        "(function deliverResult(arg) {\n      const callbacks = globalThis[arg.name]['callbacks'];"
        "\n      callbacks.delete(arg.seq);\n    })"
    )
    assert is_harness_code(reply)
    assert not is_harness_code("(function deliverResults(x) { return x })")
