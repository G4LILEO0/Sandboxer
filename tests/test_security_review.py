"""Regression tests for the findings of the security review (docs/security-review.md).

Each test names the finding it covers (SR-nn).
"""

import io
import json
import tarfile
import time
import zipfile
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from sandbox.api import oidc, tokens
from sandbox.api.main import _TOKEN_PATH_RE, create_app
from sandbox.api.routes.analyses import _stix_bundle
from sandbox.api.routes.auth_routes import safe_next
from sandbox.api.routes.intel import get_http_client
from sandbox.api.routes.sessions import _allowed_stream_type, _local_novnc
from sandbox.config import Settings, get_settings
from sandbox.core import safehttp
from sandbox.core.netguard import BlockedDestination, NetGuard
from sandbox.feeds import parsers
from sandbox.rules.importer import validate_yara
from tests.conftest import fake_resolver

GUARD = NetGuard()


# --- SR-01: DNS rebinding in outbound HTTP -----------------------------------------------


def _mock(handler):
    calls: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(record)), calls


async def test_guarded_send_connects_to_the_checked_address():
    http, calls = _mock(lambda r: httpx.Response(200, text="ok"))
    response = await safehttp.guarded_send(
        http, "GET", "https://public.example/feed.txt", guard=GUARD, resolver=fake_resolver
    )
    await response.aclose()
    [request] = calls
    assert request.url.host == "93.184.216.34"
    assert request.headers["host"] == "public.example"
    assert request.extensions["sni_hostname"] == "public.example"


async def test_guarded_send_checks_every_redirect_hop():
    http, calls = _mock(
        lambda r: httpx.Response(302, headers={"location": "http://internal.example/admin"})
    )
    with pytest.raises(BlockedDestination):
        await safehttp.guarded_send(
            http, "GET", "https://public.example/", guard=GUARD, resolver=fake_resolver
        )
    assert len(calls) == 1  # the internal host was never contacted


async def test_guarded_send_refuses_unresolved_and_literal_internal_hosts():
    http, calls = _mock(lambda r: httpx.Response(200))
    with pytest.raises(safehttp.UnresolvedHost):
        await safehttp.guarded_send(
            http, "GET", "https://gone.example/", guard=GUARD, resolver=fake_resolver
        )
    with pytest.raises(BlockedDestination):
        await safehttp.guarded_send(
            http, "POST", "http://169.254.169.254/", guard=GUARD, resolver=fake_resolver
        )
    assert calls == []


async def test_guarded_send_returns_redirect_when_redirects_are_off():
    http, calls = _mock(lambda r: httpx.Response(307, headers={"location": "/elsewhere"}))
    response = await safehttp.guarded_send(
        http,
        "POST",
        "https://public.example/hook",
        guard=GUARD,
        resolver=fake_resolver,
        max_redirects=0,
        content=b"{}",
    )
    await response.aclose()
    assert response.status_code == 307 and len(calls) == 1


async def test_redirect_walk_is_pinned(client):
    http, calls = _mock(lambda r: httpx.Response(200))
    client.app.dependency_overrides[get_http_client] = lambda: http
    response = await client.get(
        "/v1/intel/redirect-chain", params={"url": "https://public.example/x"}
    )
    assert response.json()["hops"][0]["status"] == 200
    assert calls[0].url.host == "93.184.216.34"
    assert calls[0].headers["host"] == "public.example"


async def test_checked_address_prefers_ipv4_for_dual_stack_hosts():
    # The system resolver sorts its answers, which puts "2001:..." first; Docker has no
    # IPv6 route, so the walk used to fail on its first hop for hosts like google.com.kw.
    async def dual_stack(host: str) -> list[str]:
        return ["2001:4860:4802:32::78", "216.239.38.120"]

    assert await safehttp.checked_address("dual.example", GUARD, dual_stack) == "216.239.38.120"

    async def v6_only(host: str) -> list[str]:
        return ["2001:4860:4802:32::78"]

    assert await safehttp.checked_address("v6.example", GUARD, v6_only) == "2001:4860:4802:32::78"


# --- SR-02: YARA include directives ----------------------------------------------------


def test_yara_includes_are_refused(tmp_path):
    secret = tmp_path / "secret.yar"
    secret.write_text("rule leaked { condition: true }")
    error = validate_yara(f'include "{secret}"\nrule a {{ condition: true }}')
    assert error is not None and "include" in error


# --- SR-06: OIDC algorithm confusion ----------------------------------------------------


@pytest.fixture
def idp():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="k1", alg="RS256")
    settings = Settings(
        _env_file=None, env="test", oidc_issuer="https://idp.example", oidc_client_id="sbx"
    )
    meta = {"issuer": "https://idp.example", "jwks_uri": "https://idp.example/jwks"}

    def handler(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=meta)
        return httpx.Response(200, json={"keys": [jwk]})

    oidc._CACHE.clear()
    yield key, settings, httpx.AsyncClient(transport=httpx.MockTransport(handler))
    oidc._CACHE.clear()


def _claims():
    return {"iss": "https://idp.example", "aud": "sbx", "sub": "u1", "exp": time.time() + 60}


async def test_oidc_accepts_rs256(idp):
    key, settings, http = idp
    token = jwt.encode(_claims(), key, algorithm="RS256", headers={"kid": "k1"})
    assert (await oidc.validate_jwt(http, settings, token))["sub"] == "u1"


@pytest.mark.parametrize("alg", ["HS256", "none"])
async def test_oidc_refuses_symmetric_and_none(idp, alg):
    _, settings, http = idp
    token = jwt.encode(_claims(), "x" * 32 if alg == "HS256" else None, algorithm=alg)
    header, payload, sig = token.split(".")
    forged_header = jwt.utils.base64url_encode(
        json.dumps({"alg": alg, "kid": "k1", "typ": "JWT"}).encode()
    ).decode()
    with pytest.raises(oidc.OidcError, match="not allowed"):
        await oidc.validate_jwt(http, settings, f"{forged_header}.{payload}.{sig}")


# --- SR-07 / SR-10: sign-in redirect and login CSRF --------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/ui/report.html?id=an_1", "/ui/report.html?id=an_1"),
        ("//evil.example/", "/ui/"),
        ("/\\evil.example/", "/ui/"),
        ("/\t/evil.example/", "/ui/"),
        ("https://evil.example/", "/ui/"),
    ],
)
def test_safe_next(value, expected):
    assert safe_next(value) == expected


async def test_callback_needs_the_browser_that_started_sign_in(client):
    settings = Settings(_env_file=None, env="test", auth_mode="oidc", secret_key="k" * 40)
    client.app.dependency_overrides[get_settings] = lambda: settings
    state = tokens.issue(settings.secret_key.get_secret_value(), "oidc_state", 600, v="v", n="n1")
    response = await client.get("/auth/callback", params={"code": "c", "state": state})
    assert response.status_code == 400
    assert "browser" in response.json()["detail"]


# --- SR-08: unsafe secret and auth defaults ----------------------------------------------


def test_default_secret_refused_with_oidc_in_any_env():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(Settings(_env_file=None, env="dev", auth_mode="oidc"))


def test_short_secret_refused_in_prod():
    with pytest.raises(RuntimeError, match="32"):
        create_app(Settings(_env_file=None, env="prod", auth_mode="oidc", secret_key="short"))


# --- SR-09: live-view assets from the session container --------------------------------


@pytest.mark.parametrize(
    ("path", "media", "ok"),
    [
        ("vnc.html", "text/html; charset=utf-8", True),
        ("app/ui.js", "application/javascript", True),
        ("app/styles/base.css", "text/css", True),
        ("app/images/info.svg", "image/svg+xml", True),
        ("evil.html", "text/html", False),
        ("app/ui.js", "text/html", False),
        ("x", "application/octet-stream", False),
    ],
)
def test_stream_content_types(path, media, ok):
    assert _allowed_stream_type(path, media) is ok


def test_local_novnc_stays_in_its_directory(tmp_path):
    root = tmp_path / "novnc"
    (root / "app").mkdir(parents=True)
    (root / "vnc.html").write_text("<html></html>")
    (root / "app" / "ui.js").write_text("export {}")
    (tmp_path / "secret.js").write_text("nope")
    headers = {"Content-Security-Policy": "x"}
    assert _local_novnc(root, "vnc.html", headers).status_code == 200
    assert _local_novnc(root, "app/ui.js", headers).media_type == "text/javascript"
    for bad in ("../secret.js", "missing.js"):
        with pytest.raises(Exception) as exc:
            _local_novnc(root, bad, headers)
        assert getattr(exc.value, "status_code", None) == 404


# --- SR-11: STIX export ------------------------------------------------------------------


def test_stix_patterns_escape_every_type_and_skip_unsupported():
    analysis = SimpleNamespace(id="an_1", verdict="malicious", normalised_url="https://x/")
    rows = [
        SimpleNamespace(type="domain", value="a'] OR [x:y = 'z"),
        SimpleNamespace(type="eth_address", value="0x" + "a" * 40),
    ]
    bundle = _stix_bundle(analysis, rows)
    [indicator] = bundle["objects"]
    assert indicator["pattern"] == "[domain-name:value = 'a\\'] OR [x:y = \\'z']"


# --- SR-13: tokens in logged paths -------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "logged"),
    [
        ("/v1/stream/abc.def/vnc.html", "/v1/stream/[token]/vnc.html"),
        ("/v1/files/abc.def", "/v1/files/[token]"),
        ("/v1/embed/abc.def/report", "/v1/embed/[token]/report"),
        ("/v1/embed-tokens", "/v1/embed-tokens"),
    ],
)
def test_token_paths_are_redacted(path, logged):
    assert _TOKEN_PATH_RE.sub(r"\1[token]", path) == logged


# --- SR-14: metrics in prod --------------------------------------------------------------


async def test_metrics_need_a_token_in_prod(client):
    client.app.dependency_overrides[get_settings] = lambda: Settings(
        _env_file=None, env="prod", auth_mode="oidc", secret_key="k" * 40
    )
    assert (await client.get("/metrics")).status_code == 401


# --- SR-15: archive size limits ----------------------------------------------------------


def test_feed_archive_member_limit(monkeypatch):
    monkeypatch.setattr(parsers, "MAX_ARCHIVE_MEMBER", 10)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("rules.yar", "x" * 100)
    with pytest.raises(parsers.FeedError, match="larger"):
        parsers.rule_archive(buf.getvalue(), (".yar",))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("rules.yar")
        info.size = 100
        tar.addfile(info, io.BytesIO(b"x" * 100))
    with pytest.raises(parsers.FeedError, match="too large"):
        parsers.rule_archive(buf.getvalue(), (".yar",))


# --- SR-03 / SR-05: authorisation (need PostgreSQL) -------------------------------------

ALICE = {"x-dev-user": "alice@example.org", "x-dev-roles": "analyst"}
BOB = {"x-dev-user": "bob@example.org", "x-dev-roles": "analyst"}
SENIOR = {"x-dev-user": "sam@example.org", "x-dev-roles": "senior_analyst"}
ENGINEER = {"x-dev-user": "eng@example.org", "x-dev-roles": "detection_engineer"}
RULE_ANY = json.dumps({"condition": {"not": {"fact": "no.such.fact", "op": "exists"}}})


@pytest.mark.db
async def test_only_submitter_or_senior_can_cancel(db_client):
    created = await db_client.post(
        "/v1/analyses", json={"url": "https://public.example/c"}, headers=ALICE
    )
    analysis_id = created.json()["id"]
    refused = await db_client.post(f"/v1/analyses/{analysis_id}/cancel", headers=BOB)
    assert refused.status_code == 403
    assert (await db_client.get(f"/v1/analyses/{analysis_id}", headers=ALICE)).json()[
        "status"
    ] == "queued"
    allowed = await db_client.post(f"/v1/analyses/{analysis_id}/cancel", headers=SENIOR)
    assert allowed.status_code == 202 and allowed.json()["status"] == "cancelled"


@pytest.mark.db
async def test_rule_test_leaves_out_restricted_analyses(db_client):
    from sandbox.db.models import Analysis, AnalysisVersion
    from sandbox.ids import new_id

    analysis_id = new_id("an")
    async with db_client.app.state.sessionmaker() as db:
        db.add(
            Analysis(
                id=analysis_id,
                url="https://secret-case.example/",
                normalised_url="https://secret-case.example/",
                host="secret-case.example",
                mode="automated",
                submitted_by="bob@example.org",
                status="finished",
                time_limit_s=60,
                version=1,
                restricted_to=["bob@example.org"],
            )
        )
        await db.flush()
        db.add(
            AnalysisVersion(
                id=new_id("av"),
                analysis_id=analysis_id,
                version=1,
                verdict="clean",
                score=0,
                summary={"facts": {}},
            )
        )
        await db.commit()
    response = await db_client.post(
        "/v1/rules/test",
        json={"engine": "behaviour", "body": RULE_ANY, "limit": 500},
        headers=ENGINEER,
    )
    assert response.status_code == 200, response.text
    assert analysis_id not in {r["analysis_id"] for r in response.json()["results"]}
