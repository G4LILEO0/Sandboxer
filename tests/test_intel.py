from urllib.parse import quote

import httpx
import pytest

from sandbox.api.routes.intel import get_http_client, vt_url_id
from sandbox.config import Settings, get_settings

KEYS = Settings(
    env="test",
    vt_api_key="vt-secret",
    abuseipdb_api_key="abuse-secret",
    vt_url_poll_interval_s=0,
)


def _use(client, handler, settings=KEYS):
    """Route the app's outbound HTTP through ``handler`` and apply ``settings``."""
    calls: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    mock = httpx.AsyncClient(transport=httpx.MockTransport(record))
    client.app.dependency_overrides[get_http_client] = lambda: mock
    client.app.dependency_overrides[get_settings] = lambda: settings
    return calls


async def test_ui_is_served(client):
    root = await client.get("/")
    assert root.status_code == 307
    assert root.headers["location"] == "/ui/"
    page = await client.get("/ui/")
    assert page.status_code == 200
    assert "URL Sandbox" in page.text
    assert (await client.get("/ui/js/sandbox.js")).status_code == 200


async def test_status_reports_missing_keys(client):
    _use(client, lambda r: httpx.Response(500), Settings(_env_file=None, env="test", vt_api_key=""))
    body = (await client.get("/v1/intel/status")).json()
    assert body == {"virustotal": False, "abuseipdb": False}


async def test_vt_lookup_without_key_is_503(client):
    calls = _use(
        client, lambda r: httpx.Response(200, json={}), Settings(_env_file=None, env="test")
    )
    response = await client.get("/v1/intel/vt/domain/example.com")
    assert response.status_code == 503
    assert response.json()["error"] == "vendor_not_configured"
    assert calls == []


async def test_vt_domain_lookup_forwards_key(client):
    calls = _use(client, lambda r: httpx.Response(200, json={"data": {"id": "example.com"}}))
    response = await client.get("/v1/intel/vt/domain/example.com")
    assert response.status_code == 200
    assert response.json()["data"]["id"] == "example.com"
    assert str(calls[0].url) == "https://www.virustotal.com/api/v3/domains/example.com"
    assert calls[0].headers["x-apikey"] == "vt-secret"


async def test_vendor_error_is_passed_through(client):
    _use(client, lambda r: httpx.Response(429, json={"error": {"code": "QuotaExceededError"}}))
    response = await client.get("/v1/intel/vt/hash/" + "a" * 64)
    assert response.status_code == 429
    assert response.json()["error"] == "VirusTotal HTTP 429"


@pytest.mark.parametrize(
    ("path", "error"),
    [
        ("/v1/intel/vt/ip/10.0.0.1", "private_ioc"),
        ("/v1/intel/vt/ip/not-an-ip", "invalid_ioc"),
        ("/v1/intel/vt/hash/xyz", "invalid_ioc"),
        ("/v1/intel/vt/domain/..%2F..%2Ffiles", "invalid_ioc"),
        ("/v1/intel/abuseipdb/127.0.0.1", "private_ioc"),
    ],
)
async def test_bad_iocs_never_leave(client, path, error):
    calls = _use(client, lambda r: httpx.Response(200, json={}))
    response = await client.get(path)
    assert response.status_code == 422
    assert response.json()["error"] == error
    assert calls == []


async def test_vt_url_submits_and_polls_when_unknown(client):
    url = "https://public.example/login?a=1"
    seen_report = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == f"/api/v3/urls/{vt_url_id(url)}":
            seen_report.append(1)
            if len(seen_report) == 1:
                return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
            return httpx.Response(200, json={"data": {"type": "url"}})
        if path == "/api/v3/urls" and request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "u-123"}})
        if path == "/api/v3/analyses/u-123":
            return httpx.Response(200, json={"data": {"attributes": {"status": "completed"}}})
        return httpx.Response(500)

    _use(client, handler)
    # Encoded the way the page's encodeURIComponent() does it.
    response = await client.get(f"/v1/intel/vt/url/{quote(url, safe='')}")
    assert response.status_code == 200, response.text
    assert response.json()["data"]["type"] == "url"


async def test_vt_url_submit_rejection_keeps_vendor_message(client):
    url = "https://cg0snh9sa48osyxhf/?876164590083787650943"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                400,
                json={
                    "error": {
                        "code": "InvalidArgumentError",
                        "message": "Unable to canonicalize url",
                    }
                },
            )
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    _use(client, handler)
    response = await client.get(f"/v1/intel/vt/url/{quote(url, safe='')}")
    assert response.status_code == 400
    assert response.json() == {
        "error": "VirusTotal submit HTTP 400",
        "detail": "Unable to canonicalize url",
    }


async def test_vt_url_lookup_keeps_every_question_mark(client):
    url = "https://google.com.kw/share.google?q=cg0sNh9Sa48oSYxhf?876164590083787650943"
    calls = _use(client, lambda r: httpx.Response(200, json={"data": {"type": "url"}}))
    response = await client.get(f"/v1/intel/vt/url/{quote(url, safe='')}")
    assert response.status_code == 200
    assert calls[0].url.path == f"/api/v3/urls/{vt_url_id(url)}"


async def test_abuseipdb_lookup(client):
    calls = _use(client, lambda r: httpx.Response(200, json={"data": {"abuseConfidenceScore": 5}}))
    response = await client.get("/v1/intel/abuseipdb/93.184.216.34")
    assert response.status_code == 200
    assert calls[0].headers["key"] == "abuse-secret"
    assert calls[0].url.params["ipAddress"] == "93.184.216.34"


async def test_redirect_chain_follows_hops(client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/next"})
        if request.url.path == "/next":
            return httpx.Response(301, headers={"location": "https://public.example/final"})
        return httpx.Response(200, text="done")

    _use(client, handler)
    response = await client.get(
        "/v1/intel/redirect-chain", params={"url": "hxxp://public[.]example/start"}
    )
    hops = response.json()["hops"]
    assert [h["url"] for h in hops] == [
        "http://public.example/start",
        "http://public.example/next",
        "https://public.example/final",
    ]
    assert [h["status"] for h in hops] == [302, 301, 200]


async def test_redirect_chain_refuses_internal_hop(client):
    calls = _use(
        client, lambda r: httpx.Response(302, headers={"location": "http://internal.example/"})
    )
    response = await client.get(
        "/v1/intel/redirect-chain", params={"url": "https://public.example/"}
    )
    hops = response.json()["hops"]
    assert hops[-1]["url"] == "http://internal.example/"
    assert "10.0.0.5" in hops[-1]["blocked"]
    assert len(calls) == 1  # the internal host was never contacted


async def test_redirect_chain_detects_loop(client):
    _use(client, lambda r: httpx.Response(302, headers={"location": "/"}))
    hops = (
        await client.get("/v1/intel/redirect-chain", params={"url": "https://public.example/"})
    ).json()["hops"]
    assert hops[-1]["note"] == "redirect loop detected"


async def test_redirect_chain_follows_meta_refresh_and_reports_title(client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/landing":
            page = (
                "<html><head><title>Loading&hellip;</title>"
                "<META HTTP-EQUIV='Refresh' CONTENT='0; URL=https://public.example/final'>"
            )
            return httpx.Response(200, headers={"content-type": "text/html"}, text=page)
        return httpx.Response(
            200, headers={"content-type": "text/html; charset=utf-8"}, text="<title>Twitch</title>"
        )

    calls = _use(client, handler)
    hops = (
        await client.get(
            "/v1/intel/redirect-chain", params={"url": "https://public.example/landing"}
        )
    ).json()["hops"]
    assert [h["url"] for h in hops] == [
        "https://public.example/landing",
        "https://public.example/final",
    ]
    assert hops[0]["via"] == "meta-refresh"
    assert hops[0]["location"] == "https://public.example/final"
    assert hops[0]["title"] == "Loading…"
    assert hops[1]["title"] == "Twitch"
    assert hops[1]["location"] is None
    assert calls[0].headers["accept-encoding"] == "identity"


async def test_redirect_chain_follows_refresh_header(client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers={"refresh": "3;url=/next"}, text="")
        return httpx.Response(200, headers={"content-type": "application/pdf"}, content=b"%PDF")

    _use(client, handler)
    hops = (
        await client.get("/v1/intel/redirect-chain", params={"url": "https://public.example/"})
    ).json()["hops"]
    assert [h["url"] for h in hops] == ["https://public.example/", "https://public.example/next"]
    assert hops[0]["via"] == "refresh-header"


async def test_redirect_chain_flags_script_redirect_without_following(client):
    page = "<script>window.location.href = atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGUv');</script>"
    calls = _use(
        client, lambda r: httpx.Response(200, headers={"content-type": "text/html"}, text=page)
    )
    hops = (
        await client.get("/v1/intel/redirect-chain", params={"url": "https://public.example/"})
    ).json()["hops"]
    assert len(hops) == 1 and len(calls) == 1
    assert hops[0]["script_redirect"] is True
    assert hops[0]["location"] is None


async def test_redirect_chain_reads_only_the_start_of_a_page(client):
    from sandbox.api.routes import intel

    # The refresh tag sits past the cap, so it must not be seen.
    body = (
        "<html>"
        + " " * (intel.BODY_PEEK_BYTES + 10)
        + '<meta http-equiv="refresh" content="0;url=/x">'
    )
    _use(client, lambda r: httpx.Response(200, headers={"content-type": "text/html"}, text=body))
    hops = (
        await client.get("/v1/intel/redirect-chain", params={"url": "https://public.example/"})
    ).json()["hops"]
    assert len(hops) == 1
    assert hops[0]["location"] is None


@pytest.mark.parametrize(
    ("value", "target"),
    [
        ("0; url=https://a.example/", "https://a.example/"),
        ("0;URL='/next?a=1&amp;b=2'", "/next?a=1&b=2"),
        ("https://a.example/", "https://a.example/"),
        ("5", None),
        ("", None),
        (None, None),
    ],
)
def test_refresh_target(value, target):
    from sandbox.api.routes.intel import refresh_target

    assert refresh_target(value) == target


def test_script_redirect_hint_ignores_lookalike_words():
    from sandbox.api.routes.intel import inspect_page

    assert "script_redirect" not in inspect_page(
        "<p>geolocation = enabled; if (a == location) {}</p>"
    )
    assert inspect_page("<script>location.replace('/x')</script>")["script_redirect"] is True
