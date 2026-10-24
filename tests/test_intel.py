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
