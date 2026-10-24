import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from sandbox.api.main import create_app
from sandbox.config import Settings
from sandbox.db.models import AuditLog

ANALYST = {"x-dev-user": "alice@example.org", "x-dev-roles": "analyst"}


async def test_liveness_and_request_id(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["x-request-id"]

    echoed = await client.get("/healthz", headers={"x-request-id": "abc-123"})
    assert echoed.headers["x-request-id"] == "abc-123"


async def test_ui_assets_always_revalidate(client):
    """A browser must never run a cached old script against a new page after a deploy."""
    for path in ("/ui/index.html", "/ui/js/sandbox.js", "/ui/css/style.css"):
        response = await client.get(path)
        assert response.status_code == 200, path
        assert response.headers["cache-control"] == "no-cache", path
    font = await client.get("/ui/fonts/plex-sans-400.woff2")
    assert "immutable" in font.headers["cache-control"]


async def test_readiness_fails_without_database(client):
    response = await client.get("/healthz/ready")
    assert response.status_code == 503


async def test_unknown_route_returns_json_error(client):
    response = await client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


async def test_unknown_roles_are_refused(client):
    response = await client.get("/v1/analyses/an_x", headers={"x-dev-roles": "superuser"})
    assert response.status_code == 401


async def test_oidc_mode_fails_closed(client):
    client.app.dependency_overrides.clear()
    from sandbox.config import get_settings

    client.app.dependency_overrides[get_settings] = lambda: Settings(
        _env_file=None, auth_mode="oidc"
    )
    # No session cookie or bearer token: refused, and dev headers are ignored.
    response = await client.get("/v1/analyses/an_x", headers={"x-dev-user": "eve@example.org"})
    assert response.status_code == 401


def test_dev_auth_refused_in_prod():
    with pytest.raises(RuntimeError):
        create_app(Settings(_env_file=None, env="prod", auth_mode="dev"))


def test_default_secret_refused_in_prod():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(Settings(_env_file=None, env="prod", auth_mode="oidc"))


@pytest.mark.db
async def test_readiness_with_database(db_client):
    assert (await db_client.get("/healthz/ready")).status_code == 200


@pytest.mark.db
async def test_submit_and_fetch(db_client):
    response = await db_client.post(
        "/v1/analyses",
        json={"url": "hxxps://public[.]example/login", "mode": "interactive"},
        headers=ANALYST,
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["id"].startswith("an_")
    assert body["status"] == "queued"
    assert body["normalised_url"] == "https://public.example/login"
    assert body["submitted_by"] == "alice@example.org"

    fetched = await db_client.get(f"/v1/analyses/{body['id']}", headers=ANALYST)
    assert fetched.status_code == 200
    assert fetched.json()["mode"] == "interactive"

    listed = await db_client.get("/v1/analyses", params={"domain": "public.example"})
    assert body["id"] in [item["id"] for item in listed.json()["items"]]

    by_url = await db_client.get("/v1/analyses", params={"url": "https://PUBLIC.example/login"})
    assert body["id"] in [item["id"] for item in by_url.json()["items"]]


@pytest.mark.db
async def test_unresolvable_host_is_accepted_with_warning(db_client):
    response = await db_client.post("/v1/analyses", json={"url": "https://gone.example/"})
    assert response.status_code == 202
    assert "Host did not resolve at submission time" in response.json()["warnings"]


@pytest.mark.db
@pytest.mark.parametrize(
    ("url", "error"),
    [
        ("javascript:alert(1)", "invalid_url"),
        ("http://127.0.0.1/", "blocked_destination"),
        ("http://2130706433/", "blocked_destination"),
        ("http://[::ffff:169.254.169.254]/", "blocked_destination"),
        ("https://internal.example/", "blocked_destination"),
    ],
)
async def test_submit_rejections(db_client, url, error):
    response = await db_client.post("/v1/analyses", json={"url": url}, headers=ANALYST)
    assert response.status_code == 422
    assert response.json()["error"] == error


@pytest.mark.db
async def test_refused_submission_is_audited(db_client):
    await db_client.post("/v1/analyses", json={"url": "http://10.9.8.7/"}, headers=ANALYST)
    async with db_client.app.state.sessionmaker() as db:
        rows = (
            await db.scalars(select(AuditLog).where(AuditLog.action == "analysis.refused"))
        ).all()
    assert any(r.detail.get("address") == "10.9.8.7" for r in rows)


@pytest.mark.db
async def test_audit_log_is_append_only(db_client):
    async with db_client.app.state.sessionmaker() as db:
        db.add(AuditLog(actor="t", action="test"))
        await db.commit()
        for statement in ("UPDATE audit_log SET actor = 'x'", "DELETE FROM audit_log"):
            with pytest.raises(DBAPIError, match="append-only"):
                await db.execute(text(statement))
            await db.rollback()


@pytest.mark.db
async def test_unknown_analysis_is_404(db_client):
    response = await db_client.get("/v1/analyses/an_missing")
    assert response.status_code == 404
