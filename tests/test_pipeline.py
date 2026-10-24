"""End-to-end pipeline against PostgreSQL with a fake session backend.

``FakeBackend`` replays the recorded fixture capture instead of starting containers, so
everything else is real: API submission, worker claim and supervision, event streaming,
artifact storage, analysis with the built-in rule bundle, report, downloads, re-analysis,
session controls, concurrency limits, recovery, the reaper, service tokens, embeds,
restricted visibility, feeds and metrics.
"""

import asyncio
import io
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import pyzipper
from sqlalchemy import select, text, update

from sandbox.api.deps import get_resolver
from sandbox.api.main import create_app
from sandbox.config import Settings
from sandbox.db.models import Analysis, Feed, Session
from sandbox.orchestrator import maintenance
from sandbox.orchestrator.backend import SessionHandle, Snapshot
from sandbox.orchestrator.context import WorkerContext
from sandbox.orchestrator.worker import Worker
from sandbox.rules.bundles import build_bundle
from sandbox.runner.events import STDOUT_PREFIX
from sandbox.seed import ensure_defaults
from tests.conftest import fake_resolver

pytestmark = pytest.mark.db
CAPTURE = Path(__file__).parent / "fixtures" / "captures" / "phish_chain"
ALICE = {"x-dev-user": "alice@example.org", "x-dev-roles": "analyst"}
BOB = {"x-dev-user": "bob@example.org", "x-dev-roles": "analyst"}
CAROL = {"x-dev-user": "carol@example.org", "x-dev-roles": "analyst"}
SENIOR = {"x-dev-user": "sam@example.org", "x-dev-roles": "senior_analyst"}
ENGINEER = {"x-dev-user": "eng@example.org", "x-dev-roles": "detection_engineer"}
ADMIN = {"x-dev-user": "root@example.org", "x-dev-roles": "admin"}


class FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.running: dict[str, bool] = {}
        self.handles: dict[str, SessionHandle] = {}
        self.destroyed: set[str] = set()
        self.specs = []
        self.clipboard: dict[str, str] = {}

    async def start(self, spec):
        self.specs.append(spec)
        handle = SessionHandle(
            session_id=spec.session_id,
            analysis_id=spec.analysis_id,
            backend=self.name,
            native_id=f"fake-{spec.session_id}",
            expires_at=spec.expires_at,
            stream_target="fake-session:6080" if spec.interactive else None,
            stream_secret="pw" if spec.interactive else None,
        )
        self.running[spec.session_id] = True
        self.handles[spec.session_id] = handle
        self.interactive = spec.interactive
        return handle

    async def stream(self, handle):
        raise NotImplementedError

    async def output_lines(self, handle):
        for line in (CAPTURE / "events.jsonl").read_text(encoding="utf-8").splitlines():
            yield STDOUT_PREFIX + line
        if not self.interactive:
            self.running[handle.session_id] = False

    async def is_running(self, handle):
        return self.running.get(handle.session_id, False)

    async def clipboard_set(self, handle, text):
        self.clipboard[handle.session_id] = text

    async def clipboard_get(self, handle):
        return self.clipboard.get(handle.session_id, ""), "clipboard"

    async def stop(self, handle, timeout_s=20):
        self.running[handle.session_id] = False

    async def snapshot(self, handle, dest):
        shutil.copytree(CAPTURE, dest / "out")
        return Snapshot(dest / "out", [p.name for p in (dest / "out").rglob("*") if p.is_file()])

    async def destroy(self, handle):
        self.running[handle.session_id] = False
        self.destroyed.add(handle.session_id)

    async def list_live(self):
        return [h for sid, h in self.handles.items() if sid not in self.destroyed]


@pytest.fixture
async def env(database_url, tmp_path):
    settings = Settings(
        _env_file=None,
        env="test",
        database_url=database_url,
        artifact_root=str(tmp_path / "artifacts"),
        quarantine_root=str(tmp_path / "quarantine"),
        worker_poll_s=0.05,
        rdap_base_url=None,
        worker_id="test-worker",
    )
    backend = FakeBackend()
    ctx = WorkerContext.create(settings, backend=backend)
    async with ctx.sessionmaker() as db:
        await db.execute(
            text(
                "TRUNCATE analyses, sessions, artifacts, events, jobs, rule_hits, indicator_hits, "
                "analysis_tags, iocs, analysis_versions, verdict_overrides, notes, rule_bundles, "
                "rules, rule_overrides, scoring_config, brands, feeds, feed_runs, indicators, "
                "indicator_sources, indicator_suppressions, allowlist_domains, api_clients, "
                "rate_counters, runtime_config CASCADE"
            )
        )
        await ensure_defaults(db)
        await db.commit()
    bundle = await build_bundle(ctx)
    assert bundle.status == "ready", bundle.error
    app = create_app(settings)
    app.dependency_overrides[get_resolver] = lambda: fake_resolver
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, ctx, Worker(ctx), backend
    await ctx.close()


async def _drain(worker: Worker) -> None:
    for _ in range(200):
        await worker.claim_analyses()
        await worker.run_jobs()
        if not worker.sessions and not worker._job_tasks:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("worker did not finish")


async def _wait_session(ctx, analysis_id: str) -> Session:
    for _ in range(200):
        async with ctx.sessionmaker() as db:
            session = await db.scalar(select(Session).where(Session.analysis_id == analysis_id))
        if session is not None and session.container_id:
            return session
        await asyncio.sleep(0.05)
    raise AssertionError("session never started")


async def _submit(client, headers=ALICE, **body) -> dict:
    response = await client.post(
        "/v1/analyses", json={"url": "https://public.example/", **body}, headers=headers
    )
    assert response.status_code == 202, response.text
    return response.json()


async def test_automated_pipeline(env):
    client, ctx, worker, backend = env
    created = await _submit(client)
    await _drain(worker)

    detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
    assert detail["status"] == "finished", detail
    assert detail["verdict"] == "malicious"
    assert detail["version"] == 1
    assert {"phishing", "clickfix", "malware-download"} <= set(detail["tags"])
    assert backend.destroyed  # the session container is always removed (ORC-5)

    report = (await client.get(f"/v1/analyses/{created['id']}/report", headers=ALICE)).json()
    assert report["bundle_id"]
    rules = {h["rule"] for h in report["rule_hits"]}
    assert {
        "form_posts_cross_domain",
        "clickfix_clipboard_command",
        "clickfix_powershell_lure",
    } <= rules
    assert report["redirects"][0]["type"] == "meta_refresh"
    assert any(c["name"] == "clickfix_clipboard_command" for c in report["contributions"])
    assert report["iocs"]["hashes"]

    events = (await client.get(f"/v1/analyses/{created['id']}/events", headers=ALICE)).json()[
        "events"
    ]
    kinds = {e["kind"] for e in events}
    assert {"session_start", "redirect", "download", "clipboard_write", "request_blocked"} <= kinds

    network = (
        await client.get(
            f"/v1/analyses/{created['id']}/network", params={"status": "2xx"}, headers=ALICE
        )
    ).json()
    assert network["total"] > 0 and all(str(r["status"]).startswith("2") for r in network["items"])

    csv_text = (
        await client.get(
            f"/v1/analyses/{created['id']}/iocs", params={"format": "csv"}, headers=ALICE
        )
    ).text
    assert "collector[.]example[.]net" in csv_text
    stix = (
        await client.get(
            f"/v1/analyses/{created['id']}/iocs", params={"format": "stix"}, headers=ALICE
        )
    ).json()
    assert stix["type"] == "bundle" and stix["objects"]

    found = (await client.get("/v1/analyses", params={"tag": "clickfix"}, headers=ALICE)).json()
    assert created["id"] in [i["id"] for i in found["items"]]
    found = (await client.get("/v1/analyses", params={"verdict": "benign"}, headers=ALICE)).json()
    assert created["id"] not in [i["id"] for i in found["items"]]


async def test_quarantine_download_needs_confirmation(env):
    client, ctx, worker, _ = env
    created = await _submit(client)
    await _drain(worker)
    artifacts = (await client.get(f"/v1/analyses/{created['id']}/artifacts", headers=ALICE)).json()[
        "items"
    ]
    download = next(a for a in artifacts if a["kind"] == "download")
    assert download["quarantined"] and download["name"] == "invoice_2026.exe"

    assert (
        await client.get(f"/v1/artifacts/{download['id']}/content", headers=ALICE)
    ).status_code == 403
    refused = await client.get(f"/v1/artifacts/{download['id']}/download", headers=ALICE)
    assert refused.status_code == 428
    ok = await client.get(
        f"/v1/artifacts/{download['id']}/download",
        params={"confirm": "true", "reason": "reverse engineering"},
        headers=ALICE,
    )
    assert ok.status_code == 200
    body = ok.json()
    archive = await client.get(body["url"])
    assert archive.headers["content-type"] == "application/zip"
    with pyzipper.AESZipFile(io.BytesIO(archive.content)) as zf:
        zf.setpassword(body["archive_password"].encode())
        [name] = zf.namelist()
        assert zf.read(name).startswith(b"MZ-fixture")

    dom = next(a for a in artifacts if a["kind"] == "dom")
    shown = await client.get(f"/v1/artifacts/{dom['id']}/content", headers=ALICE)
    assert shown.headers["content-type"].startswith("text/plain")  # never rendered as HTML
    assert "sandbox" in shown.headers["content-security-policy"]


async def test_reanalysis_tags_override_notes(env):
    client, ctx, worker, _ = env
    created = await _submit(client)
    await _drain(worker)
    aid = created["id"]

    assert (
        await client.post(f"/v1/analyses/{aid}/tags", json={"tag": "campaign-x"}, headers=ALICE)
    ).status_code == 201
    denied = await client.post(
        f"/v1/analyses/{aid}/verdict-override",
        json={"verdict": "benign", "reason": "test"},
        headers=ALICE,
    )
    assert denied.status_code == 403  # analysts cannot override; senior analysts can
    assert (
        await client.post(
            f"/v1/analyses/{aid}/verdict-override",
            json={"verdict": "suspicious", "reason": "known pentest"},
            headers=SENIOR,
        )
    ).status_code == 201
    await client.post(
        f"/v1/analyses/{aid}/notes", json={"body": "Reported to the SOC"}, headers=ALICE
    )

    assert (await client.post(f"/v1/analyses/{aid}/reanalyse", headers=ALICE)).status_code == 202
    await _drain(worker)
    report = (await client.get(f"/v1/analyses/{aid}/report", headers=ALICE)).json()
    assert report["version"] == 2 and len(report["versions"]) == 2
    assert report["verdict"] == "malicious"
    assert report["effective_verdict"] == "suspicious"  # shown beside the automatic one
    assert "campaign-x" in {t["tag"] for t in report["tags"]}  # analyst tags survive
    assert report["notes"][0]["author"] == "alice@example.org"
    v1 = (
        await client.get(f"/v1/analyses/{aid}/report", params={"version": 1}, headers=ALICE)
    ).json()
    assert v1["version"] == 1  # older versions stay reproducible

    audit = (await client.get("/v1/admin/audit", params={"target": aid}, headers=ADMIN)).json()
    assert {"analysis.submit", "analysis.override", "analysis.tag", "analysis.analysed"} <= {
        a["action"] for a in audit
    }


async def test_interactive_session_controls(env):
    client, ctx, worker, backend = env
    created = await _submit(client, mode="interactive")
    await worker.claim_analyses()
    for _ in range(100):
        detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
        if detail["session"] and detail["session"]["live_view"]:
            break
        await asyncio.sleep(0.05)
    session_id = detail["session"]["id"]

    view = (await client.post(f"/v1/analyses/{created['id']}/session", headers=ALICE)).json()
    assert view["view_only"] is False and "/v1/stream/" in view["view_url"]
    observer = (await client.post(f"/v1/analyses/{created['id']}/session", headers=BOB)).json()
    assert observer["view_only"] is True  # INT-8: others watch without control
    assert (await client.post(f"/v1/sessions/{session_id}/extend", headers=BOB)).status_code == 403

    before = datetime.fromisoformat(detail["session"]["expires_at"])
    extended = (await client.post(f"/v1/sessions/{session_id}/extend", headers=ALICE)).json()
    assert datetime.fromisoformat(extended["expires_at"]) > before
    paused = (await client.post(f"/v1/sessions/{session_id}/pause", headers=ALICE)).json()
    assert paused["paused_at"]
    resumed = (await client.post(f"/v1/sessions/{session_id}/resume", headers=ALICE)).json()
    assert resumed["paused_at"] is None

    assert (await client.delete(f"/v1/sessions/{session_id}", headers=ALICE)).status_code == 200
    await _drain(worker)
    detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
    assert detail["status"] == "finished"
    assert detail["session"]["end_reason"] == "analyst_ended"


async def test_interactive_clipboard_copy_in_and_out(env):
    """INT-7: explicit, audited copies in and out of a live session."""
    client, ctx, worker, backend = env
    created = await _submit(client, mode="interactive")
    await worker.claim_analyses()
    for _ in range(100):
        detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
        if detail["session"] and detail["session"]["live_view"]:
            break
        await asyncio.sleep(0.05)
    sid = detail["session"]["id"]

    view = (await client.post(f"/v1/analyses/{created['id']}/session", headers=ALICE)).json()
    assert view["clipboard"]["to_session"] and view["clipboard"]["from_session"]
    observer = (await client.post(f"/v1/analyses/{created['id']}/session", headers=BOB)).json()
    assert observer["clipboard"]["to_session"] is False

    # In: control characters are stripped before anything reaches the session.
    sent = await client.post(
        f"/v1/sessions/{sid}/clipboard",
        json={"text": "https://next.example/\x00\x1b[31m"},
        headers=ALICE,
    )
    assert sent.status_code == 200, sent.text
    assert sent.json()["status"] == "done"
    assert backend.clipboard[sid] == "https://next.example/[31m"

    # Out: whatever the analyst copied inside the session comes back.
    backend.clipboard[sid] = "powershell -enc AAAA # copied from the lure"
    read = (await client.post(f"/v1/sessions/{sid}/clipboard/read", headers=ALICE)).json()
    assert read["status"] == "done" and read["text"].startswith("powershell")
    history = (await client.get(f"/v1/sessions/{sid}/clipboard", headers=ALICE)).json()
    assert [h["direction"] for h in history] == ["out", "in"]

    # Observers cannot copy either way, or see what was copied.
    assert (
        await client.post(f"/v1/sessions/{sid}/clipboard", json={"text": "x"}, headers=BOB)
    ).status_code == 403
    assert (await client.post(f"/v1/sessions/{sid}/clipboard/read", headers=BOB)).status_code == 403
    assert (await client.get(f"/v1/sessions/{sid}/clipboard", headers=BOB)).status_code == 403

    # An admin can turn a direction off; the change is audited.
    assert (
        await client.put(
            "/v1/admin/config/clipboard_from_session", json={"value": False}, headers=ADMIN
        )
    ).status_code == 200
    off = await client.post(f"/v1/sessions/{sid}/clipboard/read", headers=ALICE)
    assert off.status_code == 403 and off.json()["error"] == "clipboard_disabled"
    too_big = await client.post(
        f"/v1/sessions/{sid}/clipboard", json={"text": "a" * 70_000}, headers=ALICE
    )
    assert too_big.status_code == 413

    events = (await client.get(f"/v1/analyses/{created['id']}/events", headers=ALICE)).json()[
        "events"
    ]
    assert {"clipboard_in", "clipboard_out"} <= {e["kind"] for e in events}
    audit = (
        await client.get("/v1/admin/audit", params={"target": created["id"]}, headers=ADMIN)
    ).json()
    assert {"session.clipboard_in", "session.clipboard_out"} <= {a["action"] for a in audit}

    assert (await client.delete(f"/v1/sessions/{sid}", headers=ALICE)).status_code == 200
    await _drain(worker)
    # Copies are refused once the session has ended.
    assert (
        await client.post(f"/v1/sessions/{sid}/clipboard", json={"text": "x"}, headers=ALICE)
    ).status_code == 409


async def test_clipboard_needs_an_interactive_session(env):
    client, ctx, worker, _ = env
    created = await _submit(client)
    await worker.claim_analyses()
    session = await _wait_session(ctx, created["id"])
    response = await client.post(
        f"/v1/sessions/{session.id}/clipboard", json={"text": "x"}, headers=ALICE
    )
    assert response.status_code == 409
    await _drain(worker)


async def test_concurrency_limit_and_queue_position(env):
    client, ctx, worker, backend = env
    await client.put("/v1/admin/config/max_concurrent_sessions", json={"value": 1}, headers=ADMIN)
    first = await _submit(client, mode="interactive")
    second = await _submit(client, headers=BOB)
    assert await worker.claim_analyses() == 1
    assert await worker.claim_analyses() == 0  # ORC-2: never beyond the limit
    queued = (await client.get(f"/v1/analyses/{second['id']}", headers=BOB)).json()
    assert queued["status"] == "queued" and queued["queue_position"] == 1
    assert queued["estimated_wait_s"] > 0
    started = await _wait_session(ctx, first["id"])
    async with ctx.sessionmaker() as db:
        await db.execute(
            update(Session)
            .where(Session.id == started.id)
            .values(end_requested_at=datetime.now(UTC))
        )
        await db.commit()
    await _drain(worker)
    done = (await client.get(f"/v1/analyses/{second['id']}", headers=BOB)).json()
    assert done["status"] == "finished"


async def test_time_limit_stops_session(env):
    client, ctx, worker, backend = env
    created = await _submit(client, mode="interactive")
    await worker.claim_analyses()
    await _wait_session(ctx, created["id"])
    async with ctx.sessionmaker() as db:
        await db.execute(
            update(Session)
            .where(Session.analysis_id == created["id"])
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()
    await _drain(worker)
    detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
    assert detail["session"]["end_reason"] == "time_limit"


async def test_recovery_and_reaper(env):
    client, ctx, worker, backend = env
    created = await _submit(client)
    async with ctx.sessionmaker() as db:
        await db.execute(
            update(Analysis)
            .where(Analysis.id == created["id"])
            .values(
                status="running",
                worker_id="dead-worker",
                heartbeat_at=datetime.now(UTC) - timedelta(minutes=10),
            )
        )
        await db.commit()
    # ORC-7: a running analysis with a stale heartbeat and no container is failed cleanly.
    assert await maintenance.recover(ctx, startup=False) == []
    detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
    assert detail["status"] == "failed" and "worker" in detail["error"]

    # ORC-5: a container whose analysis is no longer running is reaped.
    backend.handles["se_orphan"] = SessionHandle(
        "se_orphan", created["id"], "fake", "fake-orphan", datetime.now(UTC) - timedelta(hours=1)
    )
    assert await maintenance.reap(ctx, set()) == 1
    assert "se_orphan" in backend.destroyed


async def test_restricted_analysis_visibility(env):
    client, *_ = env
    created = await _submit(client, restricted_to=["bob@example.org"])
    assert (await client.get(f"/v1/analyses/{created['id']}", headers=BOB)).status_code == 200
    assert (await client.get(f"/v1/analyses/{created['id']}", headers=CAROL)).status_code == 404
    assert (await client.get(f"/v1/analyses/{created['id']}", headers=ADMIN)).status_code == 200
    listed = (await client.get("/v1/analyses", headers=CAROL)).json()
    assert created["id"] not in [i["id"] for i in listed["items"]]


async def test_quota_and_reuse(env):
    client, *_ = env
    await client.put("/v1/admin/config/user_daily_quota", json={"value": 1}, headers=ADMIN)
    await _submit(client)
    refused = await client.post(
        "/v1/analyses", json={"url": "https://public.example/x"}, headers=ALICE
    )
    assert refused.status_code == 429 and refused.json()["error"] == "quota_exceeded"
    bad = await client.put(
        "/v1/admin/config/user_daily_quota", json={"value": "lots"}, headers=ADMIN
    )
    assert bad.status_code == 422


async def test_reuse_recent_report(env):
    client, ctx, worker, _ = env
    first = await _submit(client)
    await _drain(worker)
    again = await client.post(
        "/v1/analyses", json={"url": "https://PUBLIC.example/", "reuse_recent": True}, headers=ALICE
    )
    assert again.status_code == 200
    assert again.json()["id"] == first["id"] and again.json()["reused"] is True


async def test_service_tokens_scopes_and_rate_limit(env):
    client, *_ = env
    made = (
        await client.post(
            "/v1/admin/api-clients",
            json={"name": "soar", "scopes": ["analyses:read"], "rate_limit_per_min": 3},
            headers=ADMIN,
        )
    ).json()
    bearer = {"authorization": f"Bearer {made['token']}"}
    assert (await client.get("/v1/analyses", headers=bearer)).status_code == 200
    denied = await client.post(
        "/v1/analyses", json={"url": "https://public.example/"}, headers=bearer
    )
    assert denied.status_code == 403  # API-2: a token without the scope receives 403
    await client.get("/v1/analyses", headers=bearer)
    limited = await client.get("/v1/analyses", headers=bearer)
    assert limited.status_code == 429
    bogus = await client.get("/v1/analyses", headers={"authorization": "Bearer sbx_nope"})
    assert bogus.status_code == 401
    assert (await client.get("/v1/admin/api-clients", headers=ALICE)).status_code == 403


async def test_embed_tokens(env):
    client, ctx, worker, _ = env
    created = await _submit(client)
    await _drain(worker)
    made = (
        await client.post(
            "/v1/embed-tokens",
            json={"scope": "report", "analysis_id": created["id"]},
            headers=ALICE,
        )
    ).json()
    report = await client.get(f"/v1/embed/{made['token']}/report")
    assert report.status_code == 200 and report.json()["verdict"] == "malicious"
    wrong = await client.post(
        f"/v1/embed/{made['token']}/analyses", json={"url": "https://public.example/"}
    )
    assert wrong.status_code == 403
    assert (await client.get("/v1/embed/garbage.token/report")).status_code == 401
    submit = (await client.post("/v1/embed-tokens", json={"scope": "submit"}, headers=ALICE)).json()
    queued = await client.post(
        f"/v1/embed/{submit['token']}/analyses", json={"url": "https://public.example/a"}
    )
    assert queued.status_code == 202 and queued.json()["report_token"]
    page = await client.get("/ui/embed.html")
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    await client.put(
        "/v1/admin/config/embed_allowed_origins",
        json={"value": ["https://intranet.example"]},
        headers=ADMIN,
    )


async def test_rules_bundles_and_rule_testing(env):
    client, ctx, worker, _ = env
    await _submit(client)
    await _drain(worker)
    rules = (await client.get("/v1/rules", params={"engine": "behaviour"}, headers=ALICE)).json()
    assert rules["total"] >= 13
    target = next(r for r in rules["items"] if r["name"] == "hidden_iframe")

    tested = (
        await client.post(
            "/v1/rules/test",
            json={
                "engine": "behaviour",
                "severity": "high",
                "body": '{"condition": {"fact": "clipboard.command_like", "op": "gt", "value": 0}}',
            },
            headers=ENGINEER,
        )
    ).json()
    assert tested["tested"] == 1 and tested["matched"] == 1
    yara_test = (
        await client.post(
            "/v1/rules/test",
            json={
                "engine": "yara",
                "body": 'rule t { strings: $a = "collector.example.net" condition: $a }',
            },
            headers=ENGINEER,
        )
    ).json()
    assert yara_test["matched"] == 1
    bad = await client.post(
        "/v1/rules",
        json={"engine": "yara", "name": "broken", "body": "rule x { condition: nope }"},
        headers=ENGINEER,
    )
    assert bad.status_code == 422
    assert (
        await client.post(
            f"/v1/rules/{target['id']}/disable", json={"reason": "noisy"}, headers=ALICE
        )
    ).status_code == 403
    disabled = await client.post(
        f"/v1/rules/{target['id']}/disable", json={"reason": "noisy"}, headers=ENGINEER
    )
    assert disabled.json()["locally_disabled"] is True

    before = (await client.get("/v1/rule-bundles/current", headers=ALICE)).json()
    await _drain(worker)  # the disable queued a bundle build
    after = (await client.get("/v1/rule-bundles/current", headers=ALICE)).json()
    assert after["id"] != before["id"] and after["rule_count"] == before["rule_count"] - 1
    rolled = await client.post(f"/v1/rule-bundles/{before['id']}/activate", headers=ENGINEER)
    assert rolled.json()["active"] is True  # NFR-8: one-step rollback


async def test_feeds_matching_and_drop_guard(env):
    client, ctx, worker, _ = env
    # The last URL is one the fixture capture navigated to, so analysis must match it.
    feed_urls = [f"https://bad{i}.example/" for i in range(20)] + [
        "http://172.19.0.2:8000/login.html"
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="\n".join(feed_urls))

    ctx.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async with ctx.sessionmaker() as db:
        feed = await db.scalar(select(Feed).where(Feed.name == "openphish"))
    from sandbox.feeds.runner import run_feed

    run = await run_feed(ctx, feed.id)
    assert run.status == "success" and run.rows_added == 21
    looked = (
        await client.get(
            "/v1/indicators",
            params={"type": "url", "value": "http://172.19.0.2:8000/login.html"},
            headers=ALICE,
        )
    ).json()
    assert looked["sources"][0]["feed"] == "openphish"

    feed_urls[:] = ["https://only.example/"]
    rejected = await run_feed(ctx, feed.id)
    assert rejected.status == "rejected"  # FED-5: >90% drop keeps the previous data
    status = {f["name"]: f for f in (await client.get("/v1/feeds", headers=ALICE)).json()}
    assert status["openphish"]["last_row_count"] == 21
    assert status["openphish"]["last_run"]["status"] == "rejected"

    created = await _submit(client)
    await _drain(worker)
    report = (await client.get(f"/v1/analyses/{created['id']}/report", headers=ALICE)).json()
    [hit] = report["indicator_hits"]  # ANA-3, with its source feed and confidence
    assert hit["value"] == "http://172.19.0.2:8000/login.html"
    assert hit["sources"][0]["feed"] == "openphish" and hit["sources"][0]["confidence"] == 80
    assert "known-bad" in {t["tag"] for t in report["tags"]}

    # FED-10: a local suppression removes the match on re-analysis.
    await client.post(
        "/v1/indicators/suppressions",
        headers=ENGINEER,
        json={"type": "url", "value": "http://172.19.0.2:8000/login.html", "reason": "test page"},
    )
    await client.post(f"/v1/analyses/{created['id']}/reanalyse", headers=ALICE)
    await _drain(worker)
    report = (await client.get(f"/v1/analyses/{created['id']}/report", headers=ALICE)).json()
    assert report["indicator_hits"] == []


async def test_metrics(env):
    client, ctx, worker, _ = env
    await _submit(client)
    body = (await client.get("/metrics")).text
    assert "sandbox_queue_depth 1" in body
    assert 'sandbox_feed_stale{feed="openphish"}' in body
    assert "sandbox_rule_bundle_info" in body


async def test_seed_refreshes_builtin_rules_and_merges_brand_domains(env):
    """An existing install picks up fixed built-in rules and new brand domains, while
    local disables and admin brand edits survive."""
    from sandbox.db.models import Brand, Job, Rule, RuleOverride

    _, ctx, _, _ = env
    async with ctx.sessionmaker() as db:
        rule = await db.scalar(select(Rule).where(Rule.name == "brand_impersonation"))
        rule.body, rule.content_hash, rule.version = "{}", "old", "1"
        db.add(RuleOverride(rule_id=rule.id, disabled_by="eng", reason="noisy"))
        google = await db.scalar(select(Brand).where(Brand.name == "Google"))
        google.domains = ["google.com", "corp-google.example"]
        google.enabled = False
        await db.commit()

        await ensure_defaults(db)
        await db.commit()

        await db.refresh(rule)
        assert '"brand.credential_prompt"' in rule.body
        assert rule.version == "2"
        assert await db.scalar(select(RuleOverride.active).where(RuleOverride.rule_id == rule.id))
        await db.refresh(google)
        assert {"google", "google.*", "corp-google.example"} <= set(google.domains)
        assert google.enabled is False
        jobs = list(await db.scalars(select(Job).where(Job.kind == "bundle_build")))
        assert any(j.payload.get("reason") == "builtin rules updated" for j in jobs)

        # A second start with nothing changed queues nothing new.
        count = len(jobs)
        await ensure_defaults(db)
        await db.commit()
        assert len(list(await db.scalars(select(Job).where(Job.kind == "bundle_build")))) == count


async def test_page_text_with_nul_and_lone_surrogates_is_stored(env):
    """Regression: a page console message containing NUL failed the whole session
    (Postgres jsonb rejects \u0000 and unpaired surrogates)."""
    from sandbox.db.models import Event
    from sandbox.orchestrator.ingest import insert_events

    client, ctx, worker, _ = env
    created = await _submit(client)
    nasty = {"page": "p0", "level": "log", "text": "a\x00b \ud800 /.*=.*/", "k\x00": ["x\x00"]}
    async with ctx.sessionmaker() as db:
        await insert_events(
            db,
            created["id"],
            [
                {
                    "ts": "2026-10-10T18:34:36+00:00",
                    "kind": "console",
                    "source": "browser",
                    "payload": nasty,
                }
            ],
        )
        await db.commit()
        stored = await db.scalar(
            select(Event.payload).where(Event.analysis_id == created["id"], Event.kind == "console")
        )
    assert stored["text"] == "a�b � /.*=.*/"
    assert stored["k�"] == ["x�"]
    await _drain(worker)


async def test_suricata_that_cannot_run_is_a_note(env, monkeypatch):
    """Regression: a missing Suricata image (Docker ImageNotFound) failed the whole
    analysis instead of leaving a note on the report."""
    import sandbox.analysis.suricata as suricata

    client, ctx, worker, backend = env
    snapshot = backend.snapshot

    async def snapshot_with_pcap(handle, dest):
        snap = await snapshot(handle, dest)
        (snap.root / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
        return Snapshot(snap.root, [*snap.files, "capture.pcap"])

    async def no_image(*args, **kwargs):
        raise RuntimeError('No such image: "missing/suricata:0"')

    monkeypatch.setattr(backend, "snapshot", snapshot_with_pcap)
    monkeypatch.setattr(ctx.settings, "suricata_image", "missing/suricata:0")
    monkeypatch.setattr(suricata, "run_suricata", no_image)
    created = await _submit(client)
    await _drain(worker)

    detail = (await client.get(f"/v1/analyses/{created['id']}", headers=ALICE)).json()
    assert detail["status"] == "finished", detail
    report = (await client.get(f"/v1/analyses/{created['id']}/report", headers=ALICE)).json()
    assert any(
        "Suricata failed: could not run" in n and "No such image" in n
        for n in report["summary"]["notes"]
    )
