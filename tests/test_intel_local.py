"""Local-first IoC lookup: collected IoCs and feed indicators before any vendor."""

from datetime import UTC, datetime, timedelta

import pytest

from sandbox.api.routes.intel import feed_candidates, sighting_values
from sandbox.db.models import (
    AllowlistDomain,
    Analysis,
    Feed,
    Indicator,
    IndicatorSource,
    IndicatorSuppression,
    Ioc,
)
from sandbox.ids import new_id

ALICE = {"x-dev-user": "alice@example.org", "x-dev-roles": "analyst"}
BOB = {"x-dev-user": "bob@example.org", "x-dev-roles": "analyst"}


def test_feed_candidates_for_a_url_cover_both_schemes_and_the_host():
    got = feed_candidates("url", "https://login.kit.pages.dev/verify")
    assert ("url", "https://login.kit.pages.dev/verify", "exact") in got
    assert ("url", "http://login.kit.pages.dev/verify", "other scheme") in got
    assert ("domain", "login.kit.pages.dev", "host") in got
    assert ("domain", "kit.pages.dev", "parent domain") in got


def test_feed_candidates_for_an_ip_url_use_the_ip():
    got = feed_candidates("url", "http://203.0.113.9/a.exe")
    assert ("ip", "203.0.113.9", "host") in got
    assert not any(t == "domain" for t, _, _ in got)


def test_feed_candidates_for_a_domain_add_parents():
    # Same rule as analysis matching (ANA-3): each parent down to the registrable domain.
    got = feed_candidates("domain", "a.b.evil.com")
    assert got == [
        ("domain", "a.b.evil.com", "exact"),
        ("domain", "b.evil.com", "parent domain"),
        ("domain", "evil.com", "parent domain"),
    ]


def test_sighting_values_try_the_pasted_form_and_both_schemes():
    values = sighting_values("url", "https://Evil.example/Path", "https://evil.example/Path")
    assert {
        "https://Evil.example/Path",
        "https://evil.example/Path",
        "http://evil.example/Path",
    } <= set(values)


async def test_local_lookup_rejects_garbage(client):
    response = await client.get("/v1/intel/local/hash/not-a-hash", headers=ALICE)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_ioc"


async def _analysis(
    db, url, verdict, *, submitted_by="alice@example.org", restricted=(), version=1
):
    analysis = Analysis(
        id=new_id("an"),
        url=url,
        normalised_url=url,
        host=url.split("/")[2],
        mode="automated",
        submitted_by=submitted_by,
        status="finished",
        verdict=verdict,
        score=90 if verdict == "malicious" else 0,
        time_limit_s=60,
        version=version,
        restricted_to=list(restricted),
    )
    db.add(analysis)
    await db.flush()
    return analysis


@pytest.fixture
async def seeded(db_client):
    tag = new_id("t").lower().replace("_", "")
    domain = f"kit-{tag}.example"
    url = f"https://{domain}/login"
    sha = (tag * 64)[:64]
    sha = "".join(c if c in "0123456789abcdef" else "a" for c in sha)
    now = datetime.now(UTC)
    async with db_client.app.state.sessionmaker() as db:
        feed = Feed(
            id=new_id("fd"),
            name=f"TestFeed {tag}",
            url="https://feed.example/",
            parser="plain_urls",
        )
        old_feed = Feed(
            id=new_id("fd"), name=f"OldFeed {tag}", url="https://old.example/", parser="plain_urls"
        )
        db.add_all([feed, old_feed])
        listed_url = Indicator(type="url", value=f"http://{domain}/login")
        listed_domain = Indicator(type="domain", value=domain)
        db.add_all([listed_url, listed_domain])
        await db.flush()
        db.add_all(
            [
                IndicatorSource(
                    indicator_id=listed_url.id,
                    feed_id=feed.id,
                    confidence=80,
                    tags=["phishing"],
                    expires_at=now + timedelta(days=5),
                ),
                IndicatorSource(
                    indicator_id=listed_domain.id,
                    feed_id=old_feed.id,
                    confidence=50,
                    tags=[],
                    expires_at=now - timedelta(days=1),
                ),
            ]
        )
        seen = await _analysis(db, url, "malicious")
        hidden = await _analysis(
            db, url, "malicious", submitted_by="bob@example.org", restricted=["bob@example.org"]
        )
        stale = await _analysis(db, url, "benign", version=2)
        for a, version in ((seen, 1), (hidden, 1), (stale, 1)):
            db.add(Ioc(analysis_id=a.id, version=version, type="url", value=url))
            db.add(Ioc(analysis_id=a.id, version=version, type="domain", value=domain))
        db.add(
            Ioc(
                analysis_id=seen.id,
                version=1,
                type="hash",
                value=sha,
                enrichment={"virustotal": {"last_analysis_stats": {"malicious": 7}}},
            )
        )
        await db.commit()
    return {
        "domain": domain,
        "url": url,
        "sha": sha,
        "feed": feed.name,
        "old_feed": old_feed.name,
        "seen": seen.id,
        "hidden": hidden.id,
        "stale": stale.id,
    }


async def test_url_is_listed_through_the_other_scheme(db_client, seeded):
    response = await db_client.get(f"/v1/intel/local/url/{seeded['url']}", headers=ALICE)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["summary"] == "listed"
    by_feed = {f["feed"]: f for f in body["feeds"]}
    assert by_feed[seeded["feed"]]["match"] == "other scheme"
    assert by_feed[seeded["feed"]]["active"] is True
    # Expired history is shown, flagged, and does not count.
    assert by_feed[seeded["old_feed"]]["match"] == "host"
    assert by_feed[seeded["old_feed"]]["active"] is False


async def test_sightings_respect_visibility_and_current_version(db_client, seeded):
    alice = (await db_client.get(f"/v1/intel/local/url/{seeded['url']}", headers=ALICE)).json()
    ids = {s["analysis_id"] for s in alice["sightings"]["items"]}
    assert seeded["seen"] in ids
    assert seeded["hidden"] not in ids  # restricted to bob
    assert seeded["stale"] not in ids  # IoC only in an old version
    assert alice["sightings"]["total"] == 1
    assert alice["sightings"]["by_verdict"] == {"malicious": 1}

    bob = (await db_client.get(f"/v1/intel/local/url/{seeded['url']}", headers=BOB)).json()
    assert {s["analysis_id"] for s in bob["sightings"]["items"]} >= {
        seeded["seen"],
        seeded["hidden"],
    }


async def test_hash_sighting_carries_stored_enrichment(db_client, seeded):
    body = (
        await db_client.get(f"/v1/intel/local/hash/{seeded['sha'].upper()}", headers=ALICE)
    ).json()
    assert body["value"] == seeded["sha"]
    assert body["feeds"] == []
    assert body["summary"] == "related_malicious"  # seen in a malicious analysis
    [item] = body["sightings"]["items"]
    assert item["enrichment"]["virustotal"]["last_analysis_stats"]["malicious"] == 7


async def test_suppressed_indicator_does_not_count(db_client, seeded):
    async with db_client.app.state.sessionmaker() as db:
        db.add(
            IndicatorSuppression(
                type="url",
                value=f"http://{seeded['domain']}/login",
                reason="false positive",
                created_by="eng@example.org",
            )
        )
        await db.commit()
    body = (await db_client.get(f"/v1/intel/local/url/{seeded['url']}", headers=ALICE)).json()
    assert all(f["suppressed"] for f in body["feeds"] if f["feed"] == seeded["feed"])
    assert body["summary"] == "related_malicious"  # still seen in a malicious analysis


async def test_unknown_and_allowlisted(db_client):
    tag = new_id("t").lower().replace("_", "")
    nobody = (await db_client.get(f"/v1/intel/local/domain/n-{tag}.example", headers=ALICE)).json()
    assert nobody["summary"] == "unknown"
    assert nobody["sightings"] == {"total": 0, "by_verdict": {}, "items": []}

    async with db_client.app.state.sessionmaker() as db:
        db.add(AllowlistDomain(domain=f"good-{tag}.com", source="internal", added_by="x"))
        await db.commit()
    good = (await db_client.get(f"/v1/intel/local/domain/www.good-{tag}.com", headers=ALICE)).json()
    assert good["summary"] == "allowlisted"
    assert good["allowlisted"]["site"] == f"good-{tag}.com"


async def test_private_ip_is_allowed_locally(db_client):
    body = (await db_client.get("/v1/intel/local/ip/10.1.2.3", headers=ALICE)).json()
    assert body["value"] == "10.1.2.3"
    assert body["summary"] == "unknown"
