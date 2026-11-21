"""The report endpoint must build for every IOC type the database accepts.

An analysis with an eth_address IOC (EtherHiding detections) made build_report fail
with KeyError, so /report returned 500 and every tab of the report UI stayed empty.
"""

import pytest

from sandbox.api.report import _IOC_GROUPS
from sandbox.db.models import IOC_TYPES

ALICE = {"x-dev-user": "alice@example.org", "x-dev-roles": "analyst"}


def test_every_ioc_type_has_a_report_group():
    assert set(_IOC_GROUPS) == set(IOC_TYPES)
    assert len(set(_IOC_GROUPS.values())) == len(_IOC_GROUPS)


@pytest.mark.db
async def test_report_builds_with_every_ioc_type(db_client):
    from sandbox.db.models import Analysis, AnalysisVersion, Ioc
    from sandbox.ids import new_id

    analysis_id = new_id("an")
    values = {
        "domain": "evil.example",
        "ip": "203.0.113.9",
        "url": "https://evil.example/x",
        "hash": "a" * 64,
        "email": "x@evil.example",
        "eth_address": "0x" + "ab" * 20,
    }
    async with db_client.app.state.sessionmaker() as db:
        db.add(
            Analysis(
                id=analysis_id,
                url="https://evil.example/",
                normalised_url="https://evil.example/",
                host="evil.example",
                mode="automated",
                submitted_by="alice@example.org",
                status="finished",
                time_limit_s=60,
                version=1,
            )
        )
        await db.flush()
        db.add(
            AnalysisVersion(
                id=new_id("av"),
                analysis_id=analysis_id,
                version=1,
                verdict="malicious",
                score=100,
                summary={"facts": {}},
            )
        )
        for ioc_type, value in values.items():
            db.add(Ioc(analysis_id=analysis_id, version=1, type=ioc_type, value=value))
        await db.commit()

    response = await db_client.get(f"/v1/analyses/{analysis_id}/report", headers=ALICE)
    assert response.status_code == 200, response.text
    iocs = response.json()["iocs"]
    for ioc_type, value in values.items():
        assert iocs[_IOC_GROUPS[ioc_type]] == [value]
