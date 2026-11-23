"""Check the detections against stored analyses, without detonating anything.

    python -m sandbox.detections.verify                  # every stored analysis
    python -m sandbox.detections.verify --since 2026-11-01

For each analysis version it runs every enabled detection again over the capture's
tables, rebuilt from the stored capture, and compares the result with the behaviour hits
stored when it ran. It uses the database and artifact store in ``SANDBOX_*`` settings (or
``.env``), like the API, and only reads.

* ``missing``: a detection fired then and does not now.
* ``extra``: a detection fires now and did not then (a possible new false positive).

The scoring code and weights are unchanged, so when the hit names agree the verdict
agrees too. A difference on an old analysis can also come from a rule change made
after it ran, so look at recent analyses first.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime

from sqlalchemy import select

from sandbox.analysis.engine import stored_capture
from sandbox.config import Settings
from sandbox.db.engine import make_engine, make_sessionmaker
from sandbox.db.models import Analysis, AnalysisVersion, Rule, RuleHit
from sandbox.detections import catalog
from sandbox.detections.base import Capture
from sandbox.storage import make_store


async def verify(since: datetime | None) -> int:
    settings = Settings()
    store = make_store(settings)
    engine = make_engine(settings.database_url)
    session = make_sessionmaker(engine)
    try:
        async with session() as db:
            enabled = {
                r.name: r
                for r in await db.scalars(
                    select(Rule).where(Rule.engine == "behaviour", Rule.enabled.is_(True))
                )
            }
            specs = [
                catalog.definition(d, enabled[d.name].id)
                for d in catalog.detections()
                if d.name in enabled
            ]
            q = select(AnalysisVersion, Analysis.url).join(
                Analysis, Analysis.id == AnalysisVersion.analysis_id
            )
            if since:
                q = q.where(AnalysisVersion.created_at >= since)
            checked = differ = 0
            changes: Counter[str] = Counter()
            for version, url in (await db.execute(q.order_by(AnalysisVersion.created_at))).all():
                data = await stored_capture(db, store, version.analysis_id)
                if data is None:
                    continue  # nothing to re-run the rules on
                data.domain_ages = (version.summary or {}).get("domain_ages") or {}
                stored = set(
                    await db.scalars(
                        select(RuleHit.rule_name).where(
                            RuleHit.analysis_id == version.analysis_id,
                            RuleHit.version == version.version,
                            RuleHit.engine == "behaviour",
                        )
                    )
                )
                now = {h["rule_name"] for h in catalog.run(specs, Capture(data))}
                checked += 1
                # A stored hit from a rule that is now disabled or removed is not a change.
                missing = sorted(n for n in stored - now if n in enabled)
                extra = sorted(now - stored)
                if missing or extra:
                    differ += 1
                    changes.update(f"-{n}" for n in missing)
                    changes.update(f"+{n}" for n in extra)
                    print(
                        f"{version.analysis_id} v{version.version} {version.verdict} {url}\n"
                        f"    missing {missing or '-'}  extra {extra or '-'}"
                    )
            print(f"\n{checked} analysis versions checked, {differ} differ.")
            for name, n in changes.most_common():
                print(f"  {name}: {n}")
            return 1 if differ else 0
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--since", type=datetime.fromisoformat, help="ISO date, e.g. 2026-11-01")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(verify(args.since)))


if __name__ == "__main__":
    main()
