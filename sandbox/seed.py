"""Insert built-in rules, weights, brands and feeds that are missing, and keep built-in
content current.

Built-in rule bodies are refreshed when the shipped version changes, unless a detection
engineer edited the body in Admin: that edit is kept until it is reverted. Disables and
weights always survive. Built-in brand domains are
merged into existing brand rows; keywords, extra domains and ``enabled`` set by an
admin are kept. Weights are only ever inserted, and so are feeds, except that a feed
still on a default URL its provider retired moves to the current default.
"""

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sandbox.db.models import Brand, Feed, Rule, RuleBundle, ScoringConfig
from sandbox.ids import new_id
from sandbox.orchestrator import jobs
from sandbox.rules import defaults
from sandbox.rules.importer import content_hash, validate_yara, yara_metadata


def _refresh(rule: Rule, body: str, **values) -> bool:
    """Bring a built-in rule up to the shipped body; True if it changed. A body a
    detection engineer edited in Admin (``modified_by``) is kept until it is reverted."""
    if rule.modified_by:
        return False
    digest = content_hash(body)
    if rule.content_hash == digest:
        return False
    rule.body, rule.content_hash = body, digest
    rule.version = str(int(rule.version) + 1) if (rule.version or "").isdigit() else "2"
    rule.updated_at = datetime.now(UTC)
    for key, value in values.items():
        setattr(rule, key, value)
    return True


async def ensure_defaults(db: AsyncSession) -> None:
    existing_rules = {
        (r.engine, r.name): r
        for r in (await db.scalars(select(Rule).where(Rule.source == defaults.BUILTIN_SOURCE)))
    }
    changed = 0
    for spec in defaults.BEHAVIOUR_RULES:
        rule = existing_rules.get(("behaviour", spec["name"]))
        if rule is None:
            db.add(
                Rule(
                    id=new_id("ru"),
                    engine="behaviour",
                    source=defaults.BUILTIN_SOURCE,
                    content_hash=content_hash(spec["body"]),
                    version="1",
                    licence="internal",
                    **spec,
                )
            )
            changed += 1
        else:
            changed += _refresh(
                rule,
                spec["body"],
                description=spec["description"],
                attack_ids=spec["attack_ids"],
            )
    for name, raw in defaults.BUILTIN_YARA.items():
        body = raw.strip()
        meta = yara_metadata(body)
        rule = existing_rules.get(("yara", name))
        if rule is None:
            db.add(
                Rule(
                    id=new_id("ru"),
                    engine="yara",
                    source=defaults.BUILTIN_SOURCE,
                    name=name,
                    body=body,
                    content_hash=content_hash(body),
                    version="1",
                    licence="internal",
                    error=validate_yara(body),
                    **meta,
                )
            )
            changed += 1
        else:
            changed += _refresh(
                rule,
                body,
                error=validate_yara(body),
                description=meta["description"],
                attack_ids=meta["attack_ids"],
            )

    weights = set(await db.scalars(select(ScoringConfig.tag_or_rule)))
    for key, weight in defaults.DEFAULT_WEIGHTS.items():
        if key not in weights:
            db.add(ScoringConfig(tag_or_rule=key, weight=weight, updated_by="seed"))

    brands = {b.name: b for b in await db.scalars(select(Brand))}
    for name, keywords, domains in defaults.DEFAULT_BRANDS:
        brand = brands.get(name)
        if brand is None:
            await db.execute(
                insert(Brand)
                .values(id=new_id("br"), name=name, keywords=keywords, domains=domains)
                .on_conflict_do_nothing(index_elements=[Brand.name])
            )
        elif missing := [d for d in domains if d not in brand.domains]:
            brand.domains = [*brand.domains, *missing]
    for feed in defaults.DEFAULT_FEEDS:
        await db.execute(
            insert(Feed)
            .values(id=new_id("fd"), **feed)
            .on_conflict_do_nothing(index_elements=[Feed.name])
        )
        if retired := defaults.RETIRED_FEED_URLS.get(feed["name"]):
            await db.execute(
                update(Feed)
                .where(Feed.name == feed["name"], Feed.url == retired)
                .values(url=feed["url"], licence_note=feed["licence_note"])
            )

    await db.flush()
    # A first bundle so analyses always have a pinned rule set (FED-9), and a fresh one
    # when built-in rules changed so the fixes take effect.
    has_bundle = await db.scalar(select(RuleBundle.id).where(RuleBundle.active).limit(1))
    if not has_bundle and not await jobs.has_pending(db, "bundle_build", "reason", "initial"):
        jobs.enqueue(db, "bundle_build", {"reason": "initial", "activate": True})
    elif (
        has_bundle
        and changed
        and not await jobs.has_pending(db, "bundle_build", "reason", "builtin rules updated")
    ):
        jobs.enqueue(db, "bundle_build", {"reason": "builtin rules updated", "activate": True})
