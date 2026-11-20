"""Versioned rule bundles (FED-9, NFR-8).

A bundle is every enabled, valid rule without an active local override, compiled and
validated together, then published to artifact storage:

    bundles/<id>/yara.yarc       compiled YARA
    bundles/<id>/suricata.rules  Suricata rule file
    bundles/<id>/behaviour.json  behaviour rule definitions

If anything fails to compile the bundle is marked failed and never activated, so a broken
rule never reaches analysis. Exactly one bundle is active; activating an older one is the
one-step rollback. Each analysis version records the bundle it used.
"""

import asyncio
import contextlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from sqlalchemy import select, update

from sandbox.db.audit import record_audit
from sandbox.db.models import Rule, RuleBundle, RuleOverride
from sandbox.ids import new_id
from sandbox.rules.behaviour import RuleSyntaxError, parse_rule
from sandbox.rules.importer import YARA_COMPILE_OPTIONS

log = logging.getLogger(__name__)


async def bundle_rules(db) -> list[Rule]:
    overridden = select(RuleOverride.rule_id).where(RuleOverride.active)
    rows = await db.scalars(
        select(Rule)
        .where(Rule.enabled, Rule.error.is_(None), Rule.id.not_in(overridden))
        .order_by(Rule.engine, Rule.source, Rule.name)
    )
    return list(rows)


def compile_yara(rules: list[Rule]):
    import yara

    # One namespace per rule, so identical rule names from different sets do not clash.
    return yara.compile(sources={r.id: r.body for r in rules}, **YARA_COMPILE_OPTIONS)


def behaviour_definitions(rules: list[Rule]) -> list[dict[str, Any]]:
    out = []
    for r in rules:
        parsed = parse_rule(r.body)
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity,
                "tags": list(r.tags),
                "attack_ids": list(r.attack_ids),
                "description": r.description,
                **parsed,
            }
        )
    return out


async def build_bundle(ctx, *, actor: str = "system", activate: bool = True) -> RuleBundle:
    store = ctx.store
    async with ctx.sessionmaker() as db:
        rules = await bundle_rules(db)
        bundle = RuleBundle(
            id=new_id("rb"),
            status="building",
            built_by=actor,
            rule_ids=[r.id for r in rules],
            rule_count=len(rules),
        )
        db.add(bundle)
        await db.commit()

        by_engine: dict[str, list[Rule]] = {"yara": [], "suricata": [], "behaviour": []}
        for r in rules:
            by_engine[r.engine].append(r)
        try:
            compiled = (
                await asyncio.to_thread(compile_yara, by_engine["yara"])
                if by_engine["yara"]
                else None
            )
            behaviour = behaviour_definitions(by_engine["behaviour"])
            suricata_text = "\n".join(r.body for r in by_engine["suricata"]) + "\n"
            suricata_note = (
                await validate_suricata(ctx, suricata_text) if by_engine["suricata"] else None
            )
        except (RuleSyntaxError, ValueError, RuntimeError, Exception) as exc:  # noqa: BLE001
            bundle.status, bundle.error = "failed", f"{type(exc).__name__}: {exc}"[:4000]
            record_audit(
                db,
                actor=actor,
                action="bundle.failed",
                target=bundle.id,
                detail={"error": bundle.error[:500]},
            )
            await db.commit()
            log.error("rule bundle failed", extra={"bundle": bundle.id, "error": bundle.error})
            return bundle

        prefix = f"bundles/{bundle.id}"
        if compiled is not None:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "yara.yarc"
                compiled.save(str(path))
                store.put_file(f"{prefix}/yara.yarc", path)
            bundle.yara_object_key = f"{prefix}/yara.yarc"
        store.put_bytes(f"{prefix}/suricata.rules", suricata_text.encode())
        bundle.suricata_object_key = f"{prefix}/suricata.rules"
        store.put_bytes(f"{prefix}/behaviour.json", json.dumps(behaviour, indent=1).encode())
        bundle.behaviour_object_key = f"{prefix}/behaviour.json"
        bundle.status = "ready"
        if suricata_note:
            bundle.error = suricata_note
        if activate:
            await db.execute(update(RuleBundle).where(RuleBundle.active).values(active=False))
            await db.flush()
            bundle.active = True
        record_audit(
            db,
            actor=actor,
            action="bundle.built",
            target=bundle.id,
            detail={"rules": len(rules), "active": activate},
        )
        await db.commit()
        return bundle


async def validate_suricata(ctx, rules_text: str) -> str | None:
    """Run ``suricata -T`` in the configured Suricata image; a note if it cannot run.

    Rules that Suricata rejects fail the build. Without an image, Suricata rules are
    published unvalidated and the bundle says so.
    """
    image = ctx.settings.suricata_image
    if not image:
        return "Suricata rules not validated: no suricata_image configured"
    from sandbox.analysis.suricata import run_suricata

    with tempfile.TemporaryDirectory() as tmp:
        rules = Path(tmp) / "test.rules"
        rules.write_text(rules_text)
        try:
            ok, output = await run_suricata(ctx, image, rules, pcap=None)
        except Exception as exc:
            raise RuntimeError(f"Could not run Suricata ({image}): {exc}") from exc
    if not ok:
        raise RuntimeError(f"Suricata rejected the rule set: {output[-2000:]}")
    return None


async def activate_bundle(db, bundle_id: str, actor: str) -> RuleBundle:
    bundle = await db.get(RuleBundle, bundle_id)
    if bundle is None or bundle.status != "ready":
        raise ValueError("You can activate only a ready bundle")
    await db.execute(update(RuleBundle).where(RuleBundle.active).values(active=False))
    await db.flush()
    bundle.active = True
    record_audit(db, actor=actor, action="bundle.activated", target=bundle.id)
    return bundle


async def active_bundle(db) -> RuleBundle | None:
    return await db.scalar(select(RuleBundle).where(RuleBundle.active).limit(1))


class LoadedBundle:
    """A bundle's published files, loaded for analysis."""

    def __init__(self, bundle: RuleBundle | None, store):
        self.id = bundle.id if bundle else None
        self.yara = None
        self.behaviour: list[dict[str, Any]] = []
        self.suricata_path: Path | None = None
        if bundle is None:
            return
        if bundle.yara_object_key and store.exists(bundle.yara_object_key):
            import yara

            with contextlib.suppress(yara.Error):
                self.yara = yara.load(str(store.path(bundle.yara_object_key)))
        if bundle.behaviour_object_key and store.exists(bundle.behaviour_object_key):
            self.behaviour = json.loads(store.read_bytes(bundle.behaviour_object_key))
        if bundle.suricata_object_key and store.exists(bundle.suricata_object_key):
            self.suricata_path = store.path(bundle.suricata_object_key)


async def bundle_build_job(ctx, payload: dict[str, Any]) -> None:
    await build_bundle(
        ctx, actor=payload.get("actor", "system"), activate=payload.get("activate", True)
    )
