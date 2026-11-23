"""Rules, bundles and scoring (FED-7 to FED-10, FED-13, ANA-7, section 7)."""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import any_, func, literal, or_, select, update

from sandbox.analysis.engine import load_weights, stored_capture
from sandbox.analysis.scoring import SEVERITY_FALLBACK
from sandbox.api.access import visible_clause
from sandbox.api.auth import Engineer, Principal, require_scope
from sandbox.api.deps import Db, Store
from sandbox.db.audit import record_audit
from sandbox.db.models import (
    Analysis,
    AnalysisVersion,
    Artifact,
    Rule,
    RuleBundle,
    RuleOverride,
    ScoringConfig,
)
from sandbox.detections import catalog
from sandbox.detections.base import Capture
from sandbox.ids import new_id
from sandbox.orchestrator import jobs
from sandbox.rules.bundles import activate_bundle
from sandbox.rules.defaults import BUILTIN_SOURCE, builtin_body
from sandbox.rules.importer import content_hash, validate_yara, yara_metadata
from sandbox.runtime_config import get_config

router = APIRouter(prefix="/v1", tags=["rules"])
RulesReader = Annotated[Principal, Depends(require_scope("rules:read"))]
Severity = Literal["info", "low", "medium", "high", "critical"]


def _error(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(code, {"error": error, "detail": detail})


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def rule_dict(r: Rule, overridden: bool = False, full: bool = False) -> dict[str, Any]:
    out = {
        "id": r.id,
        "engine": r.engine,
        "name": r.name,
        "description": r.description,
        "source": r.source,
        "version": r.version,
        "licence": r.licence,
        "enabled": r.enabled,
        "locally_disabled": overridden,
        "severity": r.severity,
        "tags": r.tags,
        "attack_ids": r.attack_ids,
        "error": r.error,
        "content_hash": r.content_hash,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        "modified_by": r.modified_by,
        # A behaviour rule is a detection in code (sandbox.detections): its row can be
        # disabled and re-weighted, and severity and tags edited, but not its body.
        "editable": r.source in ("local", BUILTIN_SOURCE) and r.engine != "behaviour",
    }
    if r.engine == "behaviour" and (d := catalog.get(r.name)):
        out["title"] = d.title
        out["score"] = d.score
    if full:
        out["body"] = r.body
        if r.engine == "behaviour" and (d := catalog.get(r.name)):
            out["detection"] = catalog.describe(d)
    return out


@router.get("/rules")
async def list_rules(
    principal: RulesReader,
    db: Db,
    engine: str | None = None,
    source: str | None = None,
    enabled: bool | None = None,
    severity: str | None = None,
    tag: str | None = None,
    attack: str | None = None,
    q: str | None = None,
    invalid: bool | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """FED-8: filter by engine, source, enabled flag, severity, tag and ATT&CK id."""
    overridden = select(RuleOverride.rule_id).where(RuleOverride.active)
    conds = []
    if engine:
        conds.append(Rule.engine == engine)
    if source:
        conds.append(Rule.source == source)
    if enabled is True:
        conds += [Rule.enabled, Rule.id.not_in(overridden)]
    elif enabled is False:
        conds.append(or_(~Rule.enabled, Rule.id.in_(overridden)))
    if severity:
        conds.append(Rule.severity == severity)
    if tag:
        conds.append(literal(tag) == any_(Rule.tags))
    if attack:
        conds.append(literal(attack) == any_(Rule.attack_ids))
    if q:
        conds.append(or_(Rule.name.ilike(f"%{q}%"), Rule.description.ilike(f"%{q}%")))
    if invalid is not None:
        conds.append(Rule.error.is_not(None) if invalid else Rule.error.is_(None))
    total = await db.scalar(select(func.count()).select_from(Rule).where(*conds))
    rows = list(
        await db.scalars(
            select(Rule)
            .where(*conds)
            .order_by(Rule.engine, Rule.source, Rule.name)
            .limit(limit)
            .offset(offset)
        )
    )
    off = set(await db.scalars(overridden))
    sources = (
        await db.execute(
            select(Rule.engine, Rule.source, func.count()).group_by(Rule.engine, Rule.source)
        )
    ).all()
    return {
        "total": total,
        "items": [rule_dict(r, r.id in off) for r in rows],
        "sources": [{"engine": e, "source": s, "count": c} for e, s, c in sources],
    }


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, principal: RulesReader, db: Db) -> dict[str, Any]:
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise _error(404, "not_found", f"No rule {rule_id}")
    overrides = list(
        await db.scalars(
            select(RuleOverride)
            .where(RuleOverride.rule_id == rule_id)
            .order_by(RuleOverride.created_at)
        )
    )
    return {
        **rule_dict(rule, any(o.active for o in overrides), full=True),
        "overrides": [
            {
                "by": o.disabled_by,
                "reason": o.reason,
                "active": o.active,
                "at": o.created_at.isoformat(),
            }
            for o in overrides
        ],
    }


class RuleCreate(BaseModel):
    engine: Literal["yara", "behaviour", "suricata"]
    name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_\-.:]+$")
    body: str = Field(min_length=1, max_length=200_000)
    description: str = Field("", max_length=2000)
    severity: Severity = "medium"
    tags: list[str] = Field(default_factory=list, max_length=20)
    attack_ids: list[str] = Field(default_factory=list, max_length=20)
    # Custom rules start disabled so they can be tested first (FED-13).
    enabled: bool = False


DETECTION_IN_CODE = (
    "Behaviour detections are written in code, one model for every rule: add or change "
    "one in sandbox/detections (see docs/detection-rules.md)."
)


def _validate(engine: str, body: str) -> str | None:
    if engine == "yara":
        return validate_yara(body)
    if engine == "behaviour":
        return DETECTION_IN_CODE
    if engine == "suricata" and "sid:" not in body.replace(" ", ""):
        return "Suricata rules need a sid"
    return None


@router.post("/rules", status_code=201)
async def create_rule(
    body: RuleCreate, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    error = _validate(body.engine, body.body)
    if error:
        raise _error(422, "invalid_rule", error)
    meta = yara_metadata(body.body) if body.engine == "yara" else {}
    rule = Rule(
        id=new_id("ru"),
        engine=body.engine,
        name=body.name,
        body=body.body,
        source="local",
        description=body.description or meta.get("description", ""),
        version="1",
        licence="internal",
        content_hash=content_hash(body.body),
        enabled=body.enabled,
        severity=body.severity,
        tags=body.tags or meta.get("tags", []),
        attack_ids=body.attack_ids or meta.get("attack_ids", []),
        created_by=principal.subject,
    )
    db.add(rule)
    record_audit(
        db,
        actor=principal.subject,
        action="rule.create",
        target=rule.id,
        source_ip=_ip(request),
        detail={"engine": rule.engine, "name": rule.name},
    )
    if rule.enabled:
        jobs.enqueue(
            db,
            "bundle_build",
            {"reason": "rule created", "activate": True, "actor": principal.subject},
        )
    await db.commit()
    return rule_dict(rule, full=True)


class RuleUpdate(BaseModel):
    body: str | None = Field(None, max_length=200_000)
    description: str | None = Field(None, max_length=2000)
    severity: Severity | None = None
    tags: list[str] | None = None
    attack_ids: list[str] | None = None


@router.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: str, body: RuleUpdate, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise _error(404, "not_found", f"No rule {rule_id}")
    if body.body is not None:
        if rule.engine == "behaviour":
            raise _error(409, "detection_in_code", DETECTION_IN_CODE)
        if rule.source not in ("local", BUILTIN_SOURCE):
            raise _error(
                409,
                "upstream_rule",
                "Upstream rules change through their feed. Disable the rule instead",
            )
        error = _validate(rule.engine, body.body)
        if error:
            raise _error(422, "invalid_rule", error)
        if body.body != rule.body:
            rule.body, rule.content_hash = body.body, content_hash(body.body)
            rule.error = None
            if rule.source == BUILTIN_SOURCE:
                # Seeding keeps this edit until it is reverted (POST .../revert).
                rule.modified_by = principal.subject
    for field in ("description", "severity", "tags", "attack_ids"):
        if getattr(body, field) is not None:
            setattr(rule, field, getattr(body, field))
    rule.updated_at = datetime.now(UTC)
    record_audit(
        db,
        actor=principal.subject,
        action="rule.update",
        target=rule.id,
        source_ip=_ip(request),
        detail={
            **body.model_dump(exclude_none=True, exclude={"body"}),
            **({"body_changed": True} if body.body is not None else {}),
        },
    )
    jobs.enqueue(
        db, "bundle_build", {"reason": "rule updated", "activate": True, "actor": principal.subject}
    )
    await db.commit()
    return rule_dict(rule, full=True)


@router.post("/rules/{rule_id}/revert")
async def revert_rule(
    rule_id: str, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    """Put a built-in rule edited in Admin back to the body that ships with Sandboxer."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise _error(404, "not_found", f"No rule {rule_id}")
    shipped = builtin_body(rule.engine, rule.name) if rule.source == BUILTIN_SOURCE else None
    if shipped is None:
        raise _error(409, "not_builtin", "Only built-in rules have a shipped version")
    rule.body, rule.content_hash = shipped, content_hash(shipped)
    rule.error = validate_yara(shipped) if rule.engine == "yara" else None
    rule.modified_by = None
    rule.updated_at = datetime.now(UTC)
    record_audit(
        db,
        actor=principal.subject,
        action="rule.revert",
        target=rule.id,
        source_ip=_ip(request),
        detail={"name": rule.name},
    )
    jobs.enqueue(
        db,
        "bundle_build",
        {"reason": "rule reverted", "activate": True, "actor": principal.subject},
    )
    await db.commit()
    return rule_dict(rule, full=True)


class DisableBody(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


@router.post("/rules/{rule_id}/disable")
async def disable_rule(
    rule_id: str, body: DisableBody, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    """FED-10: a local override that survives the next feed update; audited."""
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise _error(404, "not_found", f"No rule {rule_id}")
    db.add(RuleOverride(rule_id=rule.id, disabled_by=principal.subject, reason=body.reason))
    record_audit(
        db,
        actor=principal.subject,
        action="rule.disable",
        target=rule.id,
        source_ip=_ip(request),
        detail={"reason": body.reason, "name": rule.name},
    )
    jobs.enqueue(
        db,
        "bundle_build",
        {"reason": "rule disabled", "activate": True, "actor": principal.subject},
    )
    await db.commit()
    return rule_dict(rule, overridden=True)


@router.post("/rules/{rule_id}/enable")
async def enable_rule(
    rule_id: str, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise _error(404, "not_found", f"No rule {rule_id}")
    if rule.error:
        raise _error(409, "invalid_rule", f"The rule does not compile: {rule.error}")
    await db.execute(
        update(RuleOverride).where(RuleOverride.rule_id == rule.id).values(active=False)
    )
    rule.enabled = True
    record_audit(
        db,
        actor=principal.subject,
        action="rule.enable",
        target=rule.id,
        source_ip=_ip(request),
        detail={"name": rule.name},
    )
    jobs.enqueue(
        db, "bundle_build", {"reason": "rule enabled", "activate": True, "actor": principal.subject}
    )
    await db.commit()
    return rule_dict(rule)


class RuleTest(BaseModel):
    engine: Literal["yara", "behaviour"]
    body: str = Field(min_length=1, max_length=200_000)
    severity: Severity = "medium"
    limit: int = Field(50, ge=1, le=500)


@router.post("/rules/test")
async def test_rule(body: RuleTest, principal: Engineer, db: Db, store: Store) -> dict[str, Any]:
    """FED-13: run a draft rule over recent stored analyses and show which verdicts would
    change. Nothing is saved. For a behaviour detection, ``body`` is its name: it runs
    over each analysis's stored observed values, exactly as a re-analysis would."""
    detection = None
    if body.engine == "behaviour":
        detection = catalog.get(body.body.strip())
        if detection is None:
            raise _error(422, "invalid_rule", f"No detection named {body.body.strip()!r}")
    else:
        error = _validate(body.engine, body.body)
        if error:
            raise _error(422, "invalid_rule", error)
    weights = await load_weights(db)
    thresholds = await get_config(db, "verdict_thresholds")
    weight = weights.get(f"severity:{body.severity}", (SEVERITY_FALLBACK[body.severity], None))[0]
    if detection is not None:
        weight = weights.get(detection.name, (detection.score, None))[0]
    rows = (
        await db.execute(
            select(Analysis, AnalysisVersion)
            .join(
                AnalysisVersion,
                (AnalysisVersion.analysis_id == Analysis.id)
                & (AnalysisVersion.version == Analysis.version),
            )
            # Restricted analyses (ADM-7) stay out unless the engineer may see them.
            .where(visible_clause(principal))
            .order_by(Analysis.created_at.desc())
            .limit(body.limit)
        )
    ).all()
    compiled = None
    if body.engine == "yara":
        import yara

        from sandbox.rules.importer import YARA_COMPILE_OPTIONS

        compiled = yara.compile(source=body.body, **YARA_COMPILE_OPTIONS)
    results = []
    for analysis, version in rows:
        matched, evidence = False, {}
        if detection is not None:
            # A rule reads the capture's tables: rebuild them from the stored capture
            # (nothing is detonated).
            data = await stored_capture(db, store, analysis.id)
            if data is not None:
                data.domain_ages = version.summary.get("domain_ages") or {}
                outcome = detection.evaluate(Capture(data))
                matched, evidence = outcome.matched, outcome.facts
            else:
                evidence = {"note": "no stored capture"}
        else:
            artifacts = await db.scalars(
                select(Artifact).where(
                    Artifact.analysis_id == analysis.id,
                    Artifact.kind.in_(("dom", "script", "download")),
                    Artifact.deleted_at.is_(None),
                    Artifact.size < 20_000_000,
                )
            )
            for a in artifacts:
                if store.exists(a.object_key) and compiled.match(
                    data=store.read_bytes(a.object_key)
                ):
                    matched, evidence = True, {"artifact": a.name, "kind": a.kind}
                    break
        new_score = min(100, version.score + (weight if matched else 0))
        new_verdict = (
            "malicious"
            if new_score >= thresholds["malicious"]
            else "suspicious"
            if new_score >= thresholds["suspicious"]
            else version.verdict
        )
        results.append(
            {
                "analysis_id": analysis.id,
                "url": analysis.normalised_url,
                "matched": matched,
                "evidence": evidence,
                "score": version.score,
                "verdict": version.verdict,
                "new_score": new_score,
                "new_verdict": new_verdict,
                "verdict_changes": new_verdict != version.verdict,
            }
        )
    return {
        "tested": len(results),
        "matched": sum(r["matched"] for r in results),
        "verdict_changes": sum(r["verdict_changes"] for r in results),
        "weight_applied": weight,
        "results": results,
    }


# --- bundles ---------------------------------------------------------------------------


@router.get("/detections")
async def list_detections(principal: RulesReader) -> dict[str, Any]:
    """Every behaviour detection with its rule as sentences, its score, and each signal it
    reads (title, how it is computed, where the code is)."""
    return {"items": [catalog.describe(d) for d in catalog.detections()]}


def bundle_dict(b: RuleBundle) -> dict[str, Any]:
    return {
        "id": b.id,
        "built_at": b.built_at.isoformat(),
        "status": b.status,
        "active": b.active,
        "rule_count": b.rule_count,
        "error": b.error,
        "built_by": b.built_by,
    }


@router.get("/rule-bundles/current")
async def current_bundle(principal: RulesReader, db: Db) -> dict[str, Any]:
    bundle = await db.scalar(select(RuleBundle).where(RuleBundle.active))
    if bundle is None:
        raise _error(404, "no_bundle", "No active rule bundle yet")
    by_engine = (
        await db.execute(
            # Joined in SQL: a bundle can hold more rule ids than one query may bind.
            select(Rule.engine, func.count())
            .join(RuleBundle, Rule.id == any_(RuleBundle.rule_ids))
            .where(RuleBundle.id == bundle.id)
            .group_by(Rule.engine)
        )
    ).all()
    return {**bundle_dict(bundle), "rules_by_engine": dict(by_engine)}


@router.get("/rule-bundles")
async def list_bundles(
    principal: RulesReader, db: Db, limit: int = Query(20, le=200)
) -> list[dict]:
    rows = await db.scalars(select(RuleBundle).order_by(RuleBundle.built_at.desc()).limit(limit))
    return [bundle_dict(b) for b in rows]


@router.post("/rule-bundles", status_code=202)
async def build_bundle_now(
    request: Request, principal: Engineer, db: Db, activate: bool = True
) -> dict[str, Any]:
    jobs.enqueue(
        db, "bundle_build", {"reason": "manual", "activate": activate, "actor": principal.subject}
    )
    record_audit(
        db, actor=principal.subject, action="bundle.build_requested", source_ip=_ip(request)
    )
    await db.commit()
    return {"queued": True}


@router.post("/rule-bundles/{bundle_id}/activate")
async def activate(bundle_id: str, request: Request, principal: Engineer, db: Db) -> dict[str, Any]:
    """NFR-8: one-step rollback to any earlier ready bundle."""
    try:
        bundle = await activate_bundle(db, bundle_id, principal.subject)
    except ValueError as exc:
        raise _error(409, "not_ready", str(exc)) from exc
    await db.commit()
    return bundle_dict(bundle)


# --- scoring ---------------------------------------------------------------------------


@router.get("/scoring")
async def get_scoring(principal: RulesReader, db: Db) -> dict[str, Any]:
    weights = await load_weights(db)
    return {
        "weights": {k: {"weight": w, "cap": c} for k, (w, c) in sorted(weights.items())},
        "thresholds": await get_config(db, "verdict_thresholds"),
        "severity_fallback": SEVERITY_FALLBACK,
    }


class WeightBody(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    weight: int = Field(ge=-100, le=100)
    cap: int | None = Field(None, ge=0, le=100)


@router.put("/scoring")
async def set_weight(
    body: WeightBody, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    """ANA-7: a new row per change, so the history of weights is kept."""
    db.add(
        ScoringConfig(
            tag_or_rule=body.key, weight=body.weight, cap=body.cap, updated_by=principal.subject
        )
    )
    record_audit(
        db,
        actor=principal.subject,
        action="scoring.update",
        target=body.key,
        source_ip=_ip(request),
        detail=body.model_dump(),
    )
    await db.commit()
    return {"key": body.key, "weight": body.weight, "cap": body.cap}
