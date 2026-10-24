"""The report (REP-1, REP-6, section 8): built entirely from stored data."""

from typing import Any

from sqlalchemy import select

from sandbox.db.models import (
    Analysis,
    AnalysisTag,
    AnalysisVersion,
    Artifact,
    IndicatorHit,
    Ioc,
    Note,
    RuleHit,
    Session,
    VerdictOverride,
)

_IOC_GROUPS = {"domain": "domains", "ip": "ips", "url": "urls", "hash": "hashes", "email": "emails"}


def artifact_dict(a: Artifact) -> dict[str, Any]:
    return {
        "id": a.id,
        "kind": a.kind,
        "name": a.name,
        "content_type": a.content_type,
        "sha256": a.sha256,
        "md5": a.md5,
        "size": a.size,
        "quarantined": a.quarantined,
        "deleted": a.deleted_at is not None,
        "meta": a.meta,
        "created_at": a.created_at,
    }


async def latest_override(db, analysis_id: str) -> VerdictOverride | None:
    return await db.scalar(
        select(VerdictOverride)
        .where(VerdictOverride.analysis_id == analysis_id)
        .order_by(VerdictOverride.created_at.desc(), VerdictOverride.id.desc())
        .limit(1)
    )


async def current_tags(db, analysis: Analysis) -> list[AnalysisTag]:
    """Rule tags of the current version plus every analyst tag (ANA-6, ANA-12)."""
    rows = await db.scalars(
        select(AnalysisTag)
        .where(AnalysisTag.analysis_id == analysis.id)
        .where((AnalysisTag.origin == "analyst") | (AnalysisTag.version == analysis.version))
        .order_by(AnalysisTag.origin.desc(), AnalysisTag.tag)
    )
    return list(rows)


async def build_report(db, analysis: Analysis, version: int | None = None) -> dict[str, Any]:
    version = version or analysis.version
    av = await db.scalar(
        select(AnalysisVersion).where(
            AnalysisVersion.analysis_id == analysis.id, AnalysisVersion.version == version
        )
    )
    summary = av.summary if av else {}
    facts = summary.get("facts", {})

    tags = (
        await current_tags(db, analysis)
        if version == analysis.version
        else list(
            await db.scalars(
                select(AnalysisTag).where(
                    AnalysisTag.analysis_id == analysis.id, AnalysisTag.version == version
                )
            )
        )
    )
    rule_hits = list(
        await db.scalars(
            select(RuleHit).where(RuleHit.analysis_id == analysis.id, RuleHit.version == version)
        )
    )
    indicator_hits = list(
        await db.scalars(
            select(IndicatorHit).where(
                IndicatorHit.analysis_id == analysis.id, IndicatorHit.version == version
            )
        )
    )
    iocs: dict[str, list[Any]] = {group: [] for group in _IOC_GROUPS.values()}
    for ioc in await db.scalars(
        select(Ioc).where(Ioc.analysis_id == analysis.id, Ioc.version == version).order_by(Ioc.id)
    ):
        entry = ioc.value if not ioc.enrichment else {"value": ioc.value, **ioc.enrichment}
        iocs[_IOC_GROUPS[ioc.type]].append(entry)
    artifacts = list(
        await db.scalars(
            select(Artifact)
            .where(Artifact.analysis_id == analysis.id)
            .order_by(Artifact.created_at, Artifact.name)
        )
    )
    sessions = list(await db.scalars(select(Session).where(Session.analysis_id == analysis.id)))
    overrides = list(
        await db.scalars(
            select(VerdictOverride)
            .where(VerdictOverride.analysis_id == analysis.id)
            .order_by(VerdictOverride.created_at)
        )
    )
    notes = list(
        await db.scalars(
            select(Note).where(Note.analysis_id == analysis.id).order_by(Note.created_at)
        )
    )
    versions = list(
        await db.scalars(
            select(AnalysisVersion)
            .where(AnalysisVersion.analysis_id == analysis.id)
            .order_by(AnalysisVersion.version)
        )
    )
    override = overrides[-1] if overrides else None
    return {
        "id": analysis.id,
        "url": analysis.url,
        "normalised_url": analysis.normalised_url,
        "mode": analysis.mode,
        "status": analysis.status,
        "error": analysis.error,
        "verdict": av.verdict if av else analysis.verdict,
        "score": av.score if av else analysis.score,
        "effective_verdict": override.verdict if override else (av.verdict if av else None),
        "version": version,
        "versions": [
            {
                "version": v.version,
                "verdict": v.verdict,
                "score": v.score,
                "bundle_id": v.bundle_id,
                "created_at": v.created_at,
                "reason": v.summary.get("reason"),
            }
            for v in versions
        ],
        "bundle_id": av.bundle_id if av else analysis.bundle_id,
        "submitted_by": analysis.submitted_by,
        "created_at": analysis.created_at,
        "started_at": analysis.started_at,
        "finished_at": analysis.finished_at,
        "profile": analysis.profile,
        "enrich": analysis.enrich,
        "restricted_to": analysis.restricted_to,
        "summary": {
            "final_url": facts.get("final", {}).get("url"),
            "final_domain": facts.get("final", {}).get("domain"),
            "title": facts.get("final", {}).get("title"),
            "brand": facts.get("brand"),
            "notes": summary.get("notes", []),
        },
        "tags": [
            {"tag": t.tag, "origin": t.origin, "evidence": t.evidence, "added_by": t.added_by}
            for t in tags
        ],
        "redirects": facts.get("redirects", {}).get("chain", []),
        "rule_hits": [
            {
                "id": h.id,
                "rule": h.rule_name,
                "rule_id": h.rule_id,
                "engine": h.engine,
                "severity": h.severity,
                "attack": h.attack_ids,
                "tags": h.tags,
                "artifact_id": h.artifact_id,
                "detail": h.detail,
            }
            for h in rule_hits
        ],
        "indicator_hits": [
            {"id": h.id, "type": h.type, "value": h.matched_value, "sources": h.sources}
            for h in indicator_hits
        ],
        "attack": summary.get("attack", []),
        "contributions": summary.get("contributions", []),
        "thresholds": summary.get("thresholds"),
        "facts": facts,
        "network": {
            "tls": summary.get("tls", {}),
            "dns": summary.get("dns", {}),
            "domain_ages": summary.get("domain_ages", {}),
            "suricata_alerts": summary.get("suricata_alerts", []),
        },
        "iocs": iocs,
        "artifacts": [artifact_dict(a) for a in artifacts],
        "sessions": [
            {
                "id": s.id,
                "backend": s.backend,
                "interactive": s.interactive,
                "started_at": s.started_at,
                "expires_at": s.expires_at,
                "ended_at": s.ended_at,
                "end_reason": s.end_reason,
            }
            for s in sessions
        ],
        "overrides": [
            {
                "verdict": o.verdict,
                "reason": o.reason,
                "set_by": o.set_by,
                "created_at": o.created_at,
            }
            for o in overrides
        ],
        "notes": [
            {"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at}
            for n in notes
        ],
    }
