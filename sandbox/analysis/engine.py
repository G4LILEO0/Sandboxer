"""Analysis engine (step 6): stored artifacts in, versioned verdict out.

Runs after every detonation and on demand over stored artifacts with the current bundle
(ANA-13). Each run is a new ``analysis_versions`` row with its own hits, tags and IOCs,
so earlier verdicts stay reproducible (ANA-11).
"""

import json
import logging
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select, text, update

from sandbox import detection
from sandbox.analysis.dom import parse_dom
from sandbox.analysis.domains import (
    BrandRef,
    parent_domains,
    registrable,
    registration_age_days,
    site,
)
from sandbox.analysis.facts import (
    CaptureData,
    build_facts,
    chain_hosts,
    contacted_hosts,
    extract_iocs,
)
from sandbox.analysis.scoring import ScoreResult, score
from sandbox.db.audit import record_audit
from sandbox.db.models import (
    AllowlistDomain,
    Analysis,
    AnalysisTag,
    AnalysisVersion,
    Artifact,
    AttackTechnique,
    Brand,
    Event,
    IndicatorHit,
    Ioc,
    Rule,
    RuleHit,
)
from sandbox.ids import new_id
from sandbox.rules.behaviour import evaluate as evaluate_rule
from sandbox.rules.bundles import LoadedBundle, active_bundle
from sandbox.runtime_config import get_all

log = logging.getLogger(__name__)
_YARA_TARGET_KINDS = ("dom", "script", "download")
_MAX_YARA_BYTES = 20 * 1024 * 1024


@dataclass
class Evaluation:
    facts: dict[str, Any]
    rule_hits: list[dict[str, Any]]
    indicator_hits: list[dict[str, Any]]
    suricata_alerts: list[dict[str, Any]]
    tags: dict[str, list[str]]
    iocs: dict[str, list[str]]
    result: ScoreResult
    attack_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# --- pure evaluation (used by the engine, tests and rule testing) ----------------------


def behaviour_hits(
    definitions: list[dict[str, Any]], facts: dict[str, Any]
) -> list[dict[str, Any]]:
    hits = []
    for rule in definitions:
        outcome = evaluate_rule(rule, facts)
        if outcome.matched:
            hits.append(
                {
                    "id": new_id("rh"),
                    "rule_id": rule.get("id"),
                    "rule_name": rule["name"],
                    "engine": "behaviour",
                    "severity": rule.get("severity", "medium"),
                    "tags": rule.get("tags", []),
                    "attack_ids": rule.get("attack_ids", []),
                    "artifact_id": None,
                    "detail": {"description": rule.get("description", ""), "facts": outcome.facts},
                }
            )
    return hits


def tags_from(rule_hits, indicator_hits, suricata_alerts) -> dict[str, list[str]]:
    """tag -> evidence ids (ANA-6)."""
    tags: dict[str, list[str]] = {}
    for hit in rule_hits:
        for tag in hit.get("tags", []):
            tags.setdefault(tag.replace("_", "-").lower(), []).append(hit["id"])
    for hit in indicator_hits:
        tags.setdefault("known-bad", []).append(hit["id"])
        for source in hit["sources"]:
            for tag in (source.get("tags") or [])[:3]:
                if tag in (
                    "phishing",
                    "malware",
                    "malware_download",
                    "botnet_cc",
                    "payload_delivery",
                ):
                    tags.setdefault(tag.replace("_", "-"), []).append(hit["id"])
    if suricata_alerts:
        tags.setdefault("ids-alert", []).extend(f"sid:{a['sid']}" for a in suricata_alerts)
    return tags


def evaluate(
    data: CaptureData,
    *,
    behaviour: list[dict[str, Any]],
    yara_hits: list[dict[str, Any]],
    indicator_hits: list[dict[str, Any]],
    suricata_alerts: list[dict[str, Any]],
    weights: dict[str, tuple[int, int | None]],
    thresholds: dict[str, int],
) -> Evaluation:
    facts = build_facts(data)
    rule_hits = behaviour_hits(behaviour, facts) + yara_hits
    # A page that never loaded is "unknown" unless something else already scored it.
    capture_ok = facts["capture"]["navigated"] and not facts["capture"]["load_failed"]
    result = score(
        rule_hits=rule_hits,
        indicator_hits=indicator_hits,
        suricata_alerts=suricata_alerts,
        weights=weights,
        thresholds=thresholds,
        allowlisted=data.allowlisted,
        capture_ok=capture_ok,
    )
    attack = sorted({a for h in rule_hits for a in h.get("attack_ids", [])})
    return Evaluation(
        facts=facts,
        rule_hits=rule_hits,
        indicator_hits=indicator_hits,
        suricata_alerts=suricata_alerts,
        tags=tags_from(rule_hits, indicator_hits, suricata_alerts),
        iocs=extract_iocs(data, facts),
        result=result,
        attack_ids=attack,
    )


# --- loading ---------------------------------------------------------------------------


async def load_weights(db) -> dict[str, tuple[int, int | None]]:
    rows = await db.execute(
        text(
            "SELECT DISTINCT ON (tag_or_rule) tag_or_rule, weight, cap FROM scoring_config "
            "WHERE active_from <= now() ORDER BY tag_or_rule, active_from DESC, id DESC"
        )
    )
    return {key: (weight, cap) for key, weight, cap in rows}


async def load_brands(db) -> list[BrandRef]:
    rows = await db.scalars(select(Brand).where(Brand.enabled))
    return [BrandRef(b.name, tuple(k.lower() for k in b.keywords), tuple(b.domains)) for b in rows]


async def load_allowlisted(db, domains: list[str]) -> set[str]:
    if not domains:
        return set()
    rows = await db.scalars(
        select(AllowlistDomain.domain).where(AllowlistDomain.domain.in_(domains))
    )
    return set(rows)


def _other_scheme(url: str) -> str | None:
    if url.startswith("http://"):
        return "https://" + url[len("http://") :]
    if url.startswith("https://"):
        return "http://" + url[len("https://") :]
    return None


def match_candidates(
    result: dict[str, Any],
    har_entries: list[dict[str, Any]],
    hosts: list[str],
    submitted: list[str | None] = (),
) -> dict[str, set[str]]:
    """Values from one capture to look up in the feeds (ANA-3).

    - URLs are tried with both schemes. Feeds list ``http://`` and ``https://`` versions
      of the same page interchangeably, and the browser upgrades many hosts to https
      itself (HSTS preload, for example every ``.dev`` domain) without a redirect.
    - The submitted URL counts even if the page never requested it in that exact form.
    - Each contacted host's root URL is tried, so a feed entry ``http://kit.pages.dev/``
      also matches a visit to ``https://kit.pages.dev/login``.
    - Domains match the host and every parent down to its registrable domain.
    """
    from sandbox.feeds.parsers import normalise_value

    values: dict[str, set[str]] = {"domain": set(), "ip": set(), "url": set(), "hash": set()}
    raw_urls: set[str] = {u for u in submitted if u}
    raw_urls.update(u for u in (result.get("url"), result.get("final_url")) if u)
    for h in hosts:
        values["domain"].update(parent_domains(h))
        raw_urls.update((f"http://{h}/", f"https://{h}/"))
    for addresses in result.get("hosts", {}).values():
        values["ip"].update(addresses)
    for hop in result.get("redirects", []):
        raw_urls.update(u for u in (hop.get("from"), hop.get("to")) if u)
    for nav in result.get("navigations", []):
        raw_urls.add(nav.get("url", ""))
    raw_urls.update(e.get("request", {}).get("url", "") for e in har_entries[:3000])
    for d in result.get("downloads", []):
        values["hash"].update(v for v in (d.get("sha256"), d.get("md5")) if v)
    for u in raw_urls:
        if u and (n := normalise_value("url", u)):
            values["url"].add(n)
            if (flipped := _other_scheme(n)) and (m := normalise_value("url", flipped)):
                values["url"].add(m)
    return values


async def match_indicators(db, values: dict[str, set[str]]) -> list[dict[str, Any]]:
    """Match capture values against active, unsuppressed feed indicators (ANA-3)."""
    types, vals = [], []
    for ioc_type, items in values.items():
        for v in items:
            types.append(ioc_type)
            vals.append(v)
    if not vals:
        return []
    rows = await db.execute(
        text(
            """
            SELECT i.id, i.type, i.value,
                   json_agg(json_build_object('feed', f.name, 'confidence', s.confidence,
                                              'tags', s.tags, 'last_seen', s.last_seen))
            FROM unnest(CAST(:types AS text[]), CAST(:vals AS text[])) AS q(type, value)
            JOIN indicators i ON i.type = q.type AND i.value = q.value
            JOIN indicator_sources s ON s.indicator_id = i.id AND s.expires_at > now()
            JOIN feeds f ON f.id = s.feed_id
            WHERE NOT EXISTS (
                SELECT 1 FROM indicator_suppressions x WHERE x.type = i.type AND x.value = i.value
            )
            GROUP BY i.id, i.type, i.value
            """
        ),
        {"types": types, "vals": vals},
    )
    hits = []
    for indicator_id, ioc_type, value, sources in rows:
        hits.append(
            {
                "id": new_id("ih"),
                "indicator_id": indicator_id,
                "type": ioc_type,
                "matched_value": value,
                # The allowlist unit: a tenant on a hosting platform is not its platform.
                "registrable": site(value) if ioc_type == "domain" else None,
                "sources": sources,
            }
        )
    return hits


def _yara_scan(
    compiled, artifacts: list[Artifact], store, rules_by_id: dict[str, Rule]
) -> list[dict]:
    hits = []
    for artifact in artifacts:
        if artifact.size > _MAX_YARA_BYTES or not store.exists(artifact.object_key):
            continue
        data = store.read_bytes(artifact.object_key)
        try:
            matches = compiled.match(data=data, timeout=20)
        except Exception as exc:  # noqa: BLE001 - one bad file never stops the analysis
            log.warning("yara scan failed", extra={"artifact": artifact.id, "error": str(exc)})
            continue
        for m in matches:
            rule = rules_by_id.get(m.namespace)
            offsets = []
            for s in m.strings[:10]:
                if hasattr(s, "instances"):  # yara-python >= 4.3
                    for inst in s.instances[:3]:
                        offsets.append(
                            {
                                "string": s.identifier,
                                "offset": inst.offset,
                                "data": inst.matched_data[:64].decode("latin-1"),
                            }
                        )
                else:
                    offset, ident, matched = s
                    offsets.append(
                        {"string": ident, "offset": offset, "data": matched[:64].decode("latin-1")}
                    )
            hits.append(
                {
                    "id": new_id("rh"),
                    "rule_id": rule.id if rule else None,
                    "rule_name": m.rule,
                    "engine": "yara",
                    "severity": rule.severity if rule else "medium",
                    "tags": sorted(set((rule.tags if rule else []) + list(m.tags))),
                    "attack_ids": list(rule.attack_ids) if rule else [],
                    "artifact_id": artifact.id,
                    "detail": {
                        "artifact": artifact.name,
                        "kind": artifact.kind,
                        "matches": offsets,
                        "source": rule.source if rule else None,
                    },
                }
            )
    return hits


async def _enrich(ctx, iocs: dict[str, list[str]], final_domain: str | None) -> dict[str, dict]:
    """Optional VirusTotal enrichment (ANA-10); only when enabled for the analysis."""
    key = ctx.settings.vt_api_key
    if key is None:
        return {}
    targets = ([("domain", final_domain)] if final_domain else []) + [
        ("hash", h) for h in iocs["hashes"] if len(h) == 64
    ][:4]
    out = {}
    for ioc_type, value in targets:
        path = "domains" if ioc_type == "domain" else "files"
        try:
            response = await ctx.http.get(
                f"https://www.virustotal.com/api/v3/{path}/{value}",
                headers={"x-apikey": key.get_secret_value()},
                timeout=15,
            )
        except Exception as exc:  # noqa: BLE001
            out[value] = {"virustotal": {"error": str(exc)[:200]}}
            continue
        gui = "domain" if ioc_type == "domain" else "file"
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            out[value] = {
                "virustotal": {
                    "last_analysis_stats": attrs.get("last_analysis_stats"),
                    "reputation": attrs.get("reputation"),
                    "link": f"https://www.virustotal.com/gui/{gui}/{value}",
                }
            }
        else:
            out[value] = {"virustotal": {"error": f"HTTP {response.status_code}"}}
    return out


async def analyse(ctx, analysis_id: str, *, reason: str) -> AnalysisVersion | None:
    store = ctx.store
    async with ctx.sessionmaker() as db:
        analysis = await db.get(Analysis, analysis_id)
        if analysis is None:
            return None
        config = await get_all(db)
        # Detection strings edited in Admin since the last analysis take effect here.
        strings_version = await detection.refresh(db)
        artifacts = list(
            await db.scalars(
                select(Artifact).where(
                    Artifact.analysis_id == analysis_id, Artifact.deleted_at.is_(None)
                )
            )
        )
        by_kind: dict[str, list[Artifact]] = {}
        for a in artifacts:
            by_kind.setdefault(a.kind, []).append(a)
        result_art = (by_kind.get("capture_result") or [None])[0]
        if result_art is None or not store.exists(result_art.object_key):
            analysis.status, analysis.error = "failed", "No stored capture to analyse"
            analysis.finished_at = datetime.now(UTC)
            await db.commit()
            return None
        result = json.loads(store.read_bytes(result_art.object_key))

        events = [
            {"ts": e.ts.isoformat(), "kind": e.kind, "source": e.source, "payload": e.payload}
            for e in await db.scalars(
                select(Event).where(Event.analysis_id == analysis_id).order_by(Event.ts)
            )
        ]
        har_entries: list[dict] = []
        for a in by_kind.get("har", []):
            try:
                har_entries = (
                    json.loads(store.read_bytes(a.object_key)).get("log", {}).get("entries", [])
                )
            except ValueError:
                pass
        scripts = {
            a.sha256: store.read_bytes(a.object_key).decode("utf-8", "replace")
            for a in by_kind.get("script", [])
            if a.size <= _MAX_YARA_BYTES and store.exists(a.object_key)
        }
        heads = {}
        download_paths = {}
        for a in by_kind.get("download", []):
            if store.exists(a.object_key):
                with store.open(a.object_key) as fh:
                    # Enough to reach the ISO 9660 "CD001" marker at 0x8001 for magic typing.
                    heads[a.sha256] = fh.read(32780)
                download_paths[a.sha256] = str(store.path(a.object_key))
        dom_html = [
            {
                "url": a.meta.get("url", ""),
                "html": store.read_bytes(a.object_key).decode("utf-8", "replace"),
            }
            for a in by_kind.get("dom", [])
            if store.exists(a.object_key)
        ]
        dom_pages = [parse_dom(p["html"], p["url"]) for p in dom_html]
        requests: list[dict] = []
        for a in by_kind.get("requests_log", []):
            if store.exists(a.object_key):
                for line in store.read_bytes(a.object_key).decode("utf-8", "replace").splitlines():
                    try:
                        requests.append(json.loads(line))
                    except ValueError:
                        pass

        data = CaptureData(
            result=result,
            events=events,
            har_entries=har_entries,
            scripts=scripts,
            download_heads=heads,
            download_paths=download_paths,
            dom_pages=dom_pages,
            dom_html=dom_html,
            requests=requests,
            brands=await load_brands(db),
        )
        hosts = contacted_hosts(data)
        regs = sorted({registrable(h) for h in hosts})
        data.allowlisted = await load_allowlisted(db, regs)
        if ctx.settings.rdap_base_url:
            # The submitted, redirect and final domains first: they decide the verdict.
            chain = {registrable(h) for h in chain_hosts(data)}
            ordered = sorted(regs, key=lambda d: (d not in chain, d))
            for domain in [d for d in ordered if d not in data.allowlisted and "." in d][:8]:
                data.domain_ages[domain] = await registration_age_days(
                    ctx.http, ctx.settings.rdap_base_url, domain
                )

        bundle_row = await active_bundle(db)
        bundle = LoadedBundle(bundle_row, store)
        notes = []
        if bundle_row is None:
            notes.append("No active rule bundle; only feed matches were evaluated")
        rules_by_id = {r.id: r for r in await db.scalars(select(Rule).where(Rule.engine == "yara"))}
        yara_hits = (
            _yara_scan(
                bundle.yara,
                [a for k in _YARA_TARGET_KINDS for a in by_kind.get(k, [])],
                store,
                rules_by_id,
            )
            if bundle.yara is not None
            else []
        )

        match_values = match_candidates(
            result, har_entries, hosts, submitted=[analysis.url, analysis.normalised_url]
        )
        indicator_hits = await match_indicators(db, match_values)

        suricata_alerts: list[dict] = []
        pcap = (by_kind.get("pcap") or [None])[0]
        if ctx.settings.suricata_image and bundle.suricata_path and (pcap or har_entries):
            from sandbox.analysis.har_pcap import write_https_pcap
            from sandbox.analysis.suricata import parse_alerts, run_suricata

            # Suricata is optional: a Docker error (missing image, daemon down) is a note
            # on the report, not a failed analysis.
            try:
                with tempfile.TemporaryDirectory(prefix="sbx-https-") as tmp:
                    pcaps = [store.path(pcap.object_key)] if pcap else []
                    # The session pcap has HTTPS only as ciphertext; the HAR has it in
                    # plaintext, so HTTP rules can match HTTPS requests too.
                    decrypted = Path(tmp) / "https.pcap"
                    if ctx.settings.suricata_decrypted_https and write_https_pcap(
                        har_entries, decrypted
                    ):
                        pcaps.append(decrypted)
                    ok, output = (
                        await run_suricata(
                            ctx, ctx.settings.suricata_image, bundle.suricata_path, pcaps
                        )
                        if pcaps
                        else (True, "")
                    )
            except Exception as exc:
                log.warning(
                    "suricata could not run", extra={"analysis_id": analysis.id}, exc_info=True
                )
                ok, output = False, f"could not run: {exc}"
            if ok:
                suricata_alerts = parse_alerts(output)
            else:
                notes.append(f"Suricata failed: {output[-300:]}")
        elif not ctx.settings.suricata_image:
            notes.append("Suricata not configured (SANDBOX_SURICATA_IMAGE)")

        ev = evaluate(
            data,
            behaviour=bundle.behaviour,
            yara_hits=yara_hits,
            indicator_hits=indicator_hits,
            suricata_alerts=suricata_alerts,
            weights=await load_weights(db),
            thresholds=config["verdict_thresholds"],
        )
        if ev.facts["capture"]["load_failed"]:
            notes.append(f"The page did not finish loading (ended on {ev.facts['final']['url']})")
        ev.notes = notes
        enrichment = (
            await _enrich(ctx, ev.iocs, ev.facts["final"]["domain"]) if analysis.enrich else {}
        )

        version = analysis.version + 1
        techniques = (
            {
                t.id: t.name
                for t in await db.scalars(
                    select(AttackTechnique).where(AttackTechnique.id.in_(ev.attack_ids))
                )
            }
            if ev.attack_ids
            else {}
        )
        for hit in ev.rule_hits:
            db.add(RuleHit(analysis_id=analysis_id, version=version, **hit))
        for hit in ev.indicator_hits:
            db.add(
                IndicatorHit(
                    id=hit["id"],
                    analysis_id=analysis_id,
                    version=version,
                    indicator_id=hit["indicator_id"],
                    type=hit["type"],
                    matched_value=hit["matched_value"],
                    sources=hit["sources"],
                )
            )
        for tag, evidence in ev.tags.items():
            db.add(
                AnalysisTag(
                    analysis_id=analysis_id,
                    version=version,
                    tag=tag,
                    origin="rule",
                    evidence=evidence[:50],
                )
            )
        type_map = {
            "domains": "domain",
            "ips": "ip",
            "urls": "url",
            "hashes": "hash",
            "emails": "email",
            "eth_addresses": "eth_address",
        }
        for group, values in ev.iocs.items():
            for value in values:
                info = dict(enrichment.get(value, {}))
                if group == "domains" and site(value) in data.allowlisted:
                    info["allowlisted"] = True
                db.add(
                    Ioc(
                        analysis_id=analysis_id,
                        version=version,
                        type=type_map[group],
                        value=value,
                        enrichment=info,
                    )
                )
        summary = {
            "reason": reason,
            "facts": ev.facts,
            "contributions": [c.__dict__ for c in ev.result.contributions],
            "weights_used": ev.result.weights_used,
            "thresholds": config["verdict_thresholds"],
            "attack": [{"id": t, "name": techniques.get(t)} for t in ev.attack_ids],
            "suricata_alerts": ev.suricata_alerts,
            "tls": result.get("tls", {}),
            "dns": result.get("hosts", {}),
            "domain_ages": data.domain_ages,
            "notes": ev.notes,
            "detection_strings": strings_version,
        }
        row = AnalysisVersion(
            id=new_id("av"),
            analysis_id=analysis_id,
            version=version,
            bundle_id=bundle.id,
            verdict=ev.result.verdict,
            score=ev.result.score,
            summary=json.loads(json.dumps(summary, default=str)),
        )
        db.add(row)
        await db.execute(
            update(Analysis)
            .where(Analysis.id == analysis_id)
            .values(
                version=version,
                verdict=ev.result.verdict,
                score=ev.result.score,
                bundle_id=bundle.id,
                status="finished",
                finished_at=analysis.finished_at or datetime.now(UTC),
                error=None,
            )
        )
        record_audit(
            db,
            actor="analysis",
            action="analysis.analysed",
            target=analysis_id,
            detail={
                "version": version,
                "verdict": ev.result.verdict,
                "score": ev.result.score,
                "bundle": bundle.id,
                "reason": reason,
            },
        )
        from sandbox.orchestrator.detonation import queue_webhook

        await queue_webhook(db, analysis_id)
        await db.commit()
        log.info(
            "analysis complete",
            extra={
                "analysis_id": analysis_id,
                "verdict": ev.result.verdict,
                "score": ev.result.score,
                "version": version,
            },
        )
        return row


async def analyse_job(ctx, payload: dict[str, Any]) -> None:
    await analyse(ctx, payload["analysis_id"], reason=payload.get("reason", "reanalysis"))


def scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="analysis-"))
