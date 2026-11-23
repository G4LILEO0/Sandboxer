"""Rule-hit evidence (REP-4, ANA-11): what exactly a fired detection matched on.

A behaviour hit stores the rows its rule returned and how each step of the query narrowed
them down. This adds, at request time and from the stored capture, the concrete content
behind the tables the rule reads: the strings the page ran through eval, the clipboard
text, the DOM snapshots and scripts, the YARA match strings. Hits recorded before rules
were queries stored the values their detection read under dotted names
("clipboard.commands"); those are resolved by name, so old analyses keep their evidence.

``resolve`` is pure: the API passes in the hit, the detection, the version's facts, the
artifact list, the parsed capture result and a reader for artifact bytes. Content is
never interpreted, only returned as text (the report shows it with ``textContent``), and
quarantined files are never read.
"""

import json
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

SAMPLE_CAP = 64 * 1024
_MAX_SAMPLES = 30
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b")
_DOM_FACTS = ("forms.", "lure.", "brand.", "idp.", "frames.", "final.title")


@dataclass
class Context:
    hit: dict[str, Any]
    facts: dict[str, Any]  # what the hit recorded: {"dotted.path": value}
    all_facts: dict[str, Any]  # the version's full fact tree
    artifacts: list[dict[str, Any]]
    capture: dict[str, Any]
    read: Callable[[dict[str, Any]], bytes | None]
    samples: list[dict[str, Any]] = field(default_factory=list)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add_file(self, artifact: dict[str, Any], why: str) -> None:
        if artifact["id"] in self.files:
            return
        self.files[artifact["id"]] = {
            "id": artifact["id"],
            "kind": artifact["kind"],
            "name": artifact["name"],
            "size": artifact["size"],
            "sha256": artifact["sha256"],
            "quarantined": artifact["quarantined"],
            "deleted": artifact.get("deleted", False),
            "why": why,
        }

    def add_sample(self, label: str, source: str, content: str, **extra: Any) -> None:
        if len(self.samples) >= _MAX_SAMPLES:
            return
        self.samples.append(
            {
                "label": label,
                "source": source,
                "length": len(content),
                "content": content[:SAMPLE_CAP],
                "truncated": len(content) > SAMPLE_CAP,
                **extra,
            }
        )

    def text_of(self, artifact: dict[str, Any]) -> str | None:
        if artifact["quarantined"] or artifact.get("deleted"):
            return None
        data = self.read(artifact)
        return None if data is None else data.decode("utf-8", "replace")


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(text).values()), 2)


# --- resolvers, keyed by fact-path prefix ----------------------------------------------


def _dynamic_code(ctx: Context) -> None:
    execs = ((ctx.capture.get("jsapi") or {}).get("exec")) or {}
    scripts = [
        a for a in ctx.artifacts if a["kind"] == "script" and a["name"].startswith("dynamic-")
    ]
    full: list[str] = []
    for a in scripts:
        ctx.add_file(a, "code the page compiled at runtime (eval/Function/timer string)")
        if (text := ctx.text_of(a)) is not None:
            full.append(text)
            ctx.add_sample(a["name"], "dynamic script", text, entropy=entropy(text))
    for i, code in enumerate(execs.get("code_samples") or [], 1):
        if any(f.startswith(code) for f in full):
            continue  # already shown in full above
        ctx.add_sample(f"eval'd string #{i}", "capture jsapi", code, entropy=entropy(code))


def _blobs(ctx: Context) -> None:
    blobs = (ctx.capture.get("jsapi") or {}).get("blobs") or ctx.facts.get("js.blob_details")
    for i, b in enumerate(blobs or [], 1):
        ctx.add_sample(f"Blob #{i}", "capture jsapi", json.dumps(b, indent=2, default=str))


def _clipboard(ctx: Context) -> None:
    for i, c in enumerate(ctx.capture.get("clipboard") or [], 1):
        if not c.get("text"):
            continue
        how = c.get("api") or ("analyst copy" if c.get("trusted") else "page event")
        ctx.add_sample(f"Clipboard write #{i} ({how})", "capture clipboard", c["text"])


def _downloads(ctx: Context) -> None:
    for a in ctx.artifacts:
        if a["kind"] == "download":
            ctx.add_file(a, "file the page delivered")


def _forms(ctx: Context) -> None:
    forms = [
        {"page": f.get("url"), **form}
        for p in ctx.capture.get("pages") or []
        for f in p.get("frames") or []
        for form in f.get("forms") or []
    ]
    for i, form in enumerate(forms[:10], 1):
        ctx.add_sample(f"Form #{i}", "capture pages", json.dumps(form, indent=2, default=str))


def _dom(ctx: Context) -> None:
    for a in ctx.artifacts:
        if a["kind"] == "dom":
            ctx.add_file(a, "page snapshot the content facts came from")


def _scripts(ctx: Context) -> None:
    hashes = set(_SHA256.findall(json.dumps(list(ctx.facts.values()), default=str)))
    for a in ctx.artifacts:
        if a["kind"] == "script" and a["sha256"] in hashes:
            ctx.add_file(a, "script named in the facts")


# Old hits: by the dotted name of a value they recorded.
RESOLVERS: list[tuple[tuple[str, ...], Callable[[Context], None]]] = [
    (("js.code_exec_", "js.dynamic_exec_", "web3.rpc_result_linked_exec"), _dynamic_code),
    (("js.blob_",), _blobs),
    (("clipboard.",), _clipboard),
    (("downloads.",), _downloads),
    (("forms.",), _forms),
    (_DOM_FACTS, _dom),
    (("scripts.",), _scripts),
]


# Query hits: by the tables the rule (or a shared query it uses) reads.
TABLE_RESOLVERS: dict[str, Callable[[Context], None]] = {
    "code_exec": _dynamic_code,
    "rpc_strings": _dynamic_code,
    "blobs": _blobs,
    "clipboard": _clipboard,
    "downloads": _downloads,
    "archive_entries": _downloads,
    "forms": _forms,
    "frames": _dom,
    "pages": _dom,
    "lure_texts": _dom,
    "brand_claims": _dom,
    "scripts": _scripts,
    "inline_code": _scripts,
}


def _yara(ctx: Context) -> None:
    detail = ctx.hit.get("detail") or {}
    target = next((a for a in ctx.artifacts if a["id"] == ctx.hit.get("artifact_id")), None)
    if target is not None:
        ctx.add_file(target, "file the YARA rule matched")
    for m in detail.get("matches") or []:
        ctx.add_sample(
            f"{m.get('string', '?')} at offset {m.get('offset', '?')}",
            "yara match",
            str(m.get("data", "")),
        )


def _link_mentioned(ctx: Context) -> None:
    """Any artifact whose sha256 or file name appears in the recorded facts."""
    blob = json.dumps(list(ctx.facts.values()), default=str)
    hashes = set(_SHA256.findall(blob))
    for a in ctx.artifacts:
        if a["sha256"] in hashes or (len(a["name"]) > 4 and a["name"] in blob):
            ctx.add_file(a, "named in the facts")


def resolve(
    hit: dict[str, Any],
    rule: dict[str, Any] | None,
    *,
    all_facts: dict[str, Any],
    artifacts: list[dict[str, Any]],
    capture: dict[str, Any],
    read: Callable[[dict[str, Any]], bytes | None],
) -> dict[str, Any]:
    detail = hit.get("detail") or {}
    ctx = Context(hit, detail.get("facts") or {}, all_facts, artifacts, capture, read)
    detection = (rule or {}).get("detection")
    if hit.get("engine") == "yara":
        _yara(ctx)
    elif detail.get("kind") == "query":
        if detection is not None:
            from sandbox.detections import catalog

            tables = {t["name"] for t in catalog.describe(detection)["tables"]}
            done: set[Callable[[Context], None]] = set()
            for name, resolver in TABLE_RESOLVERS.items():
                if name in tables and resolver not in done:
                    done.add(resolver)
                    resolver(ctx)
    else:
        for prefixes, resolver in RESOLVERS:
            if any(p.startswith(prefixes) for p in ctx.facts):
                resolver(ctx)
    _link_mentioned(ctx)
    return {
        "hit_id": hit.get("id"),
        "rule": hit.get("rule_name"),
        "rule_id": hit.get("rule_id"),
        "engine": hit.get("engine"),
        "description": (rule or {}).get("description") or detail.get("description", ""),
        "rule_found": rule is not None,
        "rule_source": (rule or {}).get("source_text"),
        "title": detail.get("title") or getattr(detection, "title", None),
        "rule_text": detection.rule_text() if detection is not None else None,
        **_query_parts(rule, detail),
        "facts": ctx.facts if ctx.facts else {k: v for k, v in detail.items() if k != "facts"},
        "samples": ctx.samples,
        "files": list(ctx.files.values()),
        "sample_cap": SAMPLE_CAP,
    }


def _query_parts(rule: dict[str, Any] | None, detail: dict[str, Any]) -> dict[str, Any]:
    """For a query rule: the rows it returned, how many rows each step kept, and the
    shared named queries it uses, so the report can show why it fired."""
    if detail.get("kind") != "query":
        return {"kind": "conditions"}
    facts = detail.get("facts") or {}
    out: dict[str, Any] = {
        "kind": "query",
        "rows": facts.get("rows", []),
        "row_count": facts.get("row_count", len(facts.get("rows", []))),
        "steps": detail.get("checks") or [],
        "shared": [],
    }
    detection = (rule or {}).get("detection")
    if detection is not None:
        from sandbox.detections import catalog

        out["shared"] = catalog.describe(detection)["shared"]
    return out
