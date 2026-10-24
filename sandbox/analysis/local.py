"""Evaluate a runner output directory without a database: for tests and offline checks.

python -m sandbox.analysis.local tests/fixtures/captures/phish_chain
"""

import json
import sys
from pathlib import Path

from sandbox.analysis.dom import parse_dom
from sandbox.analysis.domains import BrandRef
from sandbox.analysis.engine import Evaluation, evaluate
from sandbox.analysis.facts import CaptureData
from sandbox.rules import defaults
from sandbox.rules.behaviour import parse_rule
from sandbox.rules.importer import YARA_EXTERNALS, yara_metadata


def load_capture(out: Path, *, allowlisted: set[str] | None = None) -> CaptureData:
    result = json.loads((out / "result.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    har = out / "network.har"
    har_entries = (
        json.loads(har.read_text(encoding="utf-8"))["log"]["entries"] if har.exists() else []
    )
    scripts = {
        p.stem: p.read_text(encoding="utf-8", errors="replace") for p in out.glob("scripts/*.js")
    }
    heads = {p.name: p.read_bytes()[:32780] for p in out.glob("quarantine/*")}
    urls = {d["file"]: d.get("url", "") for d in result.get("dom_snapshots", [])}
    dom_html = [
        {
            "url": urls.get(f"dom/{p.name}", ""),
            "html": p.read_text(encoding="utf-8", errors="replace"),
        }
        for p in sorted(out.glob("dom/*.html"))
    ]
    dom_pages = [parse_dom(p["html"], p["url"]) for p in dom_html]
    brands = [BrandRef(n, tuple(k), tuple(d)) for n, k, d in defaults.DEFAULT_BRANDS]
    return CaptureData(
        result=result,
        events=events,
        har_entries=har_entries,
        scripts=scripts,
        download_heads=heads,
        dom_pages=dom_pages,
        dom_html=dom_html,
        brands=brands,
        allowlisted=allowlisted or set(),
    )


def builtin_behaviour() -> list[dict]:
    return [
        {**spec, "id": spec["name"], **parse_rule(spec["body"])}
        for spec in defaults.BEHAVIOUR_RULES
    ]


def builtin_yara_hits(out: Path) -> list[dict]:
    import yara

    compiled = yara.compile(sources=defaults.BUILTIN_YARA, externals=YARA_EXTERNALS)
    meta = {name: yara_metadata(body) for name, body in defaults.BUILTIN_YARA.items()}
    hits = []
    for path in [*out.glob("dom/*.html"), *out.glob("scripts/*.js"), *out.glob("quarantine/*")]:
        for m in compiled.match(data=path.read_bytes()):
            hits.append(
                {
                    "id": f"rh_{m.rule}_{path.name}",
                    "rule_id": None,
                    "rule_name": m.rule,
                    "engine": "yara",
                    "severity": meta[m.namespace]["severity"],
                    "tags": list(m.tags),
                    "attack_ids": meta[m.namespace]["attack_ids"],
                    "artifact_id": None,
                    "detail": {"artifact": path.relative_to(out).as_posix()},
                }
            )
    return hits


def evaluate_dir(out: Path, **kwargs) -> Evaluation:
    data = load_capture(out, **kwargs)
    return evaluate(
        data,
        behaviour=builtin_behaviour(),
        yara_hits=builtin_yara_hits(out),
        indicator_hits=[],
        suricata_alerts=[],
        weights={k: (v, None) for k, v in defaults.DEFAULT_WEIGHTS.items()},
        thresholds={"suspicious": 30, "malicious": 70},
    )


if __name__ == "__main__":
    ev = evaluate_dir(Path(sys.argv[1]))
    print(
        json.dumps(
            {
                "verdict": ev.result.verdict,
                "score": ev.result.score,
                "rules": sorted({h["rule_name"] for h in ev.rule_hits}),
                "tags": sorted(ev.tags),
                "iocs": {k: len(v) for k, v in ev.iocs.items()},
            },
            indent=1,
        )
    )
