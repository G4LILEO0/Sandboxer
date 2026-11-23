"""Load the detection rules: one ``.kql`` file per detection under ``sandbox/detections/rules``.

A rule file is a short header, a line with three dashes, then the query::

    title: Sign-in page loads IdP branding from the IdP's CDN
    severity: high
    score: 45
    tags: phishing, aitm
    attack: T1566.002, T1656
    description: A page that is not the identity provider loads IdP sign-in branding
      from the IdP's CDN (AADCDN, Okta CDN) and shows a credential prompt.
    ---
    requests
    | where host matches list("microsoft.idp_cdn")
    | ...

The file name is the detection's name and its folder is its area. The rule fires when the
query returns a row; the rows are its evidence. ``_shared.kql`` in any area folder holds
named queries (``let name = ...;``) that every rule can use.

Every file is parsed when Sandboxer starts. A rule that does not parse, or names an
unknown table, column source, function or detection string, stops the start with the
file and line, so a broken rule never ships silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sandbox.detections.kql.language import Env, Query, QueryError, parse, parse_shared
from sandbox.detections.kql.tables import environment

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
SEVERITIES = ("info", "low", "medium", "high", "critical")
EVIDENCE_ROWS = 10
_TEXT_CAP = 300
_HEADER_KEYS = {"title", "severity", "score", "tags", "attack", "description"}


@dataclass
class Outcome:
    """One rule run over one capture: whether it fired, its evidence (the rows it
    returned) and how each step narrowed the rows down."""

    matched: bool
    facts: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, eq=False)
class RuleDetection:
    """A detection: one rule file, parsed."""

    name: str
    title: str
    severity: str
    score: int
    tags: tuple[str, ...]
    attack: tuple[str, ...]
    description: str
    area: str
    query: Query
    source: str  # path relative to the repository
    env: Env = field(repr=False, default=None)  # type: ignore[assignment]

    def evaluate(self, capture: Any) -> Outcome:
        """Run the rule over a capture (``base.Capture``, or the observed values of one,
        which carry it)."""
        cap = getattr(capture, "capture", capture)
        if cap is None or not hasattr(cap, "data"):
            return Outcome(False, {}, [{"note": "needs the capture"}])
        rows, run = self.query.run(cap, self.env)
        evidence = {
            "rows": [_jsonable_row(r) for r in rows[:EVIDENCE_ROWS]],
            "row_count": len(rows),
        }
        return Outcome(bool(rows), evidence, run.steps or [])

    def rule_text(self) -> str:
        return self.query.text.strip()


def _jsonable(v: Any) -> Any:
    if isinstance(v, str):
        return v if len(v) <= _TEXT_CAP else v[:_TEXT_CAP] + "…"
    if isinstance(v, (set, frozenset, tuple)):
        v = sorted(v, key=str)
    if isinstance(v, list):
        return [_jsonable(x) for x in v[:20]]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in list(v.items())[:30]}
    if v is None or isinstance(v, (bool, int, float)):
        return v
    return str(v)


def _jsonable_row(row: dict[str, Any]) -> dict[str, Any]:
    return {k: _jsonable(v) for k, v in row.items()}


def parse_header(text: str, where: str) -> tuple[dict[str, str], str, int]:
    if "\n---" not in "\n" + text:
        raise QueryError(f"{where}: put a line with --- between the header and the query")
    head, _, body = ("\n" + text).partition("\n---")
    body = body.split("\n", 1)[1] if "\n" in body else ""
    header: dict[str, str] = {}
    key = None
    for n, line in enumerate(head.strip("\n").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        if line[0].isspace() and key:
            header[key] += " " + line.strip()
            continue
        m = re.match(r"([a-z_]+):\s*(.*)$", line)
        if not m or m.group(1) not in _HEADER_KEYS:
            raise QueryError(
                f"{where}, line {n}: expected one of {', '.join(sorted(_HEADER_KEYS))}"
            )
        key = m.group(1)
        header[key] = m.group(2).strip()
    missing = _HEADER_KEYS - {"tags", "attack"} - set(header)
    if missing:
        raise QueryError(f"{where}: missing {', '.join(sorted(missing))}")
    body_line = head.count("\n") + 1
    return header, body, body_line


def _split(v: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in v.split(",") if x.strip())


def load(directory: Path = RULES_DIR) -> list[RuleDetection]:
    env = environment()
    repo = directory.parents[2]
    # Shared named queries first, so every rule can use them.
    # A shared query can use one from another area, so a file whose names are not all
    # known yet is parsed again after the others, until none is left.
    pending = sorted(directory.glob("*/_shared.kql"))
    while pending:
        errors: dict[Path, QueryError] = {}
        for path in pending:
            try:
                lets, texts = parse_shared(path.read_text(encoding="utf-8"), env)
            except QueryError as e:
                errors[path] = e
                continue
            for name, pipe in lets.items():
                if name in env.shared:
                    raise QueryError(f"{path.relative_to(repo)}: {name} is defined twice")
                env.shared[name] = Query(lets, pipe, texts[name])
        if len(errors) == len(pending):
            path, e = next(iter(errors.items()))
            raise QueryError(f"{path.relative_to(repo)}: {e}") from None
        pending = list(errors)
    out = []
    for path in sorted(directory.glob("*/*.kql")):
        if path.name.startswith("_"):
            continue
        rel = str(path.relative_to(repo)).replace("\\", "/")
        text = path.read_text(encoding="utf-8")
        header, body, line = parse_header(text, rel)
        try:
            query = parse(body, env)
        except QueryError as e:
            raise QueryError(f"{rel} (query starts on line {line + 1}): {e}") from None
        severity = header["severity"]
        if severity not in SEVERITIES:
            raise QueryError(f"{rel}: unknown severity {severity!r}")
        try:
            score = int(header["score"])
        except ValueError:
            raise QueryError(f"{rel}: score must be a whole number") from None
        if not 0 <= score <= 100:
            raise QueryError(f"{rel}: score must be 0 to 100")
        out.append(
            RuleDetection(
                name=path.stem,
                title=header["title"],
                severity=severity,
                score=score,
                tags=_split(header.get("tags", "")),
                attack=_split(header.get("attack", "")),
                description=header["description"],
                area=path.parent.name,
                query=query,
                source=rel,
                env=env,
            )
        )
    return out


def shared_source(env: Env, name: str) -> str:
    """The text of a shared named query, with the comment above it."""
    q = env.shared.get(name)
    return q.text if q else ""
