"""Detection strings: the keyword patterns, host lists, file types and points that the
fact builders (sandbox.analysis.facts, sandbox.analysis.domains) match captures against.

They ship as TOML files in ``sandbox/detection/defaults/`` (one file per area, every
entry documented) and a detection engineer changes them in Admin > Detection strings.
An edit is stored in the ``detection_overrides`` table, validated before it is saved,
audited, and picked up by the next analysis or re-analysis; reverting deletes the row
and the shipped value is used again.

How it plugs into the code: a module binds a global name to an entry key with
``bind(globals(), "_RUN_DIALOG", "clickfix.run_dialog")``. The global holds the compiled
value (a ``re.Pattern``, a set, a dict, ...) and is replaced whenever the active values
change, so the code that reads it is the same plain Python it always was. Facts are
computed synchronously on the event loop, so a swap never lands mid-analysis.

Entry types (the ``type`` field):

- ``regex``: ``pattern`` and ``flags`` (any of ``i`` ignore case, ``s`` dot matches
  newline, ``m`` multi-line, ``x`` verbose). Python ``re`` syntax.
- ``regex_list``: ``items``, each a regex as above, optionally with ``name``,
  ``points`` and ``note``.
- ``words``: ``values``, a list of strings (hosts, extensions, cookie names, ...).
- ``numbers``: ``values``, a list of whole numbers.
- ``table``: ``values``, a mapping of name to value, every value of ``value_type``
  (``str``, ``int``, ``str_list``, ``int_list`` or ``regex``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULTS_DIR = Path(__file__).with_name("defaults")
TYPES = ("regex", "regex_list", "words", "numbers", "table")
VALUE_TYPES = ("str", "int", "str_list", "int_list", "regex")
FLAG_BITS = {"i": re.I, "s": re.S, "m": re.M, "x": re.X}
# Limits that keep one edit from turning into a denial of service on every analysis.
MAX_PATTERN = 20_000
MAX_ITEMS = 5_000
MAX_STRING = 500


class DetectionValueError(ValueError):
    """An entry value that does not validate; the message says what to fix."""


@dataclass(frozen=True)
class RegexItem:
    regex: re.Pattern[str]
    name: str = ""
    points: int = 0
    note: str = ""


@dataclass
class Entry:
    key: str
    group: str
    type: str
    title: str
    description: str
    default: dict[str, Any]
    value_type: str | None = None
    # Set when an override is active.
    override: dict[str, Any] | None = None
    updated_by: str | None = None
    updated_at: datetime | None = None
    note: str = ""
    error: str | None = None
    compiled: Any = None

    @property
    def value(self) -> dict[str, Any]:
        return self.override if self.override is not None and not self.error else self.default


@dataclass
class _Binding:
    namespace: dict[str, Any]
    name: str
    key: str
    convert: Callable[[Any], Any] | None


@dataclass
class _State:
    entries: dict[str, Entry] = field(default_factory=dict)
    bindings: list[_Binding] = field(default_factory=list)
    signature: Any = None
    version: str = ""


_state = _State()


# --- validation and compilation ---------------------------------------------------------


def _flags(raw: Any, where: str) -> int:
    if raw is None:
        return 0
    if not isinstance(raw, str) or any(c not in FLAG_BITS for c in raw.lower()):
        raise DetectionValueError(f"{where}: flags must be letters from i, s, m, x")
    bits = 0
    for c in raw.lower():
        bits |= FLAG_BITS[c]
    return bits


def _regex(raw: Any, where: str) -> re.Pattern[str]:
    if not isinstance(raw, dict):
        raise DetectionValueError(f"{where}: expected a pattern and flags")
    pattern = raw.get("pattern")
    if isinstance(pattern, list) and all(isinstance(p, str) for p in pattern):
        pattern = "".join(pattern)
    if not isinstance(pattern, str) or not pattern:
        raise DetectionValueError(f"{where}: the pattern is empty")
    if len(pattern) > MAX_PATTERN:
        raise DetectionValueError(f"{where}: the pattern is longer than {MAX_PATTERN} characters")
    try:
        return re.compile(pattern, _flags(raw.get("flags"), where))
    except re.error as exc:
        raise DetectionValueError(f"{where}: not a valid regular expression ({exc})") from None


def _string(raw: Any, where: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise DetectionValueError(f"{where}: expected non-empty text")
    if len(raw) > MAX_STRING:
        raise DetectionValueError(f"{where}: longer than {MAX_STRING} characters")
    return raw


def _int(raw: Any, where: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        if isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
            return int(raw.strip())
        raise DetectionValueError(f"{where}: expected a whole number")
    return raw


def _list(raw: Any, where: str) -> list[Any]:
    if not isinstance(raw, list):
        raise DetectionValueError(f"{where}: expected a list")
    if len(raw) > MAX_ITEMS:
        raise DetectionValueError(f"{where}: more than {MAX_ITEMS} entries")
    return raw


def compile_value(type_: str, value: dict[str, Any], value_type: str | None = None) -> Any:
    """The Python value for one entry, or DetectionValueError saying what is wrong."""
    if not isinstance(value, dict):
        raise DetectionValueError("expected an object")
    if type_ == "regex":
        return _regex(value, "pattern")
    if type_ == "regex_list":
        items = _list(value.get("items"), "items")
        if not items:
            raise DetectionValueError("items: add at least one pattern")
        out = []
        for i, item in enumerate(items, 1):
            if not isinstance(item, dict):
                raise DetectionValueError(f"item {i}: expected a pattern and flags")
            out.append(
                RegexItem(
                    regex=_regex(item, f"item {i}"),
                    name=str(item.get("name") or ""),
                    points=_int(item.get("points", 0), f"item {i} points"),
                    note=str(item.get("note") or ""),
                )
            )
        return out
    if type_ == "words":
        values = _list(value.get("values"), "values")
        return tuple(_string(v, f"value {i}") for i, v in enumerate(values, 1))
    if type_ == "numbers":
        values = _list(value.get("values"), "values")
        return tuple(_int(v, f"value {i}") for i, v in enumerate(values, 1))
    if type_ == "table":
        values = value.get("values")
        if not isinstance(values, dict):
            raise DetectionValueError("values: expected a mapping of name to value")
        if len(values) > MAX_ITEMS:
            raise DetectionValueError(f"values: more than {MAX_ITEMS} entries")
        out_table: dict[str, Any] = {}
        for k, v in values.items():
            name = _string(k, "name")
            where = f"'{name}'"
            if value_type == "str":
                out_table[name] = _string(v, where)
            elif value_type == "int":
                out_table[name] = _int(v, where)
            elif value_type == "str_list":
                out_table[name] = tuple(_string(x, where) for x in _list(v, where))
            elif value_type == "int_list":
                out_table[name] = tuple(_int(x, where) for x in _list(v, where))
            elif value_type == "regex":
                out_table[name] = _regex(v, where)
            else:
                raise DetectionValueError(f"unknown value_type {value_type!r}")
        return out_table
    raise DetectionValueError(f"unknown type {type_!r}")


def _value_part(type_: str, raw: dict[str, Any]) -> dict[str, Any]:
    """The editable part of an entry, in the shape stored as an override."""
    if type_ == "regex":
        pattern = raw.get("pattern")
        if isinstance(pattern, list):
            pattern = "".join(pattern)
        return {"pattern": pattern, "flags": raw.get("flags", "")}
    if type_ == "regex_list":
        items = []
        for item in raw.get("items", []):
            item = dict(item)
            if isinstance(item.get("pattern"), list):
                item["pattern"] = "".join(item["pattern"])
            item.setdefault("flags", "")
            items.append(item)
        return {"items": items}
    return {"values": raw.get("values")}


# --- loading ----------------------------------------------------------------------------


def load_defaults(directory: Path = DEFAULTS_DIR) -> dict[str, Entry]:
    """Every shipped entry, keyed ``<file stem>.<table name>``. Raises on a broken file:
    the shipped defaults are code-reviewed and tested, so a bad one is a build error."""
    entries: dict[str, Entry] = {}
    for path in sorted(directory.glob("*.toml")):
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        group_title = doc.pop("title", path.stem)
        for name, raw in doc.items():
            if not isinstance(raw, dict):
                raise ValueError(f"{path.name}: {name} is not a table")
            key = f"{path.stem}.{name}"
            type_ = raw.get("type")
            if type_ not in TYPES:
                raise ValueError(f"{path.name}: {name} has unknown type {type_!r}")
            entry = Entry(
                key=key,
                group=group_title,
                type=type_,
                title=raw.get("title") or name.replace("_", " "),
                description=" ".join(str(raw.get("description", "")).split()),
                default=_value_part(type_, raw),
                value_type=raw.get("value_type"),
            )
            try:
                entry.compiled = compile_value(type_, entry.default, entry.value_type)
            except DetectionValueError as exc:
                raise ValueError(f"{path.name}: {name}: {exc}") from None
            entries[key] = entry
    return entries


def _version(entries: dict[str, Entry]) -> str:
    blob = json.dumps({k: e.value for k, e in sorted(entries.items())}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def _publish() -> None:
    for b in _state.bindings:
        value = _state.entries[b.key].compiled
        b.namespace[b.name] = b.convert(value) if b.convert else value
    _state.version = _version(_state.entries)


def bind(
    namespace: dict[str, Any], name: str, key: str, convert: Callable[[Any], Any] | None = None
) -> Any:
    """Bind ``namespace[name]`` to entry ``key`` (optionally through ``convert``) and
    return its current value. The binding follows every later change."""
    if key not in _state.entries:
        raise KeyError(f"No detection string {key!r} in {DEFAULTS_DIR}")
    _state.bindings.append(_Binding(namespace, name, key, convert))
    value = _state.entries[key].compiled
    return convert(value) if convert else value


def get(key: str) -> Any:
    """The compiled value of one entry."""
    return _state.entries[key].compiled


def entries() -> dict[str, Entry]:
    return _state.entries


def version() -> str:
    """A short hash of every active value, stored with each analysis version."""
    return _state.version


def apply_overrides(rows: list[dict[str, Any]]) -> list[str]:
    """Make ``rows`` ({key, value, updated_by, updated_at, note}) the active overrides,
    replacing any earlier set. A row that no longer validates (or names an entry that
    is gone) is skipped and the shipped value stays in force; the messages are returned
    and shown in Admin."""
    problems = []
    by_key = {r["key"]: r for r in rows}
    for key in by_key.keys() - _state.entries.keys():
        problems.append(f"{key}: no such detection string any more; the override is ignored")
    for key, entry in _state.entries.items():
        row = by_key.get(key)
        entry.override, entry.updated_by, entry.updated_at, entry.note = None, None, None, ""
        entry.error = None
        if row is None:
            entry.compiled = compile_value(entry.type, entry.default, entry.value_type)
            continue
        entry.override = row["value"]
        entry.updated_by, entry.updated_at = row.get("updated_by"), row.get("updated_at")
        entry.note = row.get("note") or ""
        try:
            entry.compiled = compile_value(entry.type, row["value"], entry.value_type)
            # The bound code may expect a shape a converter checks (for example a
            # table of ports); a converter error rejects the override, not the module.
            for b in _state.bindings:
                if b.key == key and b.convert:
                    b.convert(entry.compiled)
        except (DetectionValueError, ValueError, TypeError) as exc:
            entry.error = str(exc)
            entry.compiled = compile_value(entry.type, entry.default, entry.value_type)
            problems.append(f"{key}: {exc}; the shipped value is used")
    _publish()
    for p in problems:
        log.warning("detection string override skipped: %s", p)
    return problems


def check_value(key: str, value: dict[str, Any]) -> Any:
    """Validate a candidate value for ``key`` (as Admin sends it) and return it compiled."""
    entry = _state.entries.get(key)
    if entry is None:
        raise KeyError(key)
    compiled = compile_value(entry.type, value, entry.value_type)
    for b in _state.bindings:
        if b.key == key and b.convert:
            try:
                b.convert(compiled)
            except (ValueError, TypeError) as exc:
                raise DetectionValueError(str(exc)) from None
    return compiled


def normalise_value(key: str, value: dict[str, Any]) -> dict[str, Any]:
    """The stored form of an edited value: only the fields the entry type uses."""
    return _value_part(_state.entries[key].type, value)


async def refresh(db, *, force: bool = False) -> str:
    """Load the overrides from the database when they changed since the last call.
    Cheap enough to run before every analysis: one aggregate query when nothing moved."""
    from sqlalchemy import func, select

    from sandbox.db.models import DetectionOverride

    signature = (
        await db.execute(
            select(func.count(), func.max(DetectionOverride.updated_at)).select_from(
                DetectionOverride
            )
        )
    ).one()
    signature = tuple(signature)
    if not force and signature == _state.signature:
        return _state.version
    rows = [
        {
            "key": o.key,
            "value": o.value,
            "updated_by": o.updated_by,
            "updated_at": o.updated_at,
            "note": o.note,
        }
        for o in await db.scalars(select(DetectionOverride))
    ]
    apply_overrides(rows)
    _state.signature = signature
    return _state.version


def reset() -> None:
    """Drop every override (tests, and the offline CLI)."""
    apply_overrides([])
    _state.signature = None


_state.entries = load_defaults()
_state.version = _version(_state.entries)


# --- converters for bind() ----------------------------------------------------------------


def as_set(values: tuple[Any, ...]) -> set[Any]:
    return set(values)


def patterns(items: list[RegexItem]) -> list[re.Pattern[str]]:
    return [i.regex for i in items]


def named_patterns(items: list[RegexItem]) -> list[tuple[str, re.Pattern[str]]]:
    if any(not i.name for i in items):
        raise DetectionValueError("every item needs a name")
    return [(i.name, i.regex) for i in items]


def scored_patterns(items: list[RegexItem]) -> list[tuple[str, re.Pattern[str], int]]:
    return [(n, rx, i.points) for (n, rx), i in zip(named_patterns(items), items, strict=True)]


def table_of_sets(table: dict[str, tuple[Any, ...]]) -> dict[str, set[Any]]:
    return {k: set(v) for k, v in table.items()}


def int_keys(table: dict[str, Any]) -> dict[int, Any]:
    try:
        return {int(k): v for k, v in table.items()}
    except ValueError:
        raise DetectionValueError("every name must be a whole number (a port)") from None
