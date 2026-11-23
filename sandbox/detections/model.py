"""The detection model: signals and detections.

Every behaviour verdict Sandboxer gives comes from a ``Detection``. There is no other
way for page behaviour to add to a score.

* A **signal** is one named value the sandbox observed in a capture, such as
  ``clipboard.command_like`` (how many clipboard writes look like a shell command). Each
  signal has a title and a plain description of how it is computed. The code that
  computes it sits in the same area module, in that area's ``*_section`` function, and
  the detection strings it uses (Admin > Detection strings) are bound in that module.
  A signal never scores on its own.

* A **detection** combines signals into a condition and gives the result a score::

      detection(
          "idp_cdn_assets_foreign_page",
          title="Sign-in page loads IdP branding from the IdP's CDN",
          severity="high",
          score=45,
          when=cdn_assets_on_foreign_page.is_true(),
          ...
      )

  A condition is built from signal tests (``signal > 0``, ``signal.is_true()``,
  ``signal.present()``, ``signal.one_of([...])``) joined with ``all_of``, ``any_of`` and
  ``not_`` (or ``&``, ``|`` and ``~``). Because the condition is data, not code, the
  report can show every test with the value it saw, and Admin can show the rule as
  sentences.

Evaluation is cheap: the observed values are built once per capture (the report needs
them anyway), and a condition only reads values out of that tree.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
_MISSING = object()

# Every signal and detection, by name, in the order the area modules declare them.
SIGNALS: dict[str, Signal] = {}
DETECTIONS: dict[str, Detection] = {}


def get_value(facts: dict[str, Any], path: str) -> Any:
    """The value at a dotted path in the observed values, or ``_MISSING``."""
    node: Any = facts
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


def _plain(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return str(value)


# --- conditions ----------------------------------------------------------------------------


class Condition:
    """A test over the observed values. Build one from signals; never subclass it in a
    detection."""

    def __and__(self, other: Condition) -> Condition:
        return all_of(self, other)

    def __or__(self, other: Condition) -> Condition:
        return any_of(self, other)

    def __invert__(self) -> Condition:
        return not_(self)

    def tests(self) -> list[Test]:
        raise NotImplementedError

    def check(self, facts: dict[str, Any], seen: dict[str, Any], trace: list[dict]) -> bool:
        raise NotImplementedError

    def describe(self, negated: bool = False) -> list[str]:
        raise NotImplementedError


_OP_WORDS = {
    "eq": "is",
    "ne": "is not",
    "gt": "is more than",
    "gte": "is at least",
    "lt": "is less than",
    "lte": "is at most",
    "in": "is one of",
}
_OP_WORDS_NOT = {
    "eq": "is not",
    "ne": "is",
    "gt": "is not more than",
    "gte": "is less than",
    "lt": "is not less than",
    "lte": "is more than",
    "in": "is none of",
}


@dataclass(frozen=True, eq=False)
class Test(Condition):
    """One signal compared with one value."""

    path: str
    op: str
    value: Any = None

    @property
    def signal(self) -> Signal:
        try:
            return SIGNALS[self.path]
        except KeyError:
            raise KeyError(f"No signal {self.path!r} is declared") from None

    def tests(self) -> list[Test]:
        return [self]

    def wording(self, negated: bool = False) -> str:
        title = SIGNALS[self.path].title if self.path in SIGNALS else self.path
        if self.op == "exists":
            present = self.value is not False
            if negated:
                present = not present
            return f"{title}: found" if present else f"{title}: none"
        if self.op == "eq" and isinstance(self.value, bool):
            yes = self.value != negated
            return title if yes else f"not: {title}"
        words = (_OP_WORDS_NOT if negated else _OP_WORDS)[self.op]
        return f"{title} {words} {_plain(self.value)}"

    def passes(self, value: Any) -> bool:
        op, target = self.op, self.value
        if op == "exists":
            return (value is not _MISSING and value not in (None, [], {}, "")) == (
                target is not False
            )
        if value is _MISSING:
            return False
        try:
            if op == "eq":
                return value == target
            if op == "ne":
                return value != target
            if op == "gt":
                return value > target
            if op == "gte":
                return value >= target
            if op == "lt":
                return value < target
            if op == "lte":
                return value <= target
            if op == "in":
                return value in target
        except TypeError:
            return False
        return False

    def check(self, facts: dict[str, Any], seen: dict[str, Any], trace: list[dict]) -> bool:
        value = get_value(facts, self.path)
        if value is not _MISSING:
            seen[self.path] = value
        passed = self.passes(value)
        trace.append(
            {
                "signal": self.path,
                "test": self.wording(),
                "value": None if value is _MISSING else value,
                "passed": passed,
            }
        )
        return passed

    def describe(self, negated: bool = False) -> list[str]:
        return [self.wording(negated)]


@dataclass(frozen=True, eq=False)
class Group(Condition):
    kind: str  # "all" | "any" | "not"
    parts: tuple[Condition, ...]

    def tests(self) -> list[Test]:
        return [t for p in self.parts for t in p.tests()]

    def check(self, facts: dict[str, Any], seen: dict[str, Any], trace: list[dict]) -> bool:
        if self.kind == "all":
            return all(p.check(facts, seen, trace) for p in self.parts)
        if self.kind == "any":
            # Every branch is checked, so the trace shows every value the rule looked at.
            return any([p.check(facts, seen, trace) for p in self.parts])
        return not self.parts[0].check(facts, seen, trace)

    def describe(self, negated: bool = False) -> list[str]:
        if self.kind == "not":
            return self.parts[0].describe(not negated)
        joiner = "all" if (self.kind == "all") != negated else "any"
        lines = []
        for p in self.parts:
            sub = p.describe(negated)
            if len(sub) == 1:
                lines.append(sub[0])
            else:
                lines.append(sub[0])
                lines.extend("  " + s for s in sub[1:])
        head = "all of:" if joiner == "all" else "any of:"
        return [head, *("  " + line for line in lines)]


def all_of(*parts: Condition) -> Condition:
    """True when every part is true."""
    return Group("all", tuple(parts))


def any_of(*parts: Condition) -> Condition:
    """True when at least one part is true."""
    return Group("any", tuple(parts))


def not_(part: Condition) -> Condition:
    """True when the part is false."""
    return Group("not", (part,))


# --- signals -------------------------------------------------------------------------------


class _Tests:
    """The tests a signal offers. ``path`` names the signal."""

    path: str

    def __gt__(self, value: Any) -> Test:  # type: ignore[override]
        return Test(self.path, "gt", value)

    def __ge__(self, value: Any) -> Test:  # type: ignore[override]
        return Test(self.path, "gte", value)

    def __lt__(self, value: Any) -> Test:  # type: ignore[override]
        return Test(self.path, "lt", value)

    def __le__(self, value: Any) -> Test:  # type: ignore[override]
        return Test(self.path, "lte", value)

    def equals(self, value: Any) -> Test:
        return Test(self.path, "eq", value)

    def is_true(self) -> Test:
        return Test(self.path, "eq", True)

    def present(self) -> Test:
        """The value is set and not empty (a non-empty list, a name, a number)."""
        return Test(self.path, "exists", True)

    def one_of(self, values: Iterable[Any]) -> Test:
        return Test(self.path, "in", list(values))


@dataclass(frozen=True, eq=False)
class Signal(_Tests):
    """One observed value: ``path`` is ``<section>.<key>`` in the observed values."""

    path: str
    title: str
    description: str
    area: str

    def value(self, facts: dict[str, Any]) -> Any:
        v = get_value(facts, self.path)
        return None if v is _MISSING else v


@dataclass(frozen=True)
class sig(_Tests):  # noqa: N801 - reads as a function in a rule
    """A signal by path, for a detection that reads signals declared in another area:
    ``sig("clipboard.command_like") > 0``. The catalog checks every path on load."""

    path: str

    @property
    def signal(self) -> Signal:
        return SIGNALS[self.path]


def signal(path: str, title: str, description: str) -> Signal:
    """Declare a signal. Call it at module level in the area module that computes it."""
    import inspect

    module = inspect.stack()[1].frame.f_globals.get("__name__", "")
    if path in SIGNALS:
        raise ValueError(f"Signal {path} is declared twice")
    if not re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)*", path):
        raise ValueError(f"Bad signal path {path!r}")
    s = Signal(path, title, " ".join(description.split()), module.rsplit(".", 1)[-1])
    SIGNALS[path] = s
    return s


# --- detections ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    matched: bool
    facts: dict[str, Any] = field(default_factory=dict)  # every value read, by path
    checks: list[dict[str, Any]] = field(default_factory=list)  # every test, in order


@dataclass(frozen=True, eq=False)
class Detection:
    name: str
    title: str
    severity: str
    score: int
    tags: tuple[str, ...]
    attack: tuple[str, ...]
    description: str
    when: Condition
    evidence: tuple[str, ...]  # signal paths
    area: str

    def signals(self) -> list[Signal]:
        """Every signal the condition reads, then the evidence signals, without repeats."""
        paths = [t.path for t in self.when.tests()] + list(self.evidence)
        return [SIGNALS[p] for p in dict.fromkeys(paths)]

    def evaluate(self, facts: dict[str, Any]) -> Outcome:
        seen: dict[str, Any] = {}
        trace: list[dict[str, Any]] = []
        matched = self.when.check(facts, seen, trace)
        if matched:
            for path in self.evidence:
                value = get_value(facts, path)
                if value is not _MISSING:
                    seen[path] = value
        return Outcome(matched, seen, trace)

    def rule_text(self) -> str:
        """The condition as indented plain-English lines (Admin and the rules table)."""
        lines = self.when.describe()
        return "Fires when " + ("\n".join(lines) if len(lines) > 1 else lines[0])


def detection(
    name: str,
    *,
    title: str,
    severity: str,
    score: int,
    tags: Iterable[str],
    attack: Iterable[str],
    description: str,
    when: Condition,
    evidence: Iterable[Signal | sig | str] = (),
    register: bool = True,
) -> Detection:
    """Declare a detection. Call it at module level in the area module it belongs to.
    ``register=False`` builds one without adding it to the catalog (tests)."""
    import inspect

    module = inspect.stack()[1].frame.f_globals.get("__name__", "")
    if register and name in DETECTIONS:
        raise ValueError(f"Detection {name} is declared twice")
    if severity not in SEVERITIES:
        raise ValueError(f"{name}: unknown severity {severity!r}")
    if not 0 <= score <= 100:
        raise ValueError(f"{name}: score must be 0 to 100")
    d = Detection(
        name=name,
        title=title,
        severity=severity,
        score=score,
        tags=tuple(tags),
        attack=tuple(attack),
        description=" ".join(description.split()),
        when=when,
        evidence=tuple(e if isinstance(e, str) else e.path for e in evidence),
        area=module.rsplit(".", 1)[-1],
    )
    if register:
        DETECTIONS[name] = d
    return d
