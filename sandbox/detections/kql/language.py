"""The detection query language: a small subset of Kusto (KQL), the language of Microsoft
Sentinel and Defender Advanced Hunting.

A rule is a query over the capture's tables. It fires when the query returns at least one
row, and the rows it returns are the evidence. A query is parsed once, when the rules
load, into plain Python closures, so running it costs about the same as hand-written code.

Supported, with the same meaning as in Kusto:

* ``let name = <query>;`` (a named query, usable as a table or with ``in``/``exists``)
* sources: a table name, a table function ``urls_seen(list("x"))``, a ``let`` name,
  ``union a, (b | where ...)``
* operators: ``where``, ``extend``, ``project``, ``summarize ... by ...``, ``distinct``,
  ``count``, ``take``, ``mv-expand``
* aggregates: ``count()``, ``countif()``, ``dcount()``, ``dcountif()``, ``make_set()``,
  ``take_any()``, ``min()``, ``max()``, ``sum()``
* expressions: ``and``, ``or``, ``not(...)``, ``== != < <= > >= =~ !~``, ``in``,
  ``!in``, ``has``, ``!has``, ``contains``, ``!contains``, ``startswith``, ``endswith``,
  ``matches regex``, ``+ -``, ``x["key"]``, function calls, ``"strings"``,
  ``@"verbatim strings"``, numbers, ``true``/``false``

One addition: ``x matches list("key")`` tests a value against a detection string (Admin >
Detection strings), whatever its type: a pattern, a list of patterns or a word list.

Comparisons with a missing value are false, as in Kusto, and a value of the wrong type is
a miss, never an error.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Row = dict[str, Any]


class QueryError(ValueError):
    """A rule that does not parse or names something unknown. Raised when rules load."""


# --- tokens ----------------------------------------------------------------------------

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+|//[^\n]*)
  | (?P<vstr>@"(?:[^"]|"")*"|@'(?:[^']|'')*')
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*(?:-[a-z]+)?)
  | (?P<op>==|!=|<=|>=|=~|!~|\$left|\$right|[|(),;=<>\[\]+\-.*!])
    """,
    re.VERBOSE,
)

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}


def _unescape(m: re.Match[str]) -> str:
    return _ESCAPES.get(m.group(1), m.group(0))


@dataclass
class Tok:
    kind: str  # name | str | num | op | end
    value: Any
    pos: int


def tokenize(text: str) -> list[Tok]:
    out: list[Tok] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise QueryError(f"Unexpected character {text[pos]!r} at {_where(text, pos)}")
        kind = m.lastgroup or ""
        raw = m.group(0)
        if kind == "vstr":
            q = raw[1]
            out.append(Tok("str", raw[2:-1].replace(q + q, q), pos))
        elif kind == "str":
            body = raw[1:-1]
            out.append(
                Tok(
                    "str",
                    re.sub(r"\\(.)", lambda e: _ESCAPES.get(e.group(1), e.group(0)), body),
                    pos,
                )
            )
        elif kind == "num":
            out.append(Tok("num", float(raw) if "." in raw else int(raw), pos))
        elif kind in ("name", "op"):
            out.append(Tok(kind, raw, pos))
        pos = m.end()
    out.append(Tok("end", None, len(text)))
    return out


def _where(text: str, pos: int) -> str:
    line = text.count("\n", 0, pos) + 1
    col = pos - (text.rfind("\n", 0, pos) + 1) + 1
    return f"line {line}, column {col}"


# --- what a compiled query runs against -----------------------------------------------------


@dataclass
class Env:
    """Everything a query can name: the capture's tables, table functions, scalar
    functions and the shared named queries. ``tables`` and ``table_functions`` take the
    run context; scalar functions take their arguments and the run context."""

    tables: dict[str, Callable[[Any], list[Row]]] = field(default_factory=dict)
    table_functions: dict[str, Callable[..., list[Row]]] = field(default_factory=dict)
    functions: dict[str, Callable[..., Any]] = field(default_factory=dict)
    shared: dict[str, Query] = field(default_factory=dict)


class Run:
    """One run of one query over one capture: caches named results and records how many
    rows each step kept, so the report can show how the rule narrowed things down."""

    def __init__(self, ctx: Any, env: Env, record: bool = True):
        self.ctx = ctx
        self.env = env
        self.named: dict[str, list[Row]] = {}
        self.subqueries: dict[int, Any] = {}
        self.steps: list[dict[str, Any]] | None = [] if record else None

    def named_rows(self, name: str, lets: dict[str, Pipeline]) -> list[Row]:
        if name not in self.named:
            if name in lets:
                self.named[name] = lets[name].rows(self, lets, label=name)
            elif name in self.env.shared:
                self.named[name] = self._shared_rows(name)
            else:
                raise QueryError(f"Unknown table or name {name!r}")
        return self.named[name]

    def _shared_rows(self, name: str) -> list[Row]:
        """A shared named query gives the same rows for every rule on one capture, so it
        runs once per capture; each rule's trace still shows its steps."""
        cache = getattr(self.ctx, "__dict__", {}).setdefault("_kql_shared", {})
        hit = cache.get(name)
        if hit is None:
            q = self.env.shared[name]
            outer, self.steps = self.steps, []
            try:
                rows = q.body.rows(self, q.lets, label=name)
                hit = cache[name] = (rows, self.steps)
            finally:
                self.steps = outer
        rows, steps = hit
        if self.steps is not None:
            self.steps.extend(steps)
        return rows


# --- expressions -----------------------------------------------------------------------

Expr = Callable[[Row, Run], Any]
_MISS = object()


def _cmp(op: str) -> Callable[[Any, Any], bool]:
    def f(a: Any, b: Any) -> bool:
        if a is None or b is None:
            return op == "!=" and (a is None) != (b is None)
        try:
            if op == "==":
                return a == b
            if op == "!=":
                return a != b
            if op == "<":
                return a < b
            if op == "<=":
                return a <= b
            if op == ">":
                return a > b
            if op == ">=":
                return a >= b
        except TypeError:
            return False
        return False

    return f


def _text(v: Any) -> str | None:
    return v if isinstance(v, str) else None


def _has(a: Any, b: Any) -> bool:
    """Kusto ``has``: ``b`` occurs as a whole term in ``a`` (case-insensitive)."""
    a, b = _text(a), _text(b)
    if a is None or b is None:
        return False
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(b) + r"(?![A-Za-z0-9])", a, re.I) is not None


def _contains(a: Any, b: Any) -> bool:
    a, b = _text(a), _text(b)
    return a is not None and b is not None and b.lower() in a.lower()


def _starts(a: Any, b: Any) -> bool:
    a, b = _text(a), _text(b)
    return a is not None and b is not None and a.lower().startswith(b.lower())


def _ends(a: Any, b: Any) -> bool:
    a, b = _text(a), _text(b)
    return a is not None and b is not None and a.lower().endswith(b.lower())


def _eq_ci(a: Any, b: Any) -> bool:
    a, b = _text(a), _text(b)
    return a is not None and b is not None and a.lower() == b.lower()


@dataclass(frozen=True)
class ListRef:
    """``list("key")``: a detection string, read when the rule runs so Admin edits apply."""

    key: str


def regex_search(pattern: Any, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if isinstance(pattern, ListRef):
        return list_matches(value, pattern)
    if isinstance(pattern, str):
        pattern = _compiled(pattern)
    return isinstance(pattern, re.Pattern) and pattern.search(value) is not None


_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def _compiled(pattern: str) -> re.Pattern[str]:
    rx = _REGEX_CACHE.get(pattern)
    if rx is None:
        rx = _REGEX_CACHE[pattern] = re.compile(pattern)
    return rx


def list_value(ref: ListRef) -> Any:
    from sandbox.detections import strings

    return strings.get(ref.key)


def list_patterns(ref: ListRef) -> list[re.Pattern[str]]:
    value = list_value(ref)
    if isinstance(value, re.Pattern):
        return [value]
    if isinstance(value, list):
        return [item.regex for item in value]
    return []


def list_matches(value: Any, ref: ListRef) -> bool:
    """``value matches list("key")``: a pattern or a list of patterns searches the text; a
    word list holds the value (letter case ignored)."""
    if value is None:
        return False
    data = list_value(ref)
    if isinstance(data, re.Pattern):
        return isinstance(value, str) and data.search(value) is not None
    if isinstance(data, list):
        return isinstance(value, str) and any(i.regex.search(value) for i in data)
    if isinstance(data, tuple):
        return _in(value, data)
    if isinstance(data, dict):
        return _in(value, tuple(data))
    return False


def _in(value: Any, values: Any) -> bool:
    if value is None:
        return False
    if isinstance(values, ListRef):
        values = list_value(values)
        if isinstance(values, dict):
            values = tuple(values)
        elif not isinstance(values, tuple):
            return False
    if isinstance(value, str):
        low = value.lower()
        return any(isinstance(v, str) and v.lower() == low for v in values) or value in values
    try:
        return value in values
    except TypeError:
        return False


# --- pipelines ------------------------------------------------------------------------------


class Stage:
    text = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        raise NotImplementedError


@dataclass
class Pipeline:
    source: Callable[[Run, dict[str, Pipeline]], list[Row]]
    source_text: str
    stages: list[Stage]

    def rows(self, run: Run, lets: dict[str, Pipeline], label: str | None = None) -> list[Row]:
        rows = self.source(run, lets)
        steps = run.steps
        if steps is not None:
            steps.append({"query": label, "step": self.source_text, "rows": len(rows)})
        for st in self.stages:
            if not rows and not isinstance(st, Count):
                if steps is not None:
                    steps.append({"query": label, "step": st.text, "rows": 0})
                continue
            rows = st.apply(rows, run)
            if steps is not None:
                steps.append({"query": label, "step": st.text, "rows": len(rows)})
        return rows


@dataclass
class Where(Stage):
    pred: Expr
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        p = self.pred
        return [r for r in rows if p(r, run) is True]


@dataclass
class Extend(Stage):
    assigns: list[tuple[str, Expr]]
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        out = []
        for r in rows:
            n = dict(r)
            for name, e in self.assigns:
                n[name] = e(n, run)
            out.append(n)
        return out


@dataclass
class Project(Stage):
    items: list[tuple[str, Expr]]
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        return [{name: e(r, run) for name, e in self.items} for r in rows]


@dataclass
class Distinct(Stage):
    cols: list[str]
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        seen: dict[Any, Row] = {}
        for r in rows:
            key = tuple(_hashable(r.get(c)) for c in self.cols)
            seen.setdefault(key, {c: r.get(c) for c in self.cols})
        return list(seen.values())


@dataclass
class Count(Stage):
    text: str = "count"

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        return [{"Count": len(rows)}]


@dataclass
class Take(Stage):
    n: int
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        return rows[: self.n]


@dataclass
class MvExpand(Stage):
    name: str
    expr: Expr
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        out = []
        for r in rows:
            v = self.expr(r, run)
            items = (
                sorted(v, key=str)
                if isinstance(v, (set, frozenset))
                else v
                if isinstance(v, (list, tuple))
                else [v]
            )
            for item in items:
                n = dict(r)
                n[self.name] = item
                out.append(n)
        return out


def _hashable(v: Any) -> Any:
    if isinstance(v, (list, set, tuple)):
        return tuple(sorted((_hashable(x) for x in v), key=repr))
    if isinstance(v, dict):
        return tuple(sorted((k, _hashable(x)) for k, x in v.items()))
    return v


AGGREGATES: dict[str, int] = {  # name -> number of arguments
    "count": 0,
    "countif": 1,
    "dcount": 1,
    "dcountif": 2,
    "make_set": 1,
    "take_any": 1,
    "min": 1,
    "max": 1,
    "sum": 1,
}


@dataclass
class Summarize(Stage):
    aggs: list[tuple[str, str, list[Expr]]]  # (output name, aggregate, args)
    by: list[tuple[str, Expr]]
    text: str = ""

    def apply(self, rows: list[Row], run: Run) -> list[Row]:
        groups: dict[Any, list[Row]] = {}
        keys: dict[Any, Row] = {}
        for r in rows:
            vals = {name: e(r, run) for name, e in self.by}
            k = tuple(_hashable(v) for v in vals.values())
            groups.setdefault(k, []).append(r)
            keys.setdefault(k, vals)
        if not self.by and not groups:
            groups[()] = []
            keys[()] = {}
        out = []
        for k, members in groups.items():
            row = dict(keys[k])
            for name, agg, args in self.aggs:
                row[name] = _aggregate(agg, args, members, run)
            out.append(row)
        return out


def _aggregate(agg: str, args: list[Expr], rows: list[Row], run: Run) -> Any:
    if agg == "count":
        return len(rows)
    if agg == "countif":
        return sum(1 for r in rows if args[0](r, run) is True)
    vals = [args[0](r, run) for r in rows]
    if agg == "dcountif":
        vals = [v for v, r in zip(vals, rows, strict=True) if args[1](r, run) is True]
    present = [v for v in vals if v is not None and v != ""]
    if agg in ("dcount", "dcountif"):
        return len({_hashable(v) for v in present})
    if agg == "make_set":
        seen: dict[Any, Any] = {}
        for v in present:
            seen.setdefault(_hashable(v), v)
        return list(seen.values())
    if agg == "take_any":
        return present[0] if present else None
    nums = [v for v in present if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if agg == "sum":
        return sum(nums)
    if agg == "min":
        return min(nums) if nums else None
    if agg == "max":
        return max(nums) if nums else None
    raise QueryError(f"Unknown aggregate {agg}")


@dataclass
class Query:
    lets: dict[str, Pipeline]
    body: Pipeline
    text: str

    def run(self, ctx: Any, env: Env, record: bool = True) -> tuple[list[Row], Run]:
        run = Run(ctx, env, record)
        return self.body.rows(run, self.lets), run


# --- parser ---------------------------------------------------------------------------------

_COMPARE = {"==", "!=", "<", "<=", ">", ">="}
_STRING_OPS = {
    "=~": _eq_ci,
    "has": _has,
    "contains": _contains,
    "startswith": _starts,
    "endswith": _ends,
}


def _and(a: Expr, b: Expr) -> Expr:
    return lambda r, run: a(r, run) is True and b(r, run) is True


def _or(a: Expr, b: Expr) -> Expr:
    return lambda r, run: a(r, run) is True or b(r, run) is True


def _negated(left: Expr, right: Expr, test: Callable[[Any, Any], bool]) -> Expr:
    """``!in``, ``!has``, ...: false for a missing value, like the positive form."""

    def f(r: Row, run: Run) -> bool:
        a = left(r, run)
        return a is not None and not test(a, right(r, run))

    return f


class Parser:
    def __init__(self, text: str, env: Env, lets: dict[str, Pipeline] | None = None):
        self.text = text
        self.toks = tokenize(text)
        self.i = 0
        self.env = env
        self.lets: dict[str, Pipeline] = dict(lets or {})

    # helpers
    @property
    def tok(self) -> Tok:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def is_(self, value: str, kind: str | None = None) -> bool:
        t = self.tok
        return t.value == value and (kind is None or t.kind == kind) and t.kind != "str"

    def eat(self, value: str) -> Tok:
        if not self.is_(value):
            self.fail(f"expected {value!r}")
        t = self.tok
        self.i += 1
        return t

    def name(self) -> str:
        t = self.tok
        if t.kind != "name":
            self.fail("expected a name")
        self.i += 1
        return t.value

    def fail(self, msg: str) -> None:
        t = self.tok
        got = "end of query" if t.kind == "end" else repr(t.value)
        raise QueryError(f"{msg} at {_where(self.text, t.pos)} (found {got})")

    def span(self, start: int) -> str:
        end = self.tok.pos if self.tok.kind != "end" else len(self.text)
        return " ".join(self.text[self.toks[start].pos : end].split())

    # query
    def query(self) -> Query:
        while self.is_("let"):
            self.i += 1
            name = self.name()
            self.eat("=")
            self.lets[name] = self.pipeline()
            self.eat(";")
        if self.tok.kind == "end":
            self.fail("expected a query after the let statements")
        body = self.pipeline()
        if self.tok.kind != "end":
            self.fail("unexpected text after the query")
        return Query(self.lets, body, self.text)

    def shared_lets(self) -> dict[str, Pipeline]:
        """A functions file: only ``let name = <query>;`` statements."""
        self.let_text: dict[str, str] = {}
        while self.tok.kind != "end":
            start = self.tok.pos
            self.eat("let")
            name = self.name()
            self.eat("=")
            self.lets[name] = self.pipeline()
            end = self.tok.pos + 1
            self.eat(";")
            # Keep the comment lines just above the let with it: they explain it.
            before = self.text[:start].rstrip(" ").split("\n")
            comment: list[str] = []
            for line in reversed(before[:-1] if before and not before[-1].strip() else before):
                if line.strip().startswith("//"):
                    comment.insert(0, line.strip())
                else:
                    break
            self.let_text[name] = "\n".join([*comment, self.text[start:end]])
        return self.lets

    def pipeline(self) -> Pipeline:
        start = self.i
        source = self.source()
        source_text = self.span(start)
        stages = []
        while self.is_("|"):
            self.i += 1
            st_start = self.i
            st = self.stage()
            st.text = self.span(st_start)
            stages.append(st)
        return Pipeline(source, source_text, stages)

    def source(self) -> Callable[[Run, dict[str, Pipeline]], list[Row]]:
        if self.is_("union"):
            self.i += 1
            parts = [self.union_part()]
            while self.is_(","):
                self.i += 1
                parts.append(self.union_part())
            return lambda run, lets: [r for p in parts for r in p(run, lets)]
        if self.is_("("):
            self.i += 1
            inner = self.pipeline()
            self.eat(")")
            return lambda run, lets: inner.rows(run, lets)
        name = self.name()
        if self.is_("("):
            fn = self.env.table_functions.get(name)
            if fn is None:
                self.fail(f"unknown table function {name!r}")
            args = self.call_args()
            return lambda run, lets: fn(run.ctx, *[a({}, run) for a in args])
        if name in self.env.tables:
            table = self.env.tables[name]
            return lambda run, lets: table(run.ctx)
        if name in self.lets or name in self.env.shared:
            return lambda run, lets: run.named_rows(name, lets)
        self.i -= 1
        self.fail(f"unknown table {name!r}")
        raise AssertionError

    def union_part(self) -> Callable[[Run, dict[str, Pipeline]], list[Row]]:
        if self.is_("("):
            self.i += 1
            inner = self.pipeline()
            self.eat(")")
            return lambda run, lets: inner.rows(run, lets)
        return self.source()

    def stage(self) -> Stage:
        t = self.tok
        if t.kind != "name":
            self.fail("expected an operator (where, extend, project, summarize, ...)")
        op = t.value
        self.i += 1
        if op == "where":
            return Where(self.expr())
        if op == "extend":
            return Extend(self.assigns(require_name=True))
        if op == "project":
            return Project(self.assigns(require_name=False))
        if op == "distinct":
            cols = [self.name()]
            while self.is_(","):
                self.i += 1
                cols.append(self.name())
            return Distinct(cols)
        if op == "count":
            return Count()
        if op in ("take", "limit"):
            n = self.tok
            if n.kind != "num":
                self.fail("expected a number")
            self.i += 1
            return Take(int(n.value))
        if op == "mv-expand":
            name = self.name()
            if self.is_("="):
                self.i += 1
                return MvExpand(name, self.expr())
            return MvExpand(name, lambda r, run, n=name: r.get(n))
        if op == "summarize":
            aggs = []
            k = 0
            while True:
                out = None
                if self.tok.kind == "name" and self.peek().value == "=":
                    out = self.name()
                    self.eat("=")
                agg = self.name()
                if agg not in AGGREGATES:
                    self.i -= 1
                    self.fail(f"unknown aggregate {agg!r}")
                args = self.call_args()
                if len(args) != AGGREGATES[agg]:
                    self.fail(f"{agg}() takes {AGGREGATES[agg]} argument(s)")
                aggs.append((out or (f"{agg}_" if k else f"{agg}_"), agg, args))
                k += 1
                if not self.is_(","):
                    break
                self.i += 1
            by: list[tuple[str, Expr]] = []
            if self.is_("by"):
                self.i += 1
                by = self.assigns(require_name=False)
            return Summarize(aggs, by)
        self.i -= 1
        self.fail(f"unknown operator {op!r}")
        raise AssertionError

    def assigns(self, require_name: bool) -> list[tuple[str, Expr]]:
        out = []
        while True:
            if self.tok.kind == "name" and self.peek().value == "=" and self.peek().kind == "op":
                name = self.name()
                self.eat("=")
                out.append((name, self.expr()))
            elif require_name:
                self.fail("expected name = expression")
            else:
                name = self.name()
                out.append((name, lambda r, run, n=name: r.get(n)))
            if not self.is_(","):
                return out
            self.i += 1

    def call_args(self) -> list[Expr]:
        self.eat("(")
        args: list[Expr] = []
        if not self.is_(")"):
            args.append(self.expr())
            while self.is_(","):
                self.i += 1
                args.append(self.expr())
        self.eat(")")
        return args

    # expressions, lowest precedence first
    def expr(self) -> Expr:
        left = self.and_expr()
        while self.is_("or"):
            self.i += 1
            right = self.and_expr()
            left = _or(left, right)
        return left

    def and_expr(self) -> Expr:
        left = self.not_expr()
        while self.is_("and"):
            self.i += 1
            right = self.not_expr()
            left = (lambda a, b: lambda r, run: a(r, run) is True and b(r, run) is True)(
                left, right
            )
        return left

    def not_expr(self) -> Expr:
        # Kusto writes not(x); "not x" is accepted too and binds tighter than and/or.
        if self.is_("not") and self.tok.kind == "name":
            self.i += 1
            inner = self.not_expr()
            return lambda r, run: inner(r, run) is not True
        return self.comparison()

    def comparison(self) -> Expr:
        left = self.additive()
        t = self.tok
        negate = False
        if t.kind == "op" and t.value == "!" and self.peek().kind == "name":
            # !in, !has, !contains, !startswith, !endswith
            negate = True
            self.i += 1
            t = self.tok
        if t.kind == "op" and t.value in _COMPARE:
            self.i += 1
            right = self.additive()
            f = _cmp(t.value)
            return lambda r, run: f(left(r, run), right(r, run))
        if t.kind == "op" and t.value == "!~":
            self.i += 1
            right = self.additive()
            return lambda r, run: not _eq_ci(left(r, run), right(r, run))
        if t.kind in ("op", "name") and t.value in _STRING_OPS:
            self.i += 1
            right = self.additive()
            g = _STRING_OPS[t.value]
            if negate:
                return lambda r, run: (
                    left(r, run) is not None and not g(left(r, run), right(r, run))
                )
            return lambda r, run: g(left(r, run), right(r, run))
        if t.kind == "name" and t.value == "in":
            self.i += 1
            right = self.in_target()
            if negate:
                return lambda r, run: (
                    left(r, run) is not None and not _in(left(r, run), right(r, run))
                )
            return lambda r, run: _in(left(r, run), right(r, run))
        if t.kind == "name" and t.value == "matches":
            self.i += 1
            if self.is_("regex"):
                self.i += 1
            right = self.additive()
            return lambda r, run: regex_search(right(r, run), left(r, run))
        if negate:
            self.fail("expected in, has, contains, startswith or endswith after !")
        return left

    def in_target(self) -> Callable[[Row, Run], Any]:
        if self.is_("list") and self.peek().value == "(":
            return self.additive()
        self.eat("(")
        t = self.tok
        if (
            t.kind == "name"
            and (
                t.value in self.env.tables
                or t.value in self.lets
                or t.value in self.env.shared
                or t.value in self.env.table_functions
                or t.value == "union"
            )
            and self.peek().value != ","
        ):
            sub = self.pipeline()
            self.eat(")")
            key = id(sub)
            lets = self.lets

            def values(r: Row, run: Run) -> Any:
                cached = run.subqueries.get(key)
                if cached is None:
                    rows = sub.rows(run, lets, label="in (...)")
                    vals = [next(iter(x.values()), None) for x in rows]
                    cached = run.subqueries[key] = tuple(v for v in vals if v is not None)
                return cached

            return values
        items = [self.expr()]
        while self.is_(","):
            self.i += 1
            items.append(self.expr())
        self.eat(")")
        return lambda r, run: tuple(e(r, run) for e in items)

    def additive(self) -> Expr:
        left = self.postfix()
        while self.tok.kind == "op" and self.tok.value in ("+", "-"):
            op = self.tok.value
            self.i += 1
            right = self.postfix()

            def f(r: Row, run: Run, a=left, b=right, op=op) -> Any:
                x, y = a(r, run), b(r, run)
                if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                    return None
                return x + y if op == "+" else x - y

            left = f
        return left

    def postfix(self) -> Expr:
        e = self.primary()
        while self.is_("["):
            self.i += 1
            key = self.expr()
            self.eat("]")

            def idx(r: Row, run: Run, base=e, k=key) -> Any:
                b, kk = base(r, run), k(r, run)
                if isinstance(b, dict):
                    return b.get(kk)
                if isinstance(b, (list, tuple)) and isinstance(kk, int):
                    return b[kk] if -len(b) <= kk < len(b) else None
                return None

            e = idx
        return e

    def primary(self) -> Expr:
        t = self.tok
        if t.kind == "str" or t.kind == "num":
            self.i += 1
            v = t.value
            return lambda r, run: v
        if t.kind == "op" and t.value == "(":
            self.i += 1
            e = self.expr()
            self.eat(")")
            return e
        if t.kind == "op" and t.value == "-" and self.peek().kind == "num":
            self.i += 2
            v = -self.toks[self.i - 1].value
            return lambda r, run: v
        if t.kind == "name":
            self.i += 1
            name = t.value
            if name in ("true", "false"):
                v = name == "true"
                return lambda r, run: v
            if name == "null":
                return lambda r, run: None
            if self.is_("("):
                return self.call(name)
            return lambda r, run: r.get(name)
        self.fail("expected a value")
        raise AssertionError

    def call(self, name: str) -> Expr:
        if name == "list":
            self.eat("(")
            t = self.tok
            if t.kind != "str":
                self.fail('list() takes a detection string key, such as list("microsoft.idp_cdn")')
            self.i += 1
            self.eat(")")
            from sandbox.detections import strings

            if t.value not in strings.entries():
                self.i -= 2
                self.fail(f"no detection string {t.value!r}")
            ref = ListRef(t.value)
            return lambda r, run: ref
        if name == "exists":
            self.eat("(")
            target = self.name()
            if not (target in self.lets or target in self.env.shared):
                self.i -= 1
                self.fail(f"exists() takes the name of a let or shared query, not {target!r}")
            self.eat(")")
            lets = self.lets
            return lambda r, run: bool(run.named_rows(target, lets))
        fn = self.env.functions.get(name)
        if fn is None:
            self.i -= 1
            self.fail(f"unknown function {name!r}")
        args = self.call_args()
        return lambda r, run: fn(*[a(r, run) for a in args], ctx=run.ctx)


def parse(text: str, env: Env) -> Query:
    return Parser(text, env).query()


def parse_shared(text: str, env: Env) -> tuple[dict[str, Pipeline], dict[str, str]]:
    """A file of shared named queries: each query, and its text with its comment."""
    p = Parser(text, env)
    lets = p.shared_lets()
    return lets, p.let_text
