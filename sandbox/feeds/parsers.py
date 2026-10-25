"""One parser per feed format (FED-2). A new feed needs a row in ``feeds`` plus, at most,
a parser here.

Indicator parsers yield ``Record``s with normalised values; other kinds yield their own
shapes (allowlist entries, ATT&CK techniques, rule files). Parsers raise ``FeedError`` on
malformed input so the run fails and the previous data stays active (FED-5).
"""

import csv
import io
import ipaddress
import json
import re
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from sandbox.core.urls import InvalidURL, normalise_url


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class Record:
    type: str  # domain, ip, url, hash
    value: str
    tags: tuple[str, ...] = ()
    confidence: int | None = None


@dataclass
class RuleFile:
    path: str
    text: str


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str] = field(default_factory=list)
    url: str | None = None


_HEX = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9\-_]{0,61}[a-z0-9_])?\.)+[a-z0-9\-]{2,63}$")


def normalise_value(ioc_type: str, raw: str) -> str | None:
    """Canonical form used for both storage and matching; None if unusable."""
    raw = raw.strip()
    if not raw:
        return None
    if ioc_type == "url":
        try:
            return normalise_url(raw).url
        except InvalidURL:
            return None
    if ioc_type == "domain":
        value = raw.lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if not value.isascii():
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError:
                return None
        return value if _DOMAIN.match(value) else None
    if ioc_type == "ip":
        try:
            return ipaddress.ip_address(
                raw.split(":")[0] if raw.count(":") == 1 else raw
            ).compressed
        except ValueError:
            return None
    if ioc_type == "hash":
        value = raw.lower()
        return value if _HEX.match(value) else None
    return None


def _record(ioc_type: str, raw: str, tags=(), confidence=None) -> Record | None:
    value = normalise_value(ioc_type, raw)
    if value is None:
        return None
    clean_tags = tuple(sorted({t.strip().lower() for t in tags if t and t.strip()}))[:20]
    return Record(ioc_type, value, clean_tags, confidence)


# Largest file taken out of a feed archive; zip entries are refused by their declared
# size (which zipfile enforces while reading), tar members by theirs.
MAX_ARCHIVE_MEMBER = 512 * 1024 * 1024


def _zip_read(zf: zipfile.ZipFile, name: str) -> bytes:
    if zf.getinfo(name).file_size > MAX_ARCHIVE_MEMBER:
        raise FeedError(f"{name} in the archive is larger than {MAX_ARCHIVE_MEMBER} bytes")
    return zf.read(name)


def _text(data: bytes) -> str:
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                raise FeedError("Empty zip archive")
            data = _zip_read(zf, names[0])
    return data.decode("utf-8", "replace")


def _csv_rows(data: bytes) -> Iterator[list[str]]:
    lines = (line for line in _text(data).splitlines() if line and not line.startswith("#"))
    yield from csv.reader(lines)


# --- indicator feeds ---------------------------------------------------------------


def urlhaus_csv(data: bytes) -> Iterator[Record]:
    """URLhaus CSV dumps: id,dateadded,url,url_status,last_online,threat,tags,link,reporter."""
    rows = 0
    for row in _csv_rows(data):
        if len(row) < 7:
            raise FeedError(f"URLhaus row has {len(row)} columns, expected 9")
        rows += 1
        tags = [row[5], *row[6].split(",")]
        if rec := _record("url", row[2], tags):
            yield rec


_THREATFOX_TYPES = {
    "url": "url",
    "domain": "domain",
    "ip:port": "ip",
    "md5_hash": "hash",
    "sha1_hash": "hash",
    "sha256_hash": "hash",
}


def threatfox_json(data: bytes) -> Iterator[Record]:
    try:
        payload = json.loads(_text(data))
    except ValueError as exc:
        raise FeedError(f"ThreatFox export is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise FeedError("ThreatFox export: expected an object keyed by id")
    for entries in payload.values():
        for item in entries if isinstance(entries, list) else [entries]:
            ioc_type = _THREATFOX_TYPES.get(str(item.get("ioc_type", "")))
            if not ioc_type:
                continue
            raw = str(item.get("ioc_value", ""))
            if ioc_type == "ip":
                raw = raw.rsplit(":", 1)[0]
            tags = [item.get("threat_type") or "", item.get("malware_printable") or ""]
            tags += (
                (item.get("tags") or "").split(",")
                if isinstance(item.get("tags"), str)
                else (item.get("tags") or [])
            )
            conf = item.get("confidence_level")
            if rec := _record(ioc_type, raw, tags, int(conf) if conf is not None else None):
                yield rec


def malwarebazaar_csv(data: bytes) -> Iterator[Record]:
    """MalwareBazaar CSV: first_seen,sha256,md5,sha1,reporter,file_name,type,mime,signature."""
    for row in _csv_rows(data):
        if len(row) < 4:
            raise FeedError("MalwareBazaar row too short")
        tags = ["malware", row[8].strip(' "')] if len(row) > 8 else ["malware"]
        for value in (row[1], row[2]):
            if rec := _record("hash", value.strip(' "'), tags):
                yield rec


def plain_urls(data: bytes) -> Iterator[Record]:
    for line in _text(data).splitlines():
        if line.strip() and not line.startswith("#"):
            if rec := _record("url", line, ("phishing",)):
                yield rec


def plain_domains(data: bytes) -> Iterator[Record]:
    for line in _text(data).splitlines():
        if line.strip() and not line.startswith("#"):
            if rec := _record("domain", line.split()[0], ("phishing",)):
                yield rec


def phishtank_json(data: bytes) -> Iterator[Record]:
    try:
        payload = json.loads(_text(data))
    except ValueError as exc:
        raise FeedError(f"PhishTank export is not JSON: {exc}") from exc
    for item in payload:
        if item.get("verified") in ("yes", True):
            tags = ["phishing", str(item.get("target") or "")]
            if rec := _record("url", str(item.get("url", "")), tags):
                yield rec


INDICATOR_PARSERS: dict[str, Callable[[bytes], Iterator[Record]]] = {
    "urlhaus_csv": urlhaus_csv,
    "threatfox_json": threatfox_json,
    "malwarebazaar_csv": malwarebazaar_csv,
    "plain_urls": plain_urls,
    "plain_domains": plain_domains,
    "phishtank_json": phishtank_json,
}


# --- other feed kinds ------------------------------------------------------------------


def tranco_csv(data: bytes, limit: int = 10_000) -> list[tuple[int, str]]:
    """Tranco top list (rank,domain), cut to the top ``limit`` (FED-11)."""
    out = []
    for row in _csv_rows(data):
        if len(row) < 2 or not row[0].isdigit():
            raise FeedError("Tranco rows must be rank,domain")
        domain = normalise_value("domain", row[1])
        if domain:
            out.append((int(row[0]), domain))
        if len(out) >= limit:
            break
    return out


def attack_stix(data: bytes) -> list[Technique]:
    """MITRE ATT&CK STIX bundle -> technique ids and names (FED-12)."""
    try:
        bundle = json.loads(_text(data))
    except ValueError as exc:
        raise FeedError(f"ATT&CK bundle is not JSON: {exc}") from exc
    out = []
    for obj in bundle.get("objects", []):
        if (
            obj.get("type") != "attack-pattern"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        ref = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ref or not ref.get("external_id"):
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if "phase_name" in p]
        out.append(Technique(ref["external_id"], obj.get("name", ""), tactics, ref.get("url")))
    if not out:
        raise FeedError("ATT&CK bundle contained no techniques")
    return out


def rule_archive(data: bytes, suffixes: tuple[str, ...]) -> list[RuleFile]:
    """Rule files from a zip, tar(.gz) or a single text file (FED-7)."""
    files: list[RuleFile] = []
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.lower().endswith(suffixes):
                    files.append(RuleFile(name, _zip_read(zf, name).decode("utf-8", "replace")))
    elif data[:2] == b"\x1f\x8b" or data[257:262] == b"ustar":
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.lower().endswith(suffixes):
                    if member.size > MAX_ARCHIVE_MEMBER:
                        raise FeedError(f"{member.name} in the archive is too large")
                    fh = tar.extractfile(member)
                    if fh:
                        files.append(RuleFile(member.name, fh.read().decode("utf-8", "replace")))
    else:
        files.append(RuleFile("rules" + suffixes[0], data.decode("utf-8", "replace")))
    if not files:
        raise FeedError(f"No {', '.join(suffixes)} files in the archive")
    return files
