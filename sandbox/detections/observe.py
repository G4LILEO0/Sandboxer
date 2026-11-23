"""The report summary stored with each analysis, and IOC extraction.

The summary describes the capture for the report (the final page, the redirect chain,
forms, scripts, downloads, domains, the brand imitated, how the capture went). It decides
nothing: every verdict comes from the rules in ``sandbox/detections/rules``. Importing
this module also imports every area module, which registers the tables and functions the
rules read."""

import re
from collections.abc import Callable
from typing import Any

from sandbox.analysis.domains import site
from sandbox.detections import (  # noqa: F401  (clickfix and lures register tables)
    clickfix,
    downloads,
    evasion,
    forms,
    hosting,
    lures,
    navigation,
    network,
    scripts,
    web3,
)
from sandbox.detections.base import _CMD_NOISE, Capture, CaptureData, _all_frames, _host
from sandbox.detections.clickfix import _dns_cradle_iocs

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")

_ETH_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]{40}\b")


def _cookies_section(cap: Capture) -> dict[str, Any]:
    return {"end_of_session": [c.get("name") for c in cap.data.result.get("cookies", [])][:50]}


def _popups_section(cap: Capture) -> dict[str, Any]:
    return {"count": max(0, len(cap.data.result.get("pages", [])) - 1)}


def _dialogs_section(cap: Capture) -> dict[str, Any]:
    dialogs = cap.data.result.get("dialogs", [])
    return {"count": len(dialogs), "messages": [d.get("message") for d in dialogs][:10]}


# Every section of the summary, in report order.
SECTIONS: dict[str, Callable[[Capture], dict[str, Any]]] = {
    "final": hosting.final_section,
    "capture": evasion.capture_section,
    "forms": forms.forms_section,
    "scripts": scripts.scripts_section,
    "downloads": downloads.downloads_section,
    "web3": web3.web3_section,
    "domains": hosting.domains_section,
    "redirects": navigation.redirects_section,
    "brand": hosting.brand_section,
    "network": network.network_section,
    "cookies": _cookies_section,
    "frames": navigation.frames_section,
    "popups": _popups_section,
    "dialogs": _dialogs_section,
}


class Facts(dict):
    """The report summary (a plain dict, stored with the analysis) that also carries the
    capture it came from, so the rules can read its tables in the same run."""

    capture: Capture | None = None


def build_facts(data: CaptureData) -> Facts:
    """The report summary of one capture, by section, carrying the capture for the rules.
    Pure: a stored capture gives the same values again."""
    cap = Capture(data)
    facts = Facts({name: cap.section(name) for name in SECTIONS})
    facts.capture = cap
    return facts


def extract_iocs(data: CaptureData, facts: dict[str, Any]) -> dict[str, list[str]]:
    """IOCs from a capture (ANA-9): domains, IPs, URLs, hashes, emails and eth addresses."""
    r = data.result
    domains, ips, urls, hashes, emails = set(), set(), set(), set(), set()
    eth_addresses: set[str] = set()
    for host in facts["domains"]["hosts"]:
        if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host):
            ips.add(host)
        else:
            domains.add(host)
    for addresses in r.get("hosts", {}).values():
        ips.update(addresses)
    for url in [r.get("url"), r.get("final_url")]:
        if url:
            urls.add(url)
    for hop in r.get("redirects", []):
        urls.update(u for u in (hop.get("from"), hop.get("to")) if u and u.startswith("http"))
    for nav in r.get("navigations", []):
        if str(nav.get("url", "")).startswith("http"):
            urls.add(nav["url"])
    for form in facts["forms"]["cross_domain_credential_forms"]:
        if str(form.get("action", "")).startswith("http"):
            urls.add(form["action"])
    for d in facts["downloads"]["files"]:
        if d.get("sha256"):
            hashes.add(d["sha256"])
        if str(d.get("url", "")).startswith("http"):
            urls.add(d["url"])
    for d in r.get("downloads", []):
        if d.get("md5"):
            hashes.add(d["md5"])
    for entry in data.har_entries[:3000]:
        url = entry.get("request", {}).get("url", "")
        host = _host(url)
        if url.startswith("http") and host and site(host) not in data.allowlisted:
            urls.add(url[:2000])
    for frame in _all_frames(data):
        emails.update(m.lower() for m in _EMAIL.findall(frame.get("text", "")))
        for link in frame.get("links", []):
            if str(link).lower().startswith("mailto:"):
                emails.add(str(link)[7:].split("?")[0].lower())
    # Clipboard payloads: the de-obfuscated command often names the next-stage URL/host,
    # the only pointer to the payload in a browser-only sandbox (DE-CFX-008).
    for c in r.get("clipboard", []):
        text = _CMD_NOISE.sub("", str(c.get("text", "")))
        if not (c.get("api") or not c.get("trusted")):
            continue
        for u in re.findall(r"https?://[^\s'\"<>|)]{4,2000}", text):
            urls.add(u)
            if host := _host(u):
                (ips if re.fullmatch(r"[\d.]+", host) else domains).add(host)
        # A DNS cradle names no URL: its stage lives in a TXT/Name answer (DE-CFX-009).
        dns_names, dns_servers = _dns_cradle_iocs(text)
        domains.update(dns_names)
        ips.update(dns_servers)
        eth_addresses.update(a.lower() for a in _ETH_ADDRESS.findall(text))
    for call in facts.get("web3", {}).get("rpc_calls", []):
        if call.get("to"):
            eth_addresses.add(call["to"].lower())
    return {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "urls": sorted(urls)[:1000],
        "hashes": sorted(hashes),
        "emails": sorted(emails)[:200],
        "eth_addresses": sorted(eth_addresses)[:100],
    }
