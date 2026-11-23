"""observe"""

import re
from typing import Any

from sandbox.analysis.domains import (
    display_host,
    free_hosting,
    government_lookalike,
    is_confusable_idn,
    is_punycode,
    lookalike,
    registrable,
    site,
)
from sandbox.detections.base import (
    _CMD_NOISE,
    CaptureData,
    _all_frames,
    _credential_prompt,
    _frames,
    _har_requests,
    _host,
    chain_hosts,
    contacted_hosts,
)
from sandbox.detections.clickfix import _clipboard, _dns_cradle_iocs
from sandbox.detections.downloads import _archive_listing, _downloads, _mislabeled_images
from sandbox.detections.evasion import _antibot, _challenge_gate, _custom_captcha, _evasion
from sandbox.detections.exfiltration import _exfil
from sandbox.detections.forms import _apps_script, _forms, _script_posted_credentials
from sandbox.detections.hosting import (
    _abuse_interstitial,
    _brand,
    _favicon_lookups,
    _final_ipfs,
    _hosting_brand_label,
)
from sandbox.detections.lures import (
    _crash_repair,
    _fake_captcha,
    _fake_os_update,
    _fake_update,
    _lure,
    _open_download_pages,
)
from sandbox.detections.microsoft import _idp
from sandbox.detections.navigation import (
    _navigation_cause,
    _protocol_handler,
    _redirects,
    _suspicious_hidden,
    _trusted_redirectors,
)
from sandbox.detections.network import (
    _ip_lookups,
    _local_probe,
    _requests_summary,
    _web_proxy_kit,
    _websocket,
)
from sandbox.detections.scripts import _invisible_unicode, _jsapi_facts, _libraries, obfuscation
from sandbox.detections.web3 import _web3, _web3_derived

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")

_ETH_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]{40}\b")


def build_facts(data: CaptureData) -> dict[str, Any]:
    r = data.result
    final_url = r.get("final_url") or r.get("url")
    final_host = _host(final_url)
    hosts = contacted_hosts(data)
    regs = sorted({registrable(h) for h in hosts})

    scripts = []
    for sha, text in data.scripts.items():
        score, signals = obfuscation(text)
        if score:
            scripts.append({"sha256": sha, "score": score, "signals": signals})
    scripts.sort(key=lambda s: -s["score"])

    looks = [lk for h in hosts if (lk := lookalike(h, data.brands, data.allowlisted))]
    gov_looks = [g for h in hosts if (g := government_lookalike(h, data.brands, data.allowlisted))]
    ages = {d: a for d, a in data.domain_ages.items() if a is not None}
    young = sorted(
        ({"domain": d, "age_days": a} for d, a in ages.items() if a < 30),
        key=lambda x: x["age_days"],
    )
    # Domains the visitor actually travels through, as opposed to third-party resources
    # (ad and analytics domains rotate often and are frequently young).
    chain_regs = {registrable(h) for h in chain_hosts(data)}
    chain_ages = [a for d, a in ages.items() if d in chain_regs]
    final_reg = registrable(final_host) if final_host else None
    blocked = r.get("blocked", [])
    internal = [b for b in blocked if "scheme" not in b.get("reason", "")]
    hidden = sorted({src for f in _all_frames(data) for src in _suspicious_hidden(f, data)})
    reqs = _har_requests(data)
    forms = {**_forms(data), **_script_posted_credentials(data, reqs), **_apps_script(data)}
    jsapi = _jsapi_facts(data)
    challenge_gate = _challenge_gate(data, reqs)
    custom_captcha = _custom_captcha(data)
    nav_cause = _navigation_cause(data)
    libraries = _libraries(data)
    final_allowlisted = bool(final_host) and site(final_host) in data.allowlisted
    lure = {
        **_lure(data),
        **_fake_captcha(data, reqs),
        "fake_update_pages": _fake_update(data),
        "open_download_pages": _open_download_pages(data),
        "crash_repair_pages": _crash_repair(data),
        "fake_os_update_pages": _fake_os_update(data),
    }
    web3 = _web3(data, reqs)
    web3.update(
        _web3_derived(
            data,
            web3,
            libraries,
            jsapi,
            lure_page=bool(lure["fake_update_pages"] or lure["fake_captcha"]),
            final_allowlisted=final_allowlisted,
        )
    )
    # Credential/credential-like form pages served from blob: or about: documents
    # (HTML smuggling), which Chromium allows for script-created top-level/frame docs.
    smuggled = sorted(
        {
            f.get("url", "")
            for f in _all_frames(data)
            if str(f.get("url", "")).startswith(("blob:", "about:srcdoc", "about:blank"))
            and _credential_prompt(f)
        }
    )

    return {
        "final": {
            "url": final_url,
            "host": final_host,
            "domain": registrable(final_host) if final_host else None,
            "display_host": display_host(final_host) if final_host else None,
            "allowlisted": final_allowlisted,
            "free_hosting": free_hosting(final_host) if final_host else None,
            "ipfs": _final_ipfs(final_url),
            "title": r.get("title") or "",
            "abuse_interstitial": _abuse_interstitial(data, final_host) if final_host else None,
        },
        "capture": {
            "end_reason": r.get("end_reason"),
            "errors": r.get("errors", []),
            "navigated": any(
                str(n.get("url", "")).startswith(("http:", "https:"))
                for n in r.get("navigations", [])
            ),
            # The session ended on Chrome's own error page (DNS, TLS or connection failure).
            "load_failed": not str(final_url or "").startswith(("http:", "https:")),
            "duration_ms": r.get("duration_ms"),
            # A CAPTCHA/Turnstile gate was seen this session (DE-PHI-011): a run that stops
            # at one should prefer "unknown" to "benign" and be re-run interactively.
            "gated": challenge_gate or bool(custom_captcha),
            # A home-made canvas CAPTCHA no provider serves (Tycoon 2FA); it gates too.
            "custom_captcha": len(custom_captcha),
            "custom_captcha_pages": custom_captcha,
            # The session ended on a bot check (Cloudflare challenge / block page) that
            # it did not get through: the real page was never seen.
            "antibot": _antibot(data, reqs, final_host),
            "browser_mode": (r.get("browser") or {}).get("mode"),
        },
        "forms": forms,
        "scripts": {
            "count": len(data.scripts),
            "max_obfuscation_score": scripts[0]["score"] if scripts else 0,
            "obfuscated": scripts[:10],
            "libraries": libraries,
            **_invisible_unicode(data),
        },
        "js": jsapi,
        "downloads": {
            **_downloads(data),
            **_archive_listing(data),
            "mislabeled_image": len(mislabeled := _mislabeled_images(data)),
            "mislabeled_images": mislabeled[:10],
        },
        "clipboard": _clipboard(data),
        "lure": lure,
        "exfil": _exfil(data, reqs),
        "idp": _idp(data, reqs),
        "web3": web3,
        "websocket": _websocket(data, reqs),
        "evasion": _evasion(data),
        "domains": {
            "count": len(regs),
            "hosts": hosts[:200],
            "registrable": regs[:200],
            "punycode": sum(is_punycode(h) for h in hosts),
            "punycode_confusable": sum(is_confusable_idn(h) for h in hosts),
            "punycode_hosts": [
                {"host": h, "display": display_host(h)} for h in hosts if is_punycode(h)
            ],
            "lookalike": len(looks),
            "lookalikes": looks[:10],
            "government_lookalike": len(gov_looks),
            "government_lookalikes": gov_looks[:10],
            "youngest_age_days": min(ages.values()) if ages else None,
            "chain_youngest_age_days": min(chain_ages) if chain_ages else None,
            "final_age_days": ages.get(final_reg) if final_reg else None,
            "young": young[:10],
            "ages": ages,
        },
        "redirects": _redirects(data),
        "brand": {
            **_brand(data, forms["cross_domain_credential_forms"]),
            "hosting_label": _hosting_brand_label(data),
            "favicon_lookups": (favicons := _favicon_lookups(data, reqs))[:10],
            "favicon_lookup_count": len(favicons),
        },
        "network": {
            "requests": len(data.har_entries),
            "hosts": len(hosts),
            "blocked_internal": len(internal),
            "blocked": blocked[:20],
            "ip_lookups": _ip_lookups(reqs),
            "local_probe": _local_probe(data),
            "request_log": _requests_summary(data),
            "trusted_redirectors": _trusted_redirectors(data),
            **_web_proxy_kit(data, reqs),
        },
        "navigation": {**nav_cause, **_protocol_handler(data)},
        "cookies": {
            "end_of_session": [c.get("name") for c in data.result.get("cookies", [])][:50],
        },
        "frames": {
            "count": len(_frames(r)),
            "pages_seen": len({f.get("url") for f in data.dom_pages}),
            "hidden_iframes": len(hidden),
            "hidden_iframe_urls": hidden[:10],
            "smuggled_credential_pages": len(smuggled),
            "smuggled_credential_urls": smuggled[:10],
        },
        "popups": {"count": max(0, len(r.get("pages", [])) - 1)},
        "dialogs": {
            "count": len(r.get("dialogs", [])),
            "messages": [d.get("message") for d in r.get("dialogs", [])][:10],
        },
    }


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
