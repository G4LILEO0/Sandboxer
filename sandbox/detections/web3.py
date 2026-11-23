"""web3"""

import base64
import binascii
import json
import re
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _top_frames
from sandbox.detections.model import all_of, any_of, detection, not_, sig, signal

# --- HAR access (pure over the stored HAR) --------------------------------------------

_JSONRPC_METHODS = S.bind(globals(), "_JSONRPC_METHODS", "web3.jsonrpc_methods", S.as_set)

KNOWN_WEB3_ADDRESSES = S.bind(
    globals(), "KNOWN_WEB3_ADDRESSES", "web3.known_bad_addresses", S.as_set
)

EXPLORER_API_HOSTS = S.bind(globals(), "EXPLORER_API_HOSTS", "web3.explorer_api_hosts", S.as_set)


def _abi_string(hexdata: str, minimum: int = 512) -> str | None:
    """The value of an ABI-encoded dynamic string/bytes return of ``minimum``+ bytes.

    Layout: a 32-byte offset word, then at that offset a 32-byte length word and the
    data. Page-load reads on dApps return one or a few 32-byte words; EtherHiding
    contracts return kilobytes of text (L2-01)."""
    h = hexdata[2:] if hexdata[:2].lower() == "0x" else hexdata
    if len(h) < 192 or len(h) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", h):
        return None
    raw = bytes.fromhex(h)
    offset = int.from_bytes(raw[:32], "big")
    if offset + 32 > len(raw):
        return None
    size = int.from_bytes(raw[offset : offset + 32], "big")
    start = offset + 32
    if size < minimum or start + size > len(raw):
        return None
    return raw[start : start + size].decode("utf-8", "replace")


def _rpc_large_strings(resp_text: str) -> list[str]:
    if '"result"' not in resp_text:
        return []
    try:
        payload = json.loads(resp_text)
    except ValueError:
        return []
    out = []
    for item in payload if isinstance(payload, list) else [payload]:
        if isinstance(item, dict) and isinstance(item.get("result"), str):
            if (s := _abi_string(item["result"])) is not None:
                out.append(s)
    return out


def _web3(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    calls, addresses = [], set()
    large: list[str] = []
    for r in reqs:
        if r["method"] != "POST" or not r["post"]:
            continue
        body = r["post"]
        if '"jsonrpc"' not in body:
            continue
        try:
            payload = json.loads(body)
        except ValueError:
            continue
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method", "")).lower()
            if item.get("jsonrpc") == "2.0" and method in _JSONRPC_METHODS:
                params = item.get("params") or []
                to = ""
                for p in params:
                    if isinstance(p, dict) and p.get("to"):
                        to = str(p["to"])
                calls.append({"host": r["host"], "method": method, "to": to.lower()})
                if to:
                    addresses.add(to.lower())
        large.extend(_rpc_large_strings(r.get("resp_text") or ""))
    known = sorted(a for a in addresses if a in KNOWN_WEB3_ADDRESSES)
    # Fake EIP-1193 wallet provider log (A6): present only when the wallet profile is on.
    # Drainer signals: Permit/Permit2 typed-data signing, unlimited approve/setApprovalForAll.
    wallet = data.result.get("wallet_requests", [])
    drainer = [
        w
        for w in wallet
        if str(w.get("primaryType", "")).lower().startswith("permit")
        or w.get("unlimited") is True
        or str(w.get("selector", "")).lower() in ("0x095ea7b3", "0xa22cb465")
    ]
    out = {
        "rpc_calls": calls[:20],
        "rpc_call_count": len(calls),
        "contract_addresses": sorted(addresses)[:20],
        "known_malicious_contract": len(known),
        "known_contracts": known,
        "rpc_large_string_results": len(large),
        "explorer_api_hosts": sorted({r["host"] for r in reqs if r["host"] in EXPLORER_API_HOSTS}),
        # Decoded values for the linked-exec check only; not a reported fact.
        "_rpc_large_strings": large[:10],
    }
    if wallet:
        out["wallet_requests"] = wallet[:20]
        out["wallet_drainer"] = len(drainer)
    return out


_WALLET_CONNECTOR_LIBS = S.bind(
    globals(), "_WALLET_CONNECTOR_LIBS", "web3.wallet_connector_libraries", S.as_set
)

_WALLET_LIBS = S.bind(globals(), "_WALLET_LIBS", "web3.wallet_libraries", S.as_set)

_DRAINER_WORDING = S.bind(globals(), "_DRAINER_WORDING", "web3.drainer_wording")

_DAPP_UI = S.bind(globals(), "_DAPP_UI", "web3.dapp_ui")


def _web3_derived(
    data: CaptureData,
    web3: dict[str, Any],
    libraries: list[dict[str, Any]],
    jsapi: dict[str, Any],
    lure_page: bool,
    final_allowlisted: bool,
) -> dict[str, Any]:
    """EtherHiding guards (R-03, R-07) and the decoded-and-run escalation (DE-W3B-002).

    The allowlist is deliberately not a guard: EtherHiding runs on compromised
    legitimate (often allowlisted) sites. A real dApp is recognised by its wallet UI
    instead, since the fake-wallet log (wallet_requests) only exists when the opt-in
    SANDBOX_FAKE_WALLET profile is on.
    """
    # Wording is judged on top-level documents only (L2 §1.1): an ad or price widget
    # iframe saying "connect wallet" must not switch detection off for the capture.
    # The library half stays page-wide.
    dapp_ui = any(lib.get("name") in _WALLET_CONNECTOR_LIBS for lib in libraries) or any(
        _DAPP_UI.search(f"{f.get('title', '')} {f.get('text', '')}") for f in _top_frames(data)
    )
    large = web3.pop("_rpc_large_strings", [])
    reads = web3.get("rpc_call_count", 0) > 0 and not web3.get("wallet_requests")
    # A kilobyte-sized string answer is EtherHiding's shape whatever the page looks like.
    etherhiding = bool(reads and (not dapp_ui or large))
    linked = bool(reads and large and _linked_exec(large, data))
    # The contract's answer is decoded and run (DE-W3B-002). Precise form: a decoded
    # result (or its base64 layer) shares a 64-char window with eval/Function code, no
    # other condition. Fallback co-occurrence: large string results plus 1 KB+ of
    # code-only exec (never innerHTML/document.write, L2-01); on an allowlisted site
    # it also needs a lure page.
    executed = linked or bool(
        etherhiding
        and large
        and jsapi.get("code_exec_max_len", 0) >= 1024
        and (not final_allowlisted or lure_page)
    )
    # Explorer-API dead drop (DE-W3B-003): a page with no wallet UI reading an explorer.
    explorer = web3.get("explorer_api_hosts") or []
    explorer_reads = bool(
        explorer and not dapp_ui and not web3.get("wallet_requests") and not final_allowlisted
    )
    # Drainer lure (DE-W3B-006): claim/airdrop/wallet-verification wording on a top-level
    # page that loads a wallet library. The domain-age/lookalike/free-hosting half is in
    # the rule, where those facts live.
    wallet_lib = any(lib.get("name") in _WALLET_LIBS for lib in libraries)
    drainer_wording = any(
        _DRAINER_WORDING.search(f"{f.get('title', '')} {f.get('text', '')}")
        for f in _top_frames(data)
    )
    return {
        "dapp_ui": dapp_ui,
        "explorer_dead_drop": explorer_reads,
        "wallet_library": wallet_lib,
        "drainer_lure": bool(wallet_lib and drainer_wording and not final_allowlisted),
        "etherhiding_rpc": etherhiding,
        "rpc_result_linked_exec": linked,
        "rpc_result_executed": executed,
    }


_BASE64_SHAPE = re.compile(r"[A-Za-z0-9+/=\s]{64,}")


def _linked_exec(large: list[str], data: CaptureData) -> bool:
    samples = ((data.result.get("jsapi") or {}).get("exec") or {}).get("code_samples") or []
    if not samples:
        return False
    for value in large:
        candidates = [value]
        stripped = value.strip()
        if _BASE64_SHAPE.fullmatch(stripped):
            try:
                candidates.append(
                    base64.b64decode("".join(stripped.split()), validate=False).decode(
                        "utf-8", "replace"
                    )
                )
            except (ValueError, binascii.Error):
                pass
        for cand in candidates:
            windows = [cand[i : i + 64] for i in range(0, max(len(cand) - 63, 1), 64)][:64]
            if any(len(w) == 64 and any(w in s for s in samples) for w in windows):
                return True
    return False


# --- observed values ---------------------------------------------------------------------


def web3_section(cap: Capture) -> dict[str, Any]:
    """Blockchain RPC calls, EtherHiding and wallet-drainer traits."""
    data = cap.data
    lure = cap.section("lure")
    web3 = _web3(data, cap.reqs)
    web3.update(
        _web3_derived(
            data,
            web3,
            cap.section("scripts")["libraries"],
            cap.section("js"),
            lure_page=bool(lure["fake_update_pages"] or lure["fake_captcha"]),
            final_allowlisted=cap.final_allowlisted,
        )
    )
    return web3


# --- signals: the values this area observes --------------------------------------------

signal(
    "web3.rpc_calls",
    "Blockchain RPC calls",
    (
        "Host, method and contract address of each JSON-RPC 2.0 call the page posted with a "
        "read method (string web3.jsonrpc_methods), first 20."
    ),
)

signal(
    "web3.etherhiding_rpc",
    "Blockchain reads without a wallet (EtherHiding)",
    (
        "The page made blockchain JSON-RPC read calls without any wallet request, and either "
        "has no wallet UI (no wallet-connector library, string "
        "web3.wallet_connector_libraries, and no dApp wording on a top-level page, string "
        "web3.dapp_ui) or got a kilobyte-sized string answer back. The allowlist is not a "
        "guard: EtherHiding runs on compromised legitimate sites."
    ),
)

signal(
    "web3.rpc_result_executed",
    "Blockchain answer decoded and run",
    (
        "A large string answer from a blockchain read (or its base64 layer) shares a "
        "64-character window with code the page ran through eval or Function. Fallback: an "
        "EtherHiding read with large string answers plus 1 KB or more of eval'd code; on an "
        "allowlisted site this also needs a fake update or fake CAPTCHA page."
    ),
)

signal(
    "web3.rpc_large_string_results",
    "Large blockchain string answers",
    "Kilobyte-sized strings decoded from JSON-RPC answers (ABI-encoded strings).",
)

signal(
    "web3.known_malicious_contract",
    "Known malicious contracts",
    (
        "Contract addresses the page called that are on the known-bad list (string "
        "web3.known_bad_addresses)."
    ),
)

signal(
    "web3.known_contracts",
    "Known malicious contract addresses",
    "The known-bad contract addresses called.",
)

signal(
    "web3.explorer_dead_drop",
    "Blockchain explorer read without a wallet",
    (
        "The page called a blockchain explorer API (string web3.explorer_api_hosts) with no "
        "wallet UI and no wallet request, on a site that is not allowlisted: a dead-drop for "
        "the next stage."
    ),
)

signal(
    "web3.explorer_api_hosts",
    "Explorer API hosts",
    "The blockchain explorer API hosts the page called.",
)

signal(
    "web3.drainer_lure",
    "Wallet drainer lure",
    (
        "A top-level page with claim, airdrop or wallet-verification wording (string "
        "web3.drainer_wording) loads a wallet library (string web3.wallet_libraries), on a "
        "site that is not allowlisted."
    ),
)

signal(
    "web3.wallet_drainer",
    "Wallet drainer signature requests",
    (
        "Requests to the sandbox's fake wallet (only when the fake-wallet profile is on) for "
        "a Permit/Permit2 signature, an unlimited approval, or approve / setApprovalForAll."
    ),
)

signal(
    "web3.wallet_requests",
    "Fake wallet requests",
    "Requests the page made to the sandbox's fake wallet (first 20).",
)


# --- detections ------------------------------------------------------------------------

detection(
    "web3_rpc_from_non_wallet_page",
    title="Blockchain read from a page with no wallet (EtherHiding)",
    severity="high",
    score=55,
    tags=["etherhiding", "web3"],
    attack=["T1102.001", "T1105", "T1189"],
    description=(
        "A page that is not a wallet/web3 app (no wallet UI, no wallet use) read a smart "
        "contract over JSON-RPC (eth_call / eth_getStorageAt). This is the EtherHiding dead- "
        "drop loader pattern. The rule fires on allowlisted sites too, because EtherHiding "
        "runs on compromised legitimate sites."
    ),
    when=sig("web3.etherhiding_rpc").is_true(),
    evidence=[
        "web3.rpc_calls",
        "final.url",
    ],
)

detection(
    "etherhiding_payload_executed",
    title="Blockchain-hosted payload decoded and run",
    severity="critical",
    score=80,
    tags=["etherhiding", "web3", "obfuscation"],
    attack=["T1102.001", "T1027", "T1059.007"],
    description=(
        "A page read a smart contract, the answer was a kilobyte-sized string, and that "
        "string (or its base64 layer) became eval/Function code. The contract is the next- "
        "stage script store (ClearFake / EtherHiding). Without the direct link, the rule "
        "needs 1 KB+ of code-only exec (innerHTML/document.write do not count). In that case, "
        "an allowlisted site also needs a fake update/CAPTCHA lure."
    ),
    when=sig("web3.rpc_result_executed").is_true(),
    evidence=[
        "web3.rpc_calls",
        "web3.rpc_large_string_results",
        "js.code_exec_max_len",
        "final.url",
    ],
)

detection(
    "web3_known_malicious_contract",
    title="Known malicious smart contract called",
    severity="high",
    score=60,
    tags=["etherhiding", "web3", "known-bad"],
    attack=["T1102.001"],
    description="The page read a smart contract address published in EtherHiding research.",
    when=sig("web3.known_malicious_contract") > 0,
    evidence=[
        "web3.known_contracts",
        "final.url",
    ],
)

detection(
    "explorer_api_dead_drop",
    title="Blockchain explorer used as a dead drop",
    severity="medium",
    score=30,
    tags=["web3", "etherhiding", "dead-drop"],
    attack=["T1102.001"],
    description=(
        "A non-allowlisted page with no wallet UI reads a block-explorer API (Ethplorer, "
        "Blockchair, Etherscan...). EtherHiding variants use this to fetch their next stage "
        "from a transaction or token note."
    ),
    when=sig("web3.explorer_dead_drop").is_true(),
    evidence=[
        "web3.explorer_api_hosts",
        "final.url",
    ],
)

detection(
    "wallet_drainer_lure",
    title="Wallet drainer lure",
    severity="medium",
    score=30,
    tags=["web3", "drainer", "phishing"],
    attack=["T1566.002", "T1656"],
    description=(
        "Claim/airdrop or wallet-verification wording on a page that loads a wallet library, "
        "served from a young, lookalike or free-hosting domain."
    ),
    when=all_of(
        sig("web3.drainer_lure").is_true(),
        any_of(
            sig("domains.final_age_days") < 60,
            sig("domains.lookalike") > 0,
            sig("final.free_hosting").present(),
        ),
    ),
    evidence=[
        "scripts.libraries",
        "domains.final_age_days",
        "final.url",
    ],
)

detection(
    "wallet_drainer_signature",
    title="Wallet drainer signature request",
    severity="high",
    score=60,
    tags=["crypto", "wallet-drainer"],
    attack=["T1657", "T1566.002"],
    description=(
        "A page asked the (instrumented) wallet to sign a Permit/approval or an unlimited "
        "token approval right after connect, on a non-allowlisted domain: a drainer."
    ),
    when=all_of(
        sig("web3.wallet_drainer") > 0,
        not_(sig("final.allowlisted").is_true()),
    ),
    evidence=[
        "web3.wallet_requests",
        "final.url",
    ],
)
