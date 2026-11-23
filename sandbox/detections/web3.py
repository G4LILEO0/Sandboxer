"""Web3: blockchain JSON-RPC calls, the long strings they return (EtherHiding), and the
fake wallet's request log. The rules in rules/web3/ decide."""

import base64
import binascii
import json
import re
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import memo, table

# --- HAR access (pure over the stored HAR) --------------------------------------------

_JSONRPC_METHODS = S.bind(globals(), "_JSONRPC_METHODS", "web3.jsonrpc_methods", S.as_set)


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
    wallet = data.result.get("wallet_requests", [])  # the fake wallet's log (A6)
    out = {
        "rpc_calls": calls[:20],
        "rpc_call_count": len(calls),
        "contract_addresses": sorted(addresses)[:20],
        "rpc_large_string_results": len(large),
        "_calls_all": calls,
        "_large_all": large,
    }
    if wallet:
        out["wallet_requests"] = wallet[:20]
    return out


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
    """Blockchain JSON-RPC calls and the contracts they read (for the report's IOCs)."""
    w = _web3_of(cap)
    return {
        "rpc_calls": w["rpc_calls"],
        "rpc_call_count": w["rpc_call_count"],
        "contract_addresses": w["contract_addresses"],
        "rpc_large_string_results": w["rpc_large_string_results"],
        **({"wallet_requests": w["wallet_requests"]} if "wallet_requests" in w else {}),
    }


# --- tables -------------------------------------------------------------------------------


@table(
    "rpc_calls",
    "Every Ethereum JSON-RPC call the page posted (methods in web3.jsonrpc_methods).",
    {
        "host": "The RPC host",
        "method": "The method (lower case)",
        "to": "The contract address called (lower case), or empty",
    },
)
def _rpc_calls(cap: Capture) -> list[Row]:
    return memo(cap, "rpc_calls", lambda: _web3_of(cap)["_calls_all"])


@table(
    "rpc_strings",
    "The long strings (512+ bytes, first 10) JSON-RPC answers returned, ABI-decoded: page-load "
    "reads on real dApps return a few 32-byte words, EtherHiding contracts return "
    "kilobytes of code.",
    {
        "value": "The decoded string",
        "executed": "True when a 64-character piece of it, or of its base64 decoding, is "
        "in code the page ran through eval or Function",
    },
)
def _rpc_strings(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        large = _web3_of(cap)["_large_all"][:10]
        return [{"value": v, "executed": _linked_exec([v], cap.data)} for v in large]

    return memo(cap, "rpc_strings", build)


@table(
    "wallet_requests",
    "Requests the page made to the sandbox's fake wallet (only when the fake-wallet "
    "profile is on).",
    {
        "method": "The wallet method",
        "primary_type": "The typed-data primary type (Permit, PermitSingle, ...), or empty",
        "unlimited": "True for an unlimited token approval",
        "selector": "The contract call's function selector (lower case), or empty",
        "detail": "The request as logged",
    },
)
def _wallet_table(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "wallet_requests",
        lambda: [
            {
                "method": str(w.get("method", "")),
                "primary_type": str(w.get("primaryType", "")),
                "unlimited": w.get("unlimited") is True,
                "selector": str(w.get("selector", "")).lower(),
                "detail": w,
            }
            for w in cap.data.result.get("wallet_requests", [])
        ],
    )


def _web3_of(cap: Capture) -> dict[str, Any]:
    return memo(cap, "web3_raw", lambda: _web3(cap.data, cap.reqs))
