import time

import pytest

from sandbox.api import tokens
from sandbox.api.rfb import ProtocolError, ViewOnlyFilter
from sandbox.orchestrator.webhooks import sign

HANDSHAKE = b"RFB 003.008\n" + b"\x02" + b"A" * 16 + b"\x01"


def test_token_roundtrip_and_tamper():
    token = tokens.issue("k", "stream", 60, sid="se_1")
    assert tokens.verify("k", "stream", token)["sid"] == "se_1"
    with pytest.raises(tokens.TokenError):
        tokens.verify("other-key", "stream", token)
    with pytest.raises(tokens.TokenError):
        tokens.verify("k", "download", token)  # a stream token is not a download token
    body, mac = token.split(".")
    with pytest.raises(tokens.TokenError):
        tokens.verify("k", "stream", body[:-2] + "AA." + mac)


def test_token_expiry(monkeypatch):
    token = tokens.issue("k", "embed", 10)
    monkeypatch.setattr(time, "time", lambda: 10**12)
    with pytest.raises(tokens.TokenError, match="expired"):
        tokens.verify("k", "embed", token)


def test_api_token_hash_is_stable():
    token, digest = tokens.new_api_token()
    assert token.startswith("sbx_") and tokens.hash_api_token(token) == digest


def test_view_only_filter_drops_input_keeps_updates():
    f = ViewOnlyFilter()
    assert f.feed(HANDSHAKE) == HANDSHAKE
    update = b"\x03\x00" + b"\x00" * 8  # FramebufferUpdateRequest
    key = b"\x04\x01\x00\x00\x00\x00\x00\x41"  # KeyEvent
    pointer = b"\x05\x01\x00\x10\x00\x10"  # PointerEvent
    cut = b"\x06\x00\x00\x00\x00\x00\x00\x03abc"  # ClientCutText
    assert f.feed(update + key + pointer + cut + update) == update + update


def test_view_only_filter_handles_split_messages():
    f = ViewOnlyFilter()
    f.feed(HANDSHAKE)
    encodings = b"\x02\x00\x00\x02" + b"\x00\x00\x00\x07" + b"\xff\xff\xff\x21"
    assert f.feed(encodings[:5]) == b""
    assert f.feed(encodings[5:]) == encodings


def test_view_only_filter_rejects_unknown_messages():
    f = ViewOnlyFilter()
    f.feed(HANDSHAKE)
    with pytest.raises(ProtocolError):
        f.feed(b"\x7f" + b"\x00" * 10)


def test_webhook_signature():
    assert sign("s", "100", b"{}") == sign("s", "100", b"{}")
    assert sign("s", "100", b"{}") != sign("s", "101", b"{}")
    assert sign("s", "100", b"{}").startswith("sha256=")
