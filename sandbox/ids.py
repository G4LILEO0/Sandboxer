"""Prefixed, time-sortable identifiers such as ``an_01J9...``."""

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_id(prefix: str) -> str:
    """Return ``prefix_`` followed by a 26-character ULID (48-bit ms time + 80 random bits)."""
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        value, rem = divmod(value, 32)
        chars.append(_CROCKFORD[rem])
    return f"{prefix}_{''.join(reversed(chars))}"
