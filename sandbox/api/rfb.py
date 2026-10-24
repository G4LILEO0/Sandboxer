"""Filter the VNC (RFB 3.8) client-to-server stream for read-only observers (INT-8).

After the handshake, client messages are length-prefixed by type. Observers may ask for
screen updates and set formats, but keyboard, pointer, clipboard and resize messages are
dropped here, on the server, so view-only cannot be bypassed from the browser. Unknown
message types end the connection rather than being guessed at.
"""

_HANDSHAKE = 12 + 1 + 16 + 1  # ProtocolVersion, security type, VNC auth response, ClientInit
_ALLOWED = {0, 2, 3, 150, 248}  # SetPixelFormat, SetEncodings, UpdateRequest, ContUpdates, Fence
_DROPPED = {4, 5, 6, 251}  # KeyEvent, PointerEvent, ClientCutText, SetDesktopSize


class ProtocolError(Exception):
    pass


def _message_length(buf: bytes) -> int | None:
    """Total length of the message at the start of ``buf``, or None if incomplete."""
    kind = buf[0]
    fixed = {0: 20, 3: 10, 4: 8, 5: 6, 150: 10}
    if kind in fixed:
        return fixed[kind]
    if kind == 2:  # SetEncodings: 4 + 4 * count
        return None if len(buf) < 4 else 4 + 4 * int.from_bytes(buf[2:4], "big")
    if kind == 6:  # ClientCutText: 8 + length
        return None if len(buf) < 8 else 8 + int.from_bytes(buf[4:8], "big")
    if kind == 248:  # ClientFence: 9 + payload length
        return None if len(buf) < 9 else 9 + buf[8]
    if kind == 251:  # SetDesktopSize: 8 + 16 * screens
        return None if len(buf) < 8 else 8 + 16 * buf[6]
    raise ProtocolError(f"Unsupported client message type {kind}")


class ViewOnlyFilter:
    def __init__(self) -> None:
        self.handshake_left = _HANDSHAKE
        self.buffer = b""

    def feed(self, data: bytes) -> bytes:
        """Return the bytes that may be forwarded to the server."""
        out = b""
        if self.handshake_left:
            take = data[: self.handshake_left]
            out += take
            self.handshake_left -= len(take)
            data = data[len(take) :]
        self.buffer += data
        while self.buffer:
            length = _message_length(self.buffer)
            if length is None or len(self.buffer) < length:
                break
            message, self.buffer = self.buffer[:length], self.buffer[length:]
            if message[0] in _ALLOWED:
                out += message
            elif message[0] not in _DROPPED:
                raise ProtocolError(f"Unexpected message type {message[0]}")
        return out
