# SPDX-License-Identifier: Apache-2.0
"""The WebSocket protocol (RFC 6455) as far as a gateway needs it, with the standard library.

A browser viewer talks to :mod:`valetkey.gateway` over a WebSocket, and the gateway passes the
bytes on to a VNC server. That needs the opening handshake, frames in both directions, and the
control frames (ping, pong, close). Compression and extensions are never negotiated.

A client must mask every frame it sends and a server must not mask the ones it sends. A frame
that breaks a rule of the protocol raises :class:`ProtocolError`, and the connection is closed
with the status code the error carries.
"""

import base64
import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
"""The constant of RFC 6455 section 1.3, mixed into the handshake."""
MAX_PAYLOAD = 8 * 1024 * 1024
"""The largest message accepted. A VNC client sends small messages; a clipboard is the largest."""
MAX_CONTROL = 125
_SHORT = 125
_MEDIUM = 126
_LONG = 127
_SHORT_LIMIT = 0xFFFF


class Opcode(IntEnum):
    """The frame types of RFC 6455 section 5.2."""

    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class Status(IntEnum):
    """The close status codes this module sends."""

    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED = 1003
    INVALID_DATA = 1007
    TOO_BIG = 1009


class ProtocolError(Exception):
    """The peer broke the protocol; ``status`` is the close code to answer with."""

    def __init__(self, message: str, status: Status = Status.PROTOCOL_ERROR) -> None:
        """Keep the message and the close status."""
        super().__init__(message)
        self.status = status


@dataclass(frozen=True, slots=True)
class Frame:
    """One frame as it came off the wire, already unmasked."""

    opcode: Opcode
    payload: bytes
    final: bool


def accept_key(key: str) -> str:
    """Return the ``Sec-WebSocket-Accept`` value for a client's ``Sec-WebSocket-Key``."""
    digest = hashlib.sha1((key + GUID).encode("ascii"), usedforsecurity=False).digest()
    return base64.b64encode(digest).decode("ascii")


def valid_key(key: str) -> bool:
    """Tell whether ``key`` is what a client sends: 16 random bytes in base64."""
    try:
        return len(base64.b64decode(key, validate=True)) == 16  # noqa: PLR2004 - RFC 6455 4.1
    except ValueError:
        return False


def encode_frame(opcode: Opcode, payload: bytes = b"", *, mask: bytes | None = None) -> bytes:
    """Return one final frame. A server sends it unmasked; ``mask`` (four bytes) is for clients.

    Raises:
        ValueError: for a control frame longer than 125 bytes, or a mask that is not four bytes.

    """
    if opcode >= Opcode.CLOSE and len(payload) > MAX_CONTROL:
        message = "a control frame carries at most 125 bytes"
        raise ValueError(message)
    if mask is not None and len(mask) != 4:  # noqa: PLR2004 - a mask is four bytes
        message = "a mask is four bytes"
        raise ValueError(message)
    length = len(payload)
    flag = 0x80 if mask is not None else 0
    header = bytes([0x80 | opcode])
    if length <= _SHORT:
        header += bytes([flag | length])
    elif length <= _SHORT_LIMIT:
        header += bytes([flag | _MEDIUM]) + length.to_bytes(2, "big")
    else:
        header += bytes([flag | _LONG]) + length.to_bytes(8, "big")
    if mask is None:
        return header + payload
    return header + mask + unmask(payload, mask)


def unmask(payload: bytes, mask: bytes) -> bytes:
    """Return ``payload`` XOR-ed with the four-byte ``mask``, which is its own inverse."""
    if not payload:
        return payload
    repeated = (mask * (len(payload) // 4 + 1))[: len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(
        len(payload), "big"
    )


def close_payload(status: int, reason: str = "") -> bytes:
    """Return the body of a close frame: the status code and a short reason."""
    return status.to_bytes(2, "big") + reason.encode()[: MAX_CONTROL - 2]


async def read_frame(reader: asyncio.StreamReader, *, limit: int = MAX_PAYLOAD) -> Frame:
    """Read one client frame and unmask it.

    Raises:
        ProtocolError: for an unmasked frame, a reserved bit, an unknown opcode, a fragmented or
            oversized control frame, or a payload longer than ``limit`` (status 1009).
        asyncio.IncompleteReadError: when the stream ends inside a frame.

    """
    first, second = await reader.readexactly(2)
    if first & 0x70:
        message = "reserved bits are set, and no extension was negotiated"
        raise ProtocolError(message)
    try:
        opcode = Opcode(first & 0x0F)
    except ValueError:
        message = f"unknown opcode {first & 0x0F}"
        raise ProtocolError(message) from None
    final = bool(first & 0x80)
    if not second & 0x80:
        message = "a client must mask every frame"
        raise ProtocolError(message)
    length = second & 0x7F
    if length == _MEDIUM:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == _LONG:
        length = int.from_bytes(await reader.readexactly(8), "big")
    if opcode >= Opcode.CLOSE and (not final or length > MAX_CONTROL):
        message = "a control frame is never fragmented and carries at most 125 bytes"
        raise ProtocolError(message)
    if length > limit:
        message = f"a payload of {length} bytes is over the limit of {limit}"
        raise ProtocolError(message, Status.TOO_BIG)
    mask = await reader.readexactly(4)
    return Frame(opcode, unmask(await reader.readexactly(length), mask), final=final)


class _Message:
    """Puts the data frames of one message together and checks their order."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._first: Opcode | None = None
        self._parts: list[bytes] = []

    def add(self, frame: Frame) -> tuple[Opcode, bytes] | None:
        """Add a data frame; return the whole message when this one was the last."""
        if self._first is None:
            if frame.opcode is Opcode.CONTINUATION:
                message = "a continuation frame with nothing to continue"
                raise ProtocolError(message)
            self._first = frame.opcode
        elif frame.opcode is not Opcode.CONTINUATION:
            message = "a new message began before the last one ended"
            raise ProtocolError(message)
        self._parts.append(frame.payload)
        if sum(map(len, self._parts)) > self._limit:
            message = f"a message over the limit of {self._limit} bytes"
            raise ProtocolError(message, Status.TOO_BIG)
        if not frame.final:
            return None
        payload = b"".join(self._parts)
        if self._first is Opcode.TEXT:
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError:
                message = "a text message that is not UTF-8"
                raise ProtocolError(message, Status.INVALID_DATA) from None
        return self._first, payload


async def read_message(
    reader: asyncio.StreamReader, send: asyncio.StreamWriter, *, limit: int = MAX_PAYLOAD
) -> tuple[Opcode, bytes] | None:
    """Read the next whole data message, answering pings on the way.

    A message sent in fragments is put together. Returns ``(opcode, payload)`` with the opcode
    of its first frame, or ``None`` when the peer closed (its close frame is answered here).
    A pong is ignored.

    Raises:
        ProtocolError: for a protocol violation, including a text message that is not UTF-8
            (status 1007).

    """
    message = _Message(limit)
    while True:
        frame = await read_frame(reader, limit=limit)
        if frame.opcode is Opcode.PING:
            send.write(encode_frame(Opcode.PONG, frame.payload))
            await send.drain()
        elif frame.opcode is Opcode.CLOSE:
            send.write(encode_frame(Opcode.CLOSE, frame.payload[:2]))
            await send.drain()
            return None
        elif frame.opcode is not Opcode.PONG and (done := message.add(frame)) is not None:
            return done
