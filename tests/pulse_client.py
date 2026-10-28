# SPDX-License-Identifier: Apache-2.0
"""A small client of the PulseAudio native protocol, for the tests.

``pactl`` can only send the commands it has a verb for. This client sends any command number
with any body, and any bytes at all, over a unix socket, and returns what came back. It speaks
just enough to ask a server questions: the framing of a packet and the "tag structure" that
carries the arguments. It never uses shared memory, so a stream's audio is not sent.
"""

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Self

CONTROL_CHANNEL = 0xFFFFFFFF
"""The channel of a packet that is a command or a reply, not audio."""
DESCRIPTOR_SIZE = 20
VERSION = 35
"""The protocol version the client announces; a server answers with the one it speaks."""
COOKIE_SIZE = 256

# The command numbers of the native protocol (pulsecore/native-common.h), the ones the tests send.
ERROR = 0
REPLY = 2
CREATE_PLAYBACK_STREAM = 3
CREATE_RECORD_STREAM = 5
EXIT = 7
AUTH = 8
SET_CLIENT_NAME = 9
LOOKUP_SINK = 10
LOOKUP_SOURCE = 11
STAT = 13
CREATE_UPLOAD_STREAM = 15
PLAY_SAMPLE = 18
GET_SERVER_INFO = 20
GET_SINK_INFO = 21
GET_SINK_INFO_LIST = 22
GET_SOURCE_INFO = 23
GET_SOURCE_INFO_LIST = 24
GET_MODULE_INFO_LIST = 26
GET_CLIENT_INFO = 27
GET_CLIENT_INFO_LIST = 28
GET_SINK_INPUT_INFO_LIST = 30
GET_SOURCE_OUTPUT_INFO_LIST = 32
SUBSCRIBE = 35
SET_SINK_VOLUME = 36
SET_SOURCE_VOLUME = 38
SET_SINK_MUTE = 39
SET_SOURCE_MUTE = 40
SET_DEFAULT_SINK = 44
SET_DEFAULT_SOURCE = 45
KILL_CLIENT = 48
KILL_SINK_INPUT = 49
KILL_SOURCE_OUTPUT = 50
LOAD_MODULE = 51
UNLOAD_MODULE = 52
MOVE_SINK_INPUT = 67
MOVE_SOURCE_OUTPUT = 68
SUSPEND_SINK = 70
SUSPEND_SOURCE = 71
UPDATE_CLIENT_PROPLIST = 82
REMOVE_CLIENT_PROPLIST = 85
EXTENSION = 87
GET_CARD_INFO_LIST = 89
SET_CARD_PROFILE = 90
SET_SINK_PORT = 96
SET_SOURCE_PORT = 97
SET_SOURCE_OUTPUT_VOLUME = 98
SET_SOURCE_OUTPUT_MUTE = 99

ERRORS = {
    0: "OK",
    1: "ACCESS",
    2: "COMMAND",
    3: "INVALID",
    4: "EXIST",
    5: "NOENTITY",
    6: "CONNECTIONREFUSED",
    7: "PROTOCOL",
    8: "TIMEOUT",
    9: "AUTHKEY",
    10: "INTERNAL",
    11: "CONNECTIONTERMINATED",
    12: "KILLED",
    13: "INVALIDSERVER",
    14: "MODINITFAILED",
    15: "BADSTATE",
    16: "NODATA",
    17: "VERSION",
    18: "TOOLARGE",
    19: "NOTSUPPORTED",
}
"""The error numbers a server answers with, by their names without the ``PA_ERR_`` prefix."""


class ProtocolError(Exception):
    """The server sent something that is not a packet or a tag structure."""


class ClosedError(Exception):
    """The server closed the connection."""


class Tags:
    """Build the arguments of a command: a tag structure, one typed value after another."""

    def __init__(self) -> None:
        self.data = bytearray()

    def u8(self, value: int) -> Self:
        self.data += b"B" + struct.pack(">B", value)
        return self

    def u32(self, value: int) -> Self:
        self.data += b"L" + struct.pack(">I", value)
        return self

    def string(self, value: str | None) -> Self:
        if value is None:
            self.data += b"N"
        else:
            self.data += b"t" + value.encode() + b"\0"
        return self

    def arbitrary(self, value: bytes) -> Self:
        self.data += b"x" + struct.pack(">I", len(value)) + value
        return self

    def boolean(self, *, value: bool) -> Self:
        self.data += b"1" if value else b"0"
        return self

    def proplist(self, properties: dict[str, str]) -> Self:
        self.data += b"P"
        for key, text in properties.items():
            value = text.encode() + b"\0"
            self.string(key).u32(len(value)).arbitrary(value)
        self.data += b"N"
        return self

    def cvolume(self, channels: int, volume: int) -> Self:
        self.data += b"v" + struct.pack(">B", channels) + struct.pack(">I", volume) * channels
        return self


def parse(payload: bytes) -> list[Any]:  # noqa: C901, PLR0912, PLR0915 - one branch per tag
    """Read a tag structure into a list of values (integers, strings, bytes, booleans...)."""
    values: list[Any] = []
    at = 0
    while at < len(payload):
        tag = payload[at : at + 1]
        at += 1
        if tag == b"L":
            values.append(struct.unpack(">I", payload[at : at + 4])[0])
            at += 4
        elif tag == b"B":
            values.append(payload[at])
            at += 1
        elif tag in {b"r", b"R", b"U"}:
            values.append(struct.unpack(">Q", payload[at : at + 8])[0])
            at += 8
        elif tag == b"t":
            end = payload.index(b"\0", at)
            values.append(payload[at:end].decode(errors="replace"))
            at = end + 1
        elif tag == b"N":
            values.append(None)
        elif tag == b"x":
            size = struct.unpack(">I", payload[at : at + 4])[0]
            values.append(payload[at + 4 : at + 4 + size])
            at += 4 + size
        elif tag in {b"1", b"0"}:
            values.append(tag == b"1")
        elif tag == b"a":
            values.append(("sample-spec", payload[at], payload[at + 1]))
            at += 6
        elif tag == b"m":
            values.append(("channel-map", payload[at]))
            at += 1 + payload[at]
        elif tag == b"v":
            count = payload[at]
            values.append(("cvolume", count))
            at += 1 + 4 * count
        elif tag == b"V":
            values.append(("volume", struct.unpack(">I", payload[at : at + 4])[0]))
            at += 4
        elif tag == b"T":
            at += 8
        elif tag == b"P":
            properties: dict[str, bytes] = {}
            while payload[at : at + 1] != b"N":
                parts = parse_property(payload, at)
                properties[parts[0]] = parts[1]
                at = parts[2]
            at += 1
            values.append(properties)
        elif tag == b"f":
            at, info = _format_info(payload, at)
            values.append(info)
        else:
            message = f"unknown tag {tag!r} at {at - 1}"
            raise ProtocolError(message)
    return values


def parse_property(payload: bytes, at: int) -> tuple[str, bytes, int]:
    """Read one property of a property list at ``at``: its key, value and where the next starts."""
    if payload[at : at + 1] != b"t":
        message = "a property starts with a string"
        raise ProtocolError(message)
    end = payload.index(b"\0", at + 1)
    key = payload[at + 1 : end].decode(errors="replace")
    at = end + 1
    if payload[at : at + 1] != b"L" or payload[at + 5 : at + 6] != b"x":
        message = "a property has a length and a value"
        raise ProtocolError(message)
    size = struct.unpack(">I", payload[at + 6 : at + 10])[0]
    return key, payload[at + 10 : at + 10 + size], at + 10 + size


def _format_info(payload: bytes, at: int) -> tuple[int, Any]:
    """Skip a format-info value (an encoding byte and a property list); return where it ends."""
    if payload[at : at + 1] != b"B":
        message = "a format starts with its encoding"
        raise ProtocolError(message)
    at += 2
    if payload[at : at + 1] != b"P":
        message = "a format has a property list"
        raise ProtocolError(message)
    at += 1
    while payload[at : at + 1] != b"N":
        at = parse_property(payload, at)[2]
    return at + 1, "format"


@dataclass(slots=True)
class Answer:
    """What a server said to one command: ``REPLY`` or ``ERROR``, and the values after the tag."""

    command: int
    values: list[Any]
    events: list[tuple[int, list[Any]]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Tell whether the command succeeded."""
        return self.command == REPLY

    @property
    def error(self) -> str | None:
        """The name of the error, or ``None`` after a reply."""
        if self.command != ERROR:
            return None
        code = self.values[0] if self.values else -1
        return ERRORS.get(code, str(code))


class PulseClient:
    """One connection to a PulseAudio native-protocol socket."""

    def __init__(self, path: Path, *, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        self._socket.connect(str(path))
        self._tag = 0
        self._buffer = b""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection."""
        self._socket.close()

    # -- packets --

    def send_raw(self, data: bytes) -> None:
        """Send ``data`` as it is."""
        self._socket.sendall(data)

    def send_packet(self, body: bytes, channel: int = CONTROL_CHANNEL) -> None:
        """Send a packet: its descriptor, and ``body``."""
        descriptor = struct.pack(">IIIII", len(body), channel, 0, 0, 0)
        self.send_raw(descriptor + body)

    def _read(self, size: int) -> bytes:
        while len(self._buffer) < size:
            chunk = self._socket.recv(65536)
            if not chunk:
                raise ClosedError
            self._buffer += chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def read_packet(self) -> tuple[int, bytes]:
        """Return the channel and the body of the next packet.

        Raises:
            ClosedError: when the server closes the connection before one arrives.
            TimeoutError: when none arrives in time.

        """
        length, channel, _high, _low, _flags = struct.unpack(">IIIII", self._read(DESCRIPTOR_SIZE))
        return channel, self._read(length)

    def next_tag(self) -> int:
        """Return a tag for a command that has none yet."""
        self._tag += 1
        return self._tag

    # -- commands --

    def command(
        self, number: int, arguments: Tags | bytes = b"", *, tag: int | None = None
    ) -> Answer:
        """Send command ``number`` with ``arguments`` and return the answer carrying its tag.

        Packets that are not the answer (events a server pushes) are kept in ``events``.
        """
        tag = self.next_tag() if tag is None else tag
        body = Tags().u32(number).u32(tag).data + (
            arguments.data if isinstance(arguments, Tags) else arguments
        )
        self.send_packet(bytes(body))
        events: list[tuple[int, list[Any]]] = []
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            channel, payload = self.read_packet()
            if channel != CONTROL_CHANNEL:
                continue
            values = parse(payload)
            if len(values) >= 2 and values[1] == tag and values[0] in {REPLY, ERROR}:
                return Answer(values[0], values[2:], events)
            events.append((values[0], values[1:]))
        raise TimeoutError

    def authenticate(self) -> Answer:
        """Send ``AUTH`` with an empty cookie, as a client with none does."""
        return self.command(AUTH, Tags().u32(VERSION).arbitrary(b"\0" * COOKIE_SIZE))

    def name(self, properties: dict[str, str]) -> Answer:
        """Send ``SET_CLIENT_NAME`` with ``properties``."""
        return self.command(SET_CLIENT_NAME, Tags().proplist(properties))
