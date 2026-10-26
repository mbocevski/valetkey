# SPDX-License-Identifier: Apache-2.0
import asyncio
import os
import time
from typing import TYPE_CHECKING, Any

import pytest

from valetkey import websocket
from valetkey.websocket import Frame, Opcode, ProtocolError, Status

if TYPE_CHECKING:
    from collections.abc import Coroutine

MASK = b"\x01\x02\x03\x04"


class Sink:
    """What a server writes back, recorded."""

    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None


def reader_of(*chunks: bytes, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    for chunk in chunks:
        reader.feed_data(chunk)
    if eof:
        reader.feed_eof()
    return reader


def client_frame(
    opcode: Opcode, payload: bytes = b"", *, final: bool = True, mask: bytes = MASK
) -> bytes:
    frame = bytearray(websocket.encode_frame(opcode, payload, mask=mask))
    if not final:
        frame[0] &= 0x7F
    return bytes(frame)


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(asyncio.wait_for(coroutine, 10))


async def frame_of(*chunks: bytes, limit: int = 1000) -> Frame:
    return await websocket.read_frame(reader_of(*chunks), limit=limit)


async def whole_message(sink: Sink, *chunks: bytes, limit: int) -> tuple[Opcode, bytes] | None:
    return await websocket.read_message(reader_of(*chunks), sink, limit=limit)  # ty: ignore[invalid-argument-type]


def test_the_accept_key_is_the_one_in_the_rfc() -> None:
    assert websocket.accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


@pytest.mark.parametrize(
    ("key", "valid"),
    [
        ("dGhlIHNhbXBsZSBub25jZQ==", True),
        ("c2hvcnQ=", False),
        ("not base64!", False),
        ("", False),
    ],
)
def test_a_client_key_is_sixteen_bytes_of_base64(key: str, *, valid: bool) -> None:
    assert websocket.valid_key(key) is valid


@pytest.mark.parametrize(
    ("size", "header"),
    [
        (0, b"\x82\x00"),
        (125, b"\x82\x7d"),
        (126, b"\x82\x7e\x00\x7e"),
        (65535, b"\x82\x7e\xff\xff"),
    ],
)
def test_server_frames_are_unmasked_with_the_shortest_length(size: int, header: bytes) -> None:
    frame = websocket.encode_frame(Opcode.BINARY, b"x" * size)
    assert frame[: len(header)] == header
    assert frame[len(header) :] == b"x" * size


def test_a_long_frame_uses_eight_length_bytes() -> None:
    frame = websocket.encode_frame(Opcode.BINARY, b"x" * 65536)
    assert frame[:10] == b"\x82\x7f" + (65536).to_bytes(8, "big")


def test_a_client_frame_is_masked_and_unmasks_back() -> None:
    frame = websocket.encode_frame(Opcode.BINARY, b"hello", mask=MASK)
    assert frame[:2] == b"\x82\x85"
    assert frame[2:6] == MASK
    assert websocket.unmask(frame[6:], MASK) == b"hello"
    assert websocket.unmask(b"", MASK) == b""


def test_a_control_frame_is_never_longer_than_125_bytes() -> None:
    with pytest.raises(ValueError, match="at most 125"):
        websocket.encode_frame(Opcode.PING, b"x" * 126)
    assert websocket.encode_frame(Opcode.PING, b"x" * 125)


def test_a_mask_is_four_bytes() -> None:
    with pytest.raises(ValueError, match="four bytes"):
        websocket.encode_frame(Opcode.BINARY, b"x", mask=b"123")


def test_close_payload_has_the_status_and_a_short_reason() -> None:
    assert websocket.close_payload(1000) == b"\x03\xe8"
    assert websocket.close_payload(1002, "bad") == b"\x03\xeabad"
    assert len(websocket.close_payload(1000, "r" * 500)) == 125


@pytest.mark.parametrize("size", [0, 5, 126, 70000])
def test_read_frame_reads_every_length_form(size: int) -> None:
    payload = os.urandom(size)
    frame = run(frame_of(client_frame(Opcode.BINARY, payload), limit=100000))
    assert frame == Frame(Opcode.BINARY, payload, final=True)


def test_read_frame_reports_a_fragment() -> None:
    frame = run(frame_of(client_frame(Opcode.TEXT, b"a", final=False)))
    assert not frame.final


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (websocket.encode_frame(Opcode.BINARY, b"x"), "must mask"),
        (bytes([0xC2, 0x80]) + MASK, "reserved bits"),
        (bytes([0x83, 0x80]) + MASK, "unknown opcode"),
        (client_frame(Opcode.PING, b"x", final=False), "never fragmented"),
        (bytes([0x89, 0xFE, 0x00, 0x7E]) + MASK, "never fragmented"),
    ],
)
def test_read_frame_refuses_what_the_protocol_forbids(data: bytes, message: str) -> None:
    with pytest.raises(ProtocolError, match=message) as info:
        run(frame_of(data))
    assert info.value.status is Status.PROTOCOL_ERROR


def test_read_frame_refuses_a_payload_over_the_limit() -> None:
    with pytest.raises(ProtocolError) as info:
        run(frame_of(client_frame(Opcode.BINARY, b"x" * 11), limit=10))
    assert info.value.status is Status.TOO_BIG


def test_read_frame_fails_when_the_stream_ends_inside_a_frame() -> None:
    with pytest.raises(asyncio.IncompleteReadError):
        run(frame_of(client_frame(Opcode.BINARY, b"hello")[:4]))


def message_of(*frames: bytes, limit: int = 1000) -> tuple[object, Sink]:
    sink = Sink()
    return run(whole_message(sink, *frames, limit=limit)), sink


def test_a_whole_message_comes_back_with_its_opcode() -> None:
    result, sink = message_of(client_frame(Opcode.BINARY, b"data"))
    assert result == (Opcode.BINARY, b"data")
    assert sink.data == b""


def test_fragments_are_put_together() -> None:
    result, _ = message_of(
        client_frame(Opcode.BINARY, b"one ", final=False),
        client_frame(Opcode.CONTINUATION, b"two ", final=False),
        client_frame(Opcode.CONTINUATION, b"three"),
    )
    assert result == (Opcode.BINARY, b"one two three")


def test_a_ping_in_the_middle_is_answered_with_a_pong() -> None:
    result, sink = message_of(
        client_frame(Opcode.BINARY, b"a", final=False),
        client_frame(Opcode.PING, b"are you there"),
        client_frame(Opcode.CONTINUATION, b"b"),
    )
    assert result == (Opcode.BINARY, b"ab")
    assert sink.data == websocket.encode_frame(Opcode.PONG, b"are you there")


def test_a_pong_is_ignored() -> None:
    result, sink = message_of(client_frame(Opcode.PONG, b"x"), client_frame(Opcode.TEXT, b"hi"))
    assert result == (Opcode.TEXT, b"hi")
    assert sink.data == b""


def test_a_close_frame_ends_the_conversation_and_is_answered() -> None:
    result, sink = message_of(client_frame(Opcode.CLOSE, websocket.close_payload(1000, "bye")))
    assert result is None
    assert sink.data == websocket.encode_frame(Opcode.CLOSE, b"\x03\xe8")


def test_a_continuation_with_nothing_to_continue_is_refused() -> None:
    with pytest.raises(ProtocolError, match="nothing to continue"):
        message_of(client_frame(Opcode.CONTINUATION, b"x"))


def test_a_new_message_before_the_last_one_ended_is_refused() -> None:
    with pytest.raises(ProtocolError, match="before the last one ended"):
        message_of(
            client_frame(Opcode.BINARY, b"a", final=False), client_frame(Opcode.BINARY, b"b")
        )


def test_fragments_together_over_the_limit_are_refused() -> None:
    with pytest.raises(ProtocolError) as info:
        message_of(
            client_frame(Opcode.BINARY, b"x" * 6, final=False),
            client_frame(Opcode.CONTINUATION, b"x" * 6),
            limit=10,
        )
    assert info.value.status is Status.TOO_BIG


def test_text_must_be_utf8() -> None:
    with pytest.raises(ProtocolError) as info:
        message_of(client_frame(Opcode.TEXT, b"\xff\xfe"))
    assert info.value.status is Status.INVALID_DATA
    result, _ = message_of(client_frame(Opcode.TEXT, "héllo".encode()))
    assert result == (Opcode.TEXT, "héllo".encode())


def test_a_flood_of_empty_fragments_is_refused_quickly() -> None:
    frames = [client_frame(Opcode.BINARY, b"", final=False)]
    frames += [client_frame(Opcode.CONTINUATION, b"", final=False)] * 40_000
    started = time.perf_counter()
    with pytest.raises(ProtocolError, match="more than 1000 fragments") as info:
        message_of(*frames, limit=websocket.MAX_PAYLOAD)
    assert info.value.status is Status.TOO_BIG
    assert time.perf_counter() - started < 1.0


def test_a_message_of_the_most_fragments_allowed_comes_through() -> None:
    frames = [client_frame(Opcode.BINARY, b"a", final=False)]
    frames += [client_frame(Opcode.CONTINUATION, b"b", final=False)] * (websocket.MAX_FRAGMENTS - 2)
    frames.append(client_frame(Opcode.CONTINUATION, b"c"))
    result, _ = message_of(*frames)
    assert result == (Opcode.BINARY, b"a" + b"b" * (websocket.MAX_FRAGMENTS - 2) + b"c")


def test_the_running_size_still_stops_a_message_over_the_limit_across_many_fragments() -> None:
    frames = [client_frame(Opcode.BINARY, b"xx", final=False)]
    frames += [client_frame(Opcode.CONTINUATION, b"xx", final=False)] * 10
    with pytest.raises(ProtocolError, match="over the limit of 10 bytes") as info:
        message_of(*frames, limit=10)
    assert info.value.status is Status.TOO_BIG


def test_every_frame_is_reported_as_a_sign_of_life() -> None:
    seen: list[int] = []

    async def scenario() -> None:
        reader = reader_of(
            client_frame(Opcode.PONG, b"x"),
            client_frame(Opcode.PING, b""),
            client_frame(Opcode.TEXT, b"hi"),
        )
        await websocket.read_message(
            reader,
            Sink(),  # ty: ignore[invalid-argument-type]
            on_frame=lambda: seen.append(1),
        )

    run(scenario())
    assert seen == [1, 1, 1]
