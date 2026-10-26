# SPDX-License-Identifier: Apache-2.0
import asyncio
import contextlib
import json
from typing import TYPE_CHECKING, Any

import pytest

from valetkey.client import Client, DaemonError, is_running

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable
    from pathlib import Path


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 30))


@contextlib.asynccontextmanager
async def fake_daemon(
    path: Path,
    behave: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
) -> AsyncGenerator[None]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await behave(reader, writer)
        finally:
            writer.close()

    server = await asyncio.start_unix_server(handle, path=str(path))
    try:
        yield
    finally:
        server.close()
        server.close_clients()
        await server.wait_closed()


def test_a_missing_daemon_is_not_running(short_dir: Path) -> None:
    path = short_dir / "none.sock"

    async def scenario() -> None:
        assert not await is_running(path)
        with pytest.raises(DaemonError) as info:
            await Client.connect(path)
        assert info.value.code == "not_running"
        assert str(path) in info.value.message

    run(scenario())


def test_calls_return_results_and_raise_errors(short_dir: Path) -> None:
    path = short_dir / "d.sock"
    received: list[dict[str, Any]] = []

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while line := await reader.readline():
            request = json.loads(line)
            received.append(request)
            if request["op"] == "fail":
                answer = {
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "unknown_site", "message": "no", "details": {"x": 1}},
                }
            elif request["op"] == "bare":
                answer = {"id": request["id"], "ok": False}
            else:
                answer = {"id": request["id"], "ok": True, "result": {"echo": request["args"]}}
            writer.write(json.dumps(answer).encode() + b"\n")

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            assert await is_running(path)
            assert await c.call("open", site="sitex") == {"echo": {"site": "sitex"}}
            assert await c.call("sites") == {"echo": {}}
            with pytest.raises(DaemonError) as info:
                await c.call("fail")
            assert (info.value.code, info.value.message, info.value.details) == (
                "unknown_site",
                "no",
                {"x": 1},
            )
            with pytest.raises(DaemonError) as info:
                await c.call("bare")
            assert info.value.code == "error"
        assert [r["id"] for r in received] == [1, 2, 3, 4, 5, 6][: len(received)]
        assert received[0] == {"id": 1, "op": "open", "args": {"site": "sitex"}}

    run(scenario())


def test_answers_are_matched_by_id_in_any_order(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        first = json.loads(await reader.readline())
        second = json.loads(await reader.readline())
        for request in (second, first):
            answer = {"id": request["id"], "ok": True, "result": {"op": request["op"]}}
            writer.write(json.dumps(answer).encode() + b"\n")
        await reader.read()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            one, two = await asyncio.gather(c.call("a"), c.call("b"))
            assert (one, two) == ({"op": "a"}, {"op": "b"})

    run(scenario())


def test_stray_and_garbled_answers_are_ignored(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        writer.write(b"not json\n")
        writer.write(b"[1]\n")
        writer.write(b'{"no": "id"}\n')
        writer.write(b'{"id": 999, "ok": true, "result": {}}\n')
        writer.write(json.dumps({"id": request["id"], "ok": True, "result": None}).encode() + b"\n")
        writer.write(
            json.dumps({"id": request["id"], "ok": True, "result": {"late": 1}}).encode() + b"\n"
        )
        await reader.read()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            assert await c.call("x") == {}

    run(scenario())


def test_a_dropped_connection_fails_waiting_calls(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()
        writer.close()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            with pytest.raises(DaemonError) as info:
                await c.call("x")
            assert info.value.code == "connection_lost"
            with pytest.raises(DaemonError) as info:
                await c.call("y")
            assert info.value.code == "connection_lost"

    run(scenario())


def test_closing_fails_calls_still_waiting(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, _writer: asyncio.StreamWriter) -> None:
        await reader.read()

    async def scenario() -> None:
        async with fake_daemon(path, behave):
            c = await Client.connect(path)
            waiting = asyncio.ensure_future(c.call("x"))
            await asyncio.sleep(0.1)
            await c.close()
            with pytest.raises(DaemonError) as info:
                await waiting
            assert info.value.code == "connection_lost"

    run(scenario())


def test_an_oversized_answer_ends_the_connection(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = short_dir / "d.sock"
    monkeypatch.setattr("valetkey.client._READ_LIMIT", 1000)

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        writer.write(
            json.dumps({"id": request["id"], "ok": True, "result": {"t": "a" * 5000}}).encode()
            + b"\n"
        )
        await reader.read()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            with pytest.raises(DaemonError) as info:
                await c.call("x")
            assert info.value.code == "connection_lost"

    run(scenario())


def test_writing_to_a_dead_connection_is_connection_lost(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    async def scenario() -> None:
        async with fake_daemon(path, behave):
            c = await Client.connect(path)
            await asyncio.sleep(0.2)
            codes = []
            for _ in range(50):
                try:
                    await c.call("x")
                except DaemonError as error:
                    codes.append(error.code)
                    break
                await asyncio.sleep(0.01)
            assert codes == ["connection_lost"]
            await c.close()

    run(scenario())


def test_an_answer_that_arrives_just_before_the_connection_ends_is_kept(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        writer.write(
            json.dumps({"id": request["id"], "ok": True, "result": {"a": 1}}).encode() + b"\n"
        )

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            assert await c.call("x") == {"a": 1}

    run(scenario())


def test_watch_streams_the_snapshot_and_then_each_change(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        assert (request["op"], request["args"]) == ("watch", {})
        for result in (
            {"event": "snapshot", "sessions": [], "logins": []},
            {"event": "session_started", "site": "sitex"},
            {"event": "session_ended", "site": "sitex"},
        ):
            writer.write(json.dumps({"id": request["id"], "ok": True, "result": result}).encode())
            writer.write(b"\n")
        await writer.drain()
        await reader.read()  # stays open until the client leaves

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            stream = c.watch()
            events = [(await anext(stream))["event"] for _ in range(3)]
            assert events == ["snapshot", "session_started", "session_ended"]
            await stream.aclose()
            assert not c._streams  # noqa: SLF001

    run(scenario())


def test_watch_raises_the_daemons_error(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        error = {"code": "unknown_op", "message": "no such operation: watch"}
        writer.write(
            json.dumps({"id": request["id"], "ok": False, "error": error}).encode() + b"\n"
        )
        await writer.drain()
        await reader.read()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            with pytest.raises(DaemonError) as info:
                await anext(c.watch())
            assert info.value.code == "unknown_op"

    run(scenario())


def test_watch_ends_with_connection_lost_when_the_daemon_goes(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        result = {"event": "snapshot", "sessions": [], "logins": []}
        writer.write(json.dumps({"id": request["id"], "ok": True, "result": result}).encode())
        writer.write(b"\n")
        await writer.drain()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            stream = c.watch()
            assert (await anext(stream))["event"] == "snapshot"
            with pytest.raises(DaemonError) as info:
                await anext(stream)
            assert info.value.code == "connection_lost"

    run(scenario())


def test_watch_on_a_closed_connection_is_connection_lost(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(_reader: asyncio.StreamReader, _writer: asyncio.StreamWriter) -> None:
        return

    async def scenario() -> None:
        async with fake_daemon(path, behave):
            c = await Client.connect(path)
            await asyncio.sleep(0.05)
            c._writer.close()  # noqa: SLF001
            with pytest.raises(DaemonError) as info:
                await anext(c.watch())
            assert info.value.code == "connection_lost"
            await c.close()

    run(scenario())


def test_an_error_answer_for_nothing_this_client_asked_is_ignored(short_dir: Path) -> None:
    path = short_dir / "d.sock"

    async def behave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = json.loads(await reader.readline())
        stray = {"id": 999, "ok": False, "error": {"code": "x", "message": "y"}}
        writer.write(json.dumps(stray).encode() + b"\n")
        writer.write(json.dumps({"id": request["id"], "ok": True, "result": {"a": 1}}).encode())
        writer.write(b"\n")
        await writer.drain()
        await reader.read()

    async def scenario() -> None:
        async with fake_daemon(path, behave), await Client.connect(path) as c:
            assert await c.call("x") == {"a": 1}

    run(scenario())
