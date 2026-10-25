# SPDX-License-Identifier: Apache-2.0

import asyncio
import contextlib
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from valetkey import nsbridge

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator


@pytest.fixture
def socket_path() -> Iterator[Path]:
    # Unix socket paths are limited to about 100 bytes, which pytest's temporary paths can exceed.
    with tempfile.TemporaryDirectory(prefix="nsb-") as directory:
        yield Path(directory) / "s.sock"


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    writer.write_eof()
    writer.close()


async def _with_bridge(
    socket_path: Path,
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    scenario: Callable[[int], Awaitable[None]],
) -> None:
    upstream = await asyncio.start_unix_server(handler, str(socket_path))
    bridge = await nsbridge.serve("127.0.0.1", 0, str(socket_path))
    port = bridge.sockets[0].getsockname()[1]
    try:
        await scenario(port)
    finally:
        for server in (bridge, upstream):
            server.close()
            await server.wait_closed()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("127.0.0.1:3128", ("127.0.0.1", 3128)), ("localhost:0", ("localhost", 0))],
)
def test_parse_listen(value: str, expected: tuple[str, int]) -> None:
    assert nsbridge.parse_listen(value) == expected


@pytest.mark.parametrize("value", ["3128", ":3128", "127.0.0.1:", "127.0.0.1:http", "h:65536"])
def test_parse_listen_rejects_bad_values(value: str) -> None:
    with pytest.raises(ValueError, match="HOST:PORT"):
        nsbridge.parse_listen(value)


def test_forwards_both_directions_and_closes_cleanly(socket_path: Path) -> None:
    async def scenario(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        payload = b"x" * 300_000  # larger than one chunk
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), 10) == payload
        writer.close()
        await writer.wait_closed()

    asyncio.run(_with_bridge(socket_path, _echo, scenario))


def test_serves_several_connections_at_once(socket_path: Path) -> None:
    async def one(port: int, token: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(token)
        await writer.drain()
        answer = await asyncio.wait_for(reader.readexactly(len(token)), 10)
        writer.close()
        return answer

    async def scenario(port: int) -> None:
        tokens = [bytes([65 + n]) * 50 for n in range(5)]
        answers = await asyncio.gather(*(one(port, token) for token in tokens))
        assert answers == tokens

    asyncio.run(_with_bridge(socket_path, _echo, scenario))


def test_upstream_that_hangs_up_ends_the_connection(socket_path: Path) -> None:
    async def hang_up(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    async def scenario(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Keep sending after the far side has closed so the write fails inside the bridge.
        with contextlib.suppress(OSError):
            for _ in range(50):
                writer.write(b"y" * 100_000)
                await writer.drain()
                await asyncio.sleep(0.01)
        # The bridge closes its side: the client sees end-of-file or a reset, never a hang.
        with contextlib.suppress(OSError):
            assert await asyncio.wait_for(reader.read(), 10) == b""
        writer.close()

    asyncio.run(_with_bridge(socket_path, hang_up, scenario))


def test_unreachable_upstream_closes_the_client(
    socket_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        # A socket file with nobody listening: connecting is refused.
        with socket.socket(socket.AF_UNIX) as stale:
            stale.bind(str(socket_path))
        bridge = await nsbridge.serve("127.0.0.1", 0, str(socket_path))
        port = bridge.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(reader.read(), 10) == b""
        writer.close()
        bridge.close()
        await bridge.wait_closed()

    asyncio.run(scenario())
    assert "cannot reach" in capsys.readouterr().err


def test_missing_socket_exits_nonzero_with_a_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "none.sock"
    assert nsbridge.main(["--listen", "127.0.0.1:0", "--connect", str(missing)]) == 2
    assert str(missing) in capsys.readouterr().err


def test_bad_listen_address_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        nsbridge.main(["--listen", "nope", "--connect", "/x"])
    assert exit_info.value.code == 2
    assert "HOST:PORT" in capsys.readouterr().err


def test_run_serves_until_cancelled(socket_path: Path) -> None:
    async def scenario() -> None:
        upstream = await asyncio.start_unix_server(_echo, str(socket_path))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        task = asyncio.create_task(nsbridge._run("127.0.0.1", port, str(socket_path)))  # noqa: SLF001  # the loop main() wraps
        for _ in range(100):
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
            except OSError:
                await asyncio.sleep(0.02)
            else:
                break
        writer.write(b"ping")
        assert await asyncio.wait_for(reader.readexactly(4), 10) == b"ping"
        writer.close()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        upstream.close()
        await upstream.wait_closed()

    asyncio.run(scenario())


def test_main_serves_until_interrupted(socket_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    served: list[tuple[str, int, str]] = []

    async def interrupted(host: str, port: int, path: str) -> None:
        served.append((host, port, path))
        raise KeyboardInterrupt

    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(socket_path))
        monkeypatch.setattr(nsbridge, "_run", interrupted)
        assert nsbridge.main(["--listen", "127.0.0.1:3128", "--connect", str(socket_path)]) == 0
    assert served == [("127.0.0.1", 3128, str(socket_path))]


def test_runs_as_a_module_and_reports_a_missing_socket(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603  # fixed argument list, no shell
        [
            sys.executable,
            "-m",
            "valetkey.nsbridge",
            "--listen",
            "127.0.0.1:0",
            "--connect",
            str(tmp_path / "none.sock"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 2
    assert "no unix socket" in result.stderr


def test_imports_neither_cyclopts_nor_rich() -> None:
    code = "import sys, valetkey.nsbridge; print('cyclopts' in sys.modules, 'rich' in sys.modules)"
    result = subprocess.run(  # noqa: S603  # fixed argument list, no shell
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=30
    )
    assert result.stdout.split() == ["False", "False"]
