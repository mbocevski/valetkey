# SPDX-License-Identifier: Apache-2.0
import asyncio
import base64
import contextlib
import os
from typing import TYPE_CHECKING, Any

import pytest

from valetkey import gateway, websocket
from valetkey.websocket import Opcode, Status

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable
    from pathlib import Path

TOKEN = "t" * 32
KEY = base64.b64encode(b"0123456789abcdef").decode()
BANNER = b"RFB 003.008\n"


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 30))


# -- pure pieces ---------------------------------------------------------------------------


def head(*lines: str) -> bytes:
    return "\r\n".join(lines).encode("latin-1")


def test_parse_head_reads_the_request_line_and_lowercases_header_names() -> None:
    request = gateway.parse_head(head("GET /a/b?x=1 HTTP/1.1", "Host: 127.0.0.1:1", "X-Y:  z "))
    assert (request.method, request.target, request.path) == ("GET", "/a/b?x=1", "/a/b")
    assert request.headers == {"host": "127.0.0.1:1", "x-y": "z"}


@pytest.mark.parametrize(
    "lines",
    [
        ("GET /",),
        ("GET / SPDY/3",),
        ("GET / HTTP/1.1 extra",),
        ("GET / HTTP/1.1", "no colon here"),
        ("GET / HTTP/1.1", ": value"),
        ("GET / HTTP/1.1", "Host : spaced"),
        ("GET / HTTP/1.1", "Host: a", "host: b"),
    ],
)
def test_parse_head_refuses_a_malformed_request(lines: tuple[str, ...]) -> None:
    with pytest.raises(gateway._BadRequestError) as info:  # noqa: SLF001
        gateway.parse_head(head(*lines))
    assert info.value.status == 400


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.0.0.1:8080", True),
        ("localhost:3000", True),
        ("LOCALHOST", True),
        ("[::1]:3000", True),
        ("example.com", False),
        ("127.0.0.1.example.com", False),
        ("evil.test:80", False),
        ("", False),
        (None, False),
        ("[bad", False),
    ],
)
def test_only_a_loopback_name_is_this_machine(host: str | None, *, expected: bool) -> None:
    assert gateway.host_is_loopback(host) is expected


@pytest.mark.parametrize(
    ("origin", "host", "expected"),
    [
        (None, "127.0.0.1:5", True),
        ("http://127.0.0.1:5", "127.0.0.1:5", True),
        ("http://localhost:5", "localhost:5", True),
        ("http://LOCALHOST:5", "localhost:5", True),
        ("http://localhost:5", "127.0.0.1:5", False),
        ("http://127.0.0.1:6", "127.0.0.1:5", False),
        ("https://evil.example", "127.0.0.1:5", False),
        ("http://evil.example:5", "evil.example:5", False),
        ("null", "127.0.0.1:5", False),
        ("ftp://127.0.0.1:5", "127.0.0.1:5", False),
        ("http://127.0.0.1:5", None, False),
    ],
)
def test_an_origin_must_be_the_page_that_was_served(
    origin: str | None, host: str | None, *, expected: bool
) -> None:
    assert gateway.origin_is_page(origin, host) is expected


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / "viewer"
    (directory / "app").mkdir(parents=True)
    (directory / "vnc.html").write_text("<html>viewer</html>", encoding="utf-8")
    (directory / "app" / "ui.js").write_text("export const ui = 1;", encoding="utf-8")
    (directory / "app" / "data.bin").write_bytes(b"\x00\x01")
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    (directory / "app" / "leak.txt").symlink_to(tmp_path / "secret.txt")
    (directory / "app" / "up").symlink_to(tmp_path)
    return directory


@pytest.mark.parametrize(
    ("relative", "found"),
    [
        ("vnc.html", True),
        ("app/ui.js", True),
        ("app/%75i.js", True),
        ("app/missing.js", False),
        ("app", False),
        ("", False),
        ("app//ui.js", False),
        ("./vnc.html", False),
        ("app/../vnc.html", False),
        ("%2e%2e/secret.txt", False),
        ("app/%2e%2e/vnc.html", False),
        ("app\\ui.js", False),
        ("app/ui.js%00", False),
        ("app/leak.txt", False),
        ("app/up/secret.txt", False),
    ],
)
def test_only_a_regular_file_inside_the_viewer_is_served(
    root: Path, relative: str, *, found: bool
) -> None:
    assert (gateway.safe_file(root, relative) is not None) is found


# -- the server ----------------------------------------------------------------------------


class Display:
    """Stands in for the VNC server: sends a banner, records what it gets and echoes it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.received = b""
        self.connections = 0
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(self._handle, path=str(self.path))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        writer.write(BANNER)
        await writer.drain()
        try:
            while data := await reader.read(65536):
                self.received += data
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server.close_clients()
            await self._server.wait_closed()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Rig:
    def __init__(self, server: gateway.Gateway, display: Display, clock: Clock) -> None:
        self.gateway = server
        self.display = display
        self.clock = clock
        self.writers: list[asyncio.StreamWriter] = []
        self.cookie: str | None = None
        """The ``name=value`` the first page load set; sent with every request after sign_in."""

    async def sign_in(self) -> None:
        """Load the viewer page with the link, as the person's browser does, and keep the cookie."""
        status, headers, _ = await self.request(f"/{TOKEN}/vnc.html")
        assert status == 200
        self.cookie = headers["set-cookie"].split(";")[0]

    async def close_connections(self) -> None:
        for writer in self.writers:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.gateway.port)
        self.writers.append(writer)
        return reader, writer

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.gateway.port}"

    async def request(
        self, path: str, *, method: str = "GET", headers: dict[str, str | None] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        reader, writer = await self.open()
        lines = [f"{method} {path} HTTP/1.1", *self._headers(headers)]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
        raw = await reader.read()
        head_bytes, _, body = raw.partition(b"\r\n\r\n")
        status_line, *header_lines = head_bytes.decode().split("\r\n")
        found = {k.lower(): v for k, _, v in (line.partition(": ") for line in header_lines)}
        return int(status_line.split()[1]), found, body

    def _headers(self, headers: dict[str, str | None] | None) -> list[str]:
        merged: dict[str, str | None] = {"Host": self.host}
        if self.cookie is not None:
            merged["Cookie"] = self.cookie
        merged |= headers or {}
        return [f"{k}: {v}" for k, v in merged.items() if v is not None]

    async def connect(
        self,
        path: str | None = None,
        *,
        headers: dict[str, str | None] | None = None,
    ) -> tuple[int, dict[str, str], asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await self.open()
        extra: dict[str, Any] = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": KEY,
            "Sec-WebSocket-Version": "13",
            "Origin": f"http://{self.host}",
        } | (headers or {})
        target = path or f"/{TOKEN}/websockify"
        lines = [f"GET {target} HTTP/1.1", *self._headers(extra)]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
        head_bytes = await reader.readuntil(b"\r\n\r\n")
        status_line, *header_lines = head_bytes[:-4].decode().split("\r\n")
        found = {k.lower(): v for k, _, v in (line.partition(": ") for line in header_lines)}
        return int(status_line.split()[1]), found, reader, writer


@contextlib.asynccontextmanager
async def serving(
    root: Path,
    short_dir: Path,
    *,
    signed_in: bool = True,
    **options: Any,  # noqa: ANN401
) -> AsyncGenerator[Rig]:
    display = Display(short_dir / "vnc.sock")
    await display.start()
    clock = Clock()
    server = gateway.Gateway(display.path, root, token=TOKEN, clock=clock, **options)
    await server.start()
    rig = Rig(server, display, clock)
    try:
        if signed_in:
            await rig.sign_in()
        yield rig
    finally:
        await rig.close_connections()
        await server.close()
        await display.stop()


def masked(opcode: Opcode, payload: bytes = b"") -> bytes:
    return websocket.encode_frame(opcode, payload, mask=b"\x05\x06\x07\x08")


async def read_server_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    first, second = await reader.readexactly(2)
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), "big")
    return first & 0x0F, await reader.readexactly(length)


def test_the_link_names_the_token_and_the_socket_path(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            assert rig.gateway.url == (
                f"http://127.0.0.1:{rig.gateway.port}/{TOKEN}/vnc.html"
                f"?autoconnect=true&resize=scale&path={TOKEN}/websockify"
            )

    run(scenario())


def test_the_gateway_listens_on_loopback_only(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            server = rig.gateway._server  # noqa: SLF001
            assert server is not None
            assert [s.getsockname()[0] for s in server.sockets] == ["127.0.0.1"]

    run(scenario())


def test_the_default_token_is_192_bits_of_url_safe_text(root: Path, short_dir: Path) -> None:
    first = gateway.Gateway(short_dir / "x.sock", root)
    second = gateway.Gateway(short_dir / "x.sock", root)
    assert first.token != second.token
    assert len(base64.urlsafe_b64decode(first.token + "==")) == 24


def test_the_viewer_is_served_with_headers_that_forbid_caching_and_framing(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            for path in (f"/{TOKEN}/", f"/{TOKEN}", f"/{TOKEN}/vnc.html?autoconnect=true"):
                status, headers, body = await rig.request(path)
                assert (status, body) == (200, b"<html>viewer</html>"), path
                assert headers["content-type"] == "text/html; charset=utf-8"
                assert headers["cache-control"] == "no-store"
                assert headers["x-frame-options"] == "DENY"
                assert headers["content-security-policy"] == "frame-ancestors 'none'"
                assert headers["x-content-type-options"] == "nosniff"
                assert headers["referrer-policy"] == "no-referrer"
                assert headers["content-length"] == str(len(body))
            status, headers, _ = await rig.request(f"/{TOKEN}/app/ui.js")
            assert (status, headers["content-type"]) == (200, "text/javascript; charset=utf-8")
            assert (await rig.request(f"/{TOKEN}/app/data.bin"))[1]["content-type"] == (
                "application/octet-stream"
            )

    run(scenario())


def test_a_head_request_sends_no_body(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, headers, body = await rig.request(f"/{TOKEN}/vnc.html", method="HEAD")
            assert (status, body) == (200, b"")
            assert headers["content-length"] == str(len(b"<html>viewer</html>"))

    run(scenario())


@pytest.mark.parametrize(
    "path",
    ["/", "/vnc.html", "/wrong/vnc.html", f"/{TOKEN}x/vnc.html", f"/{TOKEN[:-1]}/vnc.html", "/ab"],
)
def test_a_wrong_or_missing_token_is_a_404_even_for_a_real_file(
    root: Path, short_dir: Path, path: str
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, headers, _ = await rig.request(path)
            assert status == 404
            assert headers["cache-control"] == "no-store"
            # A wrong token is a 404 for a WebSocket too, and before any other check.
            wrong = path.replace("vnc.html", "websockify")
            assert (await rig.request(wrong, headers={"Upgrade": "websocket"}))[0] == 404

    run(scenario())


def test_a_missing_file_with_the_right_token_is_a_404(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            for path in (f"/{TOKEN}/nothing.js", f"/{TOKEN}/app", f"/{TOKEN}/app/leak.txt"):
                assert (await rig.request(path))[0] == 404, path
            assert (await rig.request(f"/{TOKEN}/%2e%2e/secret.txt"))[0] == 404

    run(scenario())


def test_only_get_and_head_serve_files(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            assert (await rig.request(f"/{TOKEN}/vnc.html", method="POST"))[0] == 405

    run(scenario())


def test_a_host_that_is_not_loopback_is_forbidden(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, _, _ = await rig.request(f"/{TOKEN}/vnc.html", headers={"Host": "evil.test"})
            assert status == 403

    run(scenario())


def test_a_host_that_is_not_loopback_is_forbidden_for_a_websocket_too(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, _, _, writer = await rig.connect(
                headers={"Host": "evil.test", "Origin": "http://evil.test"}
            )
            assert status == 403
            writer.close()

    run(scenario())


def test_a_malformed_request_is_a_400_and_an_oversized_head_is_a_431(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            reader, writer = await rig.open()
            writer.write(b"nonsense\r\n\r\n")
            assert (await reader.read()).startswith(b"HTTP/1.1 400")
            reader, writer = await rig.open()
            writer.write(b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * (gateway.MAX_HEAD + 10))
            assert (await reader.read()).startswith(b"HTTP/1.1 431")

    run(scenario())


def test_a_client_that_never_finishes_its_request_is_dropped(
    root: Path, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway, "HEAD_TIMEOUT", 0.05)

    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            reader, writer = await rig.open()
            writer.write(b"GET / HTT")
            assert await reader.read() == b""

    run(scenario())


# -- the WebSocket -------------------------------------------------------------------------


def test_the_viewer_reaches_the_display_and_back(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, headers, reader, writer = await rig.connect(
                headers={"Sec-WebSocket-Protocol": "binary, other"}
            )
            assert status == 101
            assert headers["sec-websocket-accept"] == websocket.accept_key(KEY)
            assert headers["sec-websocket-protocol"] == "binary"
            assert headers["cache-control"] == "no-store"
            assert headers["x-frame-options"] == "DENY"
            assert await read_server_frame(reader) == (Opcode.BINARY, BANNER)
            writer.write(masked(Opcode.BINARY, b"RFB 003.008\n"))
            await writer.drain()
            assert await read_server_frame(reader) == (Opcode.BINARY, b"RFB 003.008\n")
            big = os.urandom(70000)
            writer.write(masked(Opcode.BINARY, big))
            await writer.drain()
            received = b""
            while len(received) < len(big):
                opcode, data = await read_server_frame(reader)
                assert opcode == Opcode.BINARY
                received += data
            assert received == big
            assert rig.display.received == b"RFB 003.008\n" + big
            writer.close()

    run(scenario())


def test_no_subprotocol_is_chosen_when_binary_is_not_offered(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, headers, _, writer = await rig.connect()
            assert status == 101
            assert "sec-websocket-protocol" not in headers
            writer.close()

    run(scenario())


def test_a_ping_is_answered_and_a_close_is_echoed(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, writer = await rig.connect()
            await read_server_frame(reader)  # the banner
            writer.write(masked(Opcode.PING, b"hi"))
            assert await read_server_frame(reader) == (Opcode.PONG, b"hi")
            writer.write(masked(Opcode.CLOSE, websocket.close_payload(1000)))
            opcode, payload = await read_server_frame(reader)
            assert (opcode, payload) == (Opcode.CLOSE, b"\x03\xe8")
            writer.close()

    run(scenario())


def test_a_foreign_origin_is_forbidden_and_a_missing_one_is_allowed(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, _, _, writer = await rig.connect(headers={"Origin": "https://evil.example"})
            assert status == 403
            writer.close()
            status, _, _, writer = await rig.connect(headers={"Origin": "null"})
            assert status == 403
            writer.close()
            status, _, _, writer = await rig.connect(headers={"Origin": None})
            assert status == 101
            writer.close()
            assert rig.display.connections == 1  # only the allowed one reached the display

    run(scenario())


@pytest.mark.parametrize(
    "bad",
    [
        {"Upgrade": "h2c"},
        {"Connection": "keep-alive"},
        {"Sec-WebSocket-Version": "8"},
        {"Sec-WebSocket-Key": "short"},
    ],
)
def test_a_request_that_is_not_a_websocket_handshake_is_a_400(
    root: Path, short_dir: Path, bad: dict[str, str | None]
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, _, _, writer = await rig.connect(headers=bad)
            assert status == 400
            writer.close()

    run(scenario())


def test_a_websocket_needs_get(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, _, _ = await rig.request(
                f"/{TOKEN}/websockify", method="POST", headers={"Upgrade": "websocket"}
            )
            assert status == 400

    run(scenario())


def test_a_new_viewer_takes_over_from_the_one_that_is_there(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            status, _, first_reader, first = await rig.connect()
            assert status == 101
            assert (await read_server_frame(first_reader))[1] == BANNER
            # The first viewer is still listed (a laptop that went to sleep looks like this).
            second_status, _, second_reader, second = await rig.connect()
            assert second_status == 101
            assert (await read_server_frame(second_reader))[1] == BANNER
            assert await first_reader.read() == b""  # the old viewer's connection was ended
            second.write(masked(Opcode.BINARY, b"hello"))
            assert await read_server_frame(second_reader) == (Opcode.BINARY, b"hello")
            assert rig.display.connections == 2
            first.close()
            second.close()

    run(scenario())


def test_a_viewer_without_the_cookie_cannot_take_over(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, writer = await rig.connect()
            await read_server_frame(reader)
            status, *_ = await rig.connect(headers={"Cookie": None})
            assert status == 404
            writer.write(masked(Opcode.BINARY, b"still here"))
            assert await read_server_frame(reader) == (Opcode.BINARY, b"still here")
            writer.close()

    run(scenario())


def test_no_new_connection_after_the_lifetime_but_a_viewer_stays(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir, lifetime=600.0) as rig:
            assert not rig.gateway.expired
            status, _, reader, writer = await rig.connect()
            assert status == 101
            await read_server_frame(reader)
            rig.clock.now += 599
            assert (await rig.request(f"/{TOKEN}/vnc.html"))[0] == 200
            rig.clock.now += 2
            assert rig.gateway.expired
            assert (await rig.request(f"/{TOKEN}/vnc.html"))[0] == 404
            status, _, _, late = await rig.connect()
            assert status == 404
            late.close()
            writer.write(masked(Opcode.BINARY, b"still here"))
            await writer.drain()
            assert await read_server_frame(reader) == (Opcode.BINARY, b"still here")
            writer.close()

    run(scenario())


def test_a_text_frame_is_refused_as_unsupported(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, writer = await rig.connect()
            await read_server_frame(reader)
            writer.write(masked(Opcode.TEXT, b"hello"))
            opcode, payload = await read_server_frame(reader)
            assert (opcode, int.from_bytes(payload[:2], "big")) == (
                Opcode.CLOSE,
                Status.UNSUPPORTED,
            )
            writer.close()

    run(scenario())


def test_an_unmasked_frame_ends_the_connection_with_a_protocol_error(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, writer = await rig.connect()
            await read_server_frame(reader)
            writer.write(websocket.encode_frame(Opcode.BINARY, b"x"))
            opcode, payload = await read_server_frame(reader)
            assert (opcode, int.from_bytes(payload[:2], "big")) == (
                Opcode.CLOSE,
                Status.PROTOCOL_ERROR,
            )
            writer.close()

    run(scenario())


def test_a_viewer_that_vanishes_frees_the_slot(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, writer = await rig.connect()
            await read_server_frame(reader)
            writer.close()
            for _ in range(100):
                status, _, _, again = await rig.connect()
                again.close()
                if status == 101:
                    break
                await asyncio.sleep(0.02)
            assert status == 101

    run(scenario())


def test_the_end_of_the_display_closes_the_viewer(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, writer = await rig.connect()
            await read_server_frame(reader)
            await rig.display.stop()
            opcode, payload = await read_server_frame(reader)
            assert (opcode, int.from_bytes(payload[:2], "big")) == (Opcode.CLOSE, Status.GOING_AWAY)
            writer.close()

    run(scenario())


def test_a_missing_display_is_a_502(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            await rig.display.stop()
            await asyncio.to_thread(rig.display.path.unlink, missing_ok=True)
            status, _, _, writer = await rig.connect()
            assert status == 502
            writer.close()
            # The refused attempt did not use up the single viewer slot.
            assert not rig.gateway._viewer  # noqa: SLF001

    run(scenario())


def test_closing_the_gateway_ends_a_viewer_and_stops_listening(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            _, _, reader, _ = await rig.connect()
            await read_server_frame(reader)
            await rig.gateway.close()
            assert await reader.read() == b""
            with pytest.raises(OSError):  # noqa: PT011 - nothing listens any more
                await asyncio.open_connection("127.0.0.1", rig.gateway.port)
            await rig.gateway.close()  # safe to repeat

    run(scenario())


# -- the link works once, then the cookie is the credential -----------------------------------


def test_the_first_page_load_spends_the_link_and_sets_a_cookie(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir, signed_in=False) as rig:
            status, headers, body = await rig.request(f"/{TOKEN}/vnc.html")
            assert (status, body) == (200, b"<html>viewer</html>")
            name, _, rest = headers["set-cookie"].partition("=")
            value, *attributes = rest.split("; ")
            assert name == gateway.COOKIE
            assert len(base64.urlsafe_b64decode(value + "==")) == 24
            assert value != TOKEN
            assert sorted(attributes) == sorted(
                ["Path=/" + TOKEN + "/", "HttpOnly", "SameSite=Strict"]
            )
            # The same link again, without the cookie, is refused as if it never worked.
            for path in (f"/{TOKEN}/vnc.html", f"/{TOKEN}/", f"/{TOKEN}"):
                assert (await rig.request(path))[0] == 404, path
            # With the cookie the page can be loaded again, and sets nothing new.
            status, headers, _ = await rig.request(
                f"/{TOKEN}/vnc.html", headers={"Cookie": f"{name}={value}"}
            )
            assert status == 200
            assert "set-cookie" not in headers

    run(scenario())


def test_nothing_but_the_page_answers_without_the_cookie(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir, signed_in=False) as rig:
            for path in (f"/{TOKEN}/app/ui.js", f"/{TOKEN}/app/data.bin", f"/{TOKEN}/websockify"):
                assert (await rig.request(path))[0] == 404, path
            status, *_ = await rig.connect()
            assert status == 404
            assert rig.display.connections == 0
            # None of that spent the link.
            assert (await rig.request(f"/{TOKEN}/vnc.html"))[0] == 200

    run(scenario())


@pytest.mark.parametrize(
    "cookie",
    [
        f"{gateway.COOKIE}=wrong",
        f"{gateway.COOKIE}=",
        "other=value",
        gateway.COOKIE,
        "x; y=z",
        None,
    ],
)
def test_a_missing_or_wrong_cookie_is_refused_on_every_path(
    root: Path, short_dir: Path, cookie: str | None
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            headers: dict[str, str | None] = {"Cookie": cookie}
            for path in (f"/{TOKEN}/vnc.html", f"/{TOKEN}/app/ui.js"):
                assert (await rig.request(path, headers=headers))[0] == 404, path
            assert (await rig.connect(headers=headers))[0] == 404

    run(scenario())


def test_the_cookie_among_other_cookies_is_found(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            assert rig.cookie is not None
            headers: dict[str, str | None] = {"Cookie": f"a=b; {rig.cookie}; c=d"}
            assert (await rig.request(f"/{TOKEN}/app/ui.js", headers=headers))[0] == 200

    run(scenario())


def test_a_head_request_for_the_page_does_not_spend_the_link(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir, signed_in=False) as rig:
            status, headers, body = await rig.request(f"/{TOKEN}/vnc.html", method="HEAD")
            assert (status, body) == (200, b"")
            assert "set-cookie" not in headers
            assert (await rig.request(f"/{TOKEN}/vnc.html"))[0] == 200

    run(scenario())


def test_a_wrong_token_with_the_right_cookie_is_still_a_404(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            assert (await rig.request("/x" * 16 + "/vnc.html"))[0] == 404
            assert (await rig.request(f"/{'x' * 32}/app/ui.js"))[0] == 404

    run(scenario())


# -- connections, silence and pings ----------------------------------------------------------


def test_more_connections_than_the_cap_are_closed_without_an_answer(
    root: Path, short_dir: Path
) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir) as rig:
            held = [await rig.open() for _ in range(gateway.MAX_CONNECTIONS)]
            await asyncio.sleep(0.05)
            refused = 0
            for _ in range(1100):
                reader, writer = await rig.open()
                if await asyncio.wait_for(reader.read(), 5) == b"":
                    refused += 1
                writer.close()
            assert refused == 1100
            # The event loop and the listener are fine: free the held ones and ask normally.
            for _, writer in held:
                writer.close()
            for _ in range(100):
                status, *_ = await rig.request(f"/{TOKEN}/vnc.html")
                if status == 200:
                    break
                await asyncio.sleep(0.02)
            assert status == 200

    run(scenario())


def test_a_silent_viewer_is_pinged_and_then_dropped(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir, ping_interval=0.05, idle_limit=0.3) as rig:
            _, _, reader, writer = await rig.connect()
            frames = [await read_server_frame(reader)]
            while frames[-1][0] != Opcode.CLOSE:
                frames.append(await asyncio.wait_for(read_server_frame(reader), 5))
            opcodes = [opcode for opcode, _ in frames]
            assert opcodes[0] == Opcode.BINARY  # the display's banner
            assert opcodes.count(Opcode.PING) >= 3
            assert int.from_bytes(frames[-1][1][:2], "big") == Status.GOING_AWAY
            assert await asyncio.wait_for(reader.read(), 5) == b""
            writer.close()
            # The slot is free for the next viewer.
            status, *_ = await rig.connect()
            assert status == 101

    run(scenario())


def test_a_viewer_that_answers_the_pings_is_kept(root: Path, short_dir: Path) -> None:
    async def scenario() -> None:
        async with serving(root, short_dir, ping_interval=0.05, idle_limit=0.3) as rig:
            _, _, reader, writer = await rig.connect()
            pongs = 0
            deadline = asyncio.get_running_loop().time() + 1.0  # more than three times the limit
            while asyncio.get_running_loop().time() < deadline:
                opcode, payload = await asyncio.wait_for(read_server_frame(reader), 5)
                assert opcode != Opcode.CLOSE
                if opcode == Opcode.PING:
                    writer.write(masked(Opcode.PONG, payload))
                    pongs += 1
            assert pongs >= 10
            writer.write(masked(Opcode.BINARY, b"alive"))
            while (frame := await read_server_frame(reader))[0] == Opcode.PING:
                pass
            assert frame == (Opcode.BINARY, b"alive")
            writer.close()

    run(scenario())
