# SPDX-License-Identifier: Apache-2.0
"""A small web server that lets one person watch and drive a login window from a browser.

The login's browser runs on a private display that a VNC server shares over a unix socket (see
:mod:`valetkey.display`). This gateway is the only thing that listens on the network, and it
listens on ``127.0.0.1`` alone, so a remote person reaches it with ``ssh -L`` and nothing else
is exposed. It serves a pinned copy of noVNC, the viewer, and passes the viewer's WebSocket to
the VNC server's socket.

The link is the credential: a 192-bit random token is the first part of every path. It works
once. The first load of the viewer page uses it up and sets a cookie holding a second random value
(``HttpOnly``, ``SameSite=Strict``, limited to the token's path). Every other request, the
WebSocket included, must present that cookie. A link that someone copies out of a log after the
person has opened it is worth nothing. Rules:

* A path without the token, or with a wrong one, is ``404``, whatever else is wrong with it.
* So is a request for anything but the page, or for the page a second time, without the cookie.
* A request whose ``Host`` is not a loopback name is ``403``: it comes through a name that
  someone else controls, which is how DNS rebinding reaches a local service.
* A WebSocket whose ``Origin`` is not the page that was served is ``403``. A page on another
  site cannot drive the viewer, even in a browser that holds the link.
* One viewer at a time. A new viewer that has the cookie takes over: the old one is closed, so a
  laptop that went to sleep does not lock its owner out.
* The gateway sends a ping every 30 seconds and drops a viewer that has sent nothing for 90.
* At most 8 connections at once. One more is closed without an answer.
* No new connection after ``lifetime`` seconds (ten minutes): everything is ``404`` from then on.
  A viewer that is already connected keeps its connection.
* Every response says ``Cache-Control: no-store`` and refuses to be framed.

The gateway never decodes the VNC protocol. It cuts bytes from the socket into binary frames
and puts the bytes of binary frames on the socket.
"""

import asyncio
import contextlib
import hmac
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from valetkey import websocket
from valetkey.websocket import Opcode, ProtocolError, Status

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

LIFETIME = 600.0
"""Seconds after the gateway starts during which a new connection is accepted."""
PING_INTERVAL = 30.0
"""Seconds between the pings sent to a viewer."""
IDLE_LIMIT = 90.0
"""Seconds of silence from a viewer, pongs included, after which it is dropped."""
MAX_CONNECTIONS = 8
"""Connections served at once, a viewer's WebSocket included."""
HEAD_TIMEOUT = 10.0
"""Seconds a client has to send its request line and headers."""
MAX_HEAD = 16 * 1024
CHUNK = 64 * 1024
COOKIE = "valetkey_viewer"
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})
INDEX = "vnc.html"
VIEWER_PARAMETERS = "autoconnect=true&resize=scale"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
_REASONS = {
    101: "Switching Protocols",
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
}

type Connector = Callable[
    [Path], "asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]]"
]


class _BadRequestError(Exception):
    """A request that cannot be served; ``status`` is the HTTP status to answer with."""

    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(message or _REASONS[status])
        self.status = status


class Request:
    """The request line and headers of one HTTP request."""

    def __init__(self, method: str, target: str, headers: Mapping[str, str]) -> None:
        """Keep the parts; header names are lower case."""
        self.method = method
        self.target = target
        self.headers = headers

    @property
    def path(self) -> str:
        """The path of the target, without the query, and still percent-encoded."""
        return urlsplit(self.target).path


def parse_head(head: bytes) -> Request:
    """Parse the request line and headers that end with a blank line.

    Raises:
        _BadRequestError: for anything but a plain HTTP/1.x request with well-formed headers.

    """
    text = head.decode("latin-1")  # every byte is a character, so this cannot fail
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):  # noqa: PLR2004 - method, target, version
        raise _BadRequestError(400)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not name or name != name.strip():
            raise _BadRequestError(400)
        key = name.lower()
        if key in headers:
            raise _BadRequestError(400, f"{key} is given twice")
        headers[key] = value.strip()
    return Request(parts[0], parts[1], headers)


def host_is_loopback(host_header: str | None) -> bool:
    """Tell whether a ``Host`` header names this machine's loopback, with or without a port."""
    if not host_header:
        return False
    try:
        name = urlsplit(f"//{host_header}").hostname
    except ValueError:
        return False
    return name in LOOPBACK_NAMES


def origin_is_page(origin: str | None, host_header: str | None) -> bool:
    """Tell whether ``origin`` is the page the viewer was served from.

    A browser sends the ``Origin`` of the page that opens a WebSocket. It must be on the same
    authority as the ``Host`` the request used, and a loopback one. No ``Origin`` at all is a
    program, not a browser page, and is let through: it has the link or it has nothing.
    """
    if origin is None:
        return True
    parts = urlsplit(origin)
    return (
        parts.scheme in {"http", "https"}
        and host_is_loopback(parts.netloc)
        and parts.netloc.lower() == (host_header or "").lower()
    )


def safe_file(root: Path, relative: str) -> Path | None:
    """Return the file under ``root`` that the URL path ``relative`` names, or ``None``.

    The path is decoded once. Empty segments, ``.``, ``..``, backslashes and NUL bytes are
    refused, and the result must be a regular file that really lies inside ``root``, so a link
    in the tree cannot lead out of it.
    """
    decoded = unquote(relative)
    segments = decoded.split("/")
    if any(s in {"", ".", ".."} or "\\" in s or "\0" in s for s in segments):
        return None
    candidate = root.joinpath(*segments)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(root.resolve()):
        return None
    return resolved


async def _unix_connect(path: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_unix_connection(path)


class Gateway:
    """The listener: serves the viewer and joins its WebSocket to the VNC server's socket."""

    def __init__(  # noqa: PLR0913 - each is a seam the tests replace
        self,
        vnc_socket: Path,
        root: Path,
        *,
        token: str | None = None,
        lifetime: float = LIFETIME,
        ping_interval: float = PING_INTERVAL,
        idle_limit: float = IDLE_LIMIT,
        clock: Callable[[], float] = time.monotonic,
        connector: Callable[
            [Path], asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]]
        ]
        | None = None,
    ) -> None:
        """Prepare a gateway for the VNC socket at ``vnc_socket`` and the viewer files in ``root``.

        ``token`` defaults to 24 random bytes (192 bits). Nothing listens until :meth:`start`.
        """
        self.token = token or secrets.token_urlsafe(24)
        self.port = 0
        self._vnc_socket = vnc_socket
        self._root = root
        self._lifetime = lifetime
        self._ping_interval = ping_interval
        self._idle_limit = idle_limit
        self._clock = clock
        self._connect = connector or _unix_connect
        self._server: asyncio.Server | None = None
        self._deadline = 0.0
        self._viewer: asyncio.Task[None] | None = None
        self._used = False
        self._cookie = secrets.token_urlsafe(24)
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def url(self) -> str:
        """The link that opens the viewer and connects it."""
        base = f"http://127.0.0.1:{self.port}/{self.token}"
        return f"{base}/{INDEX}?{VIEWER_PARAMETERS}&path={self.token}/websockify"

    async def start(self) -> int:
        """Listen on ``127.0.0.1`` on a free port and return it."""
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_HEAD)
        self.port = self._server.sockets[0].getsockname()[1]
        self._deadline = self._clock() + self._lifetime
        return self.port

    async def close(self) -> None:
        """Stop listening and end every connection, a viewer's included."""
        if self._server is not None:
            self._server.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    @property
    def expired(self) -> bool:
        """Whether the time for new connections is over."""
        return self._clock() >= self._deadline

    # -- one connection --

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None  # noqa: S101 - a handler always runs in a task
        if len(self._tasks) >= MAX_CONNECTIONS:
            writer.close()  # no answer: whoever is holding the other connections open gets none
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            return
        self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        except ConnectionError, asyncio.IncompleteReadError, TimeoutError:
            pass  # the client went away, or was too slow to speak
        finally:
            self._tasks.discard(task)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await self._read_request(reader)
            await self._route(request, reader, writer)
        except _BadRequestError as error:
            await _respond(writer, error.status, str(error).encode())

    async def _read_request(self, reader: asyncio.StreamReader) -> Request:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
        except asyncio.LimitOverrunError:
            raise _BadRequestError(431) from None
        return parse_head(head[:-4])

    async def _route(
        self, request: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        relative = self._relative_path(request)
        if relative is None:
            raise _BadRequestError(404)
        if not host_is_loopback(request.headers.get("host")):
            raise _BadRequestError(403, "the request does not name this machine's loopback address")
        has_cookie = self._has_cookie(request)
        is_page = relative in {"", INDEX}
        if not has_cookie and not (is_page and not self._used):
            raise _BadRequestError(404)
        if relative == "websockify":
            await self._websocket(request, reader, writer)
            return
        if request.method not in {"GET", "HEAD"}:
            raise _BadRequestError(405)
        path = safe_file(self._root, relative or INDEX)
        if path is None:
            raise _BadRequestError(404)
        body = await asyncio.to_thread(path.read_bytes)
        headers = {
            "Content-Type": CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")
        }
        if is_page and not has_cookie and request.method == "GET":
            self._used = True  # the link is spent by the first page that is sent
            headers["Set-Cookie"] = (
                f"{COOKIE}={self._cookie}; Path=/{self.token}/; HttpOnly; SameSite=Strict"
            )
        await _respond(writer, 200, body, headers, head_only=request.method == "HEAD")

    def _has_cookie(self, request: Request) -> bool:
        """Tell whether the request carries the cookie that the first page load set."""
        for part in request.headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE and hmac.compare_digest(value.encode(), self._cookie.encode()):
                return True
        return False

    def _relative_path(self, request: Request) -> str | None:
        """Return the part of the path after the token, or ``None`` for a 404.

        The token is compared in constant time. After ``lifetime`` there is no valid path.
        """
        first, _, rest = request.path.removeprefix("/").partition("/")
        if self.expired or not hmac.compare_digest(first.encode(), self.token.encode()):
            return None
        return rest

    async def _websocket(
        self, request: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        headers = request.headers
        if not origin_is_page(headers.get("origin"), headers.get("host")):
            raise _BadRequestError(403, "this page is not the one that was served")
        key = headers.get("sec-websocket-key", "")
        upgrade = "websocket" in headers.get("upgrade", "").lower()
        connection = "upgrade" in headers.get("connection", "").lower()
        ok = (
            request.method == "GET"
            and upgrade
            and connection
            and headers.get("sec-websocket-version") == "13"
            and websocket.valid_key(key)
        )
        if not ok:
            raise _BadRequestError(400, "not a WebSocket handshake")
        await self._replace_viewer()
        self._viewer = asyncio.current_task()
        try:
            await self._splice(headers, key, reader, writer)
        finally:
            self._viewer = None  # a newer viewer waits for this one to end before it registers

    async def _replace_viewer(self) -> None:
        """End the viewer that is connected, if any, before a new one takes its place.

        Whoever has the cookie is the person the link was for. A viewer that is still listed
        after the person's laptop slept is not someone else, and must not keep them out.
        """
        if (old := self._viewer) is not None:
            old.cancel()
            await asyncio.wait({old})

    async def _splice(
        self,
        headers: Mapping[str, str],
        key: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            vnc_reader, vnc_writer = await self._connect(self._vnc_socket)
        except OSError:
            raise _BadRequestError(502, "the display is not running") from None
        reply = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Accept": websocket.accept_key(key),
        }
        offered = [p.strip() for p in headers.get("sec-websocket-protocol", "").split(",")]
        if "binary" in offered:
            reply["Sec-WebSocket-Protocol"] = "binary"
        await _respond(writer, 101, b"", reply, status_only=True)
        try:
            await _pump(
                reader, writer, vnc_reader, vnc_writer, (self._ping_interval, self._idle_limit)
            )
        finally:
            vnc_writer.close()
            with contextlib.suppress(OSError):
                await vnc_writer.wait_closed()


class _Pipe:
    """The two ends of one viewer's connection, and the three jobs that keep them in step."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        vnc_reader: asyncio.StreamReader,
        vnc_writer: asyncio.StreamWriter,
        keepalive: tuple[float, float],
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._vnc_reader = vnc_reader
        self._vnc_writer = vnc_writer
        self._interval, self._limit = keepalive
        self._loop = asyncio.get_running_loop()
        self._heard = self._loop.time()

    def _note(self) -> None:
        self._heard = self._loop.time()

    async def to_viewer(self) -> Status:
        """Send what the display says to the viewer, in binary frames."""
        while data := await self._vnc_reader.read(CHUNK):
            self._writer.write(websocket.encode_frame(Opcode.BINARY, data))
            await self._writer.drain()
        return Status.GOING_AWAY

    async def to_display(self) -> Status:
        """Give the display what the viewer sends."""
        while True:
            try:
                message = await websocket.read_message(
                    self._reader, self._writer, on_frame=self._note
                )
            except ProtocolError as error:
                return error.status
            if message is None:
                return Status.NORMAL
            opcode, payload = message
            if opcode is not Opcode.BINARY:
                return Status.UNSUPPORTED
            self._vnc_writer.write(payload)
            await self._vnc_writer.drain()

    def _silence(self) -> float:
        return self._loop.time() - self._heard

    async def watch(self) -> Status:
        """Ping the viewer, and give up on it once it has sent nothing for the limit."""
        while self._silence() < self._limit:
            await asyncio.sleep(min(self._interval, self._limit - self._silence()))
            if self._silence() < self._limit:
                self._writer.write(websocket.encode_frame(Opcode.PING, b""))
                await self._writer.drain()
        return Status.GOING_AWAY


async def _pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    vnc_reader: asyncio.StreamReader,
    vnc_writer: asyncio.StreamWriter,
    keepalive: tuple[float, float],
) -> None:
    """Copy between the WebSocket and the VNC socket until either side ends or the viewer is gone.

    ``keepalive`` is the ping interval and the silence after which the viewer is dropped.
    """
    pipe = _Pipe(reader, writer, vnc_reader, vnc_writer, keepalive)
    tasks = [
        asyncio.ensure_future(pipe.to_viewer()),
        asyncio.ensure_future(pipe.to_display()),
        asyncio.ensure_future(pipe.watch()),
    ]
    status = Status.NORMAL
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            with contextlib.suppress(ConnectionError, asyncio.IncompleteReadError):
                status = task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    with contextlib.suppress(ConnectionError):
        writer.write(websocket.encode_frame(Opcode.CLOSE, websocket.close_payload(status)))
        await writer.drain()


async def _respond(  # noqa: PLR0913 - a response is a status, a body, headers and two flags
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    headers: Mapping[str, str] | None = None,
    *,
    head_only: bool = False,
    status_only: bool = False,
) -> None:
    """Write one response with the security headers, and flush it."""
    lines = [
        f"HTTP/1.1 {status} {_REASONS[status]}",
        *(f"{k}: {v}" for k, v in SECURITY_HEADERS.items()),
    ]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    if not status_only:
        lines += [f"Content-Length: {len(body)}", "Connection: close"]
        if "Content-Type" not in (headers or {}):
            lines.append("Content-Type: text/plain; charset=utf-8")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    writer.write(head if head_only or status_only else head + body)
    with contextlib.suppress(ConnectionError):
        await writer.drain()
