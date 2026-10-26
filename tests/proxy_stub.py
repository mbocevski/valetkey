# SPDX-License-Identifier: Apache-2.0
"""Test doubles for the proxy and the sites behind it. Not the real allowlisting proxy."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Self
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from pathlib import Path

    from valetkey.proxy import Proxy


def host_of_request(head: str) -> str:
    """The host a proxy request asks for: ``CONNECT host:443`` or ``GET http://host/path``."""
    target = head.split(maxsplit=2)[1]
    if "://" in target:
        return urlsplit(target).hostname or ""
    return target.rsplit(":", 1)[0]


class ProxyStub:
    """A stand-in for the proxy that listens on a Unix socket.

    Without ``upstream`` it answers every plain HTTP request with one canned page. With
    ``upstream`` (host and port of a local web server) it relays plain HTTP requests there,
    whatever host the browser asked for, and refuses ``CONNECT``.
    """

    def __init__(self, path: Path, upstream: tuple[str, int] | None = None) -> None:
        self.path = path
        self.upstream = upstream
        self.requests: list[str] = []
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode()
        except asyncio.IncompleteReadError:
            writer.close()  # Chrome opens spare connections it never uses
            return
        self.requests.append(head)
        if self.upstream is None:
            body = b"<html><body>proxied page</body></html>"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
        elif head.startswith("CONNECT "):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        else:
            await self._relay(head, writer)
        await writer.drain()
        writer.close()

    async def _relay(self, head: str, writer: asyncio.StreamWriter) -> None:
        assert self.upstream is not None
        request_line, *headers = head.split("\r\n")
        method, target, version = request_line.split(" ")
        parts = urlsplit(target)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        kept = [h for h in headers if h and not h.lower().startswith(("proxy-", "connection:"))]
        request = "\r\n".join([f"{method} {path} {version}", *kept, "Connection: close", "", ""])
        up_reader, up_writer = await asyncio.open_connection(*self.upstream)
        up_writer.write(request.encode())
        await up_writer.drain()
        writer.write(await up_reader.read())
        up_writer.close()

    def _serve(self) -> None:
        asyncio.set_event_loop(self._loop)
        server = self._loop.run_until_complete(
            asyncio.start_unix_server(self._handle, str(self.path))
        )
        self._ready.set()
        self._loop.run_forever()
        server.close()
        self._loop.run_until_complete(server.wait_closed())

    def __enter__(self) -> Self:
        self._thread.start()
        assert self._ready.wait(10)
        return self

    def __exit__(self, *_: object) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self._loop.close()


class PageServer:
    """A local web server for fixed pages, redirects and files, on a free loopback port.

    ``files`` maps a path to the headers and body to answer with, byte for byte, so a test can
    send any ``Content-Disposition`` or ``Content-Type`` it likes.
    """

    def __init__(
        self,
        pages: dict[str, str],
        redirects: dict[str, str] | None = None,
        files: dict[str, tuple[dict[str, str], bytes]] | None = None,
    ) -> None:
        encoded = {path: html.encode() for path, html in pages.items()}
        moved = redirects or {}
        served = files or {}
        self.hits: list[str] = []
        """The path of every request the server received."""
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                if self.path in moved:
                    self.send_response(302)
                    self.send_header("Location", moved[self.path])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.split("?", 1)[0] in served:
                    headers, content = served[self.path.split("?", 1)[0]]
                    self.send_response(200)
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                body = encoded.get(self.path)
                self.send_response(200 if body is not None else 404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body or b"not found")

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002  # signature of the base class
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        """Host and port the server listens on."""
        host, port = self._server.server_address[:2]
        return str(host), port

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(10)


class RunningProxy:
    """The real allowlisting proxy, running on its own event loop in a thread."""

    def __init__(self, proxy: Proxy, socket_path: Path) -> None:
        self.proxy = proxy
        self.socket_path = socket_path
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        self._stop = asyncio.Event()
        async with self.proxy.serving(self.socket_path):
            self._ready.set()
            await self._stop.wait()

    def refused(self) -> set[tuple[str, int]]:
        """Every ``(host, port)`` the proxy has refused and reported so far."""
        return {(r.host, r.port) for r in self.proxy.refused_since(0)[0]}

    def __enter__(self) -> Self:
        self._thread.start()
        assert self._ready.wait(10)
        return self

    def __exit__(self, *_: object) -> None:
        stop = self._stop
        assert stop is not None
        self._loop.call_soon_threadsafe(stop.set)
        self._thread.join(10)
        self._loop.close()
