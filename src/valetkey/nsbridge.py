# SPDX-License-Identifier: Apache-2.0
"""Forward TCP connections inside the network namespace to the proxy's unix socket.

The browser's namespace has no network interface, so the only way out is a unix socket on disk.
This module runs inside the namespace, listens on a loopback TCP port the browser uses as its
proxy, and splices every connection to a new connection on that socket.

It starts for every session, so it imports only the standard library, and not the command-line
framework the rest of the package uses.

Run it as ``python -m valetkey.nsbridge --listen 127.0.0.1:3128 --connect /path/to/proxy.sock``.
"""

import argparse
import asyncio
import contextlib
import sys
from pathlib import Path

_CHUNK = 65536
_MAX_PORT = 65535


def parse_listen(value: str) -> tuple[str, int]:
    """Split ``HOST:PORT`` into a host and a port.

    Raises ``ValueError`` when the port is missing or is not a number from 0 to 65535.
    """
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdecimal() or int(port) > _MAX_PORT:
        message = f"expected HOST:PORT, got {value!r}"
        raise ValueError(message)
    return host, int(port)


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy bytes from ``reader`` to ``writer`` until EOF, then half-close ``writer``."""
    try:
        while chunk := await reader.read(_CHUNK):
            writer.write(chunk)
            await writer.drain()
        writer.write_eof()
    except OSError:
        # The peer went away mid-transfer. Closing this side ends the opposite pump too.
        writer.close()


async def _splice(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    socket_path: str,
) -> None:
    """Connect to ``socket_path`` and relay both directions until each side has closed."""
    try:
        upstream_reader, upstream_writer = await asyncio.open_unix_connection(socket_path)
    except OSError as error:
        sys.stderr.write(f"nsbridge: cannot reach {socket_path}: {error}\n")
        client_writer.close()
        return
    try:
        await asyncio.gather(
            _pump(client_reader, upstream_writer),
            _pump(upstream_reader, client_writer),
        )
    finally:
        for writer in (client_writer, upstream_writer):
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


async def serve(host: str, port: int, socket_path: str) -> asyncio.Server:
    """Start listening on ``host:port`` and forward each connection to ``socket_path``.

    Returns the running server. Pass port 0 to take a free port and read it from
    ``server.sockets``.
    """

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _splice(reader, writer, socket_path)

    return await asyncio.start_server(handle, host, port)


async def _run(host: str, port: int, socket_path: str) -> None:
    server = await serve(host, port, socket_path)
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    """Run the bridge until it is killed. Return 2 for a missing socket, else 0."""
    parser = argparse.ArgumentParser(prog="nsbridge", description=__doc__.splitlines()[0])
    parser.add_argument("--listen", required=True, help="HOST:PORT to accept connections on")
    parser.add_argument("--connect", required=True, help="path of the proxy's unix socket")
    args = parser.parse_args(argv)
    try:
        host, port = parse_listen(args.listen)
    except ValueError as error:
        parser.error(str(error))
    if not Path(args.connect).is_socket():
        sys.stderr.write(f"nsbridge: no unix socket at {args.connect}\n")
        return 2
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run(host, port, args.connect))
    return 0


if __name__ == "__main__":
    sys.exit(main())
