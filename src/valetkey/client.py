# SPDX-License-Identifier: Apache-2.0
"""The client of ``valetkeyd``: what the MCP adapter and the command-line tool talk through.

The daemon speaks newline-delimited JSON on a Unix socket. A request is
``{"id": 1, "op": "snapshot", "args": {"site": "sitex"}}`` and the answer to it is
``{"id": 1, "ok": true, "result": {...}}`` or
``{"id": 1, "ok": false, "error": {"code": "...", "message": "..."}}``. :class:`Client` sends
requests, matches answers by id, and turns error answers into :class:`DaemonError`. Several
calls may be in flight on one client at once.
"""

import asyncio
import contextlib
import itertools
import json
from typing import TYPE_CHECKING, Any, Self

from valetkey import sites

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

SOCKET_NAME = "daemon.sock"
MAX_LINE_BYTES = 1024 * 1024
"""The longest request line the daemon accepts."""
_LOST = "the connection to valetkeyd was lost"
_READ_LIMIT = 64 * 1024 * 1024
"""The longest answer line the client accepts (a snapshot of a large page)."""


class DaemonError(Exception):
    """The daemon answered a request with an error, or could not be reached.

    ``code`` is a short machine-readable name such as ``unknown_site`` or ``session_running``,
    ``message`` is for people, and ``details`` holds extra fields the daemon sent with it.
    """

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        """Keep the code, the message and any details."""
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}

    def to_json(self) -> dict[str, Any]:
        """Return the error as it travels in an answer."""
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return error


def socket_path(roots: sites.Roots | None = None) -> Path:
    """Return where the daemon listens: ``$XDG_RUNTIME_DIR/valetkey/daemon.sock``.

    Raises:
        RuntimeDirUnavailableError: when ``XDG_RUNTIME_DIR`` is unset.

    """
    return sites.runtime_path(roots or sites.roots_from_env()) / SOCKET_NAME


async def is_running(path: Path | None = None) -> bool:
    """Tell whether a daemon is listening on ``path`` (default: :func:`socket_path`)."""
    try:
        client = await Client.connect(path)
    except DaemonError:
        return False
    await client.close()
    return True


class Client:
    """A connection to the daemon. Get one with :meth:`connect`."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Wrap an open connection; use :meth:`connect` instead of calling this."""
        self._writer = writer
        self._ids = itertools.count(1)
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task = asyncio.ensure_future(self._read_answers(reader))

    @classmethod
    async def connect(cls, path: Path | None = None) -> Self:
        """Connect to the daemon on ``path`` (default: :func:`socket_path`).

        Raises:
            DaemonError: with code ``not_running`` when nothing listens there.

        """
        target = path or socket_path()
        try:
            reader, writer = await asyncio.open_unix_connection(target, limit=_READ_LIMIT)
        except OSError as error:
            message = f"valetkeyd is not running ({target}: {error.strerror or error})"
            code = "not_running"
            raise DaemonError(code, message) from error
        return cls(reader, writer)

    async def call(self, op: str, **args: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON values
        """Send ``op`` with ``args`` and return the ``result`` of the answer.

        Raises:
            DaemonError: for an error answer (its code and message are the daemon's), or with
                code ``connection_lost`` if the connection ends before the answer arrives.

        """
        identifier = next(self._ids)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[identifier] = future
        line = json.dumps({"id": identifier, "op": op, "args": args}).encode() + b"\n"
        try:
            self._writer.write(line)
            await self._writer.drain()
        except OSError as error:
            self._pending.pop(identifier, None)
            code = "connection_lost"
            raise DaemonError(code, _LOST) from error
        try:
            return await future
        finally:
            self._pending.pop(identifier, None)

    async def close(self) -> None:
        """Close the connection. Calls still waiting fail with ``connection_lost``."""
        self._writer.close()
        with contextlib.suppress(OSError):
            await self._writer.wait_closed()
        await asyncio.gather(self._reader_task, return_exceptions=True)

    async def __aenter__(self) -> Self:
        """Return the client; leaving the ``async with`` block closes it."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the connection."""
        await self.close()

    async def _read_answers(self, reader: asyncio.StreamReader) -> None:
        """Hand each answer to the call waiting for it; fail all calls when the stream ends."""
        try:
            while line := await reader.readline():
                self._deliver(line)
        except OSError, ValueError:
            pass  # a broken or oversized stream ends the connection like a closed one
        finally:
            lost = DaemonError("connection_lost", _LOST)
            for future in list(self._pending.values()):
                with contextlib.suppress(asyncio.InvalidStateError):  # already answered
                    future.set_exception(lost)

    def _deliver(self, line: bytes) -> None:
        try:
            answer = json.loads(line)
            future = self._pending.get(answer["id"])
        except ValueError, KeyError, TypeError:
            return  # not an answer to anything this client sent
        if future is None or future.done():
            return
        if answer.get("ok") is True:
            future.set_result(answer.get("result") or {})
            return
        error = answer.get("error") or {}
        future.set_exception(
            DaemonError(
                str(error.get("code", "error")),
                str(error.get("message", "")),
                error.get("details"),
            )
        )
